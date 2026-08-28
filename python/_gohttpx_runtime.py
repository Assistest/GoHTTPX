import asyncio
import atexit
import json
import logging
import math
import os
import queue
import secrets
import subprocess
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

import httpx

if sys.platform == "win32":
    # Windows 原生句柄不能在其他平台导入；外部服务模式仍可跨平台使用。
    from _gohttpx_windows import JobProcess


INSTANCE_HEADER = "X-GoHTTPX-Instance"
_logger = logging.getLogger("gohttpx.runtime")
_logger.addHandler(logging.NullHandler())


class RuntimeUnavailable(Exception):
    pass


class RuntimeConfigurationError(ValueError):
    pass


def _strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("启动消息有重复字段")
        result[key] = value
    return result


@dataclass(eq=False, frozen=True)
class Instance:
    instance_id: str
    endpoint: str
    token: str = field(repr=False)
    process: object = field(repr=False)
    readers: tuple = field(repr=False)
    started_at: float = field(default_factory=time.monotonic)


class ManagedRuntime:
    def __init__(self, version, *, binary_path=None, startup_timeout=10.0, shutdown_timeout=5.0,
                 health_interval=5.0, health_timeout=1.0, health_failures=3,
                 restart_limit=5, restart_window=60.0, cooldown=30.0):
        self.version = version
        self.owner_pid = os.getpid()
        self.binary_path = Path(binary_path).resolve() if binary_path is not None else Path(__file__).resolve().parent / "_gohttpx_bin" / "gohttpx-server.exe"
        for name, value in {"startup_timeout": startup_timeout, "shutdown_timeout": shutdown_timeout,
                            "health_interval": health_interval, "health_timeout": health_timeout,
                            "restart_window": restart_window, "cooldown": cooldown}.items():
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
                raise ValueError(f"{name} 必须是有限正数")
        for name, value in {"health_failures": health_failures, "restart_limit": restart_limit}.items():
            if type(value) is not int or value < 1:
                raise ValueError(f"{name} 必须是正整数")
        self.startup_timeout, self.shutdown_timeout = startup_timeout, shutdown_timeout
        self.health_interval, self.health_timeout, self.health_failures = health_interval, health_timeout, health_failures
        self.restart_limit, self.restart_window, self.cooldown = restart_limit, restart_window, cooldown
        self._condition = threading.Condition()
        self._stop = threading.Event()
        self._thread = None
        self._current = None
        self._users = 0
        self._wanted = self._pinned = False
        self._check_requested = None
        self._state = "STOPPED"
        self._failures = deque()
        self._next_retry = 0.0
        self._starts = 0
        self._last_exit = None
        self._last_failure = None
        self._fatal = False
        atexit.register(self.shutdown)

    def acquire(self):
        with self._condition:
            if os.getpid() != self.owner_pid:
                raise RuntimeConfigurationError("不能跨 Python 进程复用 GoHTTPX 运行时")
            if self._stop.is_set():
                raise RuntimeUnavailable("GoHTTPX 运行时已关闭")
            self._users += 1

    def release(self):
        with self._condition:
            self._users = max(0, self._users - 1)
            self._condition.notify_all()

    def _request_ready(self, pin=False):
        if os.getpid() != self.owner_pid:
            raise RuntimeConfigurationError("fork 后必须创建新的 GoHTTPX client")
        if self._stop.is_set():
            raise RuntimeUnavailable("GoHTTPX 运行时已关闭")
        if self._fatal:
            raise RuntimeConfigurationError(self._last_failure)
        self._wanted = True
        self._pinned |= pin
        if self._thread is None:
            self._thread = threading.Thread(target=self._supervise, name="gohttpx-supervisor", daemon=True)
            self._thread.start()
        current = self._current
        if current is not None and self._state == "RUNNING" and current.process.poll() is None:
            return current
        self._condition.notify_all()
        return None

    def ensure(self, timeout=None, *, pin=False):
        deadline = time.monotonic() + (self.startup_timeout if timeout is None else timeout)
        with self._condition:
            while True:
                current = self._request_ready(pin)
                if current is not None:
                    return current
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RuntimeUnavailable(self._last_failure or "等待 Go 服务就绪超时")
                self._condition.wait(min(remaining, 0.1))

    async def ensure_async(self, timeout=None, *, pin=False):
        deadline = time.monotonic() + (self.startup_timeout if timeout is None else timeout)
        while True:
            with self._condition:
                current = self._request_ready(pin)
            if current is not None:
                return current
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeUnavailable(self._last_failure or "等待 Go 服务就绪超时")
            # 仅在启动/恢复期间等待，不占用线程池，也不把共享启动绑定到一个请求的取消。
            await asyncio.sleep(min(0.02, remaining))

    def report_fault(self, instance):
        with self._condition:
            if self._current is instance and not self._stop.is_set():
                self._check_requested = instance.instance_id
                self._condition.notify_all()

    def is_current(self, instance):
        with self._condition:
            return not self._stop.is_set() and self._current is instance and instance.process.poll() is None

    def status(self):
        with self._condition:
            current = self._current
            return {"state": self._state, "owner_pid": self.owner_pid,
                    "child_pid": current.process.pid if current else None,
                    "instance_id": current.instance_id if current else None,
                    "endpoint": current.endpoint if current else None,
                    "start_count": self._starts, "restart_count": max(0, self._starts - 1),
                    "active_clients": self._users, "last_exit_code": self._last_exit,
                    "last_failure": self._last_failure,
                    "retry_in_seconds": max(0.0, self._next_retry - time.monotonic())}

    @staticmethod
    def _read_stdout(stream, messages):
        try:
            line = stream.readline(4097)
            messages.put_nowait(line)
            while stream.read(4096):
                pass
        except (OSError, ValueError):
            try:
                messages.put_nowait(b"")
            except queue.Full:
                pass

    @staticmethod
    def _read_stderr(stream, tail, token):
        try:
            while True:
                chunk = stream.read(4096)
                if not chunk:
                    return
                tail.append(chunk.replace(token.encode("ascii"), b"[redacted]"))
        except (OSError, ValueError):
            return

    def _launch(self):
        if sys.platform != "win32":
            raise RuntimeConfigurationError("managed 模式目前仅支持 Windows 10+/Server 2016+；其他平台请显式配置外部 Go 服务")
        if not self.binary_path.is_file():
            raise RuntimeConfigurationError("未找到匹配的 Go 二进制；请安装 Windows 平台 wheel 或使用 configure_runtime(binary_path=绝对路径)")
        identity, token = secrets.token_hex(16), secrets.token_hex(32)
        try:
            process = JobProcess([self.binary_path, "--managed"])
        except OSError as exc:
            raise RuntimeConfigurationError(f"Windows Job/进程创建失败，winerror={getattr(exc, 'winerror', None)}") from exc
        messages, tail = queue.Queue(maxsize=1), deque(maxlen=4)
        readers = (
            threading.Thread(target=self._read_stdout, args=(process.stdout, messages), name="gohttpx-stdout", daemon=True),
            threading.Thread(target=self._read_stderr, args=(process.stderr, tail, token), name="gohttpx-stderr", daemon=True),
        )
        try:
            for reader in readers:
                reader.start()
            bootstrap = {"runtime_protocol_version": 1, "instance_id": identity, "token": token,
                         "owner_pid": self.owner_pid, "sdk_version": self.version}
            process.stdin.write((json.dumps(bootstrap) + "\n").encode("utf-8"))
            deadline = time.monotonic() + self.startup_timeout
            while True:
                if self._stop.is_set():
                    raise RuntimeUnavailable("启动已取消")
                try:
                    line = messages.get(timeout=0.05)
                    break
                except queue.Empty:
                    if process.poll() is not None:
                        raise RuntimeUnavailable(f"Go 启动期间退出，exit_code={process.returncode}")
                    if time.monotonic() >= deadline:
                        raise RuntimeUnavailable("Go 启动握手超时")
            if not line:
                raise RuntimeUnavailable("Go 启动消息缺失")
            if not line.endswith(b"\n") or len(line) > 4096:
                raise RuntimeConfigurationError("Go 启动消息不完整或超过限制")
            try:
                ready = json.loads(line.decode("utf-8"), object_pairs_hook=_strict_object)
            except (ValueError, UnicodeError) as exc:
                raise RuntimeConfigurationError("Go 启动消息不是合法 JSON") from exc
            if isinstance(ready, dict) and ready == {"runtime_protocol_version": 1, "error": "BOOTSTRAP_REJECTED"}:
                raise RuntimeConfigurationError("Go 拒绝启动握手，请确认 SDK 与 Go 二进制版本完全一致")
            expected = {"runtime_protocol_version", "instance_id", "server_version", "protocol_version", "pid", "host", "port"}
            if not isinstance(ready, dict) or set(ready) != expected:
                raise RuntimeConfigurationError("Go 启动消息字段不匹配")
            if (type(ready["runtime_protocol_version"]) is not int or ready["runtime_protocol_version"] != 1
                    or type(ready["protocol_version"]) is not int or ready["protocol_version"] != 1
                    or ready["instance_id"] != identity or ready["server_version"] != self.version
                    or type(ready["pid"]) is not int or ready["pid"] != process.pid
                    or ready["host"] != "127.0.0.1" or type(ready["port"]) is not int or not 1 <= ready["port"] <= 65535):
                raise RuntimeConfigurationError("Go 启动身份、版本或端口校验失败")
            instance = Instance(identity, f"http://127.0.0.1:{ready['port']}", token, process, readers)
            if not self._probe(instance) or process.poll() is not None:
                raise RuntimeUnavailable("Go capabilities 就绪检查失败")
            return instance
        except BaseException:
            process.close()
            for reader in readers:
                if reader.ident is not None:
                    reader.join(1)
            raise

    def _probe(self, instance):
        try:
            with httpx.Client(trust_env=False, timeout=self.health_timeout) as control:
                response = control.get(instance.endpoint + "/api/v1/capabilities", headers={
                    "Authorization": "Bearer " + instance.token, INSTANCE_HEADER: instance.instance_id})
            data = response.json()
            return (response.status_code == 200 and response.headers.get(INSTANCE_HEADER) == instance.instance_id
                    and data.get("server_version") == self.version
                    and type(data.get("protocol_version")) is int and data["protocol_version"] == 1)
        except (httpx.HTTPError, ValueError, AttributeError):
            return False

    def _dispose(self, instance, graceful):
        if graceful and instance.process.poll() is None:
            try:
                command = {"runtime_protocol_version": 1, "instance_id": instance.instance_id, "command": "shutdown"}
                instance.process.stdin.write((json.dumps(command) + "\n").encode("utf-8"))
                instance.process.wait(self.shutdown_timeout)
            except (OSError, ValueError, subprocess.TimeoutExpired):
                pass
        instance.process.close()
        for reader in instance.readers:
            reader.join(1)

    def _record_failure(self, message):
        now = time.monotonic()
        while self._failures and now - self._failures[0] >= self.restart_window:
            self._failures.popleft()
        self._failures.append(now)
        delay = self.cooldown if len(self._failures) >= self.restart_limit else min(5.0, 0.25 * 2 ** (len(self._failures) - 1))
        self._next_retry = now + delay + secrets.randbelow(50) / 1000
        self._last_failure = message
        self._state = "BACKOFF"
        _logger.warning("GoHTTPX runtime recovery: %s; retry_in=%.2fs", message, delay)

    def _supervise(self):
        next_health, health_errors = 0.0, 0
        current = None
        try:
            while not self._stop.is_set():
                with self._condition:
                    current = self._current
                    if current is None:
                        if self._fatal or not self._wanted or (not self._users and not self._pinned):
                            self._condition.wait(0.1)
                            continue
                        delay = self._next_retry - time.monotonic()
                        if delay > 0:
                            self._condition.wait(min(delay, 0.1))
                            continue
                        self._state = "STARTING" if not self._starts else "RESTARTING"
                if current is None:
                    try:
                        candidate = self._launch()
                    except Exception as exc:
                        with self._condition:
                            if isinstance(exc, RuntimeConfigurationError):
                                self._fatal = True
                                self._state, self._last_failure = "FAILED", str(exc)
                            else:
                                self._record_failure(str(exc) if isinstance(exc, RuntimeUnavailable) else "Go 启动失败")
                            self._condition.notify_all()
                        continue
                    with self._condition:
                        cancelled = self._stop.is_set()
                        if not cancelled:
                            self._current = current = candidate
                            self._starts += 1
                            self._state = "RUNNING"
                            self._last_failure = None
                            self._next_retry = 0.0
                            self._condition.notify_all()
                    if cancelled:
                        self._dispose(candidate, False)
                        break
                    next_health, health_errors = time.monotonic() + self.health_interval, 0
                    continue
                code = current.process.poll()
                with self._condition:
                    check = self._check_requested == current.instance_id
                    self._check_requested = None
                    users = self._users or self._pinned
                if code is None and users and (check or time.monotonic() >= next_health):
                    health_errors = 0 if self._probe(current) else health_errors + 1
                    next_health = time.monotonic() + self.health_interval
                if code is not None or health_errors >= self.health_failures:
                    with self._condition:
                        self._state = "RESTARTING"
                        self._current = None
                    self._dispose(current, False)
                    with self._condition:
                        self._last_exit = current.process.returncode
                        self._record_failure(f"Go exited ({self._last_exit})" if code is not None else "Go 健康检查连续失败")
                        self._condition.notify_all()
                    current = None
                    continue
                with self._condition:
                    self._condition.wait(0.1)
        except BaseException:
            with self._condition:
                self._fatal = True
                self._state, self._last_failure = "FAILED", "Go 进程管理器异常，已停止服务"
                self._condition.notify_all()
        finally:
            if current is not None:
                self._dispose(current, self._stop.is_set())
            with self._condition:
                self._current = None
                if self._stop.is_set():
                    self._state = "CLOSED"
                self._condition.notify_all()

    def shutdown(self):
        if os.getpid() != self.owner_pid:
            return
        with self._condition:
            self._stop.set()
            self._next_retry = 0.0
            if self._state != "CLOSED":
                self._state = "STOPPING" if self._thread else "CLOSED"
            self._condition.notify_all()
            thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(self.startup_timeout + self.shutdown_timeout + self.health_timeout + 3)
            if thread.is_alive():
                raise RuntimeUnavailable("Go 管理线程未在期限内结束")
        atexit.unregister(self.shutdown)
