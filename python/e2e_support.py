import os
import socket
import subprocess
import tempfile
import time
from pathlib import Path

import httpx


def reserve_loopback_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def wait_for_health(endpoint, process):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"Go 服务提前退出，exit code={process.returncode}")
        try:
            if httpx.get(endpoint + "/api/v1/health", timeout=0.2, trust_env=False).status_code == 200:
                return
        except httpx.TransportError:
            pass
        time.sleep(0.05)
    raise RuntimeError(f"Go 服务 health 超时，exit code={process.poll()}")


class GoHTTPXService:
    def __init__(self, module_dir):
        self.module_dir = Path(module_dir)
        handle, name = tempfile.mkstemp(prefix="gohttpx-test-", suffix=".exe")
        self.exe_path = Path(name).resolve()
        self.endpoint = ""
        self.token = "e2e-fixed-token"
        self.process = None
        os.close(handle)
        self.exe_path.unlink()

    def start(self):
        built = subprocess.run(
            ["go", "build", "-o", str(self.exe_path), "."],
            cwd=self.module_dir,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
        )
        if built.returncode:
            self.close()
            raise RuntimeError(f"go build 失败 ({built.returncode}):\n{built.stdout}{built.stderr}")
        port = reserve_loopback_port()
        self.endpoint = f"http://127.0.0.1:{port}"
        try:
            self.process = subprocess.Popen(
                [str(self.exe_path), "--host", "127.0.0.1", "--port", str(port), "--token", self.token],
                cwd=self.module_dir,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            wait_for_health(self.endpoint, self.process)
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(5)
        if self.exe_path.exists():
            self.exe_path.unlink()
        if self.exe_path.exists():
            raise AssertionError(f"临时 EXE 清理失败: {self.exe_path}")
