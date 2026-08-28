import asyncio
import ctypes
import gc
import json
import os
import queue
import subprocess
import sys
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from ctypes import wintypes
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import httpx

import gohttpx
import _gohttpx_runtime
from _gohttpx_runtime import INSTANCE_HEADER

if sys.platform == "win32":
    # 非 Windows CI 仍要能收集并跳过托管测试。
    from _gohttpx_windows import _kernel


class TargetServer(ThreadingHTTPServer):
    # 默认队列只有 5，Windows 会拒绝突发连接，干扰这里的运行时并发测试。
    request_queue_size = 128


class TargetHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_GET(self):
        parsed = urlsplit(self.path)
        owner = parse_qs(parsed.query).get("owner", [""])[0]
        with self.server.lock:
            self.server.calls.append((self.path, dict(self.headers)))
        if parsed.path == "/effect":
            self.server.entered.set()
            self.server.release.wait(5)
        if parsed.path == "/slow":
            time.sleep(0.3)
        body = json.dumps({"cookie": self.headers.get("Cookie", ""), "authorization": self.headers.get("Authorization", ""), "instance_header": self.headers.get(INSTANCE_HEADER, "")}).encode()
        try:
            self.send_response(500 if parsed.path == "/error" else 200)
            if parsed.path == "/set":
                self.send_header("Set-Cookie", f"owner={owner}; Path=/")
                self.send_header("Set-Cookie", f"scoped={owner}; Path=/scoped")
            if parsed.path == "/clear":
                self.send_header("Set-Cookie", "owner=; Max-Age=0; Path=/")
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass

    do_POST = do_GET


@unittest.skipUnless(sys.platform == "win32", "Windows Job 托管测试")
class ManagedRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[1]
        cls.binary = cls.root / ".tmp" / "managed-tests-server.exe"
        cls.binary.parent.mkdir(exist_ok=True)
        subprocess.run(["go", "build", "-o", str(cls.binary), "."], cwd=cls.root, check=True, text=True, encoding="utf-8", errors="replace")
        cls.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        cls.kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        cls.kernel.OpenProcess.restype = wintypes.HANDLE
        cls.kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        cls.kernel.WaitForSingleObject.restype = wintypes.DWORD
        cls.kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        cls.kernel.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
        cls.kernel.GetProcessHandleCount.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]

    @classmethod
    def tearDownClass(cls):
        gohttpx.shutdown()
        cls.binary.unlink()

    def setUp(self):
        gohttpx.configure_runtime(binary_path=self.binary)
        self.server = TargetServer(("127.0.0.1", 0), TargetHandler)
        self.server.calls = []
        self.server.lock = threading.Lock()
        self.server.entered, self.server.release = threading.Event(), threading.Event()
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.endpoint = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.release.set()
        gohttpx.shutdown()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)
        self.assertEqual(gohttpx.runtime_status()["active_clients"], 0)

    def wait_for(self, predicate, timeout=10):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = predicate()
            if value:
                return value
            time.sleep(0.02)
        self.fail(f"condition timed out: {gohttpx.runtime_status()}")

    def start_worker(self, phase="running"):
        process = subprocess.Popen(
            [sys.executable, "-B", "-u", str(self.root / "python" / "managed_test_worker.py"), "--binary", str(self.binary), "--phase", phase],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8", errors="replace", creationflags=subprocess.CREATE_NO_WINDOW,
        )
        messages = queue.Queue()

        def read_output():
            for line in process.stdout:
                messages.put(line)

        thread = threading.Thread(target=read_output, daemon=True)
        thread.start()
        self.addCleanup(self.stop_worker, process, thread)
        try:
            message = messages.get(timeout=10)
        except queue.Empty:
            process.terminate()
            process.wait(5)
            self.fail(process.stderr.read())
        return process, messages, json.loads(message)

    @staticmethod
    def stop_worker(process, thread):
        if process.poll() is None:
            process.terminate()
        process.wait(5)
        thread.join(5)
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()

    def watch_child(self, pid):
        handle = self.kernel.OpenProcess(0x00100000 | 0x0001, False, pid)
        self.assertTrue(handle, ctypes.get_last_error())

        def cleanup():
            if self.kernel.WaitForSingleObject(handle, 0) == 258:
                self.kernel.TerminateProcess(handle, 99)
                self.kernel.WaitForSingleObject(handle, 5000)
            self.kernel.CloseHandle(handle)

        self.addCleanup(cleanup)
        return handle

    def test_per_request_clients_share_one_process_but_not_cookies(self):
        pids = set()
        for index in range(12):
            with gohttpx.Client() as client:
                self.assertEqual(client.get(self.endpoint + "/echo").json()["cookie"], "")
                client.get(self.endpoint + f"/set?owner={index}")
                cookie = client.get(self.endpoint + "/echo").json()["cookie"]
                self.assertEqual(cookie, f"owner={index}")
                pids.add(gohttpx.runtime_status()["child_pid"])
        self.assertEqual(len(pids), 1)
        self.assertEqual(gohttpx.runtime_status()["state"], "RUNNING")
        self.assertEqual(gohttpx.runtime_status()["start_count"], 1)

    def test_explicit_warmup_and_unicode_binary_path(self):
        binary = self.binary.parent / "带 空格的 GoHTTPX.exe"
        binary.write_bytes(self.binary.read_bytes())
        try:
            gohttpx.configure_runtime(binary_path=binary)
            self.assertEqual(gohttpx.runtime_status()["state"], "STOPPED")
            state = gohttpx.start()
            self.assertEqual(state["active_clients"], 0)
            self.assertEqual(asyncio.run(gohttpx.astart())["child_pid"], state["child_pid"])
            gohttpx._runtime._current.process.kill()
            self.wait_for(lambda: gohttpx.runtime_status()["start_count"] == 2)
            with gohttpx.Client() as client:
                self.assertEqual(client.get(self.endpoint).status_code, 200)
            asyncio.run(gohttpx.ashutdown())
            self.assertEqual(gohttpx.runtime_status()["state"], "CLOSED")
        finally:
            gohttpx.shutdown()
            binary.unlink()

    def test_ab_cookie_updates_paths_deletion_and_control_token_isolation(self):
        with patch.dict(os.environ, {"GOHTTPX_TOKEN": "foreign-inherited-token"}):
            with gohttpx.Client() as a, gohttpx.Client() as b:
                a.get(self.endpoint + "/set?owner=A")
                b.get(self.endpoint + "/set?owner=B")
                self.assertEqual(a.get(self.endpoint + "/echo").json()["cookie"], "owner=A")
                self.assertEqual(b.get(self.endpoint + "/echo").json()["cookie"], "owner=B")
                scoped = a.get(self.endpoint + "/scoped/echo").json()
                self.assertIn("scoped=A", scoped["cookie"])
                self.assertEqual(scoped["authorization"], "")
                self.assertEqual(scoped["instance_header"], "")
                a.get(self.endpoint + "/clear")
                self.assertEqual(a.get(self.endpoint + "/echo").json()["cookie"], "")
                self.assertEqual(b.get(self.endpoint + "/echo").json()["cookie"], "owner=B")

    def test_concurrent_first_clients_start_once(self):
        def request(index):
            with gohttpx.Client(cookies={"owner": str(index)}) as client:
                response = client.get(self.endpoint + "/echo").json()
                return response["cookie"], gohttpx.runtime_status()["child_pid"]

        with ThreadPoolExecutor(max_workers=12) as pool:
            results = list(pool.map(request, range(24)))
        self.assertEqual([value[0] for value in results], [f"owner={i}" for i in range(24)])
        self.assertEqual(len({value[1] for value in results}), 1)
        self.assertEqual(gohttpx.runtime_status()["start_count"], 1)

    def test_crash_restores_same_client_cookie_and_only_restarts_once(self):
        with gohttpx.Client() as client:
            client.get(self.endpoint + "/set?owner=A")
            old = gohttpx._runtime._current
            old.process.kill()
            self.wait_for(lambda: gohttpx.runtime_status()["start_count"] == 2)
            with ThreadPoolExecutor(max_workers=12) as pool:
                results = list(pool.map(lambda _: client.get(self.endpoint + "/echo").json(), range(24)))
            self.assertTrue(all(item["cookie"] == "owner=A" for item in results))
            self.assertNotEqual(old.instance_id, gohttpx.runtime_status()["instance_id"])
            self.assertEqual(gohttpx.runtime_status()["start_count"], 2)
            gohttpx._runtime.report_fault(old)
            time.sleep(0.2)
            self.assertEqual(gohttpx.runtime_status()["start_count"], 2)

    def test_inflight_side_effect_is_not_replayed_after_crash(self):
        with gohttpx.Client() as client, ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(client.post, self.endpoint + "/effect")
            self.assertTrue(self.server.entered.wait(5))
            old = gohttpx._runtime._current
            old.process.kill()
            with self.assertRaises(gohttpx.GoRequestOutcomeUnknown) as caught:
                pending.result(5)
            self.assertEqual(caught.exception.instance_id, old.instance_id)
            self.assertFalse(isinstance(caught.exception, httpx.ConnectError))
            self.server.release.set()
            self.assertEqual(client.get(self.endpoint + "/echo").status_code, 200)
            self.assertEqual(sum(path == "/effect" for path, _ in self.server.calls), 1)

    def test_deleted_session_rebuilds_without_restarting_go(self):
        with gohttpx.Client() as client:
            entry = next(iter(client._transport._entries.values()))
            delegate = entry.ready.result()
            delegate._delete_session(delegate._client_id)
            self.assertEqual(client.post(self.endpoint + "/echo").status_code, 200)
            self.assertEqual(gohttpx.runtime_status()["start_count"], 1)
            self.assertEqual(len(self.server.calls), 1)

    def test_upstream_errors_do_not_restart_healthy_go(self):
        with gohttpx.Client() as client:
            self.assertEqual(client.get(self.endpoint + "/error").status_code, 500)
            with self.assertRaises(httpx.TimeoutException):
                client.get(self.endpoint + "/slow", timeout=0.02)
            time.sleep(0.2)
            self.assertEqual(gohttpx.runtime_status()["start_count"], 1)

    def test_wrong_instance_or_token_cannot_execute_target(self):
        with gohttpx.Client() as client:
            entry = next(iter(client._transport._entries.values()))
            instance = entry.instance
            delegate = entry.ready.result()
            for headers in ({"Authorization": "Bearer " + instance.token, INSTANCE_HEADER: "other"},
                            {"Authorization": "Bearer other", INSTANCE_HEADER: instance.instance_id}):
                result = httpx.post(instance.endpoint + f"/api/v1/clients/{delegate._client_id}/requests", headers=headers, json={}, trust_env=False)
                self.assertEqual(result.status_code, 401)
            self.assertEqual(self.server.calls, [])
            self.assertNotIn(instance.token, json.dumps(gohttpx.runtime_status()))

    def test_two_python_processes_and_kill_one_does_not_affect_other(self):
        a, a_messages, a_info = self.start_worker()
        b, messages, b_info = self.start_worker()
        handle = self.watch_child(a_info["child_pid"])
        self.assertNotEqual(a_info["endpoint"], b_info["endpoint"])
        self.assertNotEqual(a_info["instance_id"], b_info["instance_id"])
        for process, output, owner in ((a, a_messages, "A"), (b, messages, "B")):
            process.stdin.write(json.dumps({"op": "request", "url": self.endpoint + f"/set?owner={owner}"}) + "\n")
            process.stdin.flush()
            self.assertEqual(json.loads(output.get(timeout=5))["status"], 200)
        for process, output, owner in ((a, a_messages, "A"), (b, messages, "B")):
            process.stdin.write(json.dumps({"op": "request", "url": self.endpoint + "/echo"}) + "\n")
            process.stdin.flush()
            self.assertEqual(json.loads(output.get(timeout=5))["body"]["cookie"], f"owner={owner}")
        a.terminate()
        a.wait(5)
        self.assertEqual(self.kernel.WaitForSingleObject(handle, 5000), 0)
        b.stdin.write(json.dumps({"op": "request", "url": self.endpoint + "/echo"}) + "\n")
        b.stdin.flush()
        response = json.loads(messages.get(timeout=5))
        self.assertEqual(response["status"], 200)
        self.assertEqual(response["body"]["cookie"], "owner=B")
        self.assertIsNone(b.poll())

    def test_parent_exit_modes_and_startup_checkpoints_leave_no_go(self):
        for phase, operation in [("running", "exit"), ("running", "abrupt"), ("running", "exception"), ("running", "kill"), ("spawned", "kill"), ("ready", "kill")]:
            with self.subTest(phase=phase, operation=operation):
                parent, _, info = self.start_worker(phase)
                handle = self.watch_child(info["child_pid"])
                if operation == "kill":
                    parent.terminate()
                else:
                    parent.stdin.write(json.dumps({"op": operation}) + "\n")
                    parent.stdin.flush()
                parent.wait(10)
                self.assertEqual(self.kernel.WaitForSingleObject(handle, 5000), 0, "orphan Go process survived")

    def test_async_cookie_isolation_shared_runtime_and_cancelled_waiter(self):
        original_probe = gohttpx._runtime._probe

        def delayed_probe(instance):
            time.sleep(0.15)
            return original_probe(instance)

        async def scenario():
            async with gohttpx.AsyncClient() as a, gohttpx.AsyncClient() as b:
                cancelled = asyncio.create_task(a.get(self.endpoint + "/echo"))
                success = asyncio.create_task(b.get(self.endpoint + "/set?owner=B"))
                await asyncio.sleep(0.03)
                cancelled.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await cancelled
                self.assertEqual((await success).status_code, 200)
                await a.get(self.endpoint + "/set?owner=A")
                results = await asyncio.gather(a.get(self.endpoint + "/echo"), b.get(self.endpoint + "/echo"))
                self.assertEqual([r.json()["cookie"] for r in results], ["owner=A", "owner=B"])
                with gohttpx.Client() as sync:
                    self.assertEqual(sync.get(self.endpoint + "/echo").json()["cookie"], "")
                self.assertEqual(gohttpx.runtime_status()["start_count"], 1)

        with patch.object(gohttpx._runtime, "_probe", delayed_probe):
            asyncio.run(scenario())

    def test_shutdown_is_terminal_and_closing_clients_does_not_restart(self):
        client = gohttpx.Client()
        process = gohttpx._runtime._current.process
        gohttpx.shutdown()
        client.close()
        with self.assertRaises(Exception):
            gohttpx.Client()
        self.assertIsNotNone(process.returncode)
        self.assertEqual(gohttpx.runtime_status()["start_count"], 1)

    def test_job_assignment_failure_does_not_fall_back_to_popen(self):
        with patch.object(_kernel, "UpdateProcThreadAttribute", return_value=0):
            with self.assertRaises(gohttpx.RuntimeConfigurationError):
                gohttpx.Client()
        self.assertEqual(gohttpx.runtime_status()["state"], "FAILED")
        self.assertEqual(gohttpx.runtime_status()["start_count"], 0)

    def test_constructor_and_local_validation_errors_do_not_leak_references(self):
        for client_type in (gohttpx.Client, gohttpx.AsyncClient):
            with self.assertRaises(TypeError):
                client_type(auth=object())
            self.assertEqual(gohttpx.runtime_status()["active_clients"], 0)
        with gohttpx.Client() as client:
            with self.assertRaises(TypeError):
                client.get(self.endpoint, extensions={"go_req": {"typo": True}})
            request = client.build_request("GET", self.endpoint)
            request.extensions["timeout"] = {"read": -1}
            with self.assertRaises(gohttpx.GoProtocolError):
                client.send(request)
        self.assertEqual(self.server.calls, [])

    def test_missing_binary_and_version_mismatch_fail_without_restart_storm(self):
        gohttpx.configure_runtime(binary_path=self.binary.with_name("not-present.exe"))
        with self.assertRaises(gohttpx.RuntimeConfigurationError):
            gohttpx.Client()
        self.assertEqual(gohttpx.runtime_status()["state"], "FAILED")
        gohttpx.shutdown()
        gohttpx.configure_runtime(binary_path=self.binary)
        gohttpx._runtime.version = "wrong-version"
        started = time.monotonic()
        with self.assertRaises(gohttpx.RuntimeConfigurationError):
            gohttpx.Client()
        self.assertLess(time.monotonic() - started, 3)
        self.assertEqual(gohttpx.runtime_status()["start_count"], 0)

    def test_ready_frame_identity_types_and_size_are_checked(self):
        mutations = [
            lambda data: {**data, "port": True},
            lambda data: {**data, "port": 0},
            lambda data: {**data, "pid": data["pid"] + 1},
            lambda data: {**data, "host": "0.0.0.0"},
            lambda data: {**data, "instance_id": "foreign"},
            lambda data: {**data, "server_version": "wrong"},
            lambda data: {**data, "unexpected": 1},
            lambda data: (json.dumps(data)[:-1] + ',"port":1}\n').encode(),
            lambda data: b"x" * 4097,
            lambda data: b"{}",
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                gohttpx.shutdown()
                gohttpx.configure_runtime(binary_path=self.binary)

                def corrupt(stream, messages):
                    data = mutation(json.loads(stream.readline(4097)))
                    messages.put(data if isinstance(data, bytes) else (json.dumps(data) + "\n").encode())

                with patch.object(gohttpx._runtime, "_read_stdout", corrupt):
                    with self.assertRaises(gohttpx.RuntimeConfigurationError):
                        gohttpx.Client()
                self.assertIsNone(gohttpx.runtime_status()["child_pid"])
                self.assertEqual(gohttpx.runtime_status()["state"], "FAILED")

    def test_restart_backoff_cooldown_and_shutdown_during_backoff(self):
        gohttpx.configure_runtime(binary_path=self.binary, restart_limit=2, cooldown=0.6)
        with gohttpx.Client() as client:
            gohttpx._runtime._current.process.kill()
            self.wait_for(lambda: gohttpx.runtime_status()["start_count"] == 2)
            gohttpx._runtime._current.process.kill()
            state = self.wait_for(lambda: (state if (state := gohttpx.runtime_status())["state"] == "BACKOFF" else None))
            self.assertGreater(state["retry_in_seconds"], 0.4)
            self.wait_for(lambda: gohttpx.runtime_status()["start_count"] == 3)
            self.assertEqual(client.get(self.endpoint).status_code, 200)
            gohttpx._runtime._current.process.kill()
            self.wait_for(lambda: gohttpx.runtime_status()["state"] == "BACKOFF")
            gohttpx.shutdown()
            time.sleep(0.7)
            self.assertEqual(gohttpx.runtime_status()["state"], "CLOSED")
            self.assertEqual(gohttpx.runtime_status()["start_count"], 3)

    def test_unhealthy_live_process_requires_consecutive_failures(self):
        gohttpx.configure_runtime(binary_path=self.binary, health_interval=0.15)
        with gohttpx.Client() as client:
            old = gohttpx._runtime._current
            probe = gohttpx._runtime._probe
            failed = []

            def unhealthy(instance):
                if instance is old:
                    failed.append(time.monotonic())
                    return False
                return probe(instance)

            with patch.object(gohttpx._runtime, "_probe", unhealthy):
                gohttpx._runtime.report_fault(old)
                self.wait_for(lambda: len(failed) == 2)
                self.assertIsNone(old.process.poll())
                self.wait_for(lambda: gohttpx.runtime_status()["start_count"] == 2)
            self.assertEqual(len(failed), 3)
            self.assertIsNotNone(old.process.returncode)
            self.assertEqual(client.get(self.endpoint).status_code, 200)

    def test_shutdown_during_startup_reaps_unpublished_child(self):
        entered, release = threading.Event(), threading.Event()
        processes = []
        probe = gohttpx._runtime._probe

        def paused(instance):
            processes.append(instance.process)
            entered.set()
            release.wait(5)
            return probe(instance)

        with patch.object(gohttpx._runtime, "_probe", paused), ThreadPoolExecutor(max_workers=2) as pool:
            starting = pool.submit(gohttpx.Client)
            self.assertTrue(entered.wait(5))
            stopping = pool.submit(gohttpx.shutdown)
            self.wait_for(lambda: gohttpx._runtime._stop.is_set())
            release.set()
            stopping.result(5)
            with self.assertRaises(gohttpx.GoServiceUnavailable):
                starting.result(5)
        self.assertIsNotNone(processes[0].returncode)
        self.assertEqual(gohttpx.runtime_status()["state"], "CLOSED")
        self.assertEqual(gohttpx.runtime_status()["start_count"], 0)

    def test_repeated_recovery_releases_threads_handles_and_sessions(self):
        gohttpx.configure_runtime(binary_path=self.binary, restart_limit=1, cooldown=0.02)

        def idle_handles():
            gc.collect()
            counts = []
            # 等待测试目标的短命线程收尾，再检查跨代次增长。
            for _ in range(5):
                count = wintypes.DWORD()
                self.assertTrue(self.kernel.GetProcessHandleCount(wintypes.HANDLE(-1), ctypes.byref(count)))
                counts.append(count.value)
                time.sleep(0.02)
            return min(counts)

        initial_threads = {thread.ident for thread in threading.enumerate()}
        with gohttpx.Client() as client:
            client.get(self.endpoint)
            counts = [idle_handles()]
            for generation in range(1, 7):
                old = gohttpx._runtime._current
                old.process.kill()
                self.wait_for(lambda: gohttpx.runtime_status()["start_count"] == generation + 1)
                self.assertEqual(client.get(self.endpoint).status_code, 200)
                self.assertEqual(len(client._transport._entries), 1)
                self.assertIsNone(old.process._process)
                self.assertIsNone(old.process._job)
                self.assertTrue(all(stream.closed for stream in (old.process.stdin, old.process.stdout, old.process.stderr)))
                self.assertTrue(all(not reader.is_alive() for reader in old.readers))
                counts.append(idle_handles())
            self.assertLessEqual(max(counts) - min(counts), 4, counts)
        gohttpx.shutdown()
        gc.collect()
        self.assertFalse([thread for thread in threading.enumerate() if thread.ident not in initial_threads and thread.name.startswith("gohttpx-")])
        self.assertLessEqual(idle_handles(), counts[0] + 4)

    def test_async_crash_retains_cookie_and_never_replays_uncertain_post(self):
        async def scenario():
            async with gohttpx.AsyncClient() as client:
                await client.get(self.endpoint + "/set?owner=A")
                pending = asyncio.create_task(client.post(self.endpoint + "/effect"))
                while not self.server.entered.is_set():
                    await asyncio.sleep(0.01)
                gohttpx._runtime._current.process.kill()
                with self.assertRaises(gohttpx.GoRequestOutcomeUnknown):
                    await asyncio.wait_for(pending, 5)
                self.server.release.set()
                response = await client.get(self.endpoint + "/echo")
                self.assertEqual(response.json()["cookie"], "owner=A")
                self.assertEqual(gohttpx.runtime_status()["start_count"], 2)
                self.assertEqual(sum(path == "/effect" for path, _ in self.server.calls), 1)

        asyncio.run(scenario())

    def test_async_close_waiter_cancellation_still_releases_session(self):
        async def scenario():
            client = gohttpx.AsyncClient()
            pending = asyncio.create_task(client.get(self.endpoint + "/effect"))
            while not self.server.entered.is_set():
                await asyncio.sleep(0.01)
            closing = asyncio.create_task(client.aclose())
            await asyncio.sleep(0.03)
            closing.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await closing
            self.server.release.set()
            self.assertEqual((await pending).status_code, 200)
            await client.aclose()
            self.assertEqual(gohttpx.runtime_status()["active_clients"], 0)

        asyncio.run(scenario())

    def test_safe_connect_failure_retries_only_once_without_restarting_healthy_go(self):
        with gohttpx.Client() as client:
            delegate = next(iter(client._transport._entries.values())).ready.result()
            original = delegate._control.request
            attempts = []

            def fail_once(*args, **kwargs):
                attempts.append(1)
                if len(attempts) == 1:
                    raise httpx.ConnectError("injected before send")
                return original(*args, **kwargs)

            with patch.object(delegate._control, "request", fail_once):
                self.assertEqual(client.post(self.endpoint).status_code, 200)
            self.assertEqual(len(attempts), 2)
            self.assertEqual(len(self.server.calls), 1)
            self.assertEqual(gohttpx.runtime_status()["start_count"], 1)

    def test_lost_or_invalid_control_response_never_replays_sent_request(self):
        for failure in ("read", "identity", "json", "envelope"):
            with self.subTest(failure=failure), gohttpx.Client() as client:
                delegate = next(iter(client._transport._entries.values())).ready.result()
                original = delegate._control.request
                before = len(self.server.calls)

                def corrupt(*args, **kwargs):
                    response = original(*args, **kwargs)
                    if failure == "read":
                        raise httpx.ReadError("injected after target executed")
                    if failure == "identity":
                        response.headers[INSTANCE_HEADER] = "foreign"
                        return response
                    return httpx.Response(200, headers=response.headers, content=b"not json" if failure == "json" else b"{}")

                with patch.object(delegate._control, "request", corrupt):
                    with self.assertRaises(gohttpx.GoRequestOutcomeUnknown):
                        client.post(self.endpoint)
                self.assertEqual(len(self.server.calls), before + 1)

    def test_wrong_endpoint_cannot_run_a_request_on_another_live_go(self):
        other = _gohttpx_runtime.ManagedRuntime(gohttpx.__version__, binary_path=self.binary)
        other.acquire()
        try:
            foreign = other.ensure()
            with gohttpx.Client(cookies={"owner": "A"}) as client:
                delegate = next(iter(client._transport._entries.values())).ready.result()
                endpoint = delegate._endpoint
                delegate._endpoint = foreign.endpoint
                try:
                    with self.assertRaises(gohttpx.GoRequestOutcomeUnknown):
                        client.post(self.endpoint)
                    self.assertEqual(self.server.calls, [])
                finally:
                    delegate._endpoint = endpoint
                self.assertEqual(client.get(self.endpoint).text.count("owner=A"), 1)
                self.assertIsNone(foreign.process.poll())
        finally:
            other.release()
            other.shutdown()

    def test_cancel_all_async_session_waiters_still_deletes_created_session(self):
        async def scenario():
            entered, release = asyncio.Event(), asyncio.Event()
            created, deleted = [], []
            create = gohttpx._AsyncGoTransport._create_session
            delete = gohttpx._AsyncGoTransport._delete_session

            async def paused(transport, request=None):
                client_id = await create(transport, request)
                created.append(client_id)
                entered.set()
                await release.wait()
                return client_id

            async def recorded(transport, client_id):
                deleted.append(client_id)
                await delete(transport, client_id)

            with patch.object(gohttpx._AsyncGoTransport, "_create_session", paused), patch.object(gohttpx._AsyncGoTransport, "_delete_session", recorded):
                client = gohttpx.AsyncClient()
                requests = [asyncio.create_task(client.get(self.endpoint)) for _ in range(4)]
                await asyncio.wait_for(entered.wait(), 5)
                for request in requests:
                    request.cancel()
                results = await asyncio.gather(*requests, return_exceptions=True)
                self.assertTrue(all(isinstance(result, asyncio.CancelledError) for result in results))
                closing = asyncio.create_task(client.aclose())
                await asyncio.sleep(0.03)
                self.assertFalse(closing.done())
                release.set()
                await asyncio.wait_for(closing, 5)
                self.assertEqual(len(created), 1)
                self.assertEqual(deleted, created)
                self.assertEqual(self.server.calls, [])

        asyncio.run(scenario())


if __name__ == "__main__":
    unittest.main()
