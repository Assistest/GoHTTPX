import socket
import ctypes
import json
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

from gohttpx import __version__


class PackageInstallTests(unittest.TestCase):
    def get_wheel(self):
        root = Path(__file__).parent.parent
        wheels = list((root / "dist").glob(f"gohttpx-{__version__}-*.whl"))
        if not wheels:
            subprocess.run([sys.executable, "-m", "build"], check=True, text=True, encoding="utf-8", cwd=root)
            wheels = list((root / "dist").glob(f"gohttpx-{__version__}-*.whl"))
        self.assertEqual(len(wheels), 1, "expected one built wheel")
        return wheels[0]

    def test_wheel_metadata_declares_package_requirements(self):
        with zipfile.ZipFile(self.get_wheel()) as wheel:
            metadata_paths = [path for path in wheel.namelist() if Path(path).match("*.dist-info/METADATA")]
            self.assertEqual(len(metadata_paths), 1, "expected one wheel metadata file")
            metadata = wheel.read(metadata_paths[0]).decode()
            self.assertTrue(any(path.endswith("/_gohttpx_bin/gohttpx-server.exe") for path in wheel.namelist()))
            wheel_metadata = wheel.read(next(path for path in wheel.namelist() if path.endswith(".dist-info/WHEEL"))).decode()
            self.assertIn("Tag: py3-none-win_amd64", wheel_metadata)
            self.assertIn("Root-Is-Purelib: false", wheel_metadata)
        self.assertIn("Name: gohttpx", metadata)
        self.assertIn("Requires-Python: >=3.10", metadata)
        self.assertIn("Requires-Dist: httpx<0.29,>=0.28", metadata)

    @unittest.skipUnless(sys.platform == "win32", "Windows 托管 wheel")
    def test_installed_wheel_manages_go_without_compiler_or_source_path(self):
        root = Path(__file__).resolve().parents[1]
        temporary = root / ".tmp"
        temporary.mkdir(exist_ok=True)
        directory = Path(tempfile.mkdtemp(prefix="installed-wheel-", dir=temporary))
        environment = directory / "venv"
        subprocess.run([sys.executable, "-m", "venv", str(environment)], check=True, text=True, encoding="utf-8", errors="replace")
        interpreter = environment / "Scripts" / "python.exe"
        subprocess.run([str(interpreter), "-m", "pip", "install", str(self.get_wheel().resolve())], cwd=directory, check=True, text=True, encoding="utf-8", errors="replace")
        env = {key: value for key, value in os.environ.items() if key not in {"PYTHONPATH", "PYTHONHOME"}}
        env["PATH"] = str(Path(os.environ["SystemRoot"]) / "System32")
        process = subprocess.Popen(
            [str(interpreter), "-I", "-B", str(root / "python" / "installed_test_worker.py")],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=directory, env=env, text=True, encoding="utf-8", errors="replace", creationflags=subprocess.CREATE_NO_WINDOW,
        )
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.restype = ctypes.c_void_p
        kernel.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
        kernel.CloseHandle.argtypes = [ctypes.c_void_p]
        handle = None
        try:
            line = process.stdout.readline()
            self.assertTrue(line, process.stderr.read() if process.poll() is not None else "installed worker produced no ready message")
            state = json.loads(line)
            self.assertEqual(state["version"], __version__)
            self.assertTrue(Path(state["module"]).is_relative_to(environment))
            handle = kernel.OpenProcess(0x00100000, False, state["child_pid"])
            self.assertTrue(handle)
            _, error = process.communicate("exit\n", timeout=10)
            self.assertEqual(process.returncode, 0, error)
            self.assertEqual(kernel.WaitForSingleObject(handle, 5000), 0, "installed worker left Go alive")
        finally:
            if process.poll() is None:
                process.terminate()
            process.wait(5)
            for stream in (process.stdin, process.stdout, process.stderr):
                stream.close()
            if handle:
                kernel.CloseHandle(handle)

    def test_installed_package_exports_client(self):
        wheel = self.get_wheel()
        with tempfile.TemporaryDirectory() as directory:
            environment = Path(directory) / "venv"
            subprocess.run(
                [sys.executable, "-m", "venv", environment],
                check=True,
                text=True,
                encoding="utf-8",
            )
            interpreter = environment / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
            subprocess.run(
                [interpreter, "-m", "pip", "install", wheel],
                check=True,
                text=True,
                encoding="utf-8",
                cwd=directory,
            )
            with socket.socket() as server:
                server.bind(("127.0.0.1", 0))
                server.listen()
                server.settimeout(10)
                endpoint = f"http://127.0.0.1:{server.getsockname()[1]}"
                process = subprocess.Popen(
                    [
                        interpreter,
                        "-c",
                        "from gohttpx import AsyncClient, Client, GoServiceUnavailable, RequestOptions; "
                        "assert all((Client, AsyncClient, RequestOptions)); "
                        f"\ntry: Client(go_endpoint='{endpoint}') "
                        "\nexcept GoServiceUnavailable as exc: assert 'https://github.com/Assistest/GoHTTPX' in str(exc) "
                        "\nelse: raise AssertionError('expected unavailable bridge')",
                    ],
                    text=True,
                    encoding="utf-8",
                    cwd=directory,
                )
                connection, _ = server.accept()
                connection.close()
                self.assertEqual(process.wait(timeout=10), 0, "installed package did not map transport failure")


if __name__ == "__main__":
    unittest.main()
