import socket
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


class PackageInstallTests(unittest.TestCase):
    def get_wheel(self):
        root = Path(__file__).parent.parent
        wheels = list((root / "dist").glob("gohttpx-*.whl"))
        if not wheels:
            subprocess.run([sys.executable, "-m", "build"], check=True, text=True, encoding="utf-8", cwd=root)
            wheels = list((root / "dist").glob("gohttpx-*.whl"))
        self.assertEqual(len(wheels), 1, "expected one built wheel")
        return wheels[0]

    def test_wheel_metadata_declares_package_requirements(self):
        with zipfile.ZipFile(self.get_wheel()) as wheel:
            metadata_paths = [path for path in wheel.namelist() if Path(path).match("*.dist-info/METADATA")]
            self.assertEqual(len(metadata_paths), 1, "expected one wheel metadata file")
            metadata = wheel.read(metadata_paths[0]).decode()
        self.assertIn("Name: gohttpx", metadata)
        self.assertIn("Requires-Python: >=3.10", metadata)
        self.assertIn("Requires-Dist: httpx<0.29,>=0.28", metadata)

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
