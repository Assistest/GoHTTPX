import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class PackageInstallTests(unittest.TestCase):
    def test_installed_package_exports_client(self):
        root = Path(__file__).parent.parent
        wheel = root / "dist" / "gohttpx-1.0.0-py3-none-any.whl"
        with tempfile.TemporaryDirectory() as directory:
            environment = Path(directory) / "venv"
            subprocess.run(
                [sys.executable, "-m", "venv", "--system-site-packages", environment],
                check=True,
                text=True,
                encoding="utf-8",
            )
            interpreter = environment / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
            subprocess.run(
                [interpreter, "-m", "pip", "install", "--no-deps", wheel],
                check=True,
                text=True,
                encoding="utf-8",
            )
            subprocess.run(
                [interpreter, "-c", "from gohttpx import AsyncClient, Client, RequestOptions"],
                check=True,
                text=True,
                encoding="utf-8",
            )


if __name__ == "__main__":
    unittest.main()
