import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class PackageInstallTests(unittest.TestCase):
    def test_installed_package_exports_client(self):
        root = Path(__file__).parent.parent
        wheels = list((root / "dist").glob("gohttpx-*.whl"))
        self.assertEqual(len(wheels), 1, "expected one built wheel")
        wheel = wheels[0]
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
            subprocess.run(
                [interpreter, "-c", "from gohttpx import AsyncClient, Client, RequestOptions"],
                check=True,
                text=True,
                encoding="utf-8",
                cwd=directory,
            )


if __name__ == "__main__":
    unittest.main()
