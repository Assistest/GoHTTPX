import os
import subprocess
import sys
from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py
from setuptools.command.bdist_wheel import bdist_wheel


class BuildPython(build_py):
    def run(self):
        if sys.platform != "win32":
            raise RuntimeError("2.0 托管安装包只能在 Windows 构建；其他平台可从源码使用显式 go_endpoint")
        super().run()
        output = Path(self.build_lib).resolve() / "_gohttpx_bin" / "gohttpx-server.exe"
        output.parent.mkdir(parents=True, exist_ok=True)
        # 每次从当前源码构建，不能把开发目录中遗留的旧 EXE 装进新版本 wheel。
        subprocess.run(
            ["go", "build", "-trimpath", "-ldflags=-s -w", "-o", str(output), "."],
            cwd=Path(__file__).resolve().parent,
            env={**os.environ, "GOOS": "windows", "GOARCH": "amd64", "CGO_ENABLED": "0"},
            check=True, text=True, encoding="utf-8", errors="replace",
        )


class WindowsWheel(bdist_wheel):
    def finalize_options(self):
        super().finalize_options()
        self.root_is_pure = False

    def get_tag(self):
        # Python 代码没有 CPython ABI 绑定，但安装包内的 Go EXE 有明确的平台边界。
        return "py3", "none", "win_amd64"


setup(cmdclass={"build_py": BuildPython, "bdist_wheel": WindowsWheel})
