import ast
import hashlib
import os
import re
import subprocess
import sys
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def checked_version():
    project = re.search(r"(?ms)^\[project\]\s*$(.*?)(?=^\[|\Z)", (ROOT / "pyproject.toml").read_text(encoding="utf-8")).group(1)
    package_version = re.search(r'^version\s*=\s*"([^"]+)"', project, re.MULTILINE).group(1)
    module_version = next(node.value.value for node in ast.parse((ROOT / "python/gohttpx.py").read_text(encoding="utf-8")).body if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "__version__" for target in node.targets))
    server_version = re.search(r'serverVersion\s*=\s*"([^"]+)"', (ROOT / "api.go").read_text(encoding="utf-8")).group(1)
    if package_version != module_version or package_version != server_version:
        raise ValueError("pyproject、Python SDK、Go 服务版本不一致")
    tag = os.getenv("GITHUB_REF_NAME", "")
    if os.getenv("GITHUB_REF_TYPE") == "tag" and tag != "v" + package_version:
        raise ValueError("发布标签与源码版本不一致")
    return package_version


def verify_binary(binary, version, revision):
    result = subprocess.run(["go", "version", "-m", str(binary)], cwd=ROOT, check=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
    settings = {}
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0] == "build":
            key, _, value = parts[1].partition("=")
            settings[key] = value
    expected = {"vcs.revision": revision, "vcs.modified": "false", "GOOS": "windows", "GOARCH": "amd64"}
    if any(settings.get(key) != value for key, value in expected.items()):
        raise ValueError(f"发布二进制的源码 revision、clean 状态或平台不匹配：{binary.name}")
    result = subprocess.run([str(binary), "--version"], cwd=ROOT, check=True, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30)
    if not result.stdout.startswith(f"GoHTTPX server {version} protocol 1 "):
        raise ValueError(f"发布二进制版本不匹配：{binary.name}")


def write_release_notes(version):
    status = subprocess.run(["git", "status", "--porcelain"], cwd=ROOT, check=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if status.stdout.strip():
        raise ValueError("发布只能使用已提交的干净源码")
    revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, check=True, capture_output=True, text=True, encoding="utf-8", errors="replace").stdout.strip()
    directory = ROOT / "dist"
    wheel = directory / f"gohttpx-{version}-py3-none-win_amd64.whl"
    binary = directory / "gohttpx-server-windows-amd64.exe"
    artifacts = [wheel, directory / f"gohttpx-{version}.tar.gz", binary]
    verify_binary(binary, version, revision)
    # sdist 不包含 .git；正式 wheel 必须直接从干净 checkout 构建，才能核验内置 EXE 的来源。
    extracted = ROOT / ".tmp" / "release-wheel-server.exe"
    extracted.parent.mkdir(exist_ok=True)
    try:
        with zipfile.ZipFile(wheel) as archive:
            name = next(name for name in archive.namelist() if name.endswith("/_gohttpx_bin/gohttpx-server.exe"))
            extracted.write_bytes(archive.read(name))
        verify_binary(extracted, version, revision)
    finally:
        extracted.unlink(missing_ok=True)
    rows = [(path.name, path.stat().st_size, hashlib.sha256(path.read_bytes()).hexdigest()) for path in artifacts]
    (directory / "SHA256SUMS").write_text("".join(f"{digest}  {name}\n" for name, _, digest in rows), encoding="ascii")
    notes = [
        f"# GoHTTPX {version}", "",
        "## 安装", "",
        "Windows amd64、Python 3.10+；wheel 已内置匹配版本的 Go EXE，无需单独下载、安装 Go 编译器或手动启动服务。", "",
        "```powershell", f'python -m pip install --upgrade --only-binary=gohttpx "gohttpx=={version}"', "```", "",
        "## 主要变化", "",
        "- 每个 Python 进程自动托管一份 Go，动态端口；不同 client 的 session 和 Cookie 隔离。",
        "- Python 结束后通过 Windows Job 回收 Go；Go 崩溃后自动恢复，结果不确定的在途请求不会被自动重放。",
        "- 外部服务模式需显式 go_endpoint；单独传 go_token 不再选择旧固定端口。不能只复制 gohttpx.py，Linux/macOS 托管尚不支持。",
        "- 独立 EXE 仅供手动部署；普通 Python 使用只需安装 wheel。", "",
        "## 验证与来源", "",
        f"Clean source revision: `{revision}`。独立 EXE 与 wheel 内置 EXE 均检查 vcs.revision、vcs.modified=false、平台和 --version。",
        "发布流程先执行 Go 全量/race/vet、Python 全量及独立安装测试，再通过 PyPI Trusted Publishing 上传。", "",
        "| 文件 | 字节数 | SHA-256 |", "|---|---:|---|",
        *[f"| {name} | {size} | `{digest}` |" for name, size, digest in rows], "",
    ]
    (directory / "RELEASE_NOTES.md").write_text("\n".join(notes), encoding="utf-8")
    print(f"verified release {version} from {revision}")


if __name__ == "__main__":
    version = checked_version()
    if sys.argv[1:] == ["validate"]:
        print(version)
        if output := os.getenv("GITHUB_OUTPUT"):
            with Path(output).open("a", encoding="utf-8") as stream:
                stream.write(f"value={version}\n")
    elif sys.argv[1:] == ["binary"]:
        binary = ROOT / "dist" / "gohttpx-server-windows-amd64.exe"
        binary.parent.mkdir(exist_ok=True)
        subprocess.run(
            ["go", "build", "-trimpath", f"-ldflags=-s -w -X main.serverVersion={version}", "-o", str(binary), "."],
            cwd=ROOT, env={**os.environ, "GOOS": "windows", "GOARCH": "amd64", "CGO_ENABLED": "0"},
            check=True, text=True, encoding="utf-8", errors="replace",
        )
        binary.with_suffix(".exe.sha256").write_text(hashlib.sha256(binary.read_bytes()).hexdigest() + "  " + binary.name + "\n", encoding="ascii")
    elif sys.argv[1:] == ["notes"]:
        write_release_notes(version)
    else:
        raise SystemExit("usage: python tools/release.py validate|binary|notes")
