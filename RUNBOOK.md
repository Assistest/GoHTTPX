# GoHTTPX 运维说明

## 适用范围

仅用于同机 Python 后端连接 `127.0.0.1` 的 GoHTTPX bridge。它不是公网 HTTP 代理服务；除非网络已经隔离，禁止使用 `--allow-non-loopback`。

## 启动

在仓库根目录构建后，使用高强度随机 token 启动：

```powershell
$env:GOHTTPX_TOKEN = "replace-with-a-long-random-secret"
.\gohttpx-server.exe --host 127.0.0.1 --port 9876
```

不要使用 `--insecure-no-auth` 作为正式环境配置，也不要把 token 写入源码、日志或提交记录。

## 健康检查

```powershell
Invoke-RestMethod http://127.0.0.1:9876/api/v1/health
Invoke-RestMethod http://127.0.0.1:9876/api/v1/capabilities -Headers @{Authorization="Bearer $env:GOHTTPX_TOKEN"}
```

`health` 无需鉴权；`capabilities` 在正式模式必须携带 bearer token。

## 停止与升级

在启动服务的控制台按 Ctrl+C，服务最多等待 10 秒完成 graceful shutdown。不要依赖任务管理器强制结束来完成优雅关停。

升级时同时替换 Go EXE 和 `python/gohttpx.py`，并先执行 README 与 PROJECT_CONTEXT 中的完整测试命令。发布二进制前，在 GitHub Release 记录其版本、clean revision、SHA-256 和字节数。
