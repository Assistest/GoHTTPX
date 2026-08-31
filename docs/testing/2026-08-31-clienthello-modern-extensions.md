# ClientHello 现代扩展导入修复验证

日期：2026-08-31

## 问题

`C:\Users\51482\Desktop\Python\demo\main.py` 使用
`tls_spec_from_client_hello()` 导入 `C:\Users\51482\Desktop\hex.txt` 时，
GoHTTPX 2.1.1 报错：

```text
ValueError: 不支持的 TLS 扩展 34
```

输入是完整、有效的 ClientHello handshake hex dump。失败原因不是复制格式，
而是 2.1.1 的 Python 转换器和 Go 扩展白名单没有覆盖这份现代浏览器
ClientHello 中的全部扩展。

## 抓包中原先缺失的映射

- `34 (delegated_credentials)`：支持签名算法列表。
- `28 (record_size_limit)`：本次值为 `16385`。
- `27 (compress_certificate)`：原接口缺少 `zstd (3)`。
- `65037 (encrypted_client_hello)`：原接口只生成默认 GREASE ECH，未保留抓包的
  KDF、AEAD 和载荷长度特征。

## 修复

- Python 导入器现在严格解析并输出上述字段；畸形长度、越界值和未知值仍会报错，
  不会静默丢弃。
- Go JSON 接口新增 `delegated_credentials` 和 `record_size_limit`，证书压缩新增
  `zstd`，GREASE ECH 可指定候选密码套件、配置 ID 和载荷长度。
- ECH 导入只复现公开的 GREASE 形状，不复制抓包中的临时密钥、配置 ID 或密文。
- `delegated_credentials` 和 `record_size_limit` 当前用于 ClientHello 广告和指纹复现；
  不代表客户端实现了服务器 Delegated Credential 验证或 record layer 限制。
- 源码版本更新为 `2.1.2`；本记录对应发布前本地回归，公开产物以 GitHub Release 和 PyPI 为准。

用户的 `main.py` 和 `hex.txt` 均未修改。

## 线级验证

正式端到端测试让 Go 服务向本机 TLS 监听器发包并读取原始 ClientHello，确认：

- 扩展 34 的算法列表按 JSON 序列化。
- 扩展 28 的值为 `16385`。
- 扩展 27 同时包含 `zlib (1)`、`brotli (2)`、`zstd (3)`。
- 扩展 65037 使用指定的 KDF/AEAD，并产生指定长度的 GREASE ECH 载荷。
- 将捕获的 ClientHello 再交给 Python 导入后，第二次发包仍保留这些字段。

## 完整验证结果

2026-08-31 发布前从仓库根目录 fresh 执行：

| 检查 | 结果 |
|---|---|
| `go test ./... -count=1` | 通过，2.659 秒 |
| `go test -race ./... -count=1` | 通过，5.245 秒 |
| `go vet ./...` | 通过 |
| `python -m build` | 通过，生成 `gohttpx-2.1.2` sdist 与 Windows amd64 wheel |
| `python -B -m unittest discover -s python -p "test_*.py" -v` | 135 项通过，113.370 秒，无失败或跳过 |
| 安装 wheel 后、无 Go PATH 的真实 TLS 测试 | 通过 |
| 原样执行用户的 `main.py` | 通过 |

原样运行 `main.py` 的安全摘要（未记录服务端返回的公网 IP）：

```text
gohttpx version: 2.1.2
HTTP version: h2
TLS version: TLS 1.3 (772)
cipher suites: 15
extensions: 17
JA3 hash: 424f6d9c8b8928c0a0489a4f1a0f3e89
JA4: t13d1517h2_8daaf6152771_68c5a8c2958d
```

## 本地安装产物

```text
dist/gohttpx-2.1.2-py3-none-win_amd64.whl
size: 5169237 bytes
sha256: 1223a79c872a1dcf0ec1828619c314567c5980403501daf79a5e19bf0c3405ad
```

该 wheel 已强制安装到当前 Python 3.10 环境，替换本机的 2.1.1。
