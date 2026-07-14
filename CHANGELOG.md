# 更新记录

## 1.0.0

- 首次公开发布：本机 loopback GoHTTPX bridge。
- 支持 HTTPX 同步/异步调用、req/v3、uTLS 指纹、HTTP/1/2/3/H2C、mTLS 与代理配置。
- 控制服务不再以固定写超时中断协议允许的长目标请求；目标超时仍由 v1 `timeout_ms` 和 Python 控制连接超时共同约束。
