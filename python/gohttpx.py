import asyncio
import base64
import json
import math
import os
import re
import ssl
import threading
from dataclasses import dataclass, field, fields, is_dataclass, replace
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Mapping, NoReturn, Sequence
from urllib.parse import quote

import httpx

__version__ = "1.0.0"


class TLSFingerprint(str, Enum):
    GOLANG = "golang"
    RANDOMIZED = "randomized"
    RANDOMIZED_ALPN = "randomized_alpn"
    RANDOMIZED_NO_ALPN = "randomized_no_alpn"
    ANDROID_11_OKHTTP = "android_11_okhttp"
    CHROME_AUTO = "chrome_auto"
    CHROME_58 = "chrome_58"
    CHROME_62 = "chrome_62"
    CHROME_70 = "chrome_70"
    CHROME_72 = "chrome_72"
    CHROME_83 = "chrome_83"
    CHROME_87 = "chrome_87"
    CHROME_96 = "chrome_96"
    CHROME_100 = "chrome_100"
    CHROME_102 = "chrome_102"
    CHROME_106_SHUFFLE = "chrome_106_shuffle"
    CHROME_100_PSK = "chrome_100_psk"
    CHROME_112_PSK_SHUFFLE = "chrome_112_psk_shuffle"
    CHROME_114_PADDING_PSK_SHUFFLE = "chrome_114_padding_psk_shuffle"
    CHROME_115_PQ = "chrome_115_pq"
    CHROME_115_PQ_PSK = "chrome_115_pq_psk"
    CHROME_120 = "chrome_120"
    CHROME_120_PQ = "chrome_120_pq"
    CHROME_131 = "chrome_131"
    CHROME_133 = "chrome_133"
    FIREFOX_AUTO = "firefox_auto"
    FIREFOX_55 = "firefox_55"
    FIREFOX_56 = "firefox_56"
    FIREFOX_63 = "firefox_63"
    FIREFOX_65 = "firefox_65"
    FIREFOX_99 = "firefox_99"
    FIREFOX_102 = "firefox_102"
    FIREFOX_105 = "firefox_105"
    FIREFOX_120 = "firefox_120"
    IOS_AUTO = "ios_auto"
    IOS_11_1 = "ios_11_1"
    IOS_12_1 = "ios_12_1"
    IOS_13 = "ios_13"
    IOS_14 = "ios_14"
    EDGE_AUTO = "edge_auto"
    EDGE_85 = "edge_85"
    EDGE_106 = "edge_106"
    SAFARI_AUTO = "safari_auto"
    SAFARI_16_0 = "safari_16_0"
    BROWSER_360_AUTO = "360_auto"
    BROWSER_360_7_5 = "360_7_5"
    BROWSER_360_11_0 = "360_11_0"
    QQ_AUTO = "qq_auto"
    QQ_11_1 = "qq_11_1"


class Impersonate(str, Enum):
    NONE = "none"
    CHROME = "chrome"
    FIREFOX = "firefox"
    SAFARI = "safari"


@dataclass(frozen=True)
class RetryOptions:
    count: int = 0
    mode: str = "none"
    fixed_interval_ms: int = 0
    backoff_min_ms: int = 0
    backoff_max_ms: int = 0
    status_codes: tuple[int, ...] = ()


@dataclass(frozen=True)
class TransportOptions:
    tls_handshake_timeout_ms: int = 10000
    response_header_timeout_ms: int = 0
    expect_continue_timeout_ms: int = 1000
    idle_conn_timeout_ms: int = 90000
    max_idle_conns: int = 100
    max_idle_conns_per_host: int = 0
    max_conns_per_host: int = 0
    max_response_header_bytes: int = 0
    read_buffer_size: int = 0
    write_buffer_size: int = 0
    proxy_connect_headers: Mapping[str, Sequence[str]] = field(default_factory=dict)


@dataclass(frozen=True)
class HTTP2Setting:
    id: int
    value: int


@dataclass(frozen=True)
class PriorityParam:
    stream_dependency: int = 0
    exclusive: bool = False
    weight: int = 0


@dataclass(frozen=True)
class PriorityFrame:
    stream_id: int
    priority: PriorityParam


@dataclass(frozen=True)
class HTTP2Options:
    settings: tuple[HTTP2Setting, ...] = ()
    connection_flow: int | None = None
    header_priority: PriorityParam | None = None
    priority_frames: tuple[PriorityFrame, ...] = ()
    max_header_list_size: int = 0
    strict_max_concurrent_streams: bool = False
    read_idle_timeout_ms: int = 0
    ping_timeout_ms: int = 0
    write_byte_timeout_ms: int = 0


@dataclass(frozen=True)
class ClientOptions:
    tls_fingerprint: TLSFingerprint | str | None = None
    impersonate: Impersonate | str = Impersonate.NONE
    proxy_url: str | None = None
    verify: bool = True
    root_ca_pem: str | None = None
    client_cert_pem: str | None = None
    client_key_pem: str | None = None
    http_version: str = "auto"
    keep_alive: bool = True
    compression: bool = False
    allow_get_body: bool = True
    retry: RetryOptions = field(default_factory=RetryOptions)
    transport: TransportOptions = field(default_factory=TransportOptions)
    http2: HTTP2Options = field(default_factory=HTTP2Options)


@dataclass(frozen=True)
class RequestOptions:
    header_order: tuple[str, ...] = ()
    pseudo_header_order: tuple[str, ...] = ()
    force_chunked: bool = False
    close_connection: bool = False
    trace: bool = False
    dump: bool = False
    retry_count: int | None = None


class GoServiceUnavailable(httpx.TransportError):
    pass


class GoProtocolError(httpx.TransportError):
    def __init__(
        self,
        message: str,
        *,
        request: httpx.Request | None = None,
        code: str | None = None,
        request_id: str | None = None,
    ) -> None:
        super().__init__(message, request=request)
        self.code = code
        self.request_id = request_id


_UNSET = object()
_LOCAL_CONTROL_TIMEOUT = 1.0
_TARGET_TIMEOUT_GRACE = 1.0
_MAX_TARGET_TIMEOUT = 600.0
_HTTP_VERSIONS = {
    "HTTP/1.0": b"HTTP/1.0",
    "HTTP/1.1": b"HTTP/1.1",
    "HTTP/2.0": b"HTTP/2",
    "HTTP/2": b"HTTP/2",
    "HTTP/3.0": b"HTTP/3",
    "HTTP/3": b"HTTP/3",
}
_HTTP_TOKEN_BYTES = frozenset(b"!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
_RFC3339_TIMESTAMP = re.compile(
    r"(?P<date>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"
    r"(?:\.(?P<fraction>\d{1,9}))?(?P<timezone>Z|[+-]\d{2}:\d{2})"
)
_REQUEST_OPTION_FIELDS = {item.name for item in fields(RequestOptions)}


def _wire(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value):
        return {
            item.name: _wire(item_value)
            for item in fields(value)
            if (item_value := getattr(value, item.name)) is not None
        }
    if isinstance(value, Mapping):
        return {str(key): _wire(item_value) for key, item_value in value.items()}
    if isinstance(value, (list, tuple)):
        return [_wire(item) for item in value]
    return value


def _request_options(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, RequestOptions):
        result = _wire(value)
    elif isinstance(value, Mapping):
        result = dict(value)
        unknown = set(result) - _REQUEST_OPTION_FIELDS
        if unknown:
            raise TypeError(f"go_req 包含未知字段: {sorted(unknown)!r}")
    else:
        raise TypeError("go_req 必须是 RequestOptions 或 mapping")

    for name in ("header_order", "pseudo_header_order"):
        if name in result:
            item = result[name]
            if isinstance(item, (str, bytes)) or not isinstance(item, Sequence) or not all(isinstance(entry, str) for entry in item):
                raise TypeError(f"go_req.{name} 必须是字符串序列")
            result[name] = list(item)
    for name in ("force_chunked", "close_connection", "trace", "dump"):
        if name in result and type(result[name]) is not bool:
            raise TypeError(f"go_req.{name} 必须是 bool")
    if "retry_count" in result:
        retry_count = result["retry_count"]
        if retry_count is None:
            result.pop("retry_count")
        elif type(retry_count) is not int or not 0 <= retry_count <= 10:
            raise ValueError("go_req.retry_count 必须是 0 到 10 的整数")
    return result


def _decode_json(response: httpx.Response, request: httpx.Request | None) -> dict[str, Any]:
    content_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type != "application/json":
        raise GoProtocolError("Go 服务返回了非法 Content-Type", request=request)

    def reject_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    try:
        decoded = json.loads(
            response.content,
            object_pairs_hook=reject_duplicate,
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)),
        )
    except (UnicodeDecodeError, ValueError, TypeError) as exc:
        raise GoProtocolError("Go 服务返回了非法 JSON", request=request) from exc
    pending = [decoded]
    while pending:
        value = pending.pop()
        if value is None:
            raise GoProtocolError("Go 服务返回的 JSON 含 null", request=request)
        if isinstance(value, dict):
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
    if not isinstance(decoded, dict):
        raise GoProtocolError("Go 服务返回的 JSON envelope 不是对象", request=request)
    return decoded


def _raise_service_error(data: dict[str, Any], request: httpx.Request | None) -> NoReturn:
    if set(data) != {"error"} or not isinstance(data["error"], dict):
        raise GoProtocolError("Go 服务返回了非法错误 envelope", request=request)
    error = data["error"]
    required = {"code", "message", "retryable"}
    if not required.issubset(error) or set(error) - required - {"request_id"}:
        raise GoProtocolError("Go 服务返回了非法错误字段", request=request)
    code = error["code"]
    message = error["message"]
    retryable = error["retryable"]
    request_id = error.get("request_id")
    if not isinstance(code, str) or not code or not isinstance(message, str) or type(retryable) is not bool:
        raise GoProtocolError("Go 服务返回了错误类型的错误字段", request=request)
    if request_id is not None and not isinstance(request_id, str):
        raise GoProtocolError("Go 服务返回了错误类型的 request_id", request=request)
    exception_type = {
        "UPSTREAM_TIMEOUT": httpx.TimeoutException,
        "UPSTREAM_DNS_ERROR": httpx.ConnectError,
        "UPSTREAM_CONNECT_ERROR": httpx.ConnectError,
        "UPSTREAM_TLS_ERROR": httpx.ConnectError,
        "UPSTREAM_PROTOCOL_ERROR": httpx.RemoteProtocolError,
    }.get(code)
    if exception_type is None:
        raise GoProtocolError(message, request=request, code=code, request_id=request_id)
    exception = exception_type(message, request=request)
    exception.code = code
    exception.request_id = request_id
    raise exception


def _retarget_transport_error(error: BaseException, request: httpx.Request) -> BaseException:
    if isinstance(error, GoProtocolError):
        return GoProtocolError(
            str(error),
            request=request,
            code=error.code,
            request_id=error.request_id,
        )
    if isinstance(error, httpx.TransportError):
        copied = type(error)(str(error), request=request)
        for name in ("code", "request_id"):
            if hasattr(error, name):
                setattr(copied, name, getattr(error, name))
        return copied
    return error


def _client_payload(options: ClientOptions) -> dict[str, Any]:
    payload = _wire(options)
    payload["protocol_version"] = 1
    impersonate = payload.get("impersonate", "none")
    if payload.get("http_version") == "http3":
        defaults = TransportOptions()
        for name in ("expect_continue_timeout_ms", "max_idle_conns"):
            if getattr(options.transport, name) == getattr(defaults, name):
                payload["transport"][name] = 0
    if "tls_fingerprint" not in payload and impersonate == "none" and payload.get("http_version") != "http3":
        payload["tls_fingerprint"] = TLSFingerprint.ANDROID_11_OKHTTP.value
    return payload


def _created_client_id(data: dict[str, Any], request: httpx.Request | None = None) -> str:
    if set(data) != {"protocol_version", "client_id", "expires_at"}:
        raise GoProtocolError("创建会话响应包含非法字段", request=request)
    if type(data["protocol_version"]) is not int or data["protocol_version"] != 1:
        raise GoProtocolError("创建会话响应的 protocol_version 非 v1", request=request)
    client_id = data["client_id"]
    expires_at = data["expires_at"]
    if not isinstance(client_id, str) or not client_id or not isinstance(expires_at, str) or not expires_at:
        raise GoProtocolError("创建会话响应缺少合法字段", request=request)
    timestamp = _RFC3339_TIMESTAMP.fullmatch(expires_at)
    if timestamp is None:
        raise GoProtocolError("创建会话响应包含非法 expires_at", request=request)
    normalized = timestamp.group("date")
    if fraction := timestamp.group("fraction"):
        normalized += "." + fraction[:6].ljust(6, "0")
    timezone = timestamp.group("timezone")
    normalized += "+00:00" if timezone == "Z" else timezone
    try:
        expires = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise GoProtocolError("创建会话响应包含非法 expires_at", request=request) from exc
    if expires.tzinfo is None:
        raise GoProtocolError("创建会话响应包含非法 expires_at", request=request)
    return client_id


def _timeout_ms(extension: Any, request: httpx.Request) -> int:
    if extension is None:
        return 0
    if not isinstance(extension, Mapping):
        raise GoProtocolError("HTTPX timeout extension 非 mapping", request=request)
    values = []
    for value in extension.values():
        if value is None:
            continue
        if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
            raise GoProtocolError("HTTPX timeout extension 包含非法值", request=request)
        values.append(float(value))
    if not values:
        return 0
    return min(600000, math.ceil(max(values) * 1000))


def _request_payload(request: httpx.Request, body: bytes) -> dict[str, Any]:
    try:
        headers = [[name.decode("ascii"), value.decode("latin-1")] for name, value in request.headers.raw]
    except UnicodeDecodeError as exc:
        raise GoProtocolError("目标请求 header 不能编码到 Go v1 协议", request=request) from exc
    return {
        "protocol_version": 1,
        "method": request.method,
        "url": str(request.url),
        "headers": headers,
        "body_base64": base64.b64encode(body).decode("ascii"),
        "timeout_ms": _timeout_ms(request.extensions.get("timeout"), request),
        "options": _request_options(request.extensions.get("go_req")),
    }


class _GoTransport(httpx.BaseTransport):
    def __init__(self, endpoint: str, token: str | None, options: ClientOptions) -> None:
        self._endpoint = endpoint.rstrip("/")
        self._payload = _client_payload(options)
        headers = {"Authorization": f"Bearer {token}"} if token else None
        self._control = httpx.Client(headers=headers, trust_env=False)
        self._condition = threading.Condition()
        self._active = 0
        self._closing = False
        self._closed = False
        self._client_id: str | None = None
        self._generation = 0
        self._rebuilding = False
        self._failed_generation: int | None = None
        self._rebuild_error: BaseException | None = None
        try:
            capabilities = self._call("GET", "/api/v1/capabilities", None, None)
            self._validate_capabilities(capabilities, options)
            self._client_id = self._create_session()
        except BaseException:
            try:
                if self._client_id is not None:
                    self._delete_session(self._client_id)
            except BaseException:
                pass
            finally:
                self._control.close()
            raise

    def _call(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None,
        request: httpx.Request | None,
        *,
        expected_status: int = 200,
    ) -> dict[str, Any]:
        control_timeout = _LOCAL_CONTROL_TIMEOUT
        if request is not None and payload is not None and "timeout_ms" in payload:
            timeout_ms = payload["timeout_ms"] if payload is not None else 0
            control_timeout = (timeout_ms / 1000 if timeout_ms else _MAX_TARGET_TIMEOUT) + _TARGET_TIMEOUT_GRACE
        try:
            response = self._control.request(
                method,
                self._endpoint + path,
                json=payload,
                timeout=control_timeout,
            )
        except httpx.TransportError as exc:
            raise GoServiceUnavailable("无法连接本地 Go 服务", request=request) from exc
        data = _decode_json(response, request)
        if response.status_code >= 400:
            _raise_service_error(data, request)
        if response.status_code != expected_status or "error" in data:
            raise GoProtocolError("Go 服务返回了错误的状态或 envelope", request=request)
        return data

    def _create_session(self, request: httpx.Request | None = None) -> str:
        created = self._call("POST", "/api/v1/clients", self._payload, request, expected_status=201)
        candidate = created.get("client_id")
        try:
            return _created_client_id(created, request)
        except BaseException:
            if isinstance(candidate, str) and candidate:
                try:
                    self._delete_session(candidate)
                except BaseException:
                    pass
            raise

    def _delete_session(self, client_id: str) -> None:
        try:
            response = self._control.delete(
                self._endpoint + f"/api/v1/clients/{quote(client_id, safe='')}",
                timeout=_LOCAL_CONTROL_TIMEOUT,
            )
        except httpx.TransportError as exc:
            raise GoServiceUnavailable("删除 Go 会话时无法连接本地服务") from exc
        if response.status_code >= 400:
            _raise_service_error(_decode_json(response, None), None)
        if response.status_code != 204:
            raise GoProtocolError("删除 Go 会话返回了错误状态")

    @staticmethod
    def _validate_capabilities(
        data: dict[str, Any],
        options: ClientOptions,
        request: httpx.Request | None = None,
    ) -> None:
        if set(data) != {"protocol_version", "server_version", "max_body_bytes", "tls_fingerprints"}:
            raise GoProtocolError("capabilities 包含非法字段", request=request)
        if type(data.get("protocol_version")) is not int or data["protocol_version"] != 1:
            raise GoProtocolError("Go 服务不支持控制协议 v1", request=request)
        if not isinstance(data["server_version"], str) or not data["server_version"]:
            raise GoProtocolError("capabilities 缺少合法 server_version", request=request)
        if type(data["max_body_bytes"]) is not int or data["max_body_bytes"] <= 0:
            raise GoProtocolError("capabilities 缺少合法 max_body_bytes", request=request)
        fingerprints = data.get("tls_fingerprints")
        if not isinstance(fingerprints, list) or not all(isinstance(item, str) for item in fingerprints):
            raise GoProtocolError("capabilities 缺少合法 tls_fingerprints", request=request)
        available = set(fingerprints)
        if len(available) != len(fingerprints) or not {item.value for item in TLSFingerprint}.issubset(available):
            raise GoProtocolError("capabilities 的 tls_fingerprints 与 SDK 不兼容", request=request)
        fingerprint = options.tls_fingerprint
        if fingerprint is not None and _wire(fingerprint) not in fingerprints:
            raise GoProtocolError(f"Go 服务不支持 TLS 指纹 {_wire(fingerprint)!r}", request=request)

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        with self._condition:
            if self._closing or self._closed:
                raise GoServiceUnavailable("Go transport 已关闭", request=request)
            self._active += 1
            client_id = self._client_id
            generation = self._generation
        try:
            payload = _request_payload(request, request.read())
            try:
                data = self._call(
                    "POST",
                    f"/api/v1/clients/{quote(client_id or '', safe='')}/requests",
                    payload,
                    request,
                )
            except GoProtocolError as exc:
                if exc.code != "CLIENT_NOT_FOUND":
                    raise
                client_id = self._rebuild(generation, request)
                data = self._call(
                    "POST",
                    f"/api/v1/clients/{quote(client_id, safe='')}/requests",
                    payload,
                    request,
                )
            return self._response(data, request)
        finally:
            with self._condition:
                self._active -= 1
                self._condition.notify_all()

    def _rebuild(self, generation: int, request: httpx.Request) -> str:
        with self._condition:
            while self._rebuilding and self._generation == generation:
                self._condition.wait()
            if self._generation != generation:
                return self._client_id or ""
            if self._failed_generation == generation and self._rebuild_error is not None:
                raise _retarget_transport_error(self._rebuild_error, request)
            if self._closing or self._closed:
                raise GoServiceUnavailable("Go transport 已关闭", request=request)
            self._rebuilding = True

        try:
            client_id = self._create_session(request)
        except BaseException as exc:
            with self._condition:
                if isinstance(exc, Exception):
                    self._failed_generation = generation
                    self._rebuild_error = exc
                self._rebuilding = False
                self._condition.notify_all()
            raise

        with self._condition:
            self._client_id = client_id
            self._generation += 1
            self._failed_generation = None
            self._rebuild_error = None
            self._rebuilding = False
            self._condition.notify_all()
            return client_id

    @staticmethod
    def _response(data: dict[str, Any], request: httpx.Request) -> httpx.Response:
        required = {
            "protocol_version",
            "request_id",
            "status_code",
            "reason_phrase",
            "headers",
            "body_base64",
            "url",
            "http_version",
            "elapsed_ms",
        }
        if not required.issubset(data) or set(data) - required - {"trace", "dump"} or "error" in data:
            raise GoProtocolError("Go 请求响应缺少必需字段", request=request)
        if type(data["protocol_version"]) is not int or data["protocol_version"] != 1:
            raise GoProtocolError("Go 请求响应的 protocol_version 非 v1", request=request)
        if not isinstance(data["request_id"], str) or not data["request_id"]:
            raise GoProtocolError("Go 请求响应的 request_id 非法", request=request)
        status = data["status_code"]
        if type(status) is not int or not 100 <= status <= 599:
            raise GoProtocolError("Go 请求响应的 HTTP status 非法", request=request)
        reason = data["reason_phrase"]
        if not isinstance(reason, str):
            raise GoProtocolError("Go 请求响应的 reason_phrase 非法", request=request)
        version = data["http_version"]
        if not isinstance(version, str) or version not in _HTTP_VERSIONS:
            raise GoProtocolError("Go 请求响应的 HTTP version 非法", request=request)
        if not isinstance(data["url"], str):
            raise GoProtocolError("Go 请求响应的 URL 非法", request=request)
        elapsed = data["elapsed_ms"]
        if type(elapsed) not in (int, float) or not math.isfinite(elapsed) or elapsed < 0:
            raise GoProtocolError("Go 请求响应的 elapsed_ms 非法", request=request)

        raw_headers = []
        if not isinstance(data["headers"], list):
            raise GoProtocolError("Go 请求响应的 headers 非法", request=request)
        try:
            for pair in data["headers"]:
                if not isinstance(pair, list) or len(pair) != 2 or not all(isinstance(item, str) for item in pair):
                    raise ValueError
                name = pair[0].encode("ascii")
                value = pair[1].encode("latin-1")
                if not name or any(byte not in _HTTP_TOKEN_BYTES for byte in name):
                    raise ValueError
                if any((byte < 32 and byte != 9) or byte == 127 for byte in value):
                    raise ValueError
                raw_headers.append((name, value))
            body = base64.b64decode(data["body_base64"], validate=True)
            reason_bytes = reason.encode("latin-1")
            if any((byte < 32 and byte != 9) or byte == 127 for byte in reason_bytes):
                raise ValueError
        except (UnicodeEncodeError, ValueError, TypeError) as exc:
            raise GoProtocolError("Go 请求响应的 header、正文或 reason 非法", request=request) from exc

        trace = data.get("trace")
        if trace is not None:
            trace_fields = {
                "dns_lookup_ms",
                "connect_ms",
                "tls_handshake_ms",
                "first_byte_ms",
                "response_ms",
                "total_ms",
                "connection_reused",
                "remote_address",
            }
            if not isinstance(trace, dict) or set(trace) != trace_fields:
                raise GoProtocolError("Go 请求响应的 trace 非法", request=request)
            for name in trace_fields - {"connection_reused", "remote_address"}:
                if type(trace[name]) not in (int, float) or not math.isfinite(trace[name]) or trace[name] < 0:
                    raise GoProtocolError("Go 请求响应的 trace 数值非法", request=request)
            if type(trace["connection_reused"]) is not bool or not isinstance(trace["remote_address"], str):
                raise GoProtocolError("Go 请求响应的 trace 类型非法", request=request)
        dump = data.get("dump")
        if dump is not None and not isinstance(dump, str):
            raise GoProtocolError("Go 请求响应的 dump 非法", request=request)

        extensions = {
            "http_version": _HTTP_VERSIONS[version],
            "reason_phrase": reason_bytes,
        }
        if trace is not None:
            extensions["go_trace"] = trace
        if dump is not None:
            extensions["go_dump"] = dump
        return httpx.Response(
            status,
            headers=raw_headers,
            stream=httpx.ByteStream(body),
            request=request,
            extensions=extensions,
        )

    def close(self) -> None:
        with self._condition:
            if self._closed:
                return
            if self._closing:
                while not self._closed:
                    self._condition.wait()
                return
            self._closing = True
            while self._active:
                self._condition.wait()
            client_id = self._client_id

        error = None
        try:
            if client_id is not None:
                self._delete_session(client_id)
        except BaseException as exc:
            error = exc
        finally:
            self._control.close()
            with self._condition:
                self._closed = True
                self._condition.notify_all()
        if error is not None:
            raise error


class _AsyncGoTransport(httpx.AsyncBaseTransport):
    def __init__(self, endpoint: str, token: str | None, options: ClientOptions) -> None:
        self._endpoint = endpoint.rstrip("/")
        self._headers = {"Authorization": f"Bearer {token}"} if token else None
        self._options = options
        self._payload = _client_payload(options)
        self._control: httpx.AsyncClient | None = None
        self._condition = asyncio.Condition()
        self._session_lock = asyncio.Lock()
        self._session_attempt: asyncio.Task[str] | None = None
        self._session_attempt_waiters = 0
        self._active = 0
        self._closing = False
        self._closed = False
        self._client_id: str | None = None
        self._generation = 0
        self._capabilities_checked = False
        self._failed_generation: int | None = None
        self._rebuild_error: BaseException | None = None

    async def _call(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None,
        request: httpx.Request | None,
        *,
        expected_status: int = 200,
    ) -> dict[str, Any]:
        if self._control is None:
            self._control = httpx.AsyncClient(headers=self._headers, trust_env=False)
        control_timeout = _LOCAL_CONTROL_TIMEOUT
        if request is not None and payload is not None and "timeout_ms" in payload:
            timeout_ms = payload["timeout_ms"] if payload is not None else 0
            control_timeout = (timeout_ms / 1000 if timeout_ms else _MAX_TARGET_TIMEOUT) + _TARGET_TIMEOUT_GRACE
        try:
            response = await self._control.request(
                method,
                self._endpoint + path,
                json=payload,
                timeout=control_timeout,
            )
        except httpx.TransportError as exc:
            raise GoServiceUnavailable("无法连接本地 Go 服务", request=request) from exc
        data = _decode_json(response, request)
        if response.status_code >= 400:
            _raise_service_error(data, request)
        if response.status_code != expected_status or "error" in data:
            raise GoProtocolError("Go 服务返回了错误的状态或 envelope", request=request)
        return data

    async def _delete_session(self, client_id: str) -> None:
        if self._control is None:
            return
        try:
            response = await self._control.delete(
                self._endpoint + f"/api/v1/clients/{quote(client_id, safe='')}",
                timeout=_LOCAL_CONTROL_TIMEOUT,
            )
        except httpx.TransportError as exc:
            raise GoServiceUnavailable("删除 Go 会话时无法连接本地服务") from exc
        if response.status_code >= 400:
            _raise_service_error(_decode_json(response, None), None)
        if response.status_code != 204:
            raise GoProtocolError("删除 Go 会话返回了错误状态")

    async def _create_session(self, request: httpx.Request | None = None) -> str:
        if not self._capabilities_checked:
            capabilities = await self._call("GET", "/api/v1/capabilities", None, request)
            _GoTransport._validate_capabilities(capabilities, self._options, request)
            self._capabilities_checked = True
        created = await self._call("POST", "/api/v1/clients", self._payload, request, expected_status=201)
        candidate = created.get("client_id")
        try:
            return _created_client_id(created, request)
        except BaseException:
            if isinstance(candidate, str) and candidate:
                try:
                    await self._delete_session(candidate)
                except BaseException:
                    pass
            raise

    async def _run_initial_session_attempt(self, request: httpx.Request) -> str:
        client_id = await self._create_session(request)
        async with self._session_lock:
            self._client_id = client_id
        return client_id

    async def _ensure_session(self, request: httpx.Request) -> tuple[str, int]:
        async with self._session_lock:
            if self._client_id is not None:
                return self._client_id, self._generation
            async with self._condition:
                if self._closing or self._closed:
                    raise GoServiceUnavailable("Go transport 已关闭", request=request)
            if self._session_attempt is not None and self._session_attempt.done() and not self._session_attempt_waiters:
                try:
                    self._session_attempt.exception()
                except BaseException:
                    pass
                self._session_attempt = None
            if self._session_attempt is None:
                self._session_attempt = asyncio.create_task(self._run_initial_session_attempt(request))
            attempt = self._session_attempt
            self._session_attempt_waiters += 1

        try:
            client_id = await asyncio.shield(attempt)
        except BaseException as exc:
            async with self._session_lock:
                self._session_attempt_waiters -= 1
                if attempt.done() and not self._session_attempt_waiters:
                    try:
                        attempt.exception()
                    except BaseException:
                        pass
                    self._session_attempt = None
            if isinstance(exc, Exception):
                raise _retarget_transport_error(exc, request) from exc
            raise

        async with self._session_lock:
            self._session_attempt_waiters -= 1
            if not self._session_attempt_waiters:
                self._session_attempt = None
            return client_id, self._generation

    async def _rebuild(self, generation: int, request: httpx.Request) -> str:
        async with self._session_lock:
            if self._generation != generation:
                return self._client_id or ""
            if self._failed_generation == generation and self._rebuild_error is not None:
                raise _retarget_transport_error(self._rebuild_error, request)
            async with self._condition:
                if self._closing or self._closed:
                    raise GoServiceUnavailable("Go transport 已关闭", request=request)
            try:
                client_id = await self._create_session(request)
            except BaseException as exc:
                if isinstance(exc, Exception):
                    self._failed_generation = generation
                    self._rebuild_error = exc
                raise
            self._client_id = client_id
            self._generation += 1
            self._failed_generation = None
            self._rebuild_error = None
            return client_id

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        async with self._condition:
            if self._closing or self._closed:
                raise GoServiceUnavailable("Go transport 已关闭", request=request)
            self._active += 1
        try:
            client_id, generation = await self._ensure_session(request)
            payload = _request_payload(request, await request.aread())
            try:
                data = await self._call(
                    "POST",
                    f"/api/v1/clients/{quote(client_id, safe='')}/requests",
                    payload,
                    request,
                )
            except GoProtocolError as exc:
                if exc.code != "CLIENT_NOT_FOUND":
                    raise
                client_id = await self._rebuild(generation, request)
                data = await self._call(
                    "POST",
                    f"/api/v1/clients/{quote(client_id, safe='')}/requests",
                    payload,
                    request,
                )
            return _GoTransport._response(data, request)
        finally:
            async with self._condition:
                self._active -= 1
                self._condition.notify_all()

    async def aclose(self) -> None:
        async with self._condition:
            if self._closed:
                return
            if self._closing:
                while not self._closed:
                    await self._condition.wait()
                return
            self._closing = True
            while self._active:
                await self._condition.wait()

        async with self._session_lock:
            attempt = self._session_attempt
        if attempt is not None:
            try:
                await asyncio.shield(attempt)
            except Exception:
                pass
        async with self._session_lock:
            if attempt is not None and attempt is self._session_attempt and attempt.done() and not self._session_attempt_waiters:
                self._session_attempt = None
            client_id = self._client_id

        error = None
        try:
            if client_id is not None:
                await self._delete_session(client_id)
        except BaseException as exc:
            error = exc
        finally:
            if self._control is not None:
                await self._control.aclose()
            async with self._condition:
                self._closed = True
                self._condition.notify_all()
        if error is not None:
            raise error


def _resolve_client_options(
    client_options: ClientOptions | None,
    tls_fingerprint: TLSFingerprint | str | None,
    impersonate: Impersonate | str | None,
    verify: bool | str | os.PathLike[str] | ssl.SSLContext | object,
    cert: str | os.PathLike[str] | tuple[str | os.PathLike[str], str | os.PathLike[str]] | object,
    proxy: str | httpx.URL | httpx.Proxy | None | object,
    http1: bool | None,
    http2: bool | None,
) -> ClientOptions:
    if client_options is not None and not isinstance(client_options, ClientOptions):
        raise TypeError("client_options 必须是 ClientOptions")
    options = client_options or ClientOptions()
    if tls_fingerprint is not None:
        options = replace(options, tls_fingerprint=tls_fingerprint)
    if impersonate is not None:
        options = replace(options, impersonate=impersonate)

    if verify is not _UNSET:
        if isinstance(verify, ssl.SSLContext):
            raise TypeError("自定义 SSLContext 无法序列化给 Go")
        if isinstance(verify, bool):
            options = replace(options, verify=verify, root_ca_pem=None)
        elif isinstance(verify, (str, os.PathLike)):
            options = replace(options, verify=True, root_ca_pem=Path(verify).read_text(encoding="utf-8"))
        else:
            raise TypeError("verify 只支持 bool 或 CA 文件路径")
    if cert is not _UNSET:
        if isinstance(cert, (str, os.PathLike)):
            cert_text = Path(cert).read_text(encoding="utf-8")
            options = replace(options, client_cert_pem=cert_text, client_key_pem=cert_text)
        elif isinstance(cert, tuple) and len(cert) == 2:
            options = replace(
                options,
                client_cert_pem=Path(cert[0]).read_text(encoding="utf-8"),
                client_key_pem=Path(cert[1]).read_text(encoding="utf-8"),
            )
        else:
            raise TypeError("cert 只支持 PEM 文件或证书/私钥路径二元组")
    if proxy is not _UNSET:
        proxy_headers = None
        if proxy is None:
            proxy_url = None
        elif isinstance(proxy, httpx.Proxy):
            if proxy.ssl_context is not None:
                raise TypeError("带 SSLContext 的 Proxy 无法序列化给 Go")
            url = proxy.url
            if proxy.auth is not None:
                url = url.copy_with(username=proxy.auth[0], password=proxy.auth[1])
            proxy_url = str(url)
            proxy_headers = {name: proxy.headers.get_list(name) for name in proxy.headers}
        elif isinstance(proxy, (str, httpx.URL)):
            proxy_url = str(proxy)
        else:
            raise TypeError("proxy 只支持 URL 或 httpx.Proxy")
        transport_options = options.transport
        if proxy_headers is not None:
            transport_options = replace(transport_options, proxy_connect_headers=proxy_headers)
        options = replace(options, proxy_url=proxy_url, transport=transport_options)
    if http1 is not None or http2 is not None:
        supports_http1 = True if http1 is None else http1
        supports_http2 = False if http2 is None else http2
        if type(supports_http1) is not bool or type(supports_http2) is not bool or not (supports_http1 or supports_http2):
            raise ValueError("http1/http2 至少启用一个")
        version = "auto" if supports_http1 and supports_http2 else "http1" if supports_http1 else "http2"
        options = replace(options, http_version=version)
    return options


class Client(httpx.Client):
    def __init__(
        self,
        *,
        go_endpoint: str = "http://127.0.0.1:9876",
        go_token: str | None = None,
        client_options: ClientOptions | None = None,
        tls_fingerprint: TLSFingerprint | str | None = None,
        impersonate: Impersonate | str | None = None,
        verify: bool | str | os.PathLike[str] | ssl.SSLContext | object = _UNSET,
        cert: str | os.PathLike[str] | tuple[str | os.PathLike[str], str | os.PathLike[str]] | object = _UNSET,
        proxy: str | httpx.URL | httpx.Proxy | None | object = _UNSET,
        http1: bool | None = None,
        http2: bool | None = None,
        auth: httpx.Auth | tuple[str, str] | None = None,
        params: httpx.QueryParams | Mapping[str, Any] | list[tuple[str, Any]] | None = None,
        headers: httpx.Headers | Mapping[str, str] | list[tuple[str, str]] | None = None,
        cookies: httpx.Cookies | Mapping[str, str] | None = None,
        timeout: httpx.Timeout | float | None = httpx.Timeout(5.0),
        follow_redirects: bool = False,
        max_redirects: int = 20,
        event_hooks: Mapping[str, list[Any]] | None = None,
        base_url: httpx.URL | str = "",
        default_encoding: str | Any = "utf-8",
        transport: httpx.BaseTransport | None | object = _UNSET,
        mounts: Mapping[str, httpx.BaseTransport | None] | None | object = _UNSET,
    ) -> None:
        if transport is not _UNSET:
            raise TypeError("Client 不允许传入 transport")
        if mounts is not _UNSET:
            raise TypeError("Client 不允许传入 mounts")
        options = _resolve_client_options(
            client_options,
            tls_fingerprint,
            impersonate,
            verify,
            cert,
            proxy,
            http1,
            http2,
        )

        go_transport = _GoTransport(
            go_endpoint,
            os.getenv("GOHTTPX_TOKEN") if go_token is None else go_token,
            options,
        )
        try:
            super().__init__(
                auth=auth,
                params=params,
                headers=headers,
                cookies=cookies,
                timeout=timeout,
                follow_redirects=follow_redirects,
                max_redirects=max_redirects,
                event_hooks=event_hooks,
                base_url=base_url,
                transport=go_transport,
                default_encoding=default_encoding,
            )
            self._close_lock = threading.Lock()
        except BaseException:
            try:
                go_transport.close()
            except BaseException:
                pass
            raise

    def close(self) -> None:
        with self._close_lock:
            super().close()


class AsyncClient(httpx.AsyncClient):
    def __init__(
        self,
        *,
        go_endpoint: str = "http://127.0.0.1:9876",
        go_token: str | None = None,
        client_options: ClientOptions | None = None,
        tls_fingerprint: TLSFingerprint | str | None = None,
        impersonate: Impersonate | str | None = None,
        verify: bool | str | os.PathLike[str] | ssl.SSLContext | object = _UNSET,
        cert: str | os.PathLike[str] | tuple[str | os.PathLike[str], str | os.PathLike[str]] | object = _UNSET,
        proxy: str | httpx.URL | httpx.Proxy | None | object = _UNSET,
        http1: bool | None = None,
        http2: bool | None = None,
        auth: httpx.Auth | tuple[str, str] | None = None,
        params: httpx.QueryParams | Mapping[str, Any] | list[tuple[str, Any]] | None = None,
        headers: httpx.Headers | Mapping[str, str] | list[tuple[str, str]] | None = None,
        cookies: httpx.Cookies | Mapping[str, str] | None = None,
        timeout: httpx.Timeout | float | None = httpx.Timeout(5.0),
        follow_redirects: bool = False,
        max_redirects: int = 20,
        event_hooks: Mapping[str, list[Any]] | None = None,
        base_url: httpx.URL | str = "",
        default_encoding: str | Any = "utf-8",
        transport: httpx.AsyncBaseTransport | None | object = _UNSET,
        mounts: Mapping[str, httpx.AsyncBaseTransport | None] | None | object = _UNSET,
    ) -> None:
        if transport is not _UNSET:
            raise TypeError("AsyncClient 不允许传入 transport")
        if mounts is not _UNSET:
            raise TypeError("AsyncClient 不允许传入 mounts")
        options = _resolve_client_options(
            client_options,
            tls_fingerprint,
            impersonate,
            verify,
            cert,
            proxy,
            http1,
            http2,
        )
        go_transport = _AsyncGoTransport(
            go_endpoint,
            os.getenv("GOHTTPX_TOKEN") if go_token is None else go_token,
            options,
        )
        super().__init__(
            auth=auth,
            params=params,
            headers=headers,
            cookies=cookies,
            timeout=timeout,
            follow_redirects=follow_redirects,
            max_redirects=max_redirects,
            event_hooks=event_hooks,
            base_url=base_url,
            transport=go_transport,
            default_encoding=default_encoding,
        )
        self._close_lock = asyncio.Lock()
        self._close_task: asyncio.Task[None] | None = None

    async def aclose(self) -> None:
        async with self._close_lock:
            if self._close_task is None:
                self._close_task = asyncio.create_task(super().aclose())
                self._close_task.add_done_callback(lambda task: None if task.cancelled() else task.exception())
            close_task = self._close_task
        await asyncio.shield(close_task)


__all__ = [
    "__version__",
    "AsyncClient",
    "Client",
    "ClientOptions",
    "GoProtocolError",
    "GoServiceUnavailable",
    "HTTP2Options",
    "HTTP2Setting",
    "Impersonate",
    "PriorityFrame",
    "PriorityParam",
    "RequestOptions",
    "RetryOptions",
    "TLSFingerprint",
    "TransportOptions",
]
