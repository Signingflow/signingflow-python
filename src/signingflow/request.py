"""HTTPS calls. Redirects are not followed and bodies stop at 8 MB."""

import json
import re
import ssl
import uuid
from http.client import HTTPSConnection
from urllib.parse import urlsplit

from signingflow import clock
from signingflow.allowlist import operation
from signingflow.config import bad_header
from signingflow.errors import (
    APIError,
    AuthenticationError,
    ConnectionError,
    Error,
    IdempotencyError,
    InvalidRequestError,
    PermissionError,
    RateLimitError,
    invalid,
)
from signingflow.path import fill_path, query_contains_secret, resolve_url, retry_delay
from signingflow.redact import redact_message, redact_violations
from signingflow.status import (
    field_violations,
    grpc_code,
    mentions_idempotency,
    resource_name,
    server_message,
    trace_code,
)
from signingflow.version import SOURCE

MAX_RESPONSE_BYTES = 8 * 1024 * 1024
_UUID = re.compile(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")


class Sender:
    def __init__(self, config):
        self.config = config

    def call(self, operation_id, *, path_params=None, query=None, body=None, idempotency_key=None):
        spec = operation(operation_id)
        key = None
        payload = None if spec["http"] == "GET" else dict(body or {})
        if spec["idempotent"]:
            key = key_for(idempotency_key, body)
            payload["idempotencyKey"] = key
        try:
            path = fill_path(spec["path"], path_params)
            url = resolve_url(self.config.base_url, path, query)
        except InvalidRequestError as exc:
            exc.idempotency_key = key or ""
            raise
        raw_query = urlsplit(url).query
        if query_contains_secret(raw_query, self.config.api_key):
            raise InvalidRequestError("The API key must not be sent in the query string.", idempotency_key=key or "")
        retries = self.config.retries if spec["http"] == "GET" or spec["idempotent"] else 0
        encoded = None
        if payload is not None:
            try:
                encoded = json.dumps(payload).encode("utf-8")
            except (TypeError, ValueError) as exc:
                raise invalid("invalid request body") from exc
        attempt = 0
        while True:
            try:
                status, headers, data = self.exchange(spec["http"], url, encoded, self.headers(spec["http"]))
            except Error:
                raise
            except Exception as exc:
                if attempt < retries:
                    attempt += 1
                    continue
                raise _connection_error(exc, key) from exc
            if 200 <= status < 300:
                return _parse_success(status, _header(headers, "Content-Type"), data)
            if attempt < retries and _retryable(status):
                attempt += 1
                clock.sleep(retry_delay(_header(headers, "Rate-Limit-Retry-After"), _header(headers, "Rate-Limit-Reset-After"), clock.now()))
                continue
            raise _failure(status, headers, data, spec.get("capability") or "", key, self.config.api_key)

    def put_bytes(self, url, content_type, data):
        if bad_header(content_type or ""):
            raise invalid("invalid header value")
        retries = self.config.retries
        attempt = 0
        headers = {"Content-Type": content_type, "x-goog-if-generation-match": "0"}
        while True:
            try:
                status, _, _ = self.exchange("PUT", url, data, headers)
            except Error:
                raise
            except Exception as exc:
                if attempt < retries:
                    attempt += 1
                    continue
                raise ConnectionError("The upload could not be reached.", status_code=0) from exc
            if 200 <= status < 300 or status == 412:
                return
            if attempt < retries and status >= 500:
                attempt += 1
                continue
            raise APIError("Uploading the file to storage failed.", status_code=status)

    def headers(self, method):
        header = {
            "Authorization": "Bearer " + self.config.api_key,
            "X-Request-Workspace-Id": self.config.workspace_id,
            "X-Request-Env": self.config.wire_env,
            "X-Request-Source": SOURCE,
            "Accept": "application/json",
            "User-Agent": SOURCE,
        }
        if self.config.channel:
            header["X-Request-Channel"] = self.config.channel
        if self.config.funnel:
            header["X-Request-Funnel"] = self.config.funnel
        if method != "GET":
            header["Content-Type"] = "application/json"
        return header

    def exchange(self, method, url, body, headers):
        parts = urlsplit(url)
        if parts.scheme != "https" or not parts.hostname:
            raise invalid("url must be https")
        header = dict(headers or {})
        header["Accept-Encoding"] = "identity"
        for value in header.values():
            if bad_header(str(value)):
                raise invalid("invalid header value")
        path = parts.path or "/"
        if parts.query:
            path = path + "?" + parts.query
        context = self.config.ssl_context or _default_context()
        conn = HTTPSConnection(parts.hostname, parts.port or 443, timeout=self.config.timeout, context=context)
        try:
            conn.request(method, path, body=body, headers=header)
            response = conn.getresponse()
            data = _read_limited(response)
            return response.status, response.headers, data
        finally:
            conn.close()


def key_for(supplied, body):
    raw = (supplied or "").strip()
    if not raw and isinstance(body, dict):
        value = body.get("idempotencyKey")
        raw = value.strip() if isinstance(value, str) else ""
    if not raw:
        return str(uuid.uuid4())
    if not _UUID.match(raw):
        raise invalid("idempotencyKey must be a UUID.")
    return raw


def _default_context():
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def _read_limited(response):
    length = response.length
    if length is not None and length > MAX_RESPONSE_BYTES:
        raise APIError("The API response is larger than 8 MB.", status_code=response.status)
    chunks = []
    total = 0
    while True:
        piece = response.read(64 * 1024)
        if not piece:
            break
        total += len(piece)
        if total > MAX_RESPONSE_BYTES:
            raise APIError("The API response is larger than 8 MB.", status_code=response.status)
        chunks.append(piece)
    return b"".join(chunks)


def _parse_success(status, content_type, body):
    if not body or not body.strip():
        return {}
    content_type = content_type or ""
    if content_type and "json" not in content_type and "text/" not in content_type:
        raise APIError("The API returned a non-JSON body.", status_code=status)
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise APIError("The API returned invalid JSON.", status_code=status) from exc


def _failure(status, headers, body, capability, key, api_key=""):
    parsed = body.decode("utf-8", errors="replace")
    if body.strip():
        try:
            parsed = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            parsed = body.decode("utf-8", errors="replace")
    message = server_message(parsed)
    if not message:
        message = f"Request failed with status {status}." if not body else body.decode("utf-8", errors="replace")
    code = grpc_code(parsed)
    fields = {
        "status_code": status,
        "grpc_code": code,
        "trace_code": trace_code(parsed),
        "request_id": _header(headers, "X-Request-Id"),
        "idempotency_key": key or "",
        "capability": capability,
        "field_violations": redact_violations(field_violations(parsed), api_key),
        "retry_after": _header(headers, "Rate-Limit-Retry-After") or _header(headers, "Rate-Limit-Reset-After"),
    }
    message = redact_message(message, api_key)
    if status == 401:
        return AuthenticationError(message, **fields)
    if status == 403:
        return PermissionError(message, **fields)
    if status == 409 and mentions_idempotency(parsed):
        return IdempotencyError(message, resource_name=resource_name(parsed), **fields)
    if status == 429:
        return RateLimitError(message, **fields)
    if 400 <= status < 500:
        return InvalidRequestError(message, **fields)
    return APIError(message, **fields)


def _header(headers, name):
    if headers is None:
        return ""
    value = headers.get(name)
    return value or ""


def _retryable(status):
    return status in (408, 429) or status >= 500


def _connection_error(exc, key):
    text = str(exc).lower()
    timed_out = isinstance(exc, TimeoutError) or "timed out" in text
    if timed_out:
        return ConnectionError("The API timed out.", status_code=408, idempotency_key=key or "")
    return ConnectionError("The API could not be reached.", status_code=0, idempotency_key=key or "")
