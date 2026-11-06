"""Path templates, query encoding, and the upload host check."""

import re
from datetime import datetime, timezone
from urllib.parse import parse_qsl, quote, quote_plus, urlencode, urlsplit, urlunsplit

from signingflow.errors import invalid

_SEGMENT = re.compile(r"^[A-Za-z0-9_-]+$")
_TOKEN = re.compile(r"\{([^}]+)\}")


def fill_path(template, params):
    params = params or {}
    failure = None

    def replace(match):
        nonlocal failure
        if failure is not None:
            return ""
        token = match.group(1)
        name = token.split("=", 1)[0]
        short = name.rsplit(".", 1)[-1]
        value = params.get(name) or params.get(short) or ""
        if not value and (short == "name" or short.startswith("name_")):
            value = params.get("name") or ""
        if not value:
            failure = invalid(f"missing path param {short}")
            return ""
        parts = value.split("/")
        escaped = []
        for part in parts:
            if not _SEGMENT.match(part):
                failure = invalid(f"invalid path param {short}")
                return ""
            escaped.append(quote(part, safe=""))
        return "/".join(escaped)

    filled = _TOKEN.sub(replace, template)
    if failure is not None:
        raise failure
    return filled


def resolve_url(base_url, path, query):
    base = urlsplit(base_url)
    base_path = base.path if base.path.endswith("/") else base.path + "/"
    origin = urlunsplit((base.scheme, base.netloc, base_path, "", ""))
    # A path that starts with / replaces the base path and keeps the origin.
    joined = urlunsplit((base.scheme, base.netloc, "", "", ""))
    from urllib.parse import urljoin

    resolved = urljoin(origin if path.startswith("/") else joined, path)
    parts = urlsplit(resolved)
    if parts.scheme != base.scheme or parts.netloc != base.netloc:
        raise invalid("invalid path")
    pairs = []
    for key, value in parse_qsl(parts.query, keep_blank_values=True):
        pairs.append((key, value))
    for key, value in (query or {}).items():
        if value:
            pairs.append((key, value))
    raw_query = urlencode(pairs)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, raw_query, ""))


def query_contains_secret(raw_query, secret):
    """Refuse an API key in the query, including after percent-encoding."""
    if not secret or not raw_query:
        return False
    if secret in raw_query or quote_plus(secret) in raw_query:
        return True
    if _bad_percent(raw_query):
        return True
    try:
        pairs = parse_qsl(raw_query, keep_blank_values=True, strict_parsing=False, errors="strict")
    except ValueError:
        return True
    return any(secret in value for _, value in pairs)


def _bad_percent(raw):
    index = 0
    while index < len(raw):
        if raw[index] != "%":
            index += 1
            continue
        digits = raw[index + 1 : index + 3]
        if len(digits) < 2 or any(char not in "0123456789abcdefABCDEF" for char in digits):
            return True
        index += 3
    return False


def allowed_upload_url(raw, hosts):
    parsed = urlsplit(raw)
    if not parsed.scheme or not parsed.netloc:
        raise invalid("upload url rejected")
    if parsed.scheme != "https":
        raise invalid("upload url must be https")
    if parsed.username is not None or parsed.password is not None:
        raise invalid("upload url rejected")
    if "\x00" in raw or (parsed.hostname or "").endswith("."):
        raise invalid("upload url rejected")
    host = (parsed.hostname or "").lower()
    for item in hosts:
        if host == item or host.endswith("." + item):
            return raw
    raise invalid("upload host rejected")


def retry_delay(retry_after, reset_after, now):
    when = _parse_retry(retry_after)
    if when is None:
        when = _parse_retry(reset_after)
    if when is None:
        return 0
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    delay = (when - now).total_seconds()
    if delay < 0:
        return 0
    if delay > 60:
        return 60
    return delay


def _parse_retry(value):
    value = (value or "").strip()
    if not value:
        return None
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None
