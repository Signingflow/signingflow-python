"""Read fields out of a gateway error body."""

import json


def as_map(value):
    return value if isinstance(value, dict) else None


def as_str(value):
    return value if isinstance(value, str) else ""


def as_int(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return None
    return None


def grpc_code(body):
    record = as_map(body)
    if record is None:
        return None
    return as_int(record.get("code"))


def server_message(body):
    if isinstance(body, str):
        return body
    record = as_map(body)
    if record is None:
        return ""
    return as_str(record.get("message"))


def trace_code(body):
    return _find_meta(body, "trace_code")


def resource_name(body):
    url = _find_meta(body, "resource_url")
    if url:
        return url
    return _find_meta(body, "resource_id")


def field_violations(body):
    from signingflow.errors import FieldViolation

    found = []

    def visit(record):
        items = record.get("fieldViolations", record.get("field_violations"))
        if not isinstance(items, list):
            return
        for item in items:
            row = as_map(item)
            if row is None:
                continue
            field = as_str(row.get("field"))
            description = as_str(row.get("description"))
            if field or description:
                found.append(FieldViolation(field, description))

    _walk(body, visit)
    return found


def mentions_idempotency(body):
    try:
        encoded = json.dumps(body)
    except (TypeError, ValueError):
        return False
    return "idempotency" in encoded.lower()


def _find_meta(body, key):
    found = ""

    def visit(record):
        nonlocal found
        if found:
            return
        meta = as_map(record.get("metadata"))
        if meta is None:
            return
        value = as_str(meta.get(key))
        if value:
            found = value

    _walk(body, visit)
    return found


def _walk(value, visit):
    if isinstance(value, dict):
        visit(value)
        for child in value.values():
            _walk(child, visit)
    elif isinstance(value, list):
        for child in value:
            _walk(child, visit)
