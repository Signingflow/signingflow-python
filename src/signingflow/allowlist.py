"""The 15 operations used by skills and MCP tools."""

import json

from importlib.resources import files

from signingflow.errors import Error


def _load():
    try:
        raw = files("signingflow").joinpath("resources/allowlist.json").read_text(encoding="utf-8")
        parsed = json.loads(raw)
        operations = parsed["operations"]
        if len(operations) != 15:
            raise ValueError("allowlist length")
        return {item["operationId"]: item for item in operations}
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        raise RuntimeError("allowlist.json is invalid") from exc


OPERATIONS = _load()


def operation(operation_id):
    try:
        return OPERATIONS[operation_id]
    except KeyError as exc:
        raise Error(f"Unknown operation {operation_id}.") from exc
