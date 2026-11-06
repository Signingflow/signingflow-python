"""Remove secrets from text the caller may log."""

import re
from urllib.parse import quote, quote_plus

_SECRET_KEY = re.compile(r"df_sk_[A-Za-z0-9_-]+")
_BEARER = re.compile(r"(?i)Bearer\s+\S+")
_SIGNED_QUERY = re.compile(r"(?i)([?&](?:X-Goog-Signature|Signature|sig|token)=)[^&\s\"]+")
_REDACTED = "df_sk_redacted"


def redact(value, secret=""):
    for form in _secret_forms(secret):
        value = value.replace(form, _REDACTED)
    value = _SECRET_KEY.sub(_REDACTED, value)
    value = _BEARER.sub("Bearer [redacted]", value)
    return _SIGNED_QUERY.sub(r"\1[redacted]", value)


def redact_message(value, secret=""):
    cleaned = redact(value or "", secret)
    if len(cleaned) <= 500:
        return cleaned
    return cleaned[:500] + "…"


def redact_violations(items, secret=""):
    from signingflow.errors import FieldViolation

    if not items:
        return []
    return [
        FieldViolation(redact_message(item.field, secret), redact_message(item.description, secret))
        for item in items
    ]


def _secret_forms(secret):
    """Raw key and the encodings a query or error body can echo."""
    secret = secret or ""
    forms = []
    for form in (secret, quote_plus(secret, safe=""), quote(secret, safe="")):
        if form and form not in forms:
            forms.append(form)
    forms.sort(key=len, reverse=True)
    return forms
