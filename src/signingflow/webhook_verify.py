"""Verify a webhook before parsing it."""

import hashlib
import hmac
import json

from signingflow.errors import SignatureVerificationError, invalid


class Event:
    def __init__(self, payload, body_sha256):
        self.payload = payload
        self.body_sha256 = body_sha256


def construct_event(payload, signature, secret, *, previous_secret="", previous_signature=""):
    """Check the HMAC of the raw body, then parse JSON.

    Compare X-Signingflow-Signature or X-Webhook-Signature. Pass the previous
    header only together with the previous secret. There is no timestamp.
    """
    if not isinstance(payload, (bytes, bytearray)):
        raise SignatureVerificationError("Pass the raw request body.")
    payload = bytes(payload)
    if not secret:
        raise SignatureVerificationError("Webhook secret is required.")
    current = bool(signature) and _safe_equal(signature, _mac(secret, payload))
    previous = bool(previous_secret) and bool(previous_signature) and _safe_equal(previous_signature, _mac(previous_secret, payload))
    if not current and not previous:
        raise SignatureVerificationError("Webhook signature did not match.")
    digest = hashlib.sha256(payload).hexdigest()
    try:
        decoded = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise invalid("The webhook body is not JSON.") from exc
    return Event(decoded, digest)


def _mac(secret, body):
    return hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def _safe_equal(left, right):
    a = (left or "").lower().encode("utf-8")
    b = (right or "").lower().encode("utf-8")
    if len(a) != len(b):
        hmac.compare_digest(a, a)
        return False
    return hmac.compare_digest(a, b)
