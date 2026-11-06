"""Official Python SDK for the Signingflow calls used by skills and MCP tools."""

from signingflow.client import Client
from signingflow.errors import (
    APIError,
    AuthenticationError,
    ConnectionError,
    Error,
    IdempotencyError,
    InvalidRequestError,
    PermissionError,
    RateLimitError,
    SignatureVerificationError,
)
from signingflow.version import VERSION
from signingflow.webhook_verify import Event, construct_event
from signingflow.webhooks import HTTPConfig, signing_secret_of

__all__ = [
    "VERSION",
    "APIError",
    "AuthenticationError",
    "Client",
    "ConnectionError",
    "Error",
    "Event",
    "HTTPConfig",
    "IdempotencyError",
    "InvalidRequestError",
    "PermissionError",
    "RateLimitError",
    "SignatureVerificationError",
    "construct_event",
    "signing_secret_of",
]
