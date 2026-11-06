"""SDK errors. Every specific error is also an Error."""


class FieldViolation:
    def __init__(self, field, description):
        self.field = field
        self.description = description


class Error(Exception):
    def __init__(
        self,
        message="",
        *,
        status_code=0,
        grpc_code=None,
        trace_code="",
        request_id="",
        idempotency_key="",
        capability="",
        resource_name="",
        envelope_name="",
        retry_after="",
        field_violations=None,
    ):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.grpc_code = grpc_code
        self.trace_code = trace_code or ""
        self.request_id = request_id or ""
        self.idempotency_key = idempotency_key or ""
        self.capability = capability or ""
        self.resource_name = resource_name or ""
        self.envelope_name = envelope_name or ""
        self.retry_after = retry_after or ""
        self.field_violations = list(field_violations or [])


class AuthenticationError(Error):
    """HTTP 401."""


class PermissionError(Error):
    """HTTP 403."""


class IdempotencyError(Error):
    """HTTP 409 when the body says the key was already used."""


class RateLimitError(Error):
    """HTTP 429."""


class InvalidRequestError(Error):
    """Any other HTTP 4xx, or a rejected argument."""


class APIError(Error):
    """HTTP 5xx, or a body the client will not parse."""


class ConnectionError(Error):
    """The API was not reached, including a timeout."""


class SignatureVerificationError(Error):
    """A webhook MAC did not match."""


def invalid(message):
    return InvalidRequestError(message)


def attach(err, envelope_name):
    if isinstance(err, Error):
        err.envelope_name = envelope_name
    return err
