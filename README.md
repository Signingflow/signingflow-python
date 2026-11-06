# signingflow

Python SDK for the Signingflow calls used to send a document, read envelope status, and receive webhooks.

The package talks to `https://api.signingflow.com`. Keep the API key on your server. Python 3.11 or newer is required.

```bash
pip install "signingflow @ git+https://github.com/Signingflow/signingflow-python.git"
```

The package name is `signingflow`. Install it from [GitHub](https://github.com/Signingflow/signingflow-python) until it is published on PyPI.

```python
import os
import signingflow

client = signingflow.Client(
    os.environ["SIGNINGFLOW_API_KEY"],
    workspace_id=os.environ["SIGNINGFLOW_WORKSPACE_ID"],
    env="sandbox",
)

envelope = client.envelopes.send_document(
    title="NDA",
    file=pdf_bytes,
    filename="contract.pdf",
    recipients=[{"name": "Ada Lovelace", "email": "ada@example.com"}],
    message="Please sign",
)
```

`file` is the raw bytes. `b""` is an empty file. A disk path is `path`, and it is read only from `upload_root`. That directory must be one this process writes. The open refuses a symlink, a hard link, an absolute path, and a path that leaves the directory. If this runtime cannot open a path without following a symlink, the read is refused. Do not pass a path from a request field.

`env` is `sandbox` or `live`. The client always sends `X-Request-Env`. A missing environment header is treated as live by the API, so the client rejects a missing environment.

`base_url` must be `https`. The host is `api.signingflow.com` unless `allow_custom_base_url` is set. A username or password on the URL is rejected. The host comparison is case-sensitive. There is no module-level API key.

The client sends `Accept-Encoding: identity`, does not follow redirects, and stops reading once an API response passes 8 MB.

## Send and read

`envelopes.prepare_draft` stores one PDF and creates a draft. It does not email anyone.

`envelopes.send_document` stores the PDF, creates the draft, adds the recipients to the first document, and sends. `envelopes.send_from_template` starts from `templates/{id}`.

If update or send fails, the error includes `envelope_name` for the draft that was saved. After a timeout, the client returns the envelope only when `sent_time` is within two minutes after the call started and not more than a minute ahead of this clock. An older or far-future timestamp is an error.

`envelopes.list(directory="needAction")` reads pages of 10. `page_size` can be from 1 to 1000. Omitting it selects 10. `0` is rejected. `all()` walks later pages and stops after 100 follow-up pages or a repeated token.

`envelopes.download_completed(name)` reads the envelope first. It requests the download URL only when the state is `COMPLETED`. The download call returns `uri`, `download_time`, and `etag`. This client does not GET `uri`. Treat that URL as untrusted until your application checks the host. Do not send the API key to it.

`envelopes.remind(name)` notifies people who can still sign. The call is not idempotent.

## Idempotency

Creates and sends send a UUID `idempotencyKey` in the JSON body. The same key is stored for the whole environment. A repeat returns HTTP 409 and does not return the original resource. The SDK raises `signingflow.IdempotencyError` with `resource_name` when the error includes one. It does not treat that response as success.

Pass the same `idempotency_key` only to retry one request after a timeout. `update` and `remind` are not retried automatically. A query value that contains the API key is rejected, including when that key is percent-encoded.

## Webhooks

```python
destination = client.webhook_urls.create(
    display_name="Envelope events",
    http_request_uri="https://example.com/webhooks/signingflow",
    events=["DOC_ENVELOPE_COMPLETED"],
)
secret = signingflow.signing_secret_of(destination)
```

Store that secret from the create response. A later `retrieve` does not include it. Do not set `http_config`. `auth` `NONE` is rejected.

```python
event = signingflow.construct_event(
    raw_body,
    signature_header,
    secret,
    previous_secret=previous_secret,
    previous_signature=previous_signature,
)
event.payload
event.body_sha256
```

`raw_body` must be the original `bytes`. The signature is lowercase hex HMAC-SHA256 of those bytes. There is no timestamp. Compare `X-Signingflow-Signature` or `X-Webhook-Signature`. During a grace window, also pass the previous header and secret. Parse JSON only after the MAC matches. `body_sha256` is the SHA-256 of those raw bytes. Store it and reject a delivery you have already seen.

## Errors

Every SDK error is a `signingflow.Error`.

| Type | When |
| --- | --- |
| `AuthenticationError` | HTTP 401 |
| `PermissionError` | HTTP 403 |
| `IdempotencyError` | HTTP 409 whose body says the key was already used |
| `RateLimitError` | HTTP 429 |
| `InvalidRequestError` | Any other HTTP 4xx, or a rejected argument |
| `APIError` | HTTP 5xx, or a body the client will not parse |
| `ConnectionError` | The API was not reached, including a timeout |
| `SignatureVerificationError` | A webhook MAC did not match |
