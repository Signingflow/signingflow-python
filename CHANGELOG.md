# Changelog

## 0.1.0

First Python SDK for sending a document, reading envelope status, downloading a completed file, and verifying webhook signatures.

Install from GitHub with `pip install "signingflow @ git+https://github.com/Signingflow/signingflow-python.git"` until the package is on PyPI.

The API host is HTTPS `api.signingflow.com` unless a custom base URL is allowed. A file path is read only from `upload_root`. A hard link and an absolute path are rejected, and the file is not opened when the runtime cannot refuse a symlink. `construct_event` returns `payload` and `body_sha256` of the raw body. A 409 is an idempotency error only when the body says the key was already used. A timed-out send is returned only when `sent_time` falls in the two minutes after the call started. The client sends `Accept-Encoding: identity`, does not follow redirects, and stops reading an API response at 8 MB. A query value that contains the API key is rejected, including when that key is percent-encoded. An API error does not keep an API key that contains a slash or a space.
