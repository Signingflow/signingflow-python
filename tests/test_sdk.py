"""Local tests. No request leaves 127.0.0.1."""

import gzip
import os
import ssl
import subprocess
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import signingflow
from signingflow.clock import now as real_now
from signingflow.clock import sleep as real_sleep
from signingflow.jail import _nofollow_flag, read_path
from signingflow.path import allowed_upload_url, query_contains_secret, retry_delay
from signingflow import clock

ENVELOPE = "envelopes/11111111-1111-4111-8111-111111111111"
STORAGE = "storages/33333333-3333-4333-8333-333333333333"
TEMPLATE = "templates/22222222-2222-4222-8222-222222222222"
HOOK = "webhookUrls/44444444-4444-4444-8444-444444444444"
DELIVERY = "webhooks/55555555-5555-4555-8555-555555555555"


def write_json(handler, status, payload):
    raw = payload if isinstance(payload, bytes) else __import__("json").dumps(payload).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(raw)))
    handler.end_headers()
    handler.wfile.write(raw)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        return

    def do_GET(self):
        self._go()

    def do_POST(self):
        self._go()

    def do_PATCH(self):
        self._go()

    def do_PUT(self):
        self._go()

    def _go(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        self.server.seen.append((self.command, self.path, dict(self.headers), body))
        result = self.server.app(self)
        if result == "chunk":
            self._chunk()
            return
        if result == "clen":
            self.send_response(200)
            self.send_header("Content-Length", "20000000")
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            return
        if result == "redirect":
            self.send_response(302)
            self.send_header("Location", "/secret")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        status, payload, extra = result
        if extra and extra.get("gzip"):
            raw = gzip.compress(payload if isinstance(payload, bytes) else __import__("json").dumps(payload).encode())
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return
        if extra and extra.get("headers"):
            raw = payload if isinstance(payload, bytes) else __import__("json").dumps(payload).encode()
            self.send_response(status)
            for key, value in extra["headers"].items():
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return
        write_json(self, status, payload)

    def _chunk(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        piece = b"A" * (64 * 1024)
        sent = 0
        try:
            while sent < 9 * 1024 * 1024:
                self.wfile.write(f"{len(piece):x}\r\n".encode())
                self.wfile.write(piece + b"\r\n")
                self.wfile.flush()
                sent += len(piece)
        except (BrokenPipeError, ConnectionResetError):
            return


def serve(app):
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(CERT, KEY)
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    httpd.app = app
    httpd.seen = []
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd


def trust():
    context = ssl.create_default_context()
    context.load_verify_locations(CERT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def client(httpd, **options):
    options.setdefault("workspace_id", "ws")
    options.setdefault("env", "sandbox")
    options.setdefault("base_url", f"https://127.0.0.1:{httpd.server_address[1]}")
    options.setdefault("allow_custom_base_url", True)
    options.setdefault("ssl_context", trust())
    options.setdefault("max_network_retries", 0)
    options.setdefault("timeout", 2)
    return signingflow.Client("df_sk_test", **options)


def envelope_body(name=ENVELOPE, **extra):
    body = {"name": name, "display_name": "NDA", "documents": [{"uid": "doc-1", "display_name": "NDA"}]}
    body.update(extra)
    return body


class SDKTest(unittest.TestCase):
    def tearDown(self):
        clock.now = real_now
        clock.sleep = real_sleep

    def test_config_rejects_unsafe_values(self):
        with self.assertRaises(signingflow.Error):
            signingflow.Client("", workspace_id="ws", env="sandbox")
        with self.assertRaises(signingflow.Error):
            signingflow.Client("key", workspace_id="  ", env="sandbox")
        with self.assertRaises(signingflow.Error):
            signingflow.Client("key", workspace_id="ws", env="prod")
        for base in (
            "http://api.signingflow.com",
            "https://API.SIGNINGFLOW.COM",
            "https://api.signingflow.com.",
            "https://api.signingflow.com.evil.com",
            "https://user:pass@api.signingflow.com",
            "https://api.signingflow.com@evil.com",
            "https://evil.com#@api.signingflow.com",
            "https://api.signingflow.com\x00.evil.com",
        ):
            with self.assertRaises(signingflow.Error):
                signingflow.Client("key", workspace_id="ws", env="sandbox", base_url=base)
        with self.assertRaises(signingflow.InvalidRequestError):
            signingflow.Client("ke\ny", workspace_id="ws", env="sandbox")
        with self.assertRaises(signingflow.Error):
            signingflow.Client("key", workspace_id="ws", env="sandbox", timeout=0)
        with self.assertRaises(signingflow.Error):
            signingflow.Client("key", workspace_id="ws", env="sandbox", max_network_retries=-1)
        with self.assertRaises(signingflow.Error):
            signingflow.Client("key", workspace_id="ws", env="sandbox", upload_hosts=["com"])
        signingflow.Client("key", workspace_id="ws", env="LIVE", base_url="https://api.signingflow.com")

    def test_headers_redaction_and_status(self):
        def app(handler):
            if ":view" in handler.path:
                self.assertEqual(handler.headers["Authorization"], "Bearer df_sk_test")
                self.assertEqual(handler.headers["X-Request-Env"], "SANDBOX")
                self.assertEqual(handler.headers["Accept-Encoding"], "identity")
                self.assertIn("readMask=documents", handler.path)
                return 400, {
                    "message": "bad df_sk_test Bearer secret",
                    "code": 3,
                    "metadata": {"trace_code": "trace-1"},
                    "fieldViolations": [{"field": "title", "description": "?token=abc"}],
                }, {"headers": {"X-Request-Id": "req-1"}}
            return 500, {"message": "no"}, None

        httpd = serve(app)
        self.addCleanup(httpd.shutdown)
        sdk = client(httpd, channel="mail", funnel="web")
        with self.assertRaises(signingflow.InvalidRequestError) as caught:
            sdk.envelopes.retrieve(ENVELOPE, read_mask="documents")
        err = caught.exception
        self.assertEqual(err.grpc_code, 3)
        self.assertEqual(err.trace_code, "trace-1")
        self.assertEqual(err.request_id, "req-1")
        self.assertNotIn("df_sk_test", err.message)
        self.assertIn("df_sk_redacted", err.message)
        self.assertIn("[redacted]", err.field_violations[0].description)

    def test_redacts_api_key_with_slash_and_space(self):
        from urllib.parse import quote, quote_plus

        secret = "df_sk_a/b c+"
        encoded = quote_plus(secret, safe="")
        spaced = quote(secret, safe="")

        def app(handler):
            return 400, {
                "message": f"bad key {secret} query {encoded} spaced {spaced}",
                "fieldViolations": [{"field": secret, "description": f"Bearer {secret} required"}],
            }, None

        httpd = serve(app)
        self.addCleanup(httpd.shutdown)
        sdk = signingflow.Client(
            secret,
            workspace_id="ws",
            env="sandbox",
            base_url=f"https://127.0.0.1:{httpd.server_address[1]}",
            allow_custom_base_url=True,
            ssl_context=trust(),
            max_network_retries=0,
            timeout=2,
        )
        with self.assertRaises(signingflow.InvalidRequestError) as caught:
            sdk.envelopes.retrieve(ENVELOPE)
        err = caught.exception
        visible = " ".join([err.message, err.field_violations[0].field, err.field_violations[0].description])
        self.assertNotIn(secret, visible)
        self.assertNotIn("/b c+", visible)
        self.assertNotIn("c+", visible)
        self.assertNotIn(encoded, visible)
        self.assertNotIn(spaced, visible)
        self.assertNotIn("%2F", visible)

    def test_retries_reuse_one_key_and_update_does_not(self):
        calls = {"send": 0, "keys": []}

        def app(handler):
            if handler.path.endswith(":send"):
                calls["send"] += 1
                body = __import__("json").loads(handler.rfile and b"{}" or b"{}")
                # body already consumed
                return 500, {"message": "later"}, None
            return 200, envelope_body(), None

        # The handler above cannot see the body. Record from seen after the call.
        def app2(handler):
            if handler.path.endswith(":send"):
                calls["send"] += 1
                return 500, {"message": "later"}, {"headers": {"Rate-Limit-Retry-After": "2099-01-01T00:00:00Z"}}
            if handler.command == "PATCH":
                return 500, {"message": "no"}, None
            return 200, envelope_body(), None

        httpd = serve(app2)
        self.addCleanup(httpd.shutdown)
        slept = {}
        clock.sleep = lambda seconds: slept.setdefault("delay", seconds)
        clock.now = lambda: datetime(2026, 1, 2, tzinfo=timezone.utc)
        sdk = client(httpd, max_network_retries=1)
        with self.assertRaises(signingflow.APIError):
            sdk.envelopes.send(ENVELOPE)
        send_calls = [item for item in httpd.seen if item[0] == "POST" and item[1].endswith(":send")]
        self.assertEqual(len(send_calls), 2)
        first = __import__("json").loads(send_calls[0][3])["idempotencyKey"]
        second = __import__("json").loads(send_calls[1][3])["idempotencyKey"]
        self.assertEqual(first, second)
        self.assertLessEqual(slept["delay"], 60)
        before = len(httpd.seen)
        with self.assertRaises(signingflow.APIError):
            sdk.envelopes.update(ENVELOPE, {"description": "x"})
        patches = [item for item in httpd.seen[before:] if item[0] == "PATCH"]
        self.assertEqual(len(patches), 1)
        with self.assertRaises(signingflow.InvalidRequestError):
            sdk.envelopes.send(ENVELOPE, idempotency_key="not-a-uuid")

    def test_encoded_api_key_is_not_sent(self):
        httpd = serve(lambda handler: (200, {"envelopes": []}, None))
        self.addCleanup(httpd.shutdown)
        key = "df_sk_a/b c+"
        sdk = signingflow.Client(
            key,
            workspace_id="ws",
            env="sandbox",
            base_url=f"https://127.0.0.1:{httpd.server_address[1]}",
            allow_custom_base_url=True,
            ssl_context=trust(),
            max_network_retries=0,
        )
        for kwargs in (
            {"directory": "needAction", "read_mask": key},
            {"directory": key},
            {"directory": "needAction", "page_token": key},
        ):
            with self.assertRaises(signingflow.InvalidRequestError):
                sdk.envelopes.list(**kwargs)
        self.assertEqual(httpd.seen, [])
        self.assertFalse(query_contains_secret("readMask=documents", key))
        self.assertTrue(query_contains_secret("readMask=df_sk_a%2Fb+c%2B", key))
        self.assertTrue(query_contains_secret("readMask=%zz", key))

    def test_body_limits_gzip_and_redirect(self):
        def limited(kind):
            def app(handler):
                if handler.path.endswith("/secret"):
                    return 200, {"secret": True}, None
                return kind, None, None
            return app

        httpd = serve(lambda handler: ("chunk", None, None) if False else ("chunk", None, None))
        # rewrite: app returns "chunk"
        httpd.shutdown()

        httpd = serve(lambda handler: "chunk")
        self.addCleanup(httpd.shutdown)
        with self.assertRaises(signingflow.APIError) as caught:
            client(httpd).envelopes.retrieve(ENVELOPE)
        self.assertIn("8 MB", str(caught.exception))

        httpd = serve(lambda handler: "clen")
        self.addCleanup(httpd.shutdown)
        with self.assertRaises(signingflow.APIError) as caught:
            client(httpd).envelopes.retrieve(ENVELOPE)
        self.assertIn("8 MB", str(caught.exception))

        httpd = serve(lambda handler: (200, b'{"name":"%s"}' % ENVELOPE.encode(), {"gzip": True}))
        self.addCleanup(httpd.shutdown)
        with self.assertRaises(signingflow.APIError) as caught:
            client(httpd).envelopes.retrieve(ENVELOPE)
        self.assertIn("invalid JSON", str(caught.exception))
        self.assertEqual(httpd.seen[0][2]["Accept-Encoding"], "identity")

        httpd = serve(lambda handler: "redirect")
        self.addCleanup(httpd.shutdown)
        with self.assertRaises(signingflow.APIError):
            client(httpd).envelopes.retrieve(ENVELOPE)
        self.assertFalse(any(item[1].endswith("/secret") for item in httpd.seen))

    def test_upload_and_send_document(self):
        def app(handler):
            if handler.command == "PUT":
                self.assertNotIn("Authorization", handler.headers)
                self.assertEqual(handler.headers["x-goog-if-generation-match"], "0")
                return 412, b"", {"headers": {"Content-Type": "text/plain"}}
            if "batchAddStorage" in handler.path:
                return 200, {"storages": [{"name": STORAGE, "pre_signed_url": f"https://127.0.0.1:{handler.server.server_address[1]}/object"}]}, None
            if "batchAcknowledge" in handler.path:
                return 200, {}, None
            if "addEnvelope" in handler.path:
                return 200, {"envelope": {"name": ENVELOPE, "display_name": "NDA"}}, None
            if ":view" in handler.path:
                return 200, envelope_body(compliance={"profile": "STANDARD"}), None
            if handler.command == "PATCH":
                return 200, envelope_body(), None
            if handler.path.endswith(":send"):
                return 200, envelope_body(sent_time="2026-01-02T00:00:00Z"), None
            return 500, {"message": "unexpected " + handler.path}, None

        httpd = serve(app)
        self.addCleanup(httpd.shutdown)
        sdk = client(httpd, upload_hosts=["127.0.0.1"])
        envelope = sdk.envelopes.send_document(
            title="NDA",
            file=b"%PDF",
            filename="contract.pdf",
            recipients=[{"name": "Ada Lovelace", "email": "ada@example.com"}],
            message="Please sign",
        )
        self.assertEqual(envelope.name, ENVELOPE)
        methods = [item[0] for item in httpd.seen]
        self.assertIn("PUT", methods)
        self.assertTrue(any(item[1].endswith(":send") for item in httpd.seen))
        patch = next(item for item in httpd.seen if item[0] == "PATCH")
        patched = __import__("json").loads(patch[3])
        self.assertEqual(patched["documents"][0]["participants"][0]["alternate_email"], "ada@example.com")
        self.assertEqual(patched["documents"][0]["participants"][0]["action_order_number"], 1)

    def test_prepare_draft_does_not_send(self):
        def app(handler):
            if handler.command == "PUT":
                return 200, b"", {"headers": {"Content-Type": "text/plain"}}
            if "batchAddStorage" in handler.path:
                return 200, {"storages": [{"name": STORAGE, "pre_signed_url": f"https://127.0.0.1:{handler.server.server_address[1]}/object"}]}, None
            if "batchAcknowledge" in handler.path:
                return 200, {}, None
            if "addEnvelope" in handler.path:
                return 200, {"uid": "11111111-1111-4111-8111-111111111111"}, None
            return 500, {"message": handler.path}, None

        httpd = serve(app)
        self.addCleanup(httpd.shutdown)
        envelope = client(httpd, upload_hosts=["127.0.0.1"]).envelopes.prepare_draft(title="NDA", file=b"%PDF", filename="a.pdf")
        self.assertEqual(envelope.name, ENVELOPE)
        self.assertFalse(any(":send" in item[1] for item in httpd.seen))

    def test_jail(self):
        root = tempfile.mkdtemp()
        outside = tempfile.mkdtemp()
        os.makedirs(os.path.join(root, "sub"))
        secret = os.path.join(outside, "secret.pdf")
        with open(secret, "wb") as handle:
            handle.write(b"SECRET-BYTES")
        with open(os.path.join(root, "ok.pdf"), "wb") as handle:
            handle.write(b"OK")
        os.symlink(secret, os.path.join(root, "alias.pdf"))
        os.link(secret, os.path.join(root, "hard.pdf"))
        os.symlink(outside, os.path.join(root, "sub", "out"))
        sparse = os.path.join(root, "sparse.pdf")
        fd = os.open(sparse, os.O_CREAT | os.O_WRONLY, 0o600)
        os.ftruncate(fd, 25 * 1024 * 1024 + 1)
        os.close(fd)
        self.assertEqual(read_path(root, "ok.pdf"), b"OK")
        for path in ("../" + os.path.relpath(secret, root), "alias.pdf", "hard.pdf", "sub/out/secret.pdf", "/etc/passwd", secret, "ok.pdf\x00", "sparse.pdf"):
            with self.assertRaises(signingflow.InvalidRequestError) as caught:
                read_path(root, path)
            self.assertNotIn("SECRET", str(caught.exception))
        with self.assertRaises(signingflow.InvalidRequestError):
            read_path("", "ok.pdf")
        original = _nofollow_flag
        import signingflow.jail as jail

        jail._nofollow_flag = lambda: 0
        try:
            with self.assertRaises(signingflow.InvalidRequestError):
                read_path(root, "ok.pdf")
        finally:
            jail._nofollow_flag = original

    def test_send_recovery_and_idempotency(self):
        state = {"send": 0}

        def app(handler):
            if handler.path.endswith(":send"):
                state["send"] += 1
                if state["mode"] == "timeout":
                    import time
                    time.sleep(0.4)
                    return 200, envelope_body(), None
                if state["mode"] == "idem":
                    return 409, {"message": "idempotency key already used", "metadata": {"resource_url": ENVELOPE}}, None
                if state["mode"] == "bare":
                    return 409, {"message": "idempotency key already used", "metadata": {"resource_id": "11111111-1111-4111-8111-111111111111"}}, None
                return 200, envelope_body(), None
            if ":view" in handler.path:
                if state.get("fresh"):
                    sent = datetime.now(timezone.utc).isoformat()
                else:
                    sent = state.get("sent_time") or ""
                body = envelope_body()
                if sent:
                    body["sent_time"] = sent
                return 200, body, None
            if handler.command == "PUT":
                return 200, b"", {"headers": {"Content-Type": "text/plain"}}
            if "batchAddStorage" in handler.path:
                port = handler.server.server_address[1]
                return 200, {"storages": [{"name": STORAGE, "pre_signed_url": f"https://127.0.0.1:{port}/object"}]}, None
            if "batchAcknowledge" in handler.path:
                return 200, {}, None
            if "addEnvelope" in handler.path or handler.command == "PATCH":
                return 200, {"envelope": {"name": ENVELOPE, "display_name": "NDA", "documents": [{"uid": "doc-1", "display_name": "NDA"}]}}, None
            return 500, {"message": handler.path}, None

        httpd = serve(app)
        self.addCleanup(httpd.shutdown)
        sdk = client(httpd, timeout=0.15, upload_hosts=["127.0.0.1"])
        state["mode"] = "timeout"
        state["fresh"] = True
        envelope = sdk.envelopes.send_document(title="NDA", file=b"%PDF", filename="a.pdf", recipients=[{"name": "Ada", "email": "ada@example.com"}])
        self.assertEqual(envelope.name, ENVELOPE)

        state["fresh"] = False
        state["mode"] = "timeout"
        state["send"] = 0
        state["sent_time"] = "2000-01-01T00:00:00Z"
        with self.assertRaises(signingflow.ConnectionError) as caught:
            sdk.envelopes.send_document(title="NDA", file=b"%PDF", filename="a.pdf", recipients=[{"name": "Ada", "email": "ada@example.com"}])
        self.assertEqual(caught.exception.envelope_name, ENVELOPE)

        state["mode"] = "timeout"
        state["sent_time"] = "2099-01-01T00:00:00Z"
        with self.assertRaises(signingflow.ConnectionError):
            sdk.envelopes.send_document(title="NDA", file=b"%PDF", filename="a.pdf", recipients=[{"name": "Ada", "email": "ada@example.com"}])

        state["mode"] = "idem"
        state["sent_time"] = ""
        envelope = sdk.envelopes.send_document(title="NDA", file=b"%PDF", filename="a.pdf", recipients=[{"name": "Ada", "email": "ada@example.com"}])
        self.assertEqual(envelope.name, ENVELOPE)

        state["mode"] = "bare"
        with self.assertRaises(signingflow.IdempotencyError) as caught:
            sdk.envelopes.send_document(title="NDA", file=b"%PDF", filename="a.pdf", recipients=[{"name": "Ada", "email": "ada@example.com"}])
        self.assertEqual(caught.exception.envelope_name, ENVELOPE)
        self.assertNotEqual(caught.exception.resource_name, ENVELOPE)

    def test_paging_download_and_remind(self):
        pages = {"n": 0}

        def app(handler):
            if handler.path.startswith("/v1/envelopes?") or handler.path.startswith("/v1/envelopes&"):
                query = parse_qs(urlsplit(handler.path).query)
                token = (query.get("pageToken") or [""])[0]
                if pages["mode"] == "repeat":
                    return 200, {"envelopes": [{"name": ENVELOPE}], "nextPageToken": "same"}, None
                number = 0 if not token else int(token)
                return 200, {"envelopes": [{"name": ENVELOPE}], "next_page_token": str(number + 1)}, None
            if ":download" in handler.path:
                return 200, {"uri": "https://files.example/a", "download_time": "t", "etag": "e"}, None
            if ":remind" in handler.path:
                return 200, envelope_body(), None
            if ":view" in handler.path:
                state = pages.get("state", "COMPLETED")
                return 200, envelope_body(progress={"state": state}), None
            return 500, {"message": handler.path}, None

        httpd = serve(app)
        self.addCleanup(httpd.shutdown)
        sdk = client(httpd)
        pages["mode"] = "repeat"
        listed = sdk.envelopes.list(directory="needAction")
        rows = list(listed.all())
        self.assertEqual(len(rows), 2)
        pages["mode"] = "many"
        with self.assertRaises(signingflow.InvalidRequestError):
            list(sdk.envelopes.list(directory="waitingOthers").all())
        download = sdk.envelopes.download_completed(ENVELOPE)
        self.assertEqual(download.uri, "https://files.example/a")
        self.assertFalse(any(item[0] == "GET" and urlsplit(item[1]).netloc == "files.example" for item in httpd.seen))
        pages["state"] = "DRAFT"
        with self.assertRaises(signingflow.InvalidRequestError) as caught:
            sdk.envelopes.download_completed(ENVELOPE)
        self.assertEqual(caught.exception.envelope_name, ENVELOPE)
        reminded = sdk.envelopes.remind(ENVELOPE)
        self.assertEqual(reminded.name, ENVELOPE)
        with self.assertRaises(signingflow.InvalidRequestError):
            sdk.envelopes.list(directory="")
        with self.assertRaises(signingflow.InvalidRequestError):
            sdk.envelopes.list(directory="needAction", page_size=0)
        with self.assertRaises(signingflow.InvalidRequestError):
            sdk.envelopes.retrieve("envelopes/nope")

    def test_template_and_webhooks(self):
        def app(handler):
            if handler.path.endswith(":use"):
                return 200, {"envelope": {"name": ENVELOPE}}, None
            if ":view" in handler.path and "webhookUrls" in handler.path:
                return 200, {"name": HOOK, "signingSecret": "whsec_hidden", "signing_secret": "whsec_hidden", "events": ["DOC_ENVELOPE_COMPLETED"]}, None
            if handler.path.endswith(":test"):
                return 200, {"name": HOOK, "displayName": "Envelope events"}, None
            if "webhookUrls:add" in handler.path:
                return 200, {"name": HOOK, "signingSecret": "whsec_123", "events": ["DOC_ENVELOPE_COMPLETED"]}, None
            if handler.path.startswith("/v1/webhooks?") or "/v1/webhooks?" in handler.path:
                return 200, {"webhooks": [{"name": DELIVERY, "event": "DOC_ENVELOPE_COMPLETED"}]}, None
            if "/v1/webhooks/" in handler.path:
                return 200, {"name": DELIVERY, "event": "DOC_ENVELOPE_COMPLETED"}, None
            if ":view" in handler.path:
                return 200, envelope_body(), None
            if handler.command == "PATCH":
                return 200, envelope_body(), None
            if handler.path.endswith(":send"):
                return 200, envelope_body(), None
            return 500, {"message": handler.path}, None

        httpd = serve(app)
        self.addCleanup(httpd.shutdown)
        sdk = client(httpd)
        sent = sdk.envelopes.send_from_template(template=TEMPLATE, recipients=[{"name": "Ada", "email": "ada@example.com"}], message="Hi")
        self.assertEqual(sent.name, ENVELOPE)
        created = sdk.webhook_urls.create(display_name="Envelope events", http_request_uri="https://example.com/hook", events=["DOC_ENVELOPE_COMPLETED"])
        self.assertEqual(signingflow.signing_secret_of(created), "whsec_123")
        viewed = sdk.webhook_urls.retrieve(HOOK)
        self.assertEqual(viewed.signing_secret, "")
        tested = sdk.webhook_urls.test(HOOK)
        self.assertEqual(tested.name, HOOK)
        deliveries = sdk.webhook_deliveries.list()
        self.assertEqual(deliveries.data[0].event, "DOC_ENVELOPE_COMPLETED")
        self.assertEqual(sdk.webhook_deliveries.retrieve(DELIVERY).name, DELIVERY)
        with self.assertRaises(signingflow.InvalidRequestError):
            sdk.webhook_urls.create(display_name="", http_request_uri="https://example.com", events=["DOC_ENVELOPE_COMPLETED"])
        with self.assertRaises(signingflow.InvalidRequestError):
            sdk.webhook_urls.create(display_name="ok", http_request_uri="http://example.com", events=["DOC_ENVELOPE_COMPLETED"])
        with self.assertRaises(signingflow.InvalidRequestError):
            sdk.webhook_urls.create(display_name="ok", http_request_uri="https://example.com", events=[], http_config=signingflow.HTTPConfig("NONE"))
        with self.assertRaises(signingflow.InvalidRequestError):
            sdk.webhook_urls.create(display_name="ok", http_request_uri="https://example.com", events=["DOC_ENVELOPE_COMPLETED"], http_config=signingflow.HTTPConfig("BASIC"))
        with self.assertRaises(signingflow.InvalidRequestError):
            sdk.templates.use("templates/nope")
        with self.assertRaises(signingflow.InvalidRequestError):
            sdk.webhook_deliveries.retrieve("webhooks/nope")

    def test_construct_event(self):
        import hashlib
        import hmac

        body = b'{"event":"DOC_ENVELOPE_COMPLETED"}'
        secret = "whsec_123"
        signature = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest().upper()
        event = signingflow.construct_event(body, signature, secret)
        self.assertEqual(event.payload["event"], "DOC_ENVELOPE_COMPLETED")
        self.assertEqual(event.body_sha256, hashlib.sha256(body).hexdigest())
        previous = hmac.new(b"old", body, hashlib.sha256).hexdigest()
        signingflow.construct_event(body, "nope", secret, previous_secret="old", previous_signature=previous)
        with self.assertRaises(signingflow.SignatureVerificationError):
            signingflow.construct_event(body, "nope", secret, previous_secret="old")
        with self.assertRaises(signingflow.SignatureVerificationError):
            signingflow.construct_event("{}", signature, secret)
        with self.assertRaises(signingflow.SignatureVerificationError):
            signingflow.construct_event(body, signature, "")
        with self.assertRaises(signingflow.InvalidRequestError):
            signingflow.construct_event(b"not-json", hmac.new(secret.encode(), b"not-json", hashlib.sha256).hexdigest(), secret)

    def test_remaining_argument_errors(self):
        httpd = serve(lambda handler: (500, {"message": "no"}, None))
        self.addCleanup(httpd.shutdown)
        sdk = client(httpd)
        with self.assertRaises(signingflow.InvalidRequestError):
            sdk.files.create()
        with self.assertRaises(signingflow.InvalidRequestError):
            sdk.files.create(file=b"x", path="a.pdf")
        with self.assertRaises(signingflow.InvalidRequestError):
            sdk.files.create(file=b"x")
        with self.assertRaises(signingflow.InvalidRequestError):
            sdk.files.create(file=b"x", filename="a.pdf", mime_type="application/pdf\r\nX-Injected: yes")
        self.assertEqual(httpd.seen, [])
        with self.assertRaises(signingflow.InvalidRequestError):
            sdk.envelopes.create(display_name="", storage_id="id")
        with self.assertRaises(signingflow.InvalidRequestError):
            sdk.envelopes.create(display_name="NDA", storage_id="")
        with self.assertRaises(signingflow.InvalidRequestError):
            sdk.envelopes.send_document(title="", file=b"x", filename="a.pdf", recipients=[{"name": "A", "email": "a@b.c"}])
        with self.assertRaises(signingflow.InvalidRequestError):
            sdk.envelopes.send_document(title="NDA", file=b"x", filename="a.pdf", recipients=[])
        with self.assertRaises(signingflow.InvalidRequestError):
            sdk.envelopes.send_document(title="NDA", file=b"x", filename="a.pdf", recipients=[{"name": "", "email": "nope"}])
        with self.assertRaises(signingflow.APIError):
            sdk.envelopes.download(ENVELOPE)
        self.assertEqual(allowed_upload_url("https://bucket.storage.googleapis.com/a", ["storage.googleapis.com"]), "https://bucket.storage.googleapis.com/a")
        with self.assertRaises(signingflow.InvalidRequestError):
            allowed_upload_url("https://evil.example/a", ["storage.googleapis.com"])
        with self.assertRaises(signingflow.InvalidRequestError):
            allowed_upload_url("http://storage.googleapis.com/a", ["storage.googleapis.com"])
        with self.assertRaises(signingflow.InvalidRequestError):
            allowed_upload_url("https://user:pass@storage.googleapis.com/a", ["storage.googleapis.com"])
        moment = datetime(2026, 1, 2, tzinfo=timezone.utc)
        self.assertEqual(retry_delay("2026-01-02T00:02:00Z", "", moment), 60)
        self.assertEqual(retry_delay("", "", moment), 0)
        huge = b"Z" * (8 * 1024 * 1024)
        httpd = serve(lambda handler: (200, gzip.compress(huge), {"gzip": True}))
        self.addCleanup(httpd.shutdown)
        with self.assertRaises(signingflow.APIError):
            client(httpd).envelopes.retrieve(ENVELOPE)

    def test_small_branches(self):
        from datetime import datetime, timezone

        from signingflow.config import _raw_host
        from signingflow.pagination import List, list_items, next_token, page_size_of
        from signingflow.path import fill_path, resolve_url, retry_delay
        from signingflow.redact import redact_message
        from signingflow.status import as_int, field_violations, grpc_code, server_message

        clock.sleep(0)
        clock.sleep(0.001)
        self.assertTrue(redact_message("x" * 600).endswith("…"))
        with self.assertRaises(signingflow.Error):
            signingflow.Client("key", workspace_id="ws", env="sandbox", base_url="signingflow")
        signingflow.Client("key", workspace_id="ws", env="sandbox", upload_hosts=["", "storage.googleapis.com"])
        self.assertEqual(_raw_host("[::1]:443"), "[::1]")
        self.assertEqual(_raw_host("[::1"), "[::1")
        self.assertEqual(list(List(["one"]).all()), ["one"])
        stopped = List(["one"], "next", load=lambda token: List(["two"], "next"))
        self.assertEqual(next(stopped.all()), "one")
        self.assertEqual(next_token(None), "")
        self.assertEqual(next_token({"nextPageToken": "a"}), "a")
        self.assertEqual(list_items(None, "envelopes"), [])
        self.assertEqual(list_items({"envelopes": "no"}, "envelopes"), [])
        self.assertEqual(list_items({"envelopes": ["x", {"name": "a"}]}, "envelopes"), [{"name": "a"}])
        with self.assertRaises(signingflow.InvalidRequestError):
            page_size_of(True)
        with self.assertRaises(signingflow.InvalidRequestError):
            page_size_of(1001)
        self.assertIsNone(as_int(True))
        self.assertEqual(as_int(1.5), 1)
        self.assertIsNone(as_int("no"))
        self.assertIsNone(grpc_code("x"))
        self.assertEqual(server_message("plain"), "plain")
        self.assertEqual(server_message(1), "")
        self.assertEqual(field_violations({"fieldViolations": ["no", {"field": "", "description": ""}]}), [])
        with self.assertRaises(signingflow.InvalidRequestError):
            fill_path("/v1/{name}", {})
        with self.assertRaises(signingflow.InvalidRequestError):
            fill_path("/v1/{name}", {"name": "bad name"})
        with self.assertRaises(signingflow.InvalidRequestError):
            resolve_url("https://api.signingflow.com", "https://evil.example/x", None)
        moment = datetime(2026, 1, 2, tzinfo=timezone.utc)
        self.assertEqual(retry_delay("2000-01-01T00:00:00Z", "", moment), 0)
        self.assertEqual(retry_delay("not-a-time", "", moment), 0)
        root = tempfile.mkdtemp()
        open(os.path.join(root, "empty.pdf"), "wb").close()
        os.makedirs(os.path.join(root, "dir"))
        self.assertEqual(read_path(root, "empty.pdf"), b"")
        with self.assertRaises(signingflow.InvalidRequestError):
            read_path(root, "dir")
        httpd = serve(lambda handler: (200, {}, None))
        self.addCleanup(httpd.shutdown)
        with self.assertRaises(signingflow.APIError):
            client(httpd).files.create(file=b"x", filename="a.pdf")
        with self.assertRaises(signingflow.InvalidRequestError):
            client(httpd).files.create(file="nope", filename="a.pdf")

        httpd = serve(lambda handler: (200, envelope_body(), None))
        self.addCleanup(httpd.shutdown)
        sdk = signingflow.Client(
            "df_sk_test",
            workspace_id="ws",
            env="sandbox",
            base_url=f"https://127.0.0.1:{httpd.server_address[1]}",
            allow_custom_base_url=True,
            max_network_retries=0,
            timeout=2,
        )
        with self.assertRaises(signingflow.ConnectionError):
            sdk.envelopes.retrieve(ENVELOPE)

    def test_auth_and_rate_limit(self):
        httpd = serve(lambda handler: (401, {"message": "no"}, None))
        self.addCleanup(httpd.shutdown)
        with self.assertRaises(signingflow.AuthenticationError):
            client(httpd).envelopes.retrieve(ENVELOPE)
        httpd = serve(lambda handler: (403, {"message": "no"}, None))
        self.addCleanup(httpd.shutdown)
        with self.assertRaises(signingflow.PermissionError):
            client(httpd).envelopes.retrieve(ENVELOPE)
        httpd = serve(lambda handler: (429, {"message": "slow", "code": "8"}, None))
        self.addCleanup(httpd.shutdown)
        with self.assertRaises(signingflow.RateLimitError) as caught:
            client(httpd).envelopes.retrieve(ENVELOPE)
        self.assertEqual(caught.exception.grpc_code, 8)
        httpd = serve(lambda handler: (409, {"message": "conflict"}, None))
        self.addCleanup(httpd.shutdown)
        with self.assertRaises(signingflow.InvalidRequestError):
            client(httpd).envelopes.retrieve(ENVELOPE)
        httpd = serve(lambda handler: (200, b"<html></html>", {"headers": {"Content-Type": "text/html"}}))
        self.addCleanup(httpd.shutdown)
        with self.assertRaises(signingflow.APIError):
            client(httpd).envelopes.retrieve(ENVELOPE)
        httpd = serve(lambda handler: (200, b"", None))
        self.addCleanup(httpd.shutdown)
        envelope = client(httpd).envelopes.retrieve(ENVELOPE)
        self.assertEqual(envelope.name, ENVELOPE)


CERT = ""
KEY = ""


def setUpModule():
    global CERT, KEY
    directory = tempfile.mkdtemp()
    CERT = os.path.join(directory, "cert.pem")
    KEY = os.path.join(directory, "key.pem")
    subprocess.check_call(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-sha256",
            "-days",
            "1",
            "-nodes",
            "-keyout",
            KEY,
            "-out",
            CERT,
            "-subj",
            "/CN=127.0.0.1",
            "-addext",
            "subjectAltName=IP:127.0.0.1",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
