"""Create, send, and read envelopes."""

from datetime import timedelta, timezone

from signingflow import clock
from signingflow.errors import APIError, ConnectionError, IdempotencyError, attach, invalid
from signingflow.models import (
    Download,
    clean_recipients,
    created_envelope,
    decode_envelope,
    envelope_state,
    require_envelope_name,
)
from signingflow.pagination import List, list_items, next_token, page_size_of
from signingflow.path import _parse_retry
from signingflow.request import key_for
from signingflow.status import as_map, as_str

_SEND_WINDOW = timedelta(minutes=2)
_SEND_SKEW = timedelta(minutes=1)


class Envelopes:
    def __init__(self, sender, files, templates):
        self._sender = sender
        self._files = files
        self._templates = templates

    def create(self, *, display_name, storage_id, description="", idempotency_key=""):
        title = (display_name or "").strip()
        if not title:
            raise invalid("Name the draft title.")
        storage_id = (storage_id or "").strip()
        if not storage_id:
            raise invalid("storage_id is required.")
        created = self._sender.call(
            "EnvelopeService_AddEnvelope",
            idempotency_key=idempotency_key,
            body={
                "envelope": {
                    "display_name": title,
                    "description": (description or "").strip(),
                    "documents": [
                        {
                            "display_name": title,
                            "attachments": [{"storage_id": storage_id}],
                            "supplemental": False,
                        }
                    ],
                }
            },
        )
        return created_envelope(created)

    def retrieve(self, name, *, read_mask=""):
        envelope = require_envelope_name(name)
        viewed = self._sender.call(
            "EnvelopeService_ViewEnvelope",
            path_params={"name": envelope},
            query={"readMask": read_mask},
        )
        decoded = decode_envelope(viewed)
        if not decoded.name:
            decoded.name = envelope
        return decoded

    def update(self, name, body):
        envelope = require_envelope_name(name)
        payload = dict(body or {})
        if not as_str(payload.get("name")):
            payload["name"] = envelope
        updated = self._sender.call(
            "EnvelopeService_UpdateEnvelope",
            path_params={"name": envelope},
            body=payload,
        )
        return decode_envelope(updated)

    def send(self, name, *, idempotency_key=""):
        envelope = require_envelope_name(name)
        sent = self._sender.call(
            "EnvelopeService_SendEnvelope",
            path_params={"name": envelope},
            idempotency_key=idempotency_key,
            body={},
        )
        decoded = decode_envelope(sent)
        if not decoded.name:
            decoded.name = envelope
        return decoded

    def list(self, *, directory, page_size=None, page_token="", read_mask=""):
        directory = (directory or "").strip()
        if not directory:
            raise invalid("directory is required.")
        size = page_size_of(page_size)

        def load(token):
            return self._list_page(directory, size, token, read_mask)

        page = load(page_token)
        page._load = load
        return page

    def remind(self, name):
        envelope = require_envelope_name(name)
        reminded = self._sender.call(
            "EnvelopeService_RemindEnvelopeSigners",
            path_params={"name": envelope},
            body={},
        )
        decoded = decode_envelope(reminded)
        if not decoded.name:
            decoded.name = envelope
        return decoded

    def download(self, name):
        envelope = require_envelope_name(name)
        downloaded = self._sender.call(
            "EnvelopeService_DownloadEnvelope",
            path_params={"name": envelope},
        )
        record = as_map(downloaded) or {}
        return Download(
            uri=as_str(record.get("uri")),
            download_time=_first(record, "download_time", "downloadTime"),
            etag=as_str(record.get("etag")),
        )

    def prepare_draft(self, *, title, file=None, path="", filename="", message=""):
        title = (title or "").strip()
        if not title:
            raise invalid("Name the PDF and the draft title.")
        stored = self._files.create(file=file, path=path, filename=filename)
        return self.create(display_name=title, description=message, storage_id=stored.id)

    def send_document(self, *, title, file=None, path="", filename="", recipients=None, message=""):
        title = (title or "").strip()
        if not title:
            raise invalid("Name the PDF, the title, and the recipients.")
        people = clean_recipients(recipients)
        stored = self._files.create(file=file, path=path, filename=filename)
        created = self.create(display_name=title, description=message, storage_id=stored.id)
        return self._finish_send(created, people, message, title)

    def send_from_template(self, *, template, recipients=None, message=""):
        people = clean_recipients(recipients)
        created = self._templates.use(template)
        return self._finish_send(created, people, message, template)

    def download_completed(self, name):
        envelope = require_envelope_name(name)
        viewed = self.retrieve(envelope)
        if envelope_state(viewed).strip().upper() != "COMPLETED":
            err = invalid("The signed file is not ready.")
            err.envelope_name = envelope
            raise err
        return self.download(envelope)

    def _list_page(self, directory, page_size, page_token, read_mask):
        body = self._sender.call(
            "EnvelopeService_ListEnvelopes",
            path_params={"parent": "envelopes"},
            query={
                "directory": directory,
                "pageSize": str(page_size),
                "pageToken": page_token or "",
                "readMask": read_mask or "",
            },
        )
        record = as_map(body) or {}
        data = [decode_envelope(item) for item in list_items(record, "envelopes")]
        return List(data, next_token(record))

    def _finish_send(self, created, people, message, label):
        name = created.name
        try:
            require_envelope_name(name)
        except Exception:
            raise APIError(f"{label} was saved without an envelope name.") from None
        try:
            viewed = self.retrieve(name, read_mask="documents,compliance")
        except Exception as exc:
            raise attach(exc, name) from exc
        patched = _with_recipients(viewed, people, message)
        if patched is None:
            err = invalid("The draft has no document to address.")
            err.envelope_name = name
            raise err
        try:
            self.update(name, patched)
        except Exception as exc:
            raise attach(exc, name) from exc
        return self._send_or_view(name)

    def _send_or_view(self, name):
        started = clock.now()
        try:
            return self.send(name)
        except IdempotencyError as exc:
            if exc.resource_name == name:
                try:
                    return self.retrieve(name)
                except Exception:
                    raise attach(exc, name) from exc
            raise attach(exc, name) from exc
        except ConnectionError as exc:
            try:
                viewed = self.retrieve(name)
            except Exception:
                raise attach(exc, name) from exc
            sent = _parse_retry(viewed.sent_time)
            if sent is not None and _sent_during(sent, started, clock.now()):
                return viewed
            raise attach(exc, name) from exc
        except Exception as exc:
            raise attach(exc, name) from exc


def _with_recipients(envelope, people, message):
    refs = []
    for item in envelope.documents:
        uid = _first(item, "uid", "id")
        if not uid:
            continue
        refs.append({"uid": uid, "display_name": _first(item, "display_name", "displayName")})
    if not refs:
        return None
    participants = []
    for index, person in enumerate(people):
        participants.append(
            {
                "uid": key_for("", None),
                "display_name": person["name"],
                "alternate_email": person["email"],
                "role": "SIGNER",
                "type": "PERSONAL",
                "action_order_type": "SERIAL",
                "action_order_number": index + 1,
            }
        )
    profile = "STANDARD"
    if envelope.compliance and as_str(envelope.compliance.get("profile")):
        profile = as_str(envelope.compliance.get("profile"))
    description = (message or "").strip() or envelope.description
    documents = []
    for index, document in enumerate(refs):
        item = {"uid": document["uid"], "display_name": document["display_name"]}
        if index == 0:
            item["participants"] = participants
        documents.append(item)
    return {
        "name": envelope.name,
        "display_name": envelope.display_name,
        "description": description,
        "compliance": {"profile": profile},
        "documents": documents,
    }


def _sent_during(sent, started, current):
    if sent.tzinfo is None:
        sent = sent.replace(tzinfo=timezone.utc)
    if started.tzinfo is None:
        started = started.replace(tzinfo=timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    return started <= sent <= started + _SEND_WINDOW and sent <= current + _SEND_SKEW


def _first(record, *keys):
    if not record:
        return ""
    for key in keys:
        value = record.get(key)
        if isinstance(value, str) and value:
            return value
    return ""
