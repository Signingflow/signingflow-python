"""Names, recipients, and response records."""

import re

from signingflow.errors import invalid
from signingflow.status import as_map, as_str

_ENVELOPE_NAME = re.compile(r"(?i)^envelopes/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_TEMPLATE_NAME = re.compile(r"(?i)^templates/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_WEBHOOK_NAME = re.compile(r"(?i)^webhookUrls/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_DELIVERY_NAME = re.compile(r"(?i)^webhooks/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_STORAGE_ID = re.compile(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_EMAIL = re.compile(r"^[^\s@]+@[^\s@]+$")


class Envelope:
    def __init__(self, name="", uid="", display_name="", description="", progress_status="", state="", condition="", sent_time="", documents=None, compliance=None, progress=None):
        self.name = name
        self.uid = uid
        self.display_name = display_name
        self.description = description
        self.progress_status = progress_status
        self.state = state
        self.condition = condition
        self.sent_time = sent_time
        self.documents = documents or []
        self.compliance = compliance
        self.progress = progress


class Download:
    def __init__(self, uri="", download_time="", etag=""):
        self.uri = uri
        self.download_time = download_time
        self.etag = etag


class StoredFile:
    def __init__(self, name, file_id):
        self.name = name
        self.id = file_id


def require_envelope_name(name):
    name = (name or "").strip()
    if not _ENVELOPE_NAME.match(name):
        raise invalid("envelope must look like envelopes/{id}.")
    return name


def require_template_name(name):
    name = (name or "").strip()
    if not _TEMPLATE_NAME.match(name):
        raise invalid("template must look like templates/{id}.")
    return name


def require_resource_name(name, pattern, message):
    name = (name or "").strip()
    if not pattern.match(name):
        raise invalid(message)
    return name


def webhook_name(name):
    return require_resource_name(name, _WEBHOOK_NAME, "webhook url must look like webhookUrls/{id}.")


def delivery_name(name):
    return require_resource_name(name, _DELIVERY_NAME, "webhook delivery must look like webhooks/{id}.")


def clean_recipients(recipients):
    people = []
    for person in recipients or []:
        if not isinstance(person, dict):
            people.append({"name": "", "email": ""})
            continue
        people.append({"name": as_str(person.get("name")).strip(), "email": as_str(person.get("email")).strip()})
    if not people:
        raise invalid("Each recipient needs a name and an email.")
    for person in people:
        if not person["name"] or not _EMAIL.match(person["email"]):
            raise invalid("Each recipient needs a name and an email.")
    return people


def first_string(record, *keys):
    if not record:
        return ""
    for key in keys:
        value = as_str(record.get(key))
        if value:
            return value
    return ""


def decode_envelope(body):
    record = as_map(body) or {}
    nested = as_map(record.get("envelope"))
    if nested is not None:
        record = nested
    documents = []
    raw_docs = record.get("documents")
    if isinstance(raw_docs, list):
        for item in raw_docs:
            doc = as_map(item)
            if doc is not None:
                documents.append(doc)
    compliance = as_map(record.get("compliance"))
    progress = as_map(record.get("progress"))
    return Envelope(
        name=as_str(record.get("name")),
        uid=as_str(record.get("uid")),
        display_name=first_string(record, "display_name", "displayName"),
        description=as_str(record.get("description")),
        progress_status=first_string(record, "progress_status", "progressStatus"),
        state=as_str(record.get("state")),
        condition=as_str(record.get("condition")),
        sent_time=first_string(record, "sent_time", "sentTime"),
        documents=documents,
        compliance=compliance,
        progress=progress,
    )


def envelope_name_of(body):
    record = as_map(body) or {}
    nested = as_map(record.get("envelope")) or {}
    name = as_str(nested.get("name")) or as_str(record.get("name"))
    if name.startswith("envelopes/"):
        return name
    uid = as_str(nested.get("uid")) or as_str(record.get("uid"))
    if not uid:
        return ""
    return "envelopes/" + uid


def created_envelope(body):
    envelope = decode_envelope(body)
    name = envelope_name_of(body)
    if name:
        envelope.name = name
    elif not envelope.name and envelope.uid:
        envelope.name = "envelopes/" + envelope.uid
    return envelope


def envelope_state(envelope):
    if envelope.progress:
        state = as_str(envelope.progress.get("state"))
        if state:
            return state
    if envelope.progress_status:
        return envelope.progress_status
    if envelope.state:
        return envelope.state
    return envelope.condition


def find_storage(body):
    record = as_map(body)
    if record is not None and "storages" in record:
        found = find_storage(record.get("storages"))
        if found is not None:
            return found
    return _find_storage_walk(body)


def _find_storage_walk(body):
    if isinstance(body, dict):
        raw_url = first_string(body, "pre_signed_url", "preSignedUrl")
        name = as_str(body.get("name"))
        file_id = name.rsplit("/", 1)[-1]
        if name.startswith("storages/") and _STORAGE_ID.match(file_id) and raw_url:
            return name, file_id, raw_url
        for key, child in body.items():
            if key == "storages":
                continue
            found = _find_storage_walk(child)
            if found is not None:
                return found
    elif isinstance(body, list):
        for child in body:
            found = _find_storage_walk(child)
            if found is not None:
                return found
    return None
