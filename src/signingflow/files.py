"""Upload one file through a pre-signed URL."""

import os

from signingflow.config import bad_header
from signingflow.errors import APIError, invalid
from signingflow.jail import read_path
from signingflow.models import StoredFile, find_storage
from signingflow.path import allowed_upload_url

_MAX_UPLOAD_BYTES = 25 * 1024 * 1024
_MIME_BY_EXTENSION = {
    ".pdf": "application/pdf",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".txt": "text/plain",
    ".json": "application/json",
}


class Files:
    def __init__(self, sender):
        self._sender = sender

    def create(self, *, file=None, path="", filename="", mime_type="", idempotency_key=""):
        loaded = _load_file(file=file, path=path, filename=filename, mime_type=mime_type, upload_root=self._sender.config.upload_root)
        added = self._sender.call(
            "StorageService_BatchAddStorage",
            idempotency_key=idempotency_key,
            body={
                "storages": [
                    {
                        "originalName": loaded["filename"],
                        "displayName": loaded["filename"],
                        "size": str(len(loaded["data"])),
                        "extension": loaded["extension"],
                        "mimeType": loaded["mime_type"],
                    }
                ]
            },
        )
        found = find_storage(added)
        if found is None:
            raise APIError("Storage did not return an upload URL.")
        name, file_id, raw_url = found
        upload = allowed_upload_url(raw_url, self._sender.config.upload_hosts)
        self._sender.put_bytes(upload, loaded["mime_type"], loaded["data"])
        self._sender.call("StorageService_BatchAcknowledgeUpload", body={"names": [name]})
        return StoredFile(name, file_id)


def _load_file(*, file, path, filename, mime_type, upload_root):
    has_file = file is not None
    has_path = bool((path or "").strip())
    if has_file and has_path:
        raise invalid("Pass file bytes or a path, not both.")
    if not has_file and not has_path:
        raise invalid("Pass file bytes or a path.")
    if has_file:
        if not isinstance(file, (bytes, bytearray)):
            raise invalid("Pass file bytes or a path.")
        data = bytes(file)
    else:
        data = read_path(upload_root, path)
    if len(data) > _MAX_UPLOAD_BYTES:
        raise invalid("The file is larger than 25 MB.")
    filename = (filename or "").strip()
    if not filename and has_path:
        filename = os.path.basename(path)
    if filename in ("", ".", "/"):
        raise invalid("filename is required when file is not a path.")
    extension = os.path.splitext(filename)[1].lower().lstrip(".")
    mime_type = (mime_type or "").strip()
    if not mime_type:
        mime_type = _MIME_BY_EXTENSION.get("." + extension, "")
    if not mime_type:
        mime_type = "application/octet-stream"
    if bad_header(mime_type):
        raise invalid("invalid header value")
    return {"data": data, "filename": filename, "extension": extension, "mime_type": mime_type}
