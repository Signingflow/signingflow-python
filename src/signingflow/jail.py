"""Read one file from upload_root without following a leaf symlink."""

import os
import stat

from signingflow.errors import invalid

_MAX_UPLOAD_BYTES = 25 * 1024 * 1024


class JailError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def read_path(upload_root, requested, max_bytes=_MAX_UPLOAD_BYTES):
    if not (upload_root or "").strip():
        raise invalid("A filesystem path requires upload_root.")
    try:
        return _read_jailed(upload_root, requested, max_bytes)
    except JailError as exc:
        if exc.code == "too large":
            raise invalid("The file is larger than 25 MB.") from exc
        if exc.code == "outside root":
            raise invalid("The path is outside upload_root.") from exc
        if exc.code == "hard link":
            raise invalid("The file must not be a hard link.") from exc
        raise invalid("The file could not be read.") from exc


def _nofollow_flag():
    return getattr(os, "O_NOFOLLOW", 0) or 0


def _read_jailed(root, requested, max_bytes):
    # os.path.join discards the root when the next part is absolute.
    if _nofollow_flag() == 0:
        raise JailError("nofollow")
    if not requested or "\x00" in requested or os.path.isabs(requested):
        raise JailError("outside root")
    base = os.path.realpath(root)
    resolved = os.path.normpath(os.path.join(base, requested))
    if _escapes(base, resolved) or os.path.normpath(resolved) == os.path.normpath(base):
        raise JailError("outside root")
    parent = os.path.dirname(resolved)
    parent_real = os.path.realpath(parent)
    if _escapes(base, parent_real):
        raise JailError("outside root")
    leaf = os.path.basename(resolved)
    if leaf in ("", ".", ".."):
        raise JailError("outside root")
    path = os.path.join(parent_real, leaf)
    if _escapes(base, path) or os.path.normpath(path) == os.path.normpath(base):
        raise JailError("outside root")
    try:
        fd = os.open(path, os.O_RDONLY | _nofollow_flag())
    except OSError as exc:
        raise JailError("open") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise JailError("not a file")
        if info.st_nlink > 1:
            raise JailError("hard link")
        if info.st_size > max_bytes:
            raise JailError("too large")
        if info.st_size == 0:
            return b""
        return _read_exact(fd, info.st_size)
    finally:
        os.close(fd)


def _read_exact(fd, size):
    chunks = []
    remaining = size
    while remaining:
        piece = os.read(fd, remaining)
        if not piece:
            raise JailError("short")
        chunks.append(piece)
        remaining -= len(piece)
    return b"".join(chunks)


def _escapes(base, target):
    try:
        rel = os.path.relpath(target, base)
    except ValueError:
        return True
    if rel == ".":
        return False
    return any(part == ".." for part in rel.split(os.sep))
