"""One page of results, and a walk that stops."""

from signingflow.errors import invalid
from signingflow.status import as_map, as_str

MAX_PAGES = 100


class List:
    def __init__(self, data, next_page_token="", load=None):
        self.data = list(data)
        self.next_page_token = next_page_token or ""
        self._load = load

    def all(self):
        page = self
        load = page._load
        seen = set()
        pages = 0
        while True:
            for item in page.data:
                yield item
            token = page.next_page_token
            if not token or load is None:
                return
            if token in seen:
                return
            pages += 1
            if pages > MAX_PAGES:
                raise invalid("Too many pages.")
            seen.add(token)
            page = load(token)


def next_token(body):
    if not body:
        return ""
    value = as_str(body.get("next_page_token"))
    if value:
        return value
    return as_str(body.get("nextPageToken"))


def list_items(body, key):
    if not body:
        return []
    raw = body.get(key)
    if not isinstance(raw, list):
        return []
    items = []
    for item in raw:
        record = as_map(item)
        if record is not None:
            items.append(record)
    return items


def page_size_of(value):
    if value is None:
        return 10
    if isinstance(value, bool) or not isinstance(value, int) or value < 1 or value > 1000:
        raise invalid("pageSize must be a whole number from 1 to 1000.")
    return value
