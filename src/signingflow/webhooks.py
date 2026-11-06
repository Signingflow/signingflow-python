"""Webhook destinations and stored deliveries."""

from urllib.parse import urlsplit

from signingflow.errors import invalid
from signingflow.models import delivery_name, webhook_name
from signingflow.pagination import List, list_items, next_token, page_size_of
from signingflow.status import as_map, as_str


class HTTPConfig:
    """Rejected. Leave it unset so the destination uses HMAC."""

    def __init__(self, auth=""):
        self.auth = auth


class WebhookURL:
    def __init__(self, name="", display_name="", http_request_uri="", events=None, signing_secret=""):
        self.name = name
        self.display_name = display_name
        self.http_request_uri = http_request_uri
        self.events = list(events or [])
        self.signing_secret = signing_secret


class WebhookDelivery:
    def __init__(self, name="", event=""):
        self.name = name
        self.event = event


class WebhookURLs:
    def __init__(self, sender):
        self._sender = sender

    def create(self, *, display_name, http_request_uri, events, idempotency_key="", http_config=None):
        display_name = (display_name or "").strip()
        if not 1 <= len(display_name) <= 100:
            raise invalid("display_name must be 1 to 100 characters.")
        parsed = urlsplit(http_request_uri or "")
        if not parsed.netloc or parsed.scheme != "https":
            raise invalid("http_request_uri must be an https URL.")
        if not events:
            raise invalid("events is required.")
        if http_config is not None and str(getattr(http_config, "auth", "")).upper() == "NONE":
            raise invalid("auth NONE has no signature. Leave http_config empty.")
        if http_config is not None:
            raise invalid("Leave http_config empty so the destination uses HMAC.")
        created = self._sender.call(
            "WebhookUrlService_AddWebhookUrl",
            idempotency_key=idempotency_key,
            body={
                "webhookUrl": {
                    "displayName": display_name,
                    "httpRequestUri": http_request_uri,
                    "events": list(events),
                }
            },
        )
        return _decode_webhook_url(created, drop_secret=False)

    def retrieve(self, name):
        destination = webhook_name(name)
        viewed = self._sender.call("WebhookUrlService_ViewWebhookUrl", path_params={"name": destination})
        return _decode_webhook_url(viewed, drop_secret=True)

    def test(self, name):
        destination = webhook_name(name)
        tested = self._sender.call("WebhookUrlService_TestWebhookUrl", path_params={"name": destination}, body={})
        return _decode_webhook_url(tested, drop_secret=False)


class WebhookDeliveries:
    def __init__(self, sender):
        self._sender = sender

    def list(self, *, page_size=None, page_token=""):
        size = page_size_of(page_size)

        def load(token):
            return self._list_page(size, token)

        page = load(page_token)
        page._load = load
        return page

    def retrieve(self, name):
        delivery = delivery_name(name)
        viewed = self._sender.call("WebhookService_ViewWebhook", path_params={"name": delivery})
        return _decode_delivery(viewed)

    def _list_page(self, page_size, page_token):
        body = self._sender.call(
            "WebhookService_ListWebhooks",
            path_params={"parent": "webhooks"},
            query={"pageSize": str(page_size), "pageToken": page_token or ""},
        )
        record = as_map(body) or {}
        data = [_decode_delivery(item) for item in list_items(record, "webhooks")]
        return List(data, next_token(record))


def signing_secret_of(body):
    record = body if isinstance(body, dict) else getattr(body, "__dict__", None)
    if isinstance(body, WebhookURL):
        return body.signing_secret
    if not isinstance(record, dict):
        return ""
    secret = as_str(record.get("signing_secret"))
    if secret:
        return secret
    return as_str(record.get("signingSecret"))


def _decode_webhook_url(body, *, drop_secret):
    record = dict(as_map(body) or {})
    if drop_secret:
        record.pop("signing_secret", None)
        record.pop("signingSecret", None)
    events = []
    raw_events = record.get("events")
    if isinstance(raw_events, list):
        for event in raw_events:
            text = as_str(event)
            if text:
                events.append(text)
    return WebhookURL(
        name=as_str(record.get("name")),
        display_name=_first(record, "displayName", "display_name"),
        http_request_uri=_first(record, "httpRequestUri", "http_request_uri"),
        events=events,
        signing_secret=signing_secret_of(record),
    )


def _decode_delivery(body):
    record = as_map(body) or {}
    return WebhookDelivery(name=as_str(record.get("name")), event=as_str(record.get("event")))


def _first(record, *keys):
    for key in keys:
        value = as_str(record.get(key))
        if value:
            return value
    return ""
