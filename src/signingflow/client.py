"""The instance client. There is no module-level API key."""

from signingflow.config import Config
from signingflow.envelopes import Envelopes
from signingflow.files import Files
from signingflow.request import Sender
from signingflow.templates import Templates
from signingflow.webhooks import WebhookDeliveries, WebhookURLs


class Client:
    def __init__(self, api_key, **options):
        self.config = Config(api_key, **options)
        sender = Sender(self.config)
        self.files = Files(sender)
        self.templates = Templates(sender)
        self.envelopes = Envelopes(sender, self.files, self.templates)
        self.webhook_urls = WebhookURLs(sender)
        self.webhook_deliveries = WebhookDeliveries(sender)
