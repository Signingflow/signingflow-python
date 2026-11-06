"""Create an envelope from a template."""

from signingflow.models import created_envelope, require_template_name


class Templates:
    def __init__(self, sender):
        self._sender = sender

    def use(self, name, *, idempotency_key=""):
        template = require_template_name(name)
        used = self._sender.call(
            "TemplateService_UseTemplate",
            path_params={"name": template},
            idempotency_key=idempotency_key,
            body={},
        )
        return created_envelope(used)
