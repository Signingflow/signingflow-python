"""Client settings. The API key stays on the instance."""

from urllib.parse import urlsplit

OFFICIAL_HOST = "api.signingflow.com"
DEFAULT_BASE_URL = "https://api.signingflow.com"
DEFAULT_TIMEOUT = 30
DEFAULT_RETRIES = 2
DEFAULT_UPLOAD_HOSTS = ("storage.googleapis.com",)


class Config:
    def __init__(
        self,
        api_key,
        *,
        workspace_id,
        env,
        base_url=None,
        allow_custom_base_url=False,
        timeout=None,
        max_network_retries=None,
        channel=None,
        funnel=None,
        upload_hosts=None,
        upload_root=None,
        ssl_context=None,
    ):
        from signingflow.errors import Error, invalid

        self.api_key = (api_key or "").strip()
        if not self.api_key:
            raise Error("API key is required.")
        self.workspace_id = (workspace_id or "").strip()
        if not self.workspace_id:
            raise Error("workspace_id is required.")
        self.wire_env = _normalize_env(env)
        base = (base_url or "").strip() or DEFAULT_BASE_URL
        base = base.rstrip("/")
        parsed = urlsplit(base)
        if not parsed.scheme or not parsed.netloc:
            raise Error("base_url must be an absolute URL.")
        if parsed.scheme != "https":
            raise Error("base_url must be https.")
        if parsed.username is not None or parsed.password is not None:
            raise Error("base_url must not include a username or password.")
        if "\x00" in base:
            raise Error("base_url must be an absolute URL.")
        raw_host = _raw_host(parsed.netloc)
        if raw_host != OFFICIAL_HOST and not allow_custom_base_url:
            raise Error("base_url host must be api.signingflow.com, or set allow_custom_base_url.")
        self.base_url = base
        self.allow_custom_base_url = bool(allow_custom_base_url)
        self.timeout = DEFAULT_TIMEOUT if timeout is None else timeout
        if not isinstance(self.timeout, (int, float)) or isinstance(self.timeout, bool) or self.timeout <= 0:
            raise Error("timeout must be positive.")
        self.retries = DEFAULT_RETRIES if max_network_retries is None else max_network_retries
        if isinstance(self.retries, bool) or not isinstance(self.retries, int) or self.retries < 0:
            raise Error("max_network_retries must be a whole number of zero or more.")
        self.upload_hosts = _upload_hosts(upload_hosts)
        self.channel = (channel or "").strip()
        self.funnel = (funnel or "").strip()
        self.upload_root = (upload_root or "").strip()
        self.ssl_context = ssl_context
        if any(bad_header(value) for value in (self.api_key, self.workspace_id, self.channel, self.funnel)):
            raise invalid("invalid header value")


def bad_header(value):
    return "\r" in value or "\n" in value


def _normalize_env(env):
    from signingflow.errors import Error

    if env in ("sandbox", "SANDBOX"):
        return "SANDBOX"
    if env in ("live", "LIVE"):
        return "LIVE"
    raise Error("env must be sandbox or live.")


def _raw_host(netloc):
    host = netloc.rsplit("@", 1)[-1]
    if host.startswith("["):
        end = host.find("]")
        return host[: end + 1] if end != -1 else host
    return host.split(":", 1)[0]


def _upload_hosts(hosts):
    from signingflow.errors import Error

    if hosts is None:
        hosts = DEFAULT_UPLOAD_HOSTS
    cleaned = []
    for host in hosts:
        host = str(host).strip().lower()
        if not host:
            continue
        dots = host.count(".")
        if dots < 2 or host.startswith(".") or host.endswith(".") or ".." in host:
            raise Error("Each upload_hosts entry must be a specific host, not a public suffix.")
        cleaned.append(host)
    return tuple(cleaned)
