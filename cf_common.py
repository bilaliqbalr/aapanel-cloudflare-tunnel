"""Paths and checks for the cftunnel aaPanel plugin.

Tokens and tunnel credentials stay in root-only files. Commands are argument
lists. A public hostname can only point at 127.0.0.1 or localhost.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import subprocess
from urllib.parse import urlparse

PLUGIN_VERSION = "1.6"
PLUGIN_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(PLUGIN_DIR, "data")
HOME = "/etc/cloudflared/cftunnel"
CONFIG_PATH = os.path.join(HOME, "config.yml")
TOKEN_ENV = os.path.join(HOME, "tunnel.env")
CERT_DIR = os.path.join(HOME, "certs")
CRED_DIR = os.path.join(HOME, "creds")
LOGIN_DIR = os.path.join(HOME, "login")
UNIT_PATH = "/etc/systemd/system/cftunnel.service"
SERVICE_NAME = "cftunnel"
QUICK_UNIT = "cftunnel-quick"
LOGIN_UNIT = "cftunnel-login"
CLOUDFLARED_BIN = "/usr/local/bin/cloudflared"
CF_API = "https://api.cloudflare.com/client/v4"
GLOBAL_CF_DEFAULT = "/www/server/panel/plugin/cloudflare_manage/data/cf_default.json"
GLOBAL_DNS_MAGER = "/www/server/panel/config/dns_mager.conf"

PINNED_VERSION = "2026.10.0"
# sha256 of the official GitHub release assets for that version.
PINNED_SHA256 = {
    "amd64": "d33ff2d14475178d2012c2c56beba87389ac5ded27649519f198a7d3134a99db",
    "arm64": "e6422b9d4f72d3194bc5a38676f13667c06666523217b842a877d72a80b5ac08",
}

HOSTNAME_RE = re.compile(r"^(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")
PROFILE_ID_RE = re.compile(r"^[a-z0-9_]{1,32}$")
ACCOUNT_ID_RE = re.compile(r"^[0-9a-f]{32}$")
TUNNEL_ID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
TUNNEL_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,48}$")
DURATION_RE = re.compile(r"^\d{1,5}(ms|s|m|h)$")
HOST_HEADER_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")
_TOKEN_RE = re.compile(r"eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")
_BEARER_RE = re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._\-]{20,}")


def ensure_dirs() -> str:
    failed = []
    for path in (DATA_DIR, HOME, CERT_DIR, CRED_DIR, LOGIN_DIR):
        try:
            os.makedirs(path, mode=0o700, exist_ok=True)
            os.chmod(path, 0o700)
        except OSError as exc:
            failed.append("{} ({})".format(path, exc.strerror or exc.__class__.__name__))
    return "; ".join(failed)


def write_secret(path: str, text: str, mode: int = 0o600) -> None:
    parent = os.path.dirname(path)
    os.makedirs(parent, exist_ok=True)
    if parent == DATA_DIR or parent.startswith(HOME + os.sep) or parent == HOME:
        os.chmod(parent, 0o700)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)
    os.replace(tmp, path)
    os.chmod(path, mode)


def read_json(path: str, fallback):
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError):
        return fallback


def ok(msg: str = "ok", data=None) -> dict:
    out = {"status": True, "msg": msg}
    if data is not None:
        out["data"] = data
    return out


def fail(msg: str) -> dict:
    return {"status": False, "msg": redact(msg)}


def field(get, key: str, default: str = "") -> str:
    value = getattr(get, key, default)
    if value is None:
        return default
    return str(value).strip()


def flag(get, key: str, default: bool = True) -> bool:
    if not hasattr(get, key):
        return default
    return str(getattr(get, key)).lower() not in ("0", "false", "no", "off")


def redact(text: str) -> str:
    cleaned = _BEARER_RE.sub(r"\1[redacted]", text or "")
    return _TOKEN_RE.sub("[redacted]", cleaned)


def local_service(service: str) -> str:
    raw = (service or "").strip()
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only http://127.0.0.1:port or http://localhost:port is allowed.")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("The address cannot include a user or a query.")
    if parsed.path not in ("", "/"):
        raise ValueError("The address cannot include a path.")
    host = (parsed.hostname or "").lower()
    if host not in ("127.0.0.1", "localhost"):
        raise ValueError("Only 127.0.0.1 and localhost are allowed.")
    port = parsed.port
    if port is None or not (1 <= port <= 65535):
        raise ValueError("Port must be between 1 and 65535.")
    return "{}://{}:{}".format(parsed.scheme, host, port)


def parse_tunnel_token(token: str, account_id: str = "") -> dict:
    """A Zero Trust install token is base64 JSON: account id, tunnel id, secret."""
    raw = (token or "").strip()
    if not raw or any(ch.isspace() for ch in raw) or not re.fullmatch(r"[A-Za-z0-9+/=_-]{40,4096}", raw):
        raise ValueError(
            "Paste the install token from Zero Trust, Networks, Tunnels. "
            "An API token and account ID only manage DNS. They do not start the service."
        )
    padded = raw + ("=" * ((4 - len(raw) % 4) % 4))
    try:
        payload = json.loads(base64.b64decode(padded.replace("-", "+").replace("_", "/")).decode("utf-8"))
    except (ValueError, UnicodeError, json.JSONDecodeError):
        raise ValueError(
            "That value is not a tunnel install token. The API token lists zones and writes the CNAME. "
            "The service starts from the token on the tunnel's install-connector page, which already includes the account ID."
        )
    if not isinstance(payload, dict):
        raise ValueError("Tunnel token did not contain an account, tunnel, and secret.")
    account = str(payload.get("a") or "")
    tunnel_id = str(payload.get("t") or "")
    secret = str(payload.get("s") or "")
    if not re.fullmatch(r"[0-9a-fA-F]{32}", account) or not TUNNEL_ID_RE.match(tunnel_id) or len(secret) < 16:
        raise ValueError("Tunnel token is missing the account ID, tunnel ID, or secret.")
    given = (account_id or "").strip()
    if given and given.lower() != account.lower():
        raise ValueError("That account ID does not match the tunnel token.")
    return {"account_id": account.lower(), "tunnel_id": tunnel_id}


def check_hostname(hostname: str) -> str:
    name = (hostname or "").strip().lower()
    if not HOSTNAME_RE.match(name) or ".." in name or len(name) > 253:
        raise ValueError("Enter a hostname such as app.example.com.")
    return name


def run(args: list[str], timeout: int = 30, env: dict | None = None) -> tuple[bool, str]:
    if not args or any(not isinstance(part, str) or part == "" for part in args):
        return False, "invalid command"
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, env=env, check=False)
    except subprocess.TimeoutExpired:
        return False, "command timed out"
    except OSError as exc:
        return False, str(exc)
    text = redact(((result.stdout or "") + (result.stderr or "")).strip())
    return result.returncode == 0, text


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
