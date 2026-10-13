"""Install a pinned cloudflared, log in, and run the named or quick tunnel."""

from __future__ import annotations

import base64
import json
import os
import re
import secrets
import shutil
import time
import urllib.request

from cf_common import (
    ACCOUNT_ID_RE,
    CLOUDFLARED_BIN,
    CONFIG_PATH,
    CRED_DIR,
    DATA_DIR,
    CERT_DIR,
    HOME,
    LOGIN_DIR,
    LOGIN_UNIT,
    PROFILE_ID_RE,
    PINNED_SHA256,
    PINNED_VERSION,
    PLUGIN_VERSION,
    QUICK_UNIT,
    SERVICE_NAME,
    TOKEN_ENV,
    TUNNEL_ID_RE,
    TUNNEL_NAME_RE,
    UNIT_PATH,
    ensure_dirs,
    fail,
    field,
    local_service,
    ok,
    parse_tunnel_token,
    read_json,
    run,
    sha256_file,
    write_secret,
)

STATE_FILE = os.path.join(DATA_DIR, "state.json")
_LOGIN_URL_RE = re.compile(r"https://dash\.cloudflare\.com/[^\s\"']+")
_QUICK_URL_RE = re.compile(r"https://[a-z0-9-]+\.trycloudflare\.com")


def _arch() -> str:
    machine = os.uname().machine
    if machine in ("x86_64", "amd64"):
        return "amd64"
    if machine in ("aarch64", "arm64"):
        return "arm64"
    return ""


def _state() -> dict:
    data = read_json(STATE_FILE, {})
    if not isinstance(data, dict):
        data = {}
    for key in ("active_tunnel_id", "active_tunnel_name", "active_profile_id"):
        data.setdefault(key, "")
    return data


def _save_state(state: dict) -> None:
    write_secret(STATE_FILE, json.dumps(state, indent=2))


def _is_origin_cert(path: str) -> bool:
    try:
        size = os.path.getsize(path)
        if size < 32 or size > 256 * 1024:
            return False
        with open(path, "rb") as handle:
            head = handle.read(4096)
    except OSError:
        return False
    return b"-----BEGIN ARGO TUNNEL TOKEN-----" in head


def _cert_roots() -> list[str]:
    roots = [HOME, "/root/.cloudflared", "/etc/cloudflared", os.path.realpath(os.path.expanduser("~/.cloudflared"))]
    return [os.path.realpath(root) for root in roots]


def _allowed_cert(path: str) -> bool:
    real = os.path.realpath(path)
    if os.path.basename(real) != "cert.pem" and not real.endswith(".pem"):
        return False
    for root in _cert_roots():
        if real == root or real.startswith(root + os.sep):
            return True
    return False


def _origin_cert_candidates(profile_id: str) -> list[str]:
    paths = [
        os.path.join(LOGIN_DIR, profile_id, ".cloudflared", "cert.pem"),
        "/root/.cloudflared/cert.pem",
        os.path.expanduser("~/.cloudflared/cert.pem"),
        "/etc/cloudflared/cert.pem",
    ]
    log = _login_log_text()
    for match in re.finditer(r"(?:saved to:|existing certificate at)\s*(\S+)", log):
        paths.append(match.group(1).rstrip("."))
    return paths


def _login_log_text() -> str:
    parts = []
    if os.path.isdir(LOGIN_DIR):
        try:
            names = os.listdir(LOGIN_DIR)
        except OSError:
            names = []
        for name in names:
            path = os.path.join(LOGIN_DIR, name, "login.log")
            try:
                with open(path, encoding="utf-8", errors="replace") as handle:
                    parts.append(handle.read()[-8000:])
            except OSError:
                continue
    _good, journal = run(["journalctl", "-u", LOGIN_UNIT, "-n", "80", "--no-pager"], timeout=8)
    parts.append(journal)
    return "\n".join(parts)


def _login_hint() -> str:
    log = _login_log_text()
    if "Failed to write the certificate" in log or "Failed to fetch resource" in log:
        return (
            "The browser login finished, but this server did not receive the certificate. "
            "Click Browser login again and leave this page open for about two minutes. "
            "Cloudflare’s success alert does not download cert.pem; only paste a file if your browser actually saved one."
        )
    for line in reversed(log.splitlines()):
        cleaned = line.strip()
        if "existing certificate" in cleaned or "error writing cert" in cleaned:
            return cleaned[-240:]
    return ""


def _claim_origin_cert(profile_id: str) -> bool:
    if not PROFILE_ID_RE.match(profile_id):
        return False
    from dns_manager import DnsManager

    target = os.path.join(CERT_DIR, profile_id + ".pem")
    if _is_origin_cert(target):
        DnsManager().set_profile_cert(profile_id, target)
        return True
    for source in _origin_cert_candidates(profile_id):
        if not _allowed_cert(source) or not _is_origin_cert(source):
            continue
        real = os.path.realpath(source)
        try:
            os.makedirs(CERT_DIR, mode=0o700, exist_ok=True)
            if real != os.path.realpath(target):
                shutil.copyfile(real, target)
                os.chmod(target, 0o600)
        except OSError:
            continue
        if not _is_origin_cert(target):
            continue
        home_roots = [os.path.realpath(LOGIN_DIR), os.path.realpath("/root/.cloudflared"), os.path.realpath(os.path.expanduser("~/.cloudflared"))]
        if any(real == root or real.startswith(root + os.sep) for root in home_roots):
            try:
                os.remove(real)
            except OSError:
                pass
        DnsManager().set_profile_cert(profile_id, target)
        run(["systemctl", "stop", LOGIN_UNIT], timeout=15)
        return True
    return False


def claim_all_logins() -> None:
    from dns_manager import DnsManager

    for item in DnsManager()._stored():
        profile_id = str(item.get("id") or "")
        if profile_id:
            _claim_origin_cert(profile_id)


def _service_state() -> str:
    _good, text = run(["systemctl", "is-active", SERVICE_NAME], timeout=8)
    if "could not be found" in text or "not-found" in text:
        return "not installed"
    for line in text.splitlines():
        word = line.strip()
        if word in ("active", "inactive", "failed", "activating", "deactivating", "reloading"):
            return word
    return "inactive"


def _service_hint() -> str:
    _good, text = run(["journalctl", "-u", SERVICE_NAME, "-n", "20", "--no-pager"], timeout=10)
    for line in reversed(text.splitlines()):
        cleaned = line.strip()
        if cleaned and "journalctl" not in cleaned:
            return cleaned[-240:]
    return ""


def _active_cred_path() -> str:
    tunnel_id = str(_state().get("active_tunnel_id") or "")
    if not TUNNEL_ID_RE.match(tunnel_id):
        return ""
    path = os.path.join(CRED_DIR, tunnel_id + ".json")
    return path if os.path.isfile(path) else ""


def _unit_text() -> str:
    if _active_cred_path() and os.path.isfile(CONFIG_PATH):
        command = "{} --no-autoupdate --config {} tunnel run".format(CLOUDFLARED_BIN, CONFIG_PATH)
        environment = ""
    elif os.path.isfile(TOKEN_ENV):
        command = "{} --no-autoupdate tunnel run".format(CLOUDFLARED_BIN)
        environment = "EnvironmentFile={}".format(TOKEN_ENV)
    else:
        command = "{} --no-autoupdate --config {} tunnel run".format(CLOUDFLARED_BIN, CONFIG_PATH)
        environment = ""
    lines = [
        "[Unit]",
        "Description=Cloudflare Tunnel",
        "After=network-online.target",
        "Wants=network-online.target",
        "",
        "[Service]",
        "Type=simple",
        "ExecStart={}".format(command),
    ]
    if environment:
        lines.append(environment)
    lines.extend([
        "Restart=on-failure",
        "RestartSec=5s",
        "NoNewPrivileges=true",
        "",
        "[Install]",
        "WantedBy=multi-user.target",
        "",
    ])
    return "\n".join(lines)


def _start_service() -> dict:
    if not os.path.isfile(CLOUDFLARED_BIN):
        return fail("Install cloudflared first.")
    if not os.path.isfile(TOKEN_ENV) and not os.path.isfile(CONFIG_PATH):
        return fail("Paste the tunnel install token, or add a hostname, before starting the service.")
    write_secret(UNIT_PATH, _unit_text(), 0o644)
    run(["systemctl", "daemon-reload"], timeout=20)
    run(["systemctl", "enable", SERVICE_NAME], timeout=20)
    good, text = run(["systemctl", "restart", SERVICE_NAME], timeout=30)
    if not good:
        hint = _service_hint()
        return fail("Could not start the service. " + (hint or text))
    state = _service_state()
    if state not in ("active", "activating"):
        hint = _service_hint()
        return fail("Service is {}. {}".format(state, hint).strip())
    return ok("Service is {}.".format(state))


def _download(url: str, dest: str, limit: int = 80 * 1024 * 1024) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": "cftunnel"})
    with urllib.request.urlopen(request, timeout=120) as response, open(dest, "wb") as handle:
        size = 0
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > limit:
                raise OSError("download exceeded the size limit")
            handle.write(chunk)


class TunnelManager:
    def get_status(self, get) -> dict:
        dir_error = ensure_dirs()
        installed = os.path.isfile(CLOUDFLARED_BIN) and os.access(CLOUDFLARED_BIN, os.X_OK)
        version = ""
        if installed:
            _good, text = run([CLOUDFLARED_BIN, "--version"], timeout=8)
            version = text.splitlines()[0] if text else ""
        service_state = _service_state()
        enabled, enabled_text = run(["systemctl", "is-enabled", SERVICE_NAME], timeout=8)
        state = _state()
        quick_ok, quick_text = run(["systemctl", "is-active", QUICK_UNIT], timeout=8)
        hint = ""
        if service_state == "failed":
            hint = _service_hint()
        return ok(data={
            "installed": installed,
            "plugin_version": PLUGIN_VERSION,
            "version": version,
            "pinned_version": PINNED_VERSION,
            "service_active": service_state,
            "service_hint": hint,
            "connector": "token" if os.path.isfile(TOKEN_ENV) else ("config" if os.path.isfile(CONFIG_PATH) else ""),
            "service_enabled": enabled and enabled_text.strip() == "enabled",
            "active_tunnel_id": state.get("active_tunnel_id") or "",
            "active_tunnel_name": state.get("active_tunnel_name") or "",
            "active_profile_id": state.get("active_profile_id") or "",
            "quick_active": quick_ok,
            "dir_error": dir_error,
        })

    def install_cloudflared(self, get) -> dict:
        arch = _arch()
        digest = PINNED_SHA256.get(arch) or ""
        if not arch or len(digest) != 64:
            return fail("This server architecture is not in the pinned cloudflared builds.")
        ensure_dirs()
        url = "https://github.com/cloudflare/cloudflared/releases/download/{}/cloudflared-linux-{}".format(PINNED_VERSION, arch)
        tmp = os.path.join(DATA_DIR, "cloudflared.download")
        try:
            _download(url, tmp)
            if sha256_file(tmp) != digest:
                os.remove(tmp)
                return fail("The cloudflared download did not match the pinned checksum.")
            os.chmod(tmp, 0o755)
            os.makedirs(os.path.dirname(CLOUDFLARED_BIN), exist_ok=True)
            os.replace(tmp, CLOUDFLARED_BIN)
            os.chmod(CLOUDFLARED_BIN, 0o755)
        except OSError as exc:
            if os.path.exists(tmp):
                os.remove(tmp)
            return fail("Could not install cloudflared: {}".format(exc.__class__.__name__))
        return ok("cloudflared {} installed.".format(PINNED_VERSION))

    def _profile_cert(self, profile_id: str):
        from dns_manager import DnsManager

        profile_id = (profile_id or "").strip()
        if not PROFILE_ID_RE.match(profile_id):
            return None, "Choose an account you added in this plugin (not the aaPanel one)."
        profile = DnsManager().find_profile(profile_id)
        if not profile:
            return None, "That account was not found. Add it again under Accounts, then click Browser login on that row."
        if profile.get("virtual"):
            return None, "aaPanel’s saved Cloudflare account is DNS-only. Add the same token under Accounts, then use Browser login on that row."
        return profile, ""

    def cf_login_start(self, get) -> dict:
        if not os.path.isfile(CLOUDFLARED_BIN):
            return fail("Install cloudflared first.")
        profile, error = self._profile_cert(field(get, "profile_id"))
        if error:
            return fail(error)
        if _claim_origin_cert(profile["id"]):
            return ok("Browser login is already saved.", {"logged_in": True, "profile_id": profile["id"]})
        login_home = os.path.join(LOGIN_DIR, profile["id"])
        os.makedirs(login_home, mode=0o700, exist_ok=True)
        os.chmod(login_home, 0o700)
        run(["systemctl", "stop", LOGIN_UNIT], timeout=15)
        log_path = os.path.join(login_home, "login.log")
        try:
            os.close(os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600))
        except OSError:
            log_path = ""
        command = [
            "systemd-run", "--unit", LOGIN_UNIT, "--collect",
            "--working-directory", login_home,
            "-p", "Environment=HOME=" + login_home,
            "-E", "HOME=" + login_home,
        ]
        if log_path:
            command.extend(["-p", "StandardError=file:" + log_path])
        command.extend([CLOUDFLARED_BIN, "tunnel", "login"])
        good, text = run(command, timeout=20)
        if not good and log_path:
            good, text = run([
                "systemd-run", "--unit", LOGIN_UNIT, "--collect",
                "--working-directory", login_home,
                "-p", "Environment=HOME=" + login_home,
                "-E", "HOME=" + login_home,
                CLOUDFLARED_BIN, "tunnel", "login",
            ], timeout=20)
        if not good:
            return fail("Could not start login: " + text)
        url = ""
        for _ in range(16):
            match = _LOGIN_URL_RE.search(_login_log_text())
            if match:
                url = match.group(0)
                break
            time.sleep(0.5)
        if not url:
            return fail("Cloudflare did not return a login URL. Open the log and try again.")
        return ok("Open this URL and approve the zone.", {"url": url, "profile_id": profile["id"]})

    def cf_login_status(self, get) -> dict:
        profile, error = self._profile_cert(field(get, "profile_id"))
        if error:
            return fail(error)
        ready = _claim_origin_cert(profile["id"])
        detail = "" if ready else _login_hint()
        return ok("ok" if ready else "waiting", {"logged_in": ready, "profile_id": profile["id"], "detail": detail})

    def save_origin_cert(self, get) -> dict:
        profile, error = self._profile_cert(field(get, "profile_id"))
        if error:
            return fail(error)
        raw = field(get, "origin_cert")
        if len(raw) > 64 * 1024 or "-----BEGIN ARGO TUNNEL TOKEN-----" not in raw or "-----END ARGO TUNNEL TOKEN-----" not in raw:
            return fail("Paste the downloaded cert.pem file. It starts with BEGIN ARGO TUNNEL TOKEN.")
        target = os.path.join(CERT_DIR, profile["id"] + ".pem")
        try:
            os.makedirs(CERT_DIR, mode=0o700, exist_ok=True)
            write_secret(target, raw if raw.endswith("\n") else raw + "\n", 0o600)
        except OSError as exc:
            return fail("Could not store the certificate: {}".format(exc.strerror or exc.__class__.__name__))
        if not _is_origin_cert(target):
            try:
                os.remove(target)
            except OSError:
                pass
            return fail("That file is not a Cloudflare origin certificate.")
        from dns_manager import DnsManager

        DnsManager().set_profile_cert(profile["id"], target)
        run(["systemctl", "stop", LOGIN_UNIT], timeout=15)
        return ok("Certificate saved. You can create a tunnel now.", {"logged_in": True, "profile_id": profile["id"]})

    def _run_cf(self, args: list[str], cert_path: str = "", timeout: int = 30):
        if not os.path.isfile(CLOUDFLARED_BIN):
            return False, "cloudflared is not installed."
        env = os.environ.copy()
        env.pop("TUNNEL_TOKEN", None)
        if cert_path:
            if not os.path.isfile(cert_path):
                return False, "This profile is not logged in."
            env["TUNNEL_ORIGIN_CERT"] = cert_path
        return run([CLOUDFLARED_BIN, *args], timeout=timeout, env=env)

    def _write_credentials(self, account_id: str, tunnel_id: str, tunnel_secret: str) -> str:
        ensure_dirs()
        path = os.path.join(CRED_DIR, tunnel_id + ".json")
        write_secret(path, json.dumps({
            "AccountTag": account_id,
            "TunnelID": tunnel_id,
            "TunnelSecret": tunnel_secret,
        }, indent=2), 0o600)
        return path

    def _activate_tunnel(self, tunnel_id: str, tunnel_name: str, profile_id: str) -> None:
        state = _state()
        state["active_tunnel_id"] = tunnel_id
        state["active_tunnel_name"] = (tunnel_name or tunnel_id[:8])[:48]
        if profile_id:
            state["active_profile_id"] = profile_id
        _save_state(state)

    def ensure_connector(self, tunnel_id: str = "", profile_id: str = "") -> dict:
        """Make sure this tunnel can run: local credentials JSON, or a connector token."""
        tunnel_id = tunnel_id or str(_state().get("active_tunnel_id") or "")
        if not TUNNEL_ID_RE.match(tunnel_id):
            return fail("Select a tunnel first.")
        cred = os.path.join(CRED_DIR, tunnel_id + ".json")
        if os.path.isfile(cred):
            return ok(data={"mode": "config", "cred": cred, "tunnel_id": tunnel_id})
        from dns_manager import DnsManager

        dns = DnsManager()
        state = _state()
        profile = dns.find_profile(profile_id or state.get("active_profile_id") or "")
        token = (profile or {}).get("token") or ""
        account_id = str((profile or {}).get("account_id") or "").lower()
        if token and ACCOUNT_ID_RE.match(account_id):
            result = dns._request(
                "GET",
                "/accounts/{}/cfd_tunnel/{}/token".format(account_id, tunnel_id),
                dns._auth_for(profile),
            )
            raw = result.get("data") if result.get("status") else ""
            if isinstance(raw, str) and len(raw.strip()) > 20:
                write_secret(TOKEN_ENV, "TUNNEL_TOKEN={}\n".format(raw.strip()), 0o600)
                return ok(data={
                    "mode": "token",
                    "tunnel_id": tunnel_id,
                    "account_id": account_id,
                    "profile_id": profile["id"],
                })
            if not result.get("status"):
                return fail(
                    "Could not fetch the tunnel connector token: {}. "
                    "Recreate the tunnel after the API token has Account → Cloudflare Tunnel → Edit."
                    .format(result.get("msg") or "API error")
                )
        cert = (profile or {}).get("cert_path") or ""
        if cert and os.path.isfile(cert) and os.path.isfile(CLOUDFLARED_BIN):
            env = os.environ.copy()
            env.pop("TUNNEL_TOKEN", None)
            env["TUNNEL_ORIGIN_CERT"] = cert
            good, text = run(
                [CLOUDFLARED_BIN, "tunnel", "token", "--cred-file", cred, tunnel_id],
                timeout=20,
                env=env,
            )
            if good and os.path.isfile(cred):
                os.chmod(cred, 0o600)
                return ok(data={"mode": "config", "cred": cred, "tunnel_id": tunnel_id})
            return fail("Could not store tunnel credentials. " + text)
        return fail(
            "No credential file for this tunnel. Click Use on the tunnel again after the API token "
            "includes Cloudflare Tunnel Edit, or create a new tunnel with that token."
        )

    def push_remote_ingress(self, tunnel_id: str, items: list, profile_id: str = "") -> dict:
        from dns_manager import DnsManager

        dns = DnsManager()
        state = _state()
        profile = dns.find_profile(profile_id or state.get("active_profile_id") or "")
        account_id = str((profile or {}).get("account_id") or "").lower()
        if not profile or not ((profile.get("token") or "") and ACCOUNT_ID_RE.match(account_id)):
            return fail("Remote tunnel config needs an API token with an account id.")
        ingress = []
        for item in items:
            rule = {"hostname": item["hostname"], "service": item["service"]}
            origin = item.get("origin_request") or {}
            if origin:
                rule["originRequest"] = origin
            ingress.append(rule)
        ingress.append({"service": "http_status:404"})
        result = dns._request(
            "PUT",
            "/accounts/{}/cfd_tunnel/{}/configurations".format(account_id, tunnel_id),
            dns._auth_for(profile),
            {"config": {"ingress": ingress}},
        )
        if not result["status"]:
            return fail("Could not publish hostname rules to Cloudflare: " + result["msg"])
        return ok("Remote tunnel config updated.")

    def list_tunnels(self, get) -> dict:
        from dns_manager import DnsManager

        rows = []
        errors = []
        seen = set()
        claim_all_logins()
        dns = DnsManager()
        for profile in dns._stored():
            token = profile.get("token") or ""
            account_id = str(profile.get("account_id") or "").lower()
            if token and not ACCOUNT_ID_RE.match(account_id):
                discovered, _err = dns.discover_account_id(dns._auth_for(profile))
                if ACCOUNT_ID_RE.match(discovered):
                    account_id = discovered
                    profiles = dns._read_profiles()
                    for item in profiles:
                        if item.get("id") == profile["id"]:
                            item["account_id"] = account_id
                            dns._write_profiles(profiles)
                            break
                    profile["account_id"] = account_id
            if token and ACCOUNT_ID_RE.match(account_id):
                result = dns._request(
                    "GET",
                    "/accounts/{}/cfd_tunnel?is_deleted=false&per_page=100".format(account_id),
                    dns._auth_for(profile),
                )
                if not result["status"]:
                    errors.append(profile["name"] + ": " + result["msg"])
                    continue
                for tunnel in result.get("data") or []:
                    tunnel_id = str(tunnel.get("id") or "")
                    if not TUNNEL_ID_RE.match(tunnel_id) or tunnel_id in seen:
                        continue
                    seen.add(tunnel_id)
                    rows.append({
                        "id": tunnel_id,
                        "name": str(tunnel.get("name") or ""),
                        "connections": len(tunnel.get("connections") or []),
                        "profile_id": profile["id"],
                        "profile_name": profile["name"],
                        "via": "api",
                    })
                continue
            cert = profile.get("cert_path") or ""
            if not (cert and os.path.isfile(cert)):
                continue
            good, text = self._run_cf(["tunnel", "list", "--output", "json"], cert_path=cert)
            if not good:
                errors.append(profile["name"] + ": " + text[:160])
                continue
            start = text.find("[")
            try:
                payload = json.loads(text[start:] if start >= 0 else "[]")
            except json.JSONDecodeError:
                payload = []
            for tunnel in payload or []:
                tunnel_id = str(tunnel.get("id") or "")
                if not TUNNEL_ID_RE.match(tunnel_id) or tunnel_id in seen:
                    continue
                seen.add(tunnel_id)
                rows.append({
                    "id": tunnel_id,
                    "name": str(tunnel.get("name") or ""),
                    "connections": len(tunnel.get("connections") or []),
                    "profile_id": profile["id"],
                    "profile_name": profile["name"],
                    "via": "cert",
                })
        if not rows and errors:
            return fail("; ".join(errors))
        if not rows:
            return fail(
                "No tunnels yet. Add an API token that includes Account → Cloudflare Tunnel → Edit, "
                "enter the Account ID if asked, then create a tunnel. Browser login is optional."
            )
        return ok(data=rows)

    def create_tunnel(self, get) -> dict:
        name = field(get, "tunnel_name")
        profile_id = field(get, "profile_id")
        if not TUNNEL_NAME_RE.match(name):
            return fail("Tunnel name must be 1-48 letters, numbers, _ or -.")
        from dns_manager import DnsManager

        dns = DnsManager()
        _claim_origin_cert(profile_id)
        profile = dns.find_profile(profile_id)
        if not profile or profile.get("virtual"):
            return fail("Choose an account you added under Accounts.")
        token = profile.get("token") or ""
        account_id = str(profile.get("account_id") or "").lower()
        if token and not ACCOUNT_ID_RE.match(account_id):
            account_id, account_error = dns.discover_account_id(dns._auth_for(profile), field(get, "cf_account_id"))
            if account_error:
                return fail(account_error)
            profiles = dns._read_profiles()
            for item in profiles:
                if item.get("id") == profile["id"]:
                    item["account_id"] = account_id
                    dns._write_profiles(profiles)
                    break
            profile["account_id"] = account_id
        if token and ACCOUNT_ID_RE.match(account_id):
            tunnel_secret = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
            result = dns._request(
                "POST",
                "/accounts/{}/cfd_tunnel".format(account_id),
                dns._auth_for(profile),
                {"name": name, "config_src": "local", "tunnel_secret": tunnel_secret},
            )
            if not result["status"]:
                return fail(
                    "Create failed: {}. Create a custom API token with Account → Cloudflare Tunnel → Edit "
                    "and Zone → DNS → Edit, then update this account."
                    .format(result["msg"])
                )
            payload = result.get("data") or {}
            tunnel_id = str(payload.get("id") or "")
            if not TUNNEL_ID_RE.match(tunnel_id):
                return fail("Cloudflare created a tunnel but did not return its id.")
            creds = payload.get("credentials_file") if isinstance(payload.get("credentials_file"), dict) else {}
            secret = str(creds.get("TunnelSecret") or tunnel_secret)
            account_tag = str(creds.get("AccountTag") or account_id)
            self._write_credentials(account_tag, tunnel_id, secret)
            self._activate_tunnel(tunnel_id, name, profile["id"])
            token_result = dns._request(
                "GET",
                "/accounts/{}/cfd_tunnel/{}/token".format(account_id, tunnel_id),
                dns._auth_for(profile),
            )
            raw = token_result.get("data") if token_result.get("status") else ""
            if isinstance(raw, str) and len(raw.strip()) > 20:
                write_secret(TOKEN_ENV, "TUNNEL_TOKEN={}\n".format(raw.strip()), 0o600)
            return ok("Tunnel created with the API token. Click Use if it is not already active, then add a hostname.", {
                "id": tunnel_id,
                "name": name,
                "profile_id": profile["id"],
                "profile_name": profile["name"],
                "via": "api",
            })
        cert = profile.get("cert_path") or ""
        if not os.path.isfile(cert):
            return fail(
                "This account has no Cloudflare Tunnel API permission and no browser certificate. "
                "Update the API token (Account → Cloudflare Tunnel → Edit), or paste Account ID and recreate the token."
            )
        good, text = self._run_cf(["tunnel", "create", name], cert_path=cert, timeout=60)
        if not good:
            return fail("Create failed: " + text)
        match = re.search(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", text)
        tunnel_id = match.group(0) if match else ""
        if tunnel_id:
            legacy = os.path.expanduser("~/.cloudflared/{}.json".format(tunnel_id))
            target = os.path.join(CRED_DIR, tunnel_id + ".json")
            if os.path.isfile(legacy) and not os.path.isfile(target):
                shutil.move(legacy, target)
                os.chmod(target, 0o600)
            self._activate_tunnel(tunnel_id, name, profile["id"])
        return ok("Tunnel created on {}.".format(profile["name"]), {
            "id": tunnel_id,
            "name": name,
            "profile_id": profile["id"],
            "profile_name": profile["name"],
            "via": "cert",
        })

    def select_tunnel(self, get) -> dict:
        tunnel_id = field(get, "tunnel_id")
        if not TUNNEL_ID_RE.match(tunnel_id):
            return fail("Missing tunnel id.")
        from dns_manager import DnsManager

        profile_id = field(get, "profile_id")
        self._activate_tunnel(tunnel_id, field(get, "tunnel_name"), profile_id)
        ready = self.ensure_connector(tunnel_id, profile_id)
        if not ready.get("status"):
            return fail(ready.get("msg") or "Could not prepare this tunnel.")
        return ok("Active tunnel set. Add a hostname, then Install and start.")

    def delete_tunnel(self, get) -> dict:
        tunnel_id = field(get, "tunnel_id")
        if not TUNNEL_ID_RE.match(tunnel_id):
            return fail("Missing tunnel id.")
        from dns_manager import DnsManager

        dns = DnsManager()
        profile = dns.find_profile(field(get, "profile_id"))
        token = (profile or {}).get("token") or ""
        account_id = str((profile or {}).get("account_id") or "").lower()
        if token and ACCOUNT_ID_RE.match(account_id):
            result = dns._request(
                "DELETE",
                "/accounts/{}/cfd_tunnel/{}".format(account_id, tunnel_id),
                dns._auth_for(profile),
            )
            if not result["status"]:
                return fail("Delete failed: " + result["msg"])
        else:
            cert = (profile or {}).get("cert_path") or ""
            if not cert:
                state = _state()
                if state.get("active_tunnel_id") == tunnel_id:
                    saved = dns.find_profile(state.get("active_profile_id") or "")
                    cert = (saved or {}).get("cert_path") or ""
            self._run_cf(["tunnel", "cleanup", tunnel_id], cert_path=cert, timeout=20)
            good, text = self._run_cf(["tunnel", "delete", "-f", tunnel_id], cert_path=cert, timeout=30)
            if not good:
                return fail("Delete failed: " + text)
        cred = os.path.join(CRED_DIR, tunnel_id + ".json")
        if os.path.isfile(cred):
            os.remove(cred)
        state = _state()
        if state.get("active_tunnel_id") == tunnel_id:
            state["active_tunnel_id"] = ""
            state["active_tunnel_name"] = ""
            state["active_profile_id"] = ""
            _save_state(state)
        return ok("Tunnel deleted.")

    def set_tunnel_token(self, get) -> dict:
        try:
            parsed = parse_tunnel_token(field(get, "tunnel_token"), field(get, "account_id"))
        except ValueError as exc:
            return fail(str(exc))
        dir_error = ensure_dirs()
        if dir_error:
            return fail("Directory setup failed: " + dir_error)
        write_secret(TOKEN_ENV, "TUNNEL_TOKEN={}\n".format(field(get, "tunnel_token").strip()), 0o600)
        state = _state()
        state["active_tunnel_id"] = parsed["tunnel_id"]
        state["active_tunnel_name"] = state.get("active_tunnel_name") or parsed["tunnel_id"][:8]
        _save_state(state)
        started = _start_service()
        if not started.get("status"):
            return started
        return ok("Tunnel token saved and the service is starting.", {"tunnel_id": parsed["tunnel_id"], "account_id": parsed["account_id"]})

    def service_action(self, get) -> dict:
        action = field(get, "act")
        if action == "install":
            return _start_service()
        if action == "uninstall":
            run(["systemctl", "disable", "--now", SERVICE_NAME], timeout=30)
            if os.path.isfile(UNIT_PATH):
                os.remove(UNIT_PATH)
            run(["systemctl", "daemon-reload"], timeout=20)
            return ok("Service removed. Tunnel credentials were kept.")
        if action not in ("start", "stop", "restart", "enable", "disable"):
            return fail("Unknown service action.")
        good, text = run(["systemctl", action, SERVICE_NAME], timeout=30)
        if not good:
            return fail(text or "systemctl {} failed.".format(action))
        return ok("Service {}.".format(action))

    def get_log(self, get) -> dict:
        _good, named = run(["journalctl", "-u", SERVICE_NAME, "-n", "200", "--no-pager"], timeout=10)
        _quick, quick = run(["journalctl", "-u", QUICK_UNIT, "-n", "80", "--no-pager"], timeout=10)
        return ok(data={"log": named, "quick_log": quick})

    def quick_start(self, get) -> dict:
        if not os.path.isfile(CLOUDFLARED_BIN):
            return fail("Install cloudflared first.")
        try:
            service = local_service("http://127.0.0.1:{}".format(field(get, "port")))
        except ValueError as exc:
            return fail(str(exc))
        run(["systemctl", "stop", QUICK_UNIT], timeout=20)
        good, text = run([
            "systemd-run", "--unit", QUICK_UNIT, "--collect",
            CLOUDFLARED_BIN, "tunnel", "--no-autoupdate", "--url", service,
        ], timeout=20)
        if not good:
            return fail("Could not start the quick tunnel: " + text)
        url = ""
        import time
        for _ in range(20):
            _ok, log = run(["journalctl", "-u", QUICK_UNIT, "-n", "80", "--no-pager"], timeout=8)
            match = _QUICK_URL_RE.search(log)
            if match:
                url = match.group(0)
                break
            time.sleep(0.5)
        if not url:
            return ok("Quick tunnel is starting. Refresh the log in a moment.", {"url": "", "service": service})
        return ok("Quick tunnel is live.", {"url": url, "service": service})

    def quick_status(self, get) -> dict:
        active, _text = run(["systemctl", "is-active", QUICK_UNIT], timeout=8)
        _good, log = run(["journalctl", "-u", QUICK_UNIT, "-n", "80", "--no-pager"], timeout=8)
        match = _QUICK_URL_RE.search(log)
        return ok(data={"running": active, "url": match.group(0) if match else ""})

    def quick_stop(self, get) -> dict:
        run(["systemctl", "stop", QUICK_UNIT], timeout=20)
        return ok("Quick tunnel stopped.")
