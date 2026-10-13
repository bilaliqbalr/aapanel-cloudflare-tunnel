"""Hostname rules for the named tunnel. Every origin is a localhost port."""

from __future__ import annotations

import json
import os

from cf_common import (
    CERT_DIR,
    CLOUDFLARED_BIN,
    CONFIG_PATH,
    CRED_DIR,
    DATA_DIR,
    DURATION_RE,
    HOST_HEADER_RE,
    SERVICE_NAME,
    TUNNEL_ID_RE,
    check_hostname,
    fail,
    field,
    flag,
    local_service,
    ok,
    read_json,
    run,
    write_secret,
)

INGRESS_FILE = os.path.join(DATA_DIR, "ingress.json")
STATE_FILE = os.path.join(DATA_DIR, "state.json")

ORIGIN_REQUEST_FIELDS = {
    "connectTimeout": "duration",
    "tlsTimeout": "duration",
    "noTLSVerify": "bool",
    "disableChunkedEncoding": "bool",
    "http2Origin": "bool",
    "httpHostHeader": "host",
    "originServerName": "host",
}


def coerce_origin_request(raw) -> dict:
    if not raw:
        return {}
    if not isinstance(raw, dict):
        raise ValueError("Origin options must be an object.")
    out = {}
    for key, value in raw.items():
        kind = ORIGIN_REQUEST_FIELDS.get(key)
        if not kind or value in ("", None):
            continue
        if kind == "bool":
            if isinstance(value, bool):
                out[key] = value
            elif isinstance(value, str):
                out[key] = value.lower() in ("1", "true", "yes", "on")
            else:
                raise ValueError("{} must be true or false.".format(key))
        elif kind == "duration":
            text = str(value).strip()
            if not DURATION_RE.match(text):
                raise ValueError("{} must look like 30s or 1m.".format(key))
            out[key] = text
        else:
            text = str(value).strip()
            if not HOST_HEADER_RE.match(text):
                raise ValueError("{} must be a hostname.".format(key))
            out[key] = text
    return out


def _yaml_string(value: str) -> str:
    return json.dumps(str(value))


def _yaml_value(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return _yaml_string(value)


class IngressManager:
    def _items(self) -> list:
        data = read_json(INGRESS_FILE, [])
        return data if isinstance(data, list) else []

    def _save(self, items: list) -> None:
        write_secret(INGRESS_FILE, json.dumps(items, indent=2))

    def _state(self) -> dict:
        data = read_json(STATE_FILE, {})
        return data if isinstance(data, dict) else {}

    def get_ingress(self, get) -> dict:
        return ok(data=self._items())

    def get_origin_request_fields(self, get) -> dict:
        return ok(data=ORIGIN_REQUEST_FIELDS)

    def _origin_from_get(self, get):
        raw = field(get, "origin_request_json")
        if not raw:
            return {}, False
        try:
            return coerce_origin_request(json.loads(raw)), True
        except json.JSONDecodeError:
            raise ValueError("Origin options must be JSON.")

    def add_ingress(self, get) -> dict:
        try:
            hostname = check_hostname(field(get, "hostname"))
            service = local_service(field(get, "service"))
            origin, sent = self._origin_from_get(get)
        except ValueError as exc:
            return fail(str(exc))
        state = self._state()
        tunnel_id = str(state.get("active_tunnel_id") or "")
        if not TUNNEL_ID_RE.match(tunnel_id):
            return fail("Select a tunnel first.")
        auto_dns = flag(get, "auto_dns", True)
        from dns_manager import DnsManager

        dns = DnsManager()
        if auto_dns and not dns._all_profiles():
            return fail("Add a Cloudflare API token, or turn off automatic DNS.")
        previous = self._items()
        prior = next((item for item in previous if item.get("hostname") == hostname), None)
        if prior and not sent:
            origin = prior.get("origin_request") or {}
        items = [item for item in previous if item.get("hostname") != hostname]
        row = {
            "hostname": hostname,
            "service": service,
            "proxied": flag(get, "proxied", True),
            "zone_id": field(get, "zone_id"),
        }
        if origin:
            row["origin_request"] = origin
        items.append(row)
        self._save(items)
        if auto_dns:
            good, message = dns.upsert_cname(
                hostname,
                tunnel_id + ".cfargotunnel.com",
                zone_id=row["zone_id"],
                proxied=row["proxied"],
                replace_existing=flag(get, "replace_dns", False),
            )
            if not good:
                self._save(previous)
                return fail("DNS was not changed, and the hostname was not saved. " + message)
        applied = self.apply_config(get)
        if not applied.get("status"):
            self._save(previous)
            return fail("The hostname was not saved. " + applied.get("msg", ""))
        return ok("Hostname added.")

    def set_ingress_options(self, get) -> dict:
        try:
            hostname = check_hostname(field(get, "hostname"))
        except ValueError as exc:
            return fail(str(exc))
        items = self._items()
        target = next((item for item in items if item.get("hostname") == hostname), None)
        if not target:
            return fail("That hostname is not in the list.")
        service = field(get, "service")
        if service:
            try:
                target["service"] = local_service(service)
            except ValueError as exc:
                return fail(str(exc))
        if hasattr(get, "origin_request_json"):
            raw = field(get, "origin_request_json")
            if raw in ("", "{}", "null"):
                target.pop("origin_request", None)
            else:
                try:
                    target["origin_request"] = coerce_origin_request(json.loads(raw))
                except (ValueError, json.JSONDecodeError) as exc:
                    return fail(str(exc))
        self._save(items)
        applied = self.apply_config(get)
        if not applied.get("status"):
            return fail("Options saved, but applying them failed. " + applied.get("msg", ""))
        return ok("Options updated.")

    def remove_ingress(self, get) -> dict:
        try:
            hostname = check_hostname(field(get, "hostname"))
        except ValueError as exc:
            return fail(str(exc))
        items = self._items()
        target = next((item for item in items if item.get("hostname") == hostname), None)
        if not target:
            return fail("That hostname is not in the list.")
        self._save([item for item in items if item.get("hostname") != hostname])
        dns_msg = "DNS was left as it is."
        if flag(get, "delete_dns", True):
            from dns_manager import DnsManager

            _good, dns_msg = DnsManager().delete_cname(hostname, zone_id=target.get("zone_id") or "")
        applied = self.apply_config(get)
        if not applied.get("status"):
            return fail("Hostname removed. {} Applying the config failed: {}".format(dns_msg, applied.get("msg")))
        return ok("Hostname removed. " + dns_msg)

    def _cert(self) -> str:
        from dns_manager import DnsManager

        state = self._state()
        profile = DnsManager().find_profile(str(state.get("active_profile_id") or ""))
        cert = (profile or {}).get("cert_path") or ""
        if cert and os.path.isfile(cert) and os.path.realpath(cert).startswith(os.path.realpath(CERT_DIR) + os.sep):
            return cert
        for item in DnsManager()._stored():
            path = item.get("cert_path") or ""
            if path and os.path.isfile(path):
                return path
        return ""

    def _credentials(self, tunnel_id: str):
        from tunnel_manager import TunnelManager

        ready = TunnelManager().ensure_connector(tunnel_id)
        if not ready.get("status"):
            return "", ready.get("msg") or "Could not prepare tunnel credentials."
        data = ready.get("data") or {}
        if data.get("mode") == "config" and data.get("cred") and os.path.isfile(data["cred"]):
            return data["cred"], ""
        if data.get("mode") == "token":
            return "", ""
        return "", "Could not prepare tunnel credentials."

    def apply_config(self, get) -> dict:
        from tunnel_manager import TunnelManager, _start_service

        state = self._state()
        tunnel_id = str(state.get("active_tunnel_id") or "")
        if not TUNNEL_ID_RE.match(tunnel_id):
            return fail("No tunnel is selected.")
        manager = TunnelManager()
        ready = manager.ensure_connector(tunnel_id, str(state.get("active_profile_id") or ""))
        if not ready.get("status"):
            return fail(ready.get("msg") or "Could not prepare tunnel credentials.")
        mode = (ready.get("data") or {}).get("mode") or "config"
        cred = (ready.get("data") or {}).get("cred") or ""
        lines = ["tunnel: {}".format(tunnel_id)]
        if mode == "config" and cred:
            lines.append("credentials-file: {}".format(cred))
        lines.append("ingress:")
        for item in self._items():
            lines.append("  - hostname: {}".format(_yaml_string(item["hostname"])))
            lines.append("    service: {}".format(_yaml_string(item["service"])))
            origin = item.get("origin_request") or {}
            if origin:
                lines.append("    originRequest:")
                for key in sorted(origin):
                    lines.append("      {}: {}".format(key, _yaml_value(origin[key])))
        lines.append("  - service: http_status:404")
        write_secret(CONFIG_PATH, "\n".join(lines) + "\n")
        if mode == "token":
            remote = manager.push_remote_ingress(
                tunnel_id,
                self._items(),
                str(state.get("active_profile_id") or ""),
            )
            if not remote.get("status"):
                return fail(remote.get("msg") or "Could not publish hostname rules.")
        installed, _text = run(["systemctl", "cat", SERVICE_NAME], timeout=8)
        if installed:
            started = _start_service()
            if not started.get("status"):
                return fail(started.get("msg") or "Config written, but the service did not restart.")
        return ok("Config written.")
