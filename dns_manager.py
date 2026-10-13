"""Cloudflare API profiles, zone lookup, and tunnel CNAME records.

Local profiles live in data/api_profiles.json mode 0600. Tokens already saved
by aaPanel's Cloudflare or DNS screens are read for DNS only and are not copied.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import time
import urllib.error
import urllib.request

from cf_common import (
    ACCOUNT_ID_RE,
    CF_API,
    DATA_DIR,
    GLOBAL_CF_DEFAULT,
    GLOBAL_DNS_MAGER,
    PROFILE_ID_RE,
    fail,
    field,
    ok,
    parse_tunnel_token,
    read_json,
    write_secret,
)

PROFILES_FILE = os.path.join(DATA_DIR, "api_profiles.json")
_ZONES_TTL = 60


class DnsManager:
    _zones_cache: dict = {}

    def _read_profiles(self) -> list:
        data = read_json(PROFILES_FILE, [])
        return data if isinstance(data, list) else []

    def _write_profiles(self, profiles: list) -> None:
        write_secret(PROFILES_FILE, json.dumps(profiles, indent=2))

    @staticmethod
    def _new_id(name: str) -> str:
        safe = "".join(ch if ch.isalnum() else "_" for ch in (name or "profile").lower())[:12] or "p"
        return "{}_{}".format(safe, secrets.token_hex(3))

    def _stored(self) -> list:
        rows = []
        for item in self._read_profiles():
            if not isinstance(item, dict) or not PROFILE_ID_RE.match(str(item.get("id") or "")):
                continue
            rows.append({
                "id": item["id"],
                "name": str(item.get("name") or item["id"])[:48],
                "token": str(item.get("token") or ""),
                "cert_path": str(item.get("cert_path") or ""),
                "account_id": str(item.get("account_id") or "").lower(),
                "virtual": False,
            })
        return rows

    @staticmethod
    def _auth_from_cfg(cfg) -> dict | None:
        if not isinstance(cfg, dict):
            return None
        token = cfg.get("API Token") or cfg.get("api_token")
        if token:
            return {"Authorization": "Bearer " + str(token)}
        email = cfg.get("E-Mail") or cfg.get("email")
        key = cfg.get("API Key") or cfg.get("api_key")
        if email and key:
            return {"X-Auth-Email": str(email), "X-Auth-Key": str(key)}
        return None

    def _virtual(self) -> list:
        rows = []
        cfg = read_json(GLOBAL_CF_DEFAULT, None)
        auth = self._auth_from_cfg(cfg)
        if auth:
            rows.append({
                "id": "__cloudflare_manage__",
                "name": "aaPanel Cloudflare",
                "auth": auth,
                "virtual": True,
            })
        manager = read_json(GLOBAL_DNS_MAGER, None)
        if isinstance(manager, dict):
            for index, item in enumerate(manager.get("CloudFlareDns") or []):
                found = self._auth_from_cfg(item)
                if not found:
                    continue
                rows.append({
                    "id": "__dns_mager_{}__".format(index),
                    "name": "aaPanel DNS #{}".format(index + 1),
                    "auth": found,
                    "virtual": True,
                })
        return rows

    def _all_profiles(self) -> list:
        return self._stored() + self._virtual()

    def find_profile(self, profile_id: str):
        for item in self._all_profiles():
            if item["id"] == profile_id:
                return item
        return None

    def set_profile_cert(self, profile_id: str, cert_path: str) -> bool:
        if not PROFILE_ID_RE.match(profile_id):
            return False
        profiles = self._read_profiles()
        for item in profiles:
            if item.get("id") == profile_id:
                item["cert_path"] = cert_path
                self._write_profiles(profiles)
                return True
        return False

    @staticmethod
    def _auth_for(profile: dict) -> dict:
        if profile.get("auth"):
            return profile["auth"]
        return {"Authorization": "Bearer " + profile.get("token", "")}

    def _public_row(self, item: dict, virtual: bool) -> dict:
        token = "" if virtual else str(item.get("token") or "")
        cert_path = "" if virtual else str(item.get("cert_path") or "")
        account_id = "" if virtual else str(item.get("account_id") or "")
        api_ready = bool(token and ACCOUNT_ID_RE.match(account_id))
        return {
            "id": item["id"],
            "name": item.get("name") or item["id"],
            "virtual": virtual,
            "tail": token[-4:] if token else "",
            "has_token": bool(token) or virtual,
            "account_id": account_id,
            "api_ready": api_ready,
            "logged_in": bool(cert_path and os.path.isfile(cert_path)),
            "can_create_tunnels": (not virtual) and (api_ready or bool(cert_path and os.path.isfile(cert_path))),
        }

    def discover_account_id(self, auth: dict, preferred: str = "") -> tuple[str, str]:
        preferred = (preferred or "").strip().lower()
        if ACCOUNT_ID_RE.match(preferred):
            return preferred, ""
        result = self._request("GET", "/accounts?per_page=50", auth)
        if not result["status"]:
            return "", result["msg"]
        accounts = result.get("data") or []
        rows = [item for item in accounts if isinstance(item, dict) and ACCOUNT_ID_RE.match(str(item.get("id") or "").lower())]
        if not rows:
            return "", "This API token cannot list accounts. Paste the Account ID from the Cloudflare dashboard overview."
        if len(rows) == 1:
            return str(rows[0]["id"]).lower(), ""
        names = ", ".join("{} ({})".format(item.get("name") or "account", item["id"]) for item in rows[:6])
        return "", "This token can see several accounts: {}. Paste the Account ID you want to use.".format(names)

    def list_profiles(self, get) -> dict:
        rows = [self._public_row(item, False) for item in self._read_profiles() if item.get("id")]
        rows.extend(self._public_row(item, True) for item in self._virtual())
        return ok(data=rows)

    def _clean_api_token(self, token: str) -> str:
        text = (token or "").strip().strip('"').strip("'").replace("\u200b", "").replace("\ufeff", "")
        if text.lower().startswith("bearer "):
            text = text[7:].strip()
        return text

    def _verify_token(self, token: str, account_id: str = "") -> str:
        token = self._clean_api_token(token)
        if len(token) < 20 or len(token) > 4096 or any(ch.isspace() for ch in token):
            return "Paste only the API token secret, without the word Bearer."
        try:
            parse_tunnel_token(token)
        except ValueError:
            pass
        else:
            return (
                "That is a tunnel install token. Paste it in the Service card and click Save and start. "
                "This box needs an API token from My Profile, API Tokens."
            )
        auth = {"Authorization": "Bearer " + token}
        user = self._request("GET", "/user/tokens/verify", auth)
        if user["status"] or user["msg"].startswith("Could not reach"):
            return "" if user["status"] else user["msg"]
        account_id = (account_id or "").strip().lower()
        if re.fullmatch(r"[0-9a-f]{32}", account_id):
            account = self._request("GET", "/accounts/{}/tokens/verify".format(account_id), auth)
            if account["status"] or account["msg"].startswith("Could not reach"):
                return "" if account["status"] else account["msg"]
        zones = self._request("GET", "/zones?per_page=1", auth)
        if zones["status"] or zones["msg"].startswith("Could not reach"):
            return "" if zones["status"] else zones["msg"]
        return (
            "Cloudflare rejected this API token ({}). "
            "Use the secret from My Profile → API Tokens → Edit zone DNS. "
            "If the token was created under Manage Account → Account API Tokens, enter that account ID too. "
            "A tunnel install token belongs in the Service card."
        ).format(zones.get("msg") or user.get("msg") or "Invalid API Token")

    def _prepare_token(self, token: str, preferred_account: str = "") -> tuple[str, str, str]:
        """Returns (account_id, error, cleaned_token)."""
        token = self._clean_api_token(token)
        error = self._verify_token(token, preferred_account)
        if error:
            return "", error, token
        account_id, account_error = self.discover_account_id(
            {"Authorization": "Bearer " + token},
            preferred_account,
        )
        if account_error:
            return "", account_error, token
        return account_id, "", token

    def add_profile(self, get) -> dict:
        name = field(get, "profile_name")[:48]
        token = self._clean_api_token(field(get, "token"))
        if not name or any(ch in name for ch in "\r\n\x00"):
            return fail("Enter a profile name.")
        account_id = ""
        if token:
            account_id, error, token = self._prepare_token(token, field(get, "cf_account_id"))
            if error:
                return fail(error)
        profiles = self._read_profiles()
        if any(item.get("name") == name for item in profiles):
            return fail("A profile with that name already exists.")
        if token and any(item.get("token") == token for item in profiles):
            return fail("This token is already saved on another profile.")
        profile_id = self._new_id(name)
        profiles.append({
            "id": profile_id,
            "name": name,
            "token": token,
            "account_id": account_id,
            "cert_path": "",
        })
        self._write_profiles(profiles)
        DnsManager._zones_cache.clear()
        msg = "Account added."
        if account_id:
            msg = "Account added. You can create tunnels with this API token — Browser login is optional."
        return ok(msg, {"id": profile_id, "name": name, "account_id": account_id})

    def update_profile_token(self, get) -> dict:
        profile_id = field(get, "profile_id")
        if not PROFILE_ID_RE.match(profile_id):
            return fail("Choose a profile saved in this plugin.")
        account_id, error, token = self._prepare_token(field(get, "token"), field(get, "cf_account_id"))
        if error:
            return fail(error)
        profiles = self._read_profiles()
        for item in profiles:
            if item.get("id") == profile_id:
                item["token"] = token
                item["account_id"] = account_id
                self._write_profiles(profiles)
                DnsManager._zones_cache.clear()
                return ok("Token updated.", {"account_id": account_id})
        return fail("Profile not found.")

    def delete_profile(self, get) -> dict:
        profile_id = field(get, "profile_id")
        if not PROFILE_ID_RE.match(profile_id):
            return fail("A saved Cloudflare account cannot be removed from this screen.")
        profiles = self._read_profiles()
        removed = next((item for item in profiles if item.get("id") == profile_id), None)
        kept = [item for item in profiles if item.get("id") != profile_id]
        if removed is None:
            return fail("Profile not found.")
        cert_path = str((removed or {}).get("cert_path") or "")
        cert_root = os.path.realpath("/etc/cloudflared/cftunnel/certs")
        if cert_path and os.path.isfile(cert_path) and os.path.realpath(cert_path).startswith(cert_root + os.sep):
            os.remove(cert_path)
        self._write_profiles(kept)
        DnsManager._zones_cache.clear()
        return ok("Profile removed.")

    def _request(self, method: str, path: str, auth: dict, body=None) -> dict:
        if not auth:
            return fail("No Cloudflare credentials are available.")
        data = None if body is None else json.dumps(body).encode("utf-8")
        request = urllib.request.Request(CF_API + path, data=data, method=method)
        for key, value in auth.items():
            request.add_header(key, value)
        if body is not None:
            request.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            try:
                payload = json.loads(exc.read().decode("utf-8") or "{}")
            except (OSError, json.JSONDecodeError, UnicodeError):
                return fail("Cloudflare returned HTTP {}.".format(exc.code))
        except (OSError, json.JSONDecodeError, UnicodeError) as exc:
            return fail("Could not reach Cloudflare: {}".format(exc.__class__.__name__))
        if not payload.get("success"):
            message = "API error"
            errors = payload.get("errors") or [{}]
            if errors and isinstance(errors[0], dict):
                message = str(errors[0].get("message") or message)
            return fail(message)
        return ok(data=payload.get("result"))

    def _zones_for(self, profile: dict) -> list:
        cached = DnsManager._zones_cache.get(profile["id"])
        if cached and (time.time() - cached["at"]) < _ZONES_TTL:
            return cached["zones"]
        zones = []
        page = 1
        while page <= 20:
            result = self._request("GET", "/zones?per_page=50&page={}".format(page), self._auth_for(profile))
            if not result["status"]:
                break
            chunk = result.get("data") or []
            for zone in chunk:
                zone_id = str(zone.get("id") or "")
                name = str(zone.get("name") or "")
                if zone_id and name:
                    zones.append({"id": zone_id, "name": name, "status": zone.get("status") or ""})
            if len(chunk) < 50:
                break
            page += 1
        DnsManager._zones_cache[profile["id"]] = {"at": time.time(), "zones": zones}
        return zones

    def list_zones(self, get) -> dict:
        seen = set()
        rows = []
        for profile in self._all_profiles():
            for zone in self._zones_for(profile):
                if zone["id"] in seen:
                    continue
                seen.add(zone["id"])
                rows.append({
                    "id": zone["id"],
                    "name": zone["name"],
                    "status": zone["status"],
                    "profile_id": profile["id"],
                    "profile_name": profile["name"],
                })
        if not rows and not self._all_profiles():
            return fail("Add a Cloudflare API token first.")
        return ok(data=rows)

    def _zone_for_host(self, hostname: str, zone_id: str = ""):
        if zone_id:
            for profile in self._all_profiles():
                for zone in self._zones_for(profile):
                    if zone["id"] == zone_id:
                        return profile, zone["id"], ""
            return None, "", "That zone is not on any saved Cloudflare account."
        best = None
        for profile in self._all_profiles():
            for zone in self._zones_for(profile):
                name = zone["name"]
                if hostname == name or hostname.endswith("." + name) or hostname == "*." + name:
                    if best is None or len(name) > len(best[1]["name"]):
                        best = (profile, zone)
        if not best:
            return None, "", "No Cloudflare zone matches {}.".format(hostname)
        return best[0], best[1]["id"], ""

    def upsert_cname(
        self,
        hostname: str,
        target: str,
        zone_id: str = "",
        proxied: bool = True,
        replace_existing: bool = False,
    ):
        profile, resolved, error = self._zone_for_host(hostname, zone_id)
        if error:
            return False, error
        auth = self._auth_for(profile)
        existing = self._request("GET", "/zones/{}/dns_records?name={}".format(resolved, hostname), auth)
        if not existing["status"]:
            return False, existing["msg"]
        records = existing.get("data") or []
        # Cloudflare proxied CNAMEs at the apex use CNAME flattening, so MX/TXT/NS/CAA
        # can stay on the same name. A/AAAA still conflict until replaced.
        cname_ok_alongside = {"MX", "TXT", "NS", "CAA", "SRV"}
        cname = next((item for item in records if item.get("type") == "CNAME"), None)
        address = [item for item in records if item.get("type") in ("A", "AAAA")]
        others = [
            item for item in records
            if item.get("type") not in ("CNAME", "A", "AAAA") and item.get("type") not in cname_ok_alongside
        ]
        if others:
            kinds = sorted({str(item.get("type") or "?") for item in others})
            return False, "A DNS record already exists for this hostname and is not a CNAME. Remove the {} record(s) for this name in Cloudflare DNS first.".format(", ".join(kinds))
        if address:
            if not replace_existing:
                return False, (
                    "This hostname still has A/AAAA records pointing at a server IP. "
                    "Tick “Replace existing A/AAAA” to point the name at the tunnel, or remove those records in Cloudflare first."
                )
            for item in address:
                deleted = self._request(
                    "DELETE",
                    "/zones/{}/dns_records/{}".format(resolved, item["id"]),
                    auth,
                )
                if not deleted["status"]:
                    return False, "Could not remove the old {} record: {}".format(item.get("type"), deleted["msg"])
        if not proxied and any(item.get("type") in cname_ok_alongside for item in records) and cname is None:
            return False, (
                "A DNS-only CNAME cannot share this hostname with MX/TXT. "
                "Keep the hostname proxied (orange cloud), or use a subdomain such as www."
            )
        body = {"type": "CNAME", "name": hostname, "content": target, "proxied": bool(proxied), "ttl": 1}
        if cname:
            result = self._request("PUT", "/zones/{}/dns_records/{}".format(resolved, cname["id"]), auth, body)
        else:
            result = self._request("POST", "/zones/{}/dns_records".format(resolved), auth, body)
        if not result["status"]:
            return False, result["msg"]
        return True, "DNS updated on {}.".format(profile["name"])

    def delete_cname(self, hostname: str, zone_id: str = ""):
        profile, resolved, error = self._zone_for_host(hostname, zone_id)
        if error:
            return False, error
        auth = self._auth_for(profile)
        existing = self._request("GET", "/zones/{}/dns_records?name={}".format(resolved, hostname), auth)
        if not existing["status"]:
            return False, existing["msg"]
        for record in existing.get("data") or []:
            content = str(record.get("content") or "")
            if record.get("type") == "CNAME" and content.endswith(".cfargotunnel.com"):
                self._request("DELETE", "/zones/{}/dns_records/{}".format(resolved, record["id"]), auth)
        return True, "Tunnel CNAME removed on {}.".format(profile["name"])
