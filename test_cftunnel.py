"""Checks that stay local: origins, hostnames, tokens, and YAML."""

import json
import os
import tempfile
import unittest
from unittest import mock

import base64

from cf_common import check_hostname, local_service, parse_tunnel_token, redact
from ingress_manager import coerce_origin_request


class LocalOriginTest(unittest.TestCase):
    def test_accepts_localhost_ports(self):
        self.assertEqual(local_service("http://127.0.0.1:8080"), "http://127.0.0.1:8080")
        self.assertEqual(local_service("https://localhost:443"), "https://localhost:443")

    def test_rejects_other_targets(self):
        for raw in (
            "http://10.0.0.5:80",
            "http://example.com:80",
            "tcp://127.0.0.1:22",
            "http://127.0.0.1:80/admin",
            "http://user:pass@127.0.0.1:80",
            "http://127.0.0.1",
            "hello_world",
        ):
            with self.assertRaises(ValueError):
                local_service(raw)

    def test_hostname_rules(self):
        self.assertEqual(check_hostname("App.Example.com"), "app.example.com")
        self.assertEqual(check_hostname("*.example.com"), "*.example.com")
        for raw in ("localhost", "app", "bad host.com", "a..com"):
            with self.assertRaises(ValueError):
                check_hostname(raw)

    def test_origin_options_drop_unknown_keys(self):
        cleaned = coerce_origin_request({
            "noTLSVerify": True,
            "connectTimeout": "30s",
            "httpHostHeader": "app.example.com",
            "caPool": "/etc/passwd",
            "proxyAddress": "1.2.3.4",
        })
        self.assertEqual(cleaned["connectTimeout"], "30s")
        self.assertNotIn("caPool", cleaned)
        self.assertNotIn("proxyAddress", cleaned)

    def test_tunnel_token_requires_account_tunnel_and_secret(self):
        account = "0123456789abcdef0123456789abcdef"
        tunnel = "11111111-2222-3333-4444-555555555555"
        token = base64.b64encode(json.dumps({
            "a": account, "t": tunnel, "s": "c2VjcmV0c2VjcmV0c2VjcmV0",
        }, separators=(",", ":")).encode()).decode()
        parsed = parse_tunnel_token(token, account)
        self.assertEqual(parsed["tunnel_id"], tunnel)
        with self.assertRaises(ValueError):
            parse_tunnel_token("a" * 40, account)
        with self.assertRaises(ValueError):
            parse_tunnel_token(token, "ffffffffffffffffffffffffffffffff")

    def test_redact_strips_bearer_tokens(self):
        sample = "Authorization Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        self.assertNotIn("eyJhbGci", redact(sample))


class ProfileStoreTest(unittest.TestCase):
    def test_account_token_is_accepted_when_zone_list_works(self):
        import dns_manager

        manager = dns_manager.DnsManager()
        calls = []

        def fake_request(self, method, path, auth, body=None):
            calls.append(path)
            if path == "/user/tokens/verify":
                return {"status": False, "msg": "Invalid API Token"}
            if path.startswith("/zones"):
                return {"status": True, "msg": "ok", "data": []}
            return {"status": False, "msg": "unexpected"}

        with mock.patch.object(dns_manager.DnsManager, "_request", fake_request):
            self.assertEqual(manager._verify_token("a" * 40), "")
        self.assertIn("/zones?per_page=1", calls)

    def test_tunnel_install_token_is_not_an_api_token(self):
        import dns_manager

        account = "0123456789abcdef0123456789abcdef"
        tunnel = "11111111-2222-3333-4444-555555555555"
        token = base64.b64encode(json.dumps({
            "a": account, "t": tunnel, "s": "c2VjcmV0c2VjcmV0c2VjcmV0",
        }, separators=(",", ":")).encode()).decode()
        message = dns_manager.DnsManager()._verify_token(token)
        self.assertIn("Service card", message)

    def test_login_cert_outside_the_profile_dir_is_claimed(self):
        import tunnel_manager

        with tempfile.TemporaryDirectory() as tmp:
            source = os.path.join(tmp, "cert.pem")
            with open(source, "w", encoding="utf-8") as handle:
                handle.write("-----BEGIN ARGO TUNNEL TOKEN-----\nYQ==\n-----END ARGO TUNNEL TOKEN-----\n")
            cert_dir = os.path.join(tmp, "certs")
            with mock.patch.object(tunnel_manager, "CERT_DIR", cert_dir), \
                    mock.patch.object(tunnel_manager, "_origin_cert_candidates", lambda profile_id: [source]), \
                    mock.patch.object(tunnel_manager, "_allowed_cert", lambda path: True), \
                    mock.patch.object(tunnel_manager, "run", return_value=(True, "")), \
                    mock.patch("dns_manager.DnsManager.set_profile_cert", return_value=True):
                self.assertTrue(tunnel_manager._claim_origin_cert("work_abc123"))
            saved = os.path.join(cert_dir, "work_abc123.pem")
            self.assertTrue(os.path.isfile(saved))
            with open(saved, encoding="utf-8") as handle:
                self.assertIn("ARGO TUNNEL TOKEN", handle.read())

    def test_reloaded_tunnel_manager_exports_login_claim(self):
        import cftunnel_main

        cftunnel_main._reload_plugin_modules()
        import tunnel_manager
        self.assertTrue(callable(tunnel_manager.claim_all_logins))
        self.assertEqual(tunnel_manager.PLUGIN_VERSION, "1.6")

    def test_api_tunnel_create_writes_credentials(self):
        import tunnel_manager

        with tempfile.TemporaryDirectory() as tmp:
            cred_dir = os.path.join(tmp, "creds")
            os.makedirs(cred_dir)
            profile = {
                "id": "work_abc123",
                "name": "Work",
                "token": "a" * 40,
                "account_id": "0123456789abcdef0123456789abcdef",
                "cert_path": "",
                "virtual": False,
            }
            tunnel_id = "11111111-2222-3333-4444-555555555555"

            def fake_request(self, method, path, auth, body=None):
                if method == "GET" and path.endswith("/token"):
                    return {"status": True, "msg": "ok", "data": "eyJ" + "a" * 80}
                assert method == "POST"
                return {"status": True, "msg": "ok", "data": {
                    "id": tunnel_id,
                    "name": "demo",
                    "credentials_file": {
                        "AccountTag": profile["account_id"],
                        "TunnelID": tunnel_id,
                        "TunnelSecret": body["tunnel_secret"],
                    },
                }}

            with mock.patch.object(tunnel_manager, "CRED_DIR", cred_dir), \
                    mock.patch.object(tunnel_manager, "DATA_DIR", tmp), \
                    mock.patch.object(tunnel_manager, "TOKEN_ENV", os.path.join(tmp, "tunnel.env")), \
                    mock.patch.object(tunnel_manager, "ensure_dirs", return_value=""), \
                    mock.patch("dns_manager.DnsManager.find_profile", return_value=profile), \
                    mock.patch("dns_manager.DnsManager._request", fake_request), \
                    mock.patch.object(tunnel_manager, "_claim_origin_cert", return_value=False), \
                    mock.patch.object(tunnel_manager, "_save_state"):
                result = tunnel_manager.TunnelManager().create_tunnel(type("G", (), {
                    "tunnel_name": "demo",
                    "profile_id": "work_abc123",
                })())
            self.assertTrue(result["status"], result)
            cred = os.path.join(cred_dir, tunnel_id + ".json")
            self.assertTrue(os.path.isfile(cred))
            with open(cred, encoding="utf-8") as handle:
                payload = json.load(handle)
            self.assertEqual(payload["TunnelID"], tunnel_id)

    def test_apex_dns_replace_removes_a_records(self):
        import dns_manager

        calls = []

        def fake_request(self, method, path, auth, body=None):
            calls.append((method, path, body))
            if method == "GET" and "dns_records" in path:
                return {"status": True, "msg": "ok", "data": [
                    {"id": "rec1", "type": "A", "name": "example.com", "content": "1.2.3.4"},
                ]}
            if method == "DELETE":
                return {"status": True, "msg": "ok", "data": {}}
            if method == "POST":
                return {"status": True, "msg": "ok", "data": {"id": "cname1"}}
            return {"status": False, "msg": "unexpected"}

        with mock.patch.object(dns_manager.DnsManager, "_zone_for_host", return_value=({"id": "p", "name": "Work"}, "zone1", "")), \
                mock.patch.object(dns_manager.DnsManager, "_auth_for", return_value={"Authorization": "Bearer x"}), \
                mock.patch.object(dns_manager.DnsManager, "_request", fake_request):
            good, message = dns_manager.DnsManager().upsert_cname(
                "example.com",
                "11111111-2222-3333-4444-555555555555.cfargotunnel.com",
                replace_existing=True,
            )
        self.assertTrue(good, message)
        self.assertTrue(any(item[0] == "DELETE" for item in calls))
        self.assertTrue(any(item[0] == "POST" for item in calls))

    def test_apex_mx_txt_allowed_with_proxied_cname(self):
        import dns_manager

        calls = []

        def fake_request(self, method, path, auth, body=None):
            calls.append((method, path, body))
            if method == "GET" and "dns_records" in path:
                return {"status": True, "msg": "ok", "data": [
                    {"id": "mx1", "type": "MX", "name": "example.com", "content": "mail"},
                    {"id": "txt1", "type": "TXT", "name": "example.com", "content": "v=spf1"},
                ]}
            if method == "POST":
                return {"status": True, "msg": "ok", "data": {"id": "cname1"}}
            return {"status": False, "msg": "unexpected"}

        with mock.patch.object(dns_manager.DnsManager, "_zone_for_host", return_value=({"id": "p", "name": "Work"}, "zone1", "")), \
                mock.patch.object(dns_manager.DnsManager, "_auth_for", return_value={"Authorization": "Bearer x"}), \
                mock.patch.object(dns_manager.DnsManager, "_request", fake_request):
            good, message = dns_manager.DnsManager().upsert_cname(
                "example.com",
                "11111111-2222-3333-4444-555555555555.cfargotunnel.com",
                proxied=True,
            )
        self.assertTrue(good, message)
        self.assertFalse(any(item[0] == "DELETE" for item in calls))
        self.assertTrue(any(item[0] == "POST" for item in calls))

    def test_stored_profile_without_token_is_findable(self):
        import dns_manager

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "api_profiles.json")
            with mock.patch.object(dns_manager, "PROFILES_FILE", path):
                with open(path, "w", encoding="utf-8") as handle:
                    json.dump([{"id": "work_abc123", "name": "Work", "token": "", "cert_path": ""}], handle)
                found = dns_manager.DnsManager().find_profile("work_abc123")
            self.assertIsNotNone(found)
            self.assertEqual(found["id"], "work_abc123")

    def test_pasted_origin_cert_is_saved(self):
        import tunnel_manager

        pem = "-----BEGIN ARGO TUNNEL TOKEN-----\nYQ==\n-----END ARGO TUNNEL TOKEN-----\n"
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(tunnel_manager, "CERT_DIR", tmp), \
                    mock.patch.object(tunnel_manager.TunnelManager, "_profile_cert", return_value=({"id": "work_abc123"}, "")), \
                    mock.patch.object(tunnel_manager, "run", return_value=(True, "")), \
                    mock.patch("dns_manager.DnsManager.set_profile_cert", return_value=True):
                saved = tunnel_manager.TunnelManager().save_origin_cert(type("G", (), {
                    "profile_id": "work_abc123",
                    "origin_cert": pem,
                })())
            self.assertTrue(saved["status"])
            with open(os.path.join(tmp, "work_abc123.pem"), encoding="utf-8") as handle:
                self.assertIn("ARGO TUNNEL TOKEN", handle.read())
        rejected = tunnel_manager.TunnelManager().save_origin_cert(type("G", (), {
            "profile_id": "work_abc123",
            "origin_cert": "not a certificate",
        })())
        self.assertFalse(rejected["status"])

    def test_saved_token_is_not_returned(self):
        import dns_manager

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "api_profiles.json")
            with mock.patch.object(dns_manager, "PROFILES_FILE", path):
                with open(path, "w", encoding="utf-8") as handle:
                    json.dump([{"id": "work_abc123", "name": "Work", "token": "x" * 40, "cert_path": ""}], handle)
                rows = dns_manager.DnsManager().list_profiles(object())["data"]
            self.assertEqual(rows[0]["tail"], "xxxx")
            self.assertNotIn("token", rows[0])
            blob = json.dumps(rows)
            self.assertNotIn("x" * 20, blob)


if __name__ == "__main__":
    unittest.main()
