#!/usr/bin/python
# coding: utf-8
"""aaPanel entry. Calls go to /plugin?action=a&name=cftunnel&s=<method>."""

import os
import sys

try:
    os.chdir("/www/server/panel")
except OSError:
    pass
if os.path.isdir("class"):
    sys.path.append("class/")

PLUGIN_PATH = os.path.dirname(os.path.abspath(__file__))
if PLUGIN_PATH not in sys.path:
    sys.path.insert(0, PLUGIN_PATH)


def _reload_plugin_modules():
    """Drop cached copies so an upgrade is picked up without restarting the panel."""
    import importlib

    if PLUGIN_PATH in sys.path:
        sys.path.remove(PLUGIN_PATH)
    sys.path.insert(0, PLUGIN_PATH)
    for name in ("cf_common", "dns_manager", "ingress_manager", "tunnel_manager"):
        sys.modules.pop(name, None)
    for name in ("cf_common", "dns_manager", "ingress_manager", "tunnel_manager"):
        importlib.import_module(name)


def _safe(func, get):
    try:
        _reload_plugin_modules()
        return func(get)
    except Exception as exc:
        return {"status": False, "msg": "{}: {}".format(exc.__class__.__name__, exc)}


class cftunnel_main:
    def get_status(self, get):
        def run(get):
            from tunnel_manager import TunnelManager
            return TunnelManager().get_status(get)
        return _safe(run, get)

    def install_cloudflared(self, get):
        def run(get):
            from tunnel_manager import TunnelManager
            return TunnelManager().install_cloudflared(get)
        return _safe(run, get)

    def list_profiles(self, get):
        def run(get):
            import tunnel_manager
            claim = getattr(tunnel_manager, "claim_all_logins", None)
            if claim:
                claim()
            from dns_manager import DnsManager
            return DnsManager().list_profiles(get)
        return _safe(run, get)

    def add_profile(self, get):
        def run(get):
            from dns_manager import DnsManager
            return DnsManager().add_profile(get)
        return _safe(run, get)

    def update_profile_token(self, get):
        def run(get):
            from dns_manager import DnsManager
            return DnsManager().update_profile_token(get)
        return _safe(run, get)

    def delete_profile(self, get):
        def run(get):
            from dns_manager import DnsManager
            return DnsManager().delete_profile(get)
        return _safe(run, get)

    def cf_login_start(self, get):
        def run(get):
            from tunnel_manager import TunnelManager
            return TunnelManager().cf_login_start(get)
        return _safe(run, get)

    def cf_login_status(self, get):
        def run(get):
            from tunnel_manager import TunnelManager
            return TunnelManager().cf_login_status(get)
        return _safe(run, get)

    def save_origin_cert(self, get):
        def run(get):
            from tunnel_manager import TunnelManager
            return TunnelManager().save_origin_cert(get)
        return _safe(run, get)

    def list_zones(self, get):
        def run(get):
            from dns_manager import DnsManager
            return DnsManager().list_zones(get)
        return _safe(run, get)

    def list_tunnels(self, get):
        def run(get):
            from tunnel_manager import TunnelManager
            return TunnelManager().list_tunnels(get)
        return _safe(run, get)

    def create_tunnel(self, get):
        def run(get):
            from tunnel_manager import TunnelManager
            return TunnelManager().create_tunnel(get)
        return _safe(run, get)

    def select_tunnel(self, get):
        def run(get):
            from tunnel_manager import TunnelManager
            return TunnelManager().select_tunnel(get)
        return _safe(run, get)

    def delete_tunnel(self, get):
        def run(get):
            from tunnel_manager import TunnelManager
            return TunnelManager().delete_tunnel(get)
        return _safe(run, get)

    def get_ingress(self, get):
        def run(get):
            from ingress_manager import IngressManager
            return IngressManager().get_ingress(get)
        return _safe(run, get)

    def add_ingress(self, get):
        def run(get):
            from ingress_manager import IngressManager
            return IngressManager().add_ingress(get)
        return _safe(run, get)

    def set_ingress_options(self, get):
        def run(get):
            from ingress_manager import IngressManager
            return IngressManager().set_ingress_options(get)
        return _safe(run, get)

    def remove_ingress(self, get):
        def run(get):
            from ingress_manager import IngressManager
            return IngressManager().remove_ingress(get)
        return _safe(run, get)

    def apply_config(self, get):
        def run(get):
            from ingress_manager import IngressManager
            return IngressManager().apply_config(get)
        return _safe(run, get)

    def set_tunnel_token(self, get):
        def run(get):
            from tunnel_manager import TunnelManager
            return TunnelManager().set_tunnel_token(get)
        return _safe(run, get)

    def service_action(self, get):
        def run(get):
            from tunnel_manager import TunnelManager
            return TunnelManager().service_action(get)
        return _safe(run, get)

    def get_log(self, get):
        def run(get):
            from tunnel_manager import TunnelManager
            return TunnelManager().get_log(get)
        return _safe(run, get)

    def quick_start(self, get):
        def run(get):
            from tunnel_manager import TunnelManager
            return TunnelManager().quick_start(get)
        return _safe(run, get)

    def quick_status(self, get):
        def run(get):
            from tunnel_manager import TunnelManager
            return TunnelManager().quick_status(get)
        return _safe(run, get)

    def quick_stop(self, get):
        def run(get):
            from tunnel_manager import TunnelManager
            return TunnelManager().quick_stop(get)
        return _safe(run, get)
