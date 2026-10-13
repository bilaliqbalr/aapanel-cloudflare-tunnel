# Cloudflare Tunnel (aaPanel plugin)

Publish a process listening on `127.0.0.1` / `localhost` through Cloudflare — either a real hostname or a temporary `*.trycloudflare.com` link.

**Author:** Phalcosoft  
**Plugin name:** `cftunnel`  
**Version:** 1.5.2

## Features

- Pinned `cloudflared` install with checksum verification
- Multiple API token profiles (tokens stay on the server; UI shows only a short tail)
- Optional read-only listing of aaPanel’s saved Cloudflare credentials (not copied)
- Create / list / select / delete tunnels via API (Browser login optional)
- Hostname → localhost port ingress (HTTP or HTTPS to origin)
- Apex / subdomain DNS CNAME (proxied); can replace existing A/AAAA; keeps MX/TXT on the root
- Quick tunnel without an API token
- Own systemd unit `cftunnel` (does not take over a generic `cloudflared` service)

Origins are limited to `127.0.0.1` and `localhost` only.

## Requirements

- aaPanel (Linux, amd64 or arm64)
- Root for `/usr/local/bin/cloudflared`, `/etc/cloudflared/cftunnel`, and systemd
- Cloudflare zone on the account that will host the public name

## Install

1. Build the import zip:

   ```bash
   bash pack.sh
   ```

2. In aaPanel: **App Store** → **Third-party apps / Import** → upload `dist/cftunnel.zip`
3. Open **Cloudflare Tunnel**

Install path: `/www/server/panel/plugin/cftunnel/`  
Runtime config / credentials: `/etc/cloudflared/cftunnel/` (removed on uninstall)

## Recommended setup

1. **Install cloudflared** (button hides once installed).
2. Create a **custom API token** in Cloudflare:
   - Account → **Cloudflare Tunnel** → Edit  
   - Zone → **DNS** → Edit  
   - Zone → **Zone** → Read  
   Include your account and zone. Paste it under **Accounts** (Account ID if prompted).
3. Skip Browser login when the account shows **ready for tunnels**.
4. **Named tunnel** → choose account → name → **Create** → **Use**.
5. **Hostname** → public name + local port (leave “HTTPS origin” unchecked for plain HTTP apps).  
   For a root domain that still has A/AAAA, tick **Replace existing A/AAAA**. MX/TXT on the apex can stay.
6. **Service** → **Install and start** until status is active.

### Two different secrets

| Secret | Where | Purpose |
|--------|--------|---------|
| API token | Accounts | Zones, DNS CNAME, create tunnels via API |
| Tunnel install token | Service (optional) | Connector-token mode from Zero Trust → Tunnels |

Browser login / `cert.pem` is optional and often fails on headless servers. Prefer the API token path.

### Quick link

Enter a local port and **Start** for a temporary `*.trycloudflare.com` URL. No API token required. **Stop** when done.

## Uninstall

Use aaPanel’s plugin uninstall, or:

```bash
bash /www/server/panel/plugin/cftunnel/uninstall.sh
```

Removes the plugin, `cftunnel` unit, and `/etc/cloudflared/cftunnel`. Does **not** remove `/usr/local/bin/cloudflared`.

## Develop

| File | Role |
|------|------|
| `cftunnel_main.py` | aaPanel entry (`cftunnel_main`) |
| `cf_common.py` | Paths, validation, safe subprocess helpers |
| `dns_manager.py` | Profiles, zones, CNAME upsert/delete |
| `tunnel_manager.py` | cloudflared install, tunnels, service, quick tunnel |
| `ingress_manager.py` | Hostname rules and config apply |
| `static/js/main.js` | Plugin UI |
| `pack.sh` | Builds `dist/cftunnel.zip` |

```bash
python3 test_cftunnel.py
bash pack.sh
```

## Security notes

- Tokens and credentials are stored with restrictive modes under the plugin `data/` dir and `/etc/cloudflared/cftunnel/`
- UI never returns full API tokens
- Commands use argument lists (no shell)
- DNS upsert will not clobber non-CNAME records except optional A/AAAA replace; tunnel CNAME delete only removes `*.cfargotunnel.com` CNAMEs

## Notes

- Zip contents must sit at the archive root (`info.json` at top level)
- Do not put `PATH=` assignments in `install.sh` (aaPanel rewrites those lines)
- CSRF uses the panel `x-http-token` header (also read from the parent frame when the plugin runs in an iframe)
