#!/bin/bash
# aaPanel runs this after copying the zip into /www/server/panel/plugin/cftunnel/.
# Do not set the process search path in this file. aaPanel rewrites that
# assignment and the install then fails.
set -eu
install_tmp="/tmp/bt_install.pl"
PLUGIN_DIR="/www/server/panel/plugin/cftunnel"

install_cftunnel() {
    mkdir -p "${PLUGIN_DIR}/data" /etc/cloudflared/cftunnel
    chmod 700 "${PLUGIN_DIR}/data" /etc/cloudflared/cftunnel
    rm -rf "${PLUGIN_DIR}/__pycache__"
    find "${PLUGIN_DIR}" -name '*.pyc' -delete
    chmod 755 "${PLUGIN_DIR}" "${PLUGIN_DIR}/static" "${PLUGIN_DIR}/static/js" "${PLUGIN_DIR}/install.sh" "${PLUGIN_DIR}/uninstall.sh"
    chmod 644 "${PLUGIN_DIR}/"*.py "${PLUGIN_DIR}/"*.json "${PLUGIN_DIR}/"*.html "${PLUGIN_DIR}/icon.png" "${PLUGIN_DIR}/static/js/"*.js
    echo "Cloudflare Tunnel installed. Open the plugin, install cloudflared, then add an account." > "${install_tmp}"
}

uninstall_cftunnel() {
    systemctl disable --now cftunnel >/dev/null 2>&1 || true
    systemctl stop cftunnel-quick cftunnel-login >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/cftunnel.service
    systemctl daemon-reload >/dev/null 2>&1 || true
    rm -rf /etc/cloudflared/cftunnel "${PLUGIN_DIR}"
    echo "Cloudflare Tunnel removed, including its credentials." > "${install_tmp}"
}

if [ "${1:-}" = "install" ]; then
    install_cftunnel
else
    uninstall_cftunnel
fi
