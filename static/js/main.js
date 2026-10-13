(function (global) {
  if (global.__cftunnelBoot) return;
  global.__cftunnelBoot = true;

  function token() {
    var docs = [document];
    try {
      if (window.parent && window.parent.document) docs.push(window.parent.document);
    } catch (err) {}
    for (var i = 0; i < docs.length; i++) {
      var el = docs[i].getElementById("request_token_head");
      if (el && el.getAttribute("token")) return el.getAttribute("token");
    }
    return "";
  }

  function textFromHtml(html) {
    var title = /<h4[^>]*>([\s\S]*?)<\/h4>/i.exec(html || "");
    var raw = title ? title[1] : html;
    return String(raw || "").replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();
  }

  function post(method, data) {
    var body = new URLSearchParams();
    Object.keys(data || {}).forEach(function (key) {
      if (data[key] === undefined || data[key] === null) return;
      body.append(key, String(data[key]));
    });
    return fetch("/plugin?action=a&name=cftunnel&s=" + encodeURIComponent(method), {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "x-http-token": token(),
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
      },
      body: body.toString(),
    }).then(function (response) {
      return response.text();
    }).then(function (text) {
      var trimmed = String(text || "").replace(/^\uFEFF/, "").trim();
      if (trimmed.charAt(0) === "{" || trimmed.charAt(0) === "[") {
        try { return JSON.parse(trimmed); } catch (err) {}
      }
      return { status: false, msg: textFromHtml(trimmed).slice(0, 500) || "The panel returned an error." };
    });
  }

  function esc(value) {
    return String(value == null ? "" : value)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }

  function enlargeHostDialog() {
    try {
      var frame = window.frameElement;
      if (!frame) return;
      var layer = frame.closest ? frame.closest(".layui-layer") : null;
      if (!layer && frame.parentElement) {
        var node = frame.parentElement;
        while (node && node !== document.documentElement) {
          if (node.classList && node.classList.contains("layui-layer")) {
            layer = node;
            break;
          }
          node = node.parentElement;
        }
      }
      if (!layer) return;
      var width = Math.min(980, Math.floor((window.parent.innerWidth || 1200) * 0.94));
      var height = Math.min(860, Math.floor((window.parent.innerHeight || 800) * 0.9));
      layer.style.width = width + "px";
      layer.style.height = height + "px";
      layer.style.maxWidth = "980px";
      layer.style.maxHeight = "90vh";
      layer.style.top = Math.max(16, Math.floor(((window.parent.innerHeight || height) - height) / 2)) + "px";
      layer.style.left = Math.max(16, Math.floor(((window.parent.innerWidth || width) - width) / 2)) + "px";
      layer.style.margin = "0";
      frame.style.width = "100%";
      frame.style.height = Math.max(320, height - 48) + "px";
      var content = layer.querySelector(".layui-layer-content");
      if (content) {
        content.style.height = Math.max(320, height - 48) + "px";
        content.style.overflow = "hidden";
      }
    } catch (err) {}
  }

  function ensureStyle() {
    if (document.getElementById("cftunnel-style")) return;
    var style = document.createElement("style");
    style.id = "cftunnel-style";
    var light = [
      "#cftunnel-app,#cftunnel-app *{box-sizing:border-box}",
      "html,body{margin:0;height:100%;overflow:hidden;background:transparent}",
      "#cftunnel-app{font:13px/1.45 -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#333;padding:12px 16px 16px;max-width:980px;height:100%;max-height:100%;overflow:auto;-webkit-overflow-scrolling:touch}",
      ".cf-card{border:1px solid #e6e6e6;border-radius:8px;padding:0;margin-bottom:12px;background:#fff;overflow:hidden}",
      ".cf-head{display:flex;align-items:center;justify-content:space-between;gap:10px;width:100%;margin:0;padding:12px 14px;border:0;background:transparent;cursor:pointer;text-align:left;color:inherit}",
      ".cf-head h3{margin:0;font-size:15px}",
      ".cf-chevron{flex:0 0 auto;color:#888;font-size:12px;transition:transform .15s ease}",
      ".cf-card.is-collapsed .cf-chevron{transform:rotate(-90deg)}",
      ".cf-body{padding:0 14px 10px}",
      ".cf-card.is-collapsed .cf-body{display:none}",
      ".cf-row{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:10px}",
      ".cf-row input,.cf-row select{height:34px;border:1px solid #ddd;border-radius:4px;padding:0 8px;background:#fff;color:#222}",
      ".cf-grow{flex:1 1 200px;min-width:160px}",
      ".cf-port{flex:0 0 88px;width:88px}",
      ".cf-select{flex:1 1 220px;min-width:180px;max-width:100%}",
      ".cf-check{display:inline-flex;align-items:center;gap:6px;height:34px;white-space:nowrap}",
      ".cf-options{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:8px;margin-bottom:10px}",
      ".cf-options input{height:34px;width:100%;border:1px solid #ddd;border-radius:4px;padding:0 8px;background:#fff;color:#222}",
      ".cf-btn{height:34px;padding:0 12px;border:0;border-radius:4px;background:#20a53a;color:#fff;cursor:pointer;flex:0 0 auto}",
      ".cf-btn.alt{background:#fff;color:#333;border:1px solid #ddd}",
      ".cf-btn.stop{background:#d9534f}",
      ".cf-note,.cf-empty{color:#777;margin:0 0 8px}",
      ".cf-item{display:flex;justify-content:space-between;gap:12px;align-items:center;padding:8px 0;border-bottom:1px solid #f0f0f0}",
      ".cf-item:last-child{border-bottom:0}",
      ".cf-actions{display:flex;gap:8px;flex:0 0 auto}",
      ".cf-cert{width:100%;min-height:88px;margin:0 0 8px;padding:8px;border:1px solid #ddd;border-radius:4px;background:#fff;color:#222;font:12px/1.4 ui-monospace,Menlo,monospace;resize:vertical}",
      ".cf-log{background:#1e1e1e;color:#e8e8e8;padding:12px;min-height:160px;max-height:280px;overflow:auto;white-space:pre-wrap;word-break:break-word;font:12px/1.45 ui-monospace,Menlo,monospace;border-radius:4px;margin:0 0 8px}",
      ".cf-warn{background:#fff6e8;border:1px solid #f0d7a6;color:#8a5a00;padding:8px 10px;border-radius:4px;margin-bottom:8px;word-break:break-word}",
      ".cf-msg{display:none;margin:0 0 10px;padding:8px 10px;border-radius:4px;border:1px solid #cfe8d4;background:#f3fbf5;color:#1f6b34;word-break:break-word}",
      ".cf-msg.err{border-color:#f0c2c0;background:#fff5f5;color:#a33}",
      ".cf-steps{margin:0 0 8px;padding-left:18px}",
      ".cf-steps li{margin:0 0 4px}",
      ".cf-hidden{display:none !important}",
    ];
    var darkSel = "html.dark #cftunnel-app,html[theme-mode=\"dark\"] #cftunnel-app";
    var dark = [
      darkSel + "{color:#e8e8e8}",
      darkSel + " .cf-card{background:#1e1e22;border-color:#3a3a42;color:#e8e8e8}",
      darkSel + " .cf-row input," + darkSel + " .cf-row select," + darkSel + " .cf-options input," + darkSel + " .cf-cert{background:#2a2a30;color:#f3f3f3;border-color:#4a4a52}",
      darkSel + " .cf-btn.alt{background:#2a2a30;color:#f3f3f3;border-color:#4a4a52}",
      darkSel + " .cf-note," + darkSel + " .cf-empty{color:#b5b5b5}",
      darkSel + " .cf-chevron{color:#aaa}",
      darkSel + " .cf-item{border-color:#3a3a42}",
      darkSel + " .cf-warn{background:#3a2e14;border-color:#6b5424;color:#f3d7a1}",
      darkSel + " .cf-msg{background:#1e2a22;border-color:#3a5a42;color:#bde5c8}",
      darkSel + " .cf-msg.err{background:#2a1e1e;border-color:#6a3a3a;color:#f0b0b0}",
    ];
    style.textContent = light.concat(dark).join("");
    document.head.appendChild(style);
  }

  function section(id, title, bodyHtml, collapsed) {
    return [
      '<div class="cf-card' + (collapsed ? " is-collapsed" : "") + '" data-card="' + id + '" data-section="' + id + '">',
      '<button type="button" class="cf-head" data-toggle aria-expanded="' + (collapsed ? "false" : "true") + '">',
      "<h3>" + title + "</h3><span class=\"cf-chevron\" aria-hidden=\"true\">▾</span></button>",
      '<div class="cf-body">' + bodyHtml + "</div></div>",
    ].join("");
  }

  function bindSections(root) {
    var key = "cftunnel-sections";
    var saved = {};
    try { saved = JSON.parse(localStorage.getItem(key) || "{}") || {}; } catch (err) { saved = {}; }
    root.querySelectorAll("[data-section]").forEach(function (card) {
      var id = card.getAttribute("data-section");
      if (Object.prototype.hasOwnProperty.call(saved, id)) {
        card.classList.toggle("is-collapsed", !!saved[id]);
        var head = card.querySelector("[data-toggle]");
        if (head) head.setAttribute("aria-expanded", saved[id] ? "false" : "true");
      }
      var toggle = card.querySelector("[data-toggle]");
      if (!toggle) return;
      toggle.onclick = function () {
        var next = !card.classList.contains("is-collapsed");
        card.classList.toggle("is-collapsed", next);
        toggle.setAttribute("aria-expanded", next ? "false" : "true");
        try {
          saved[id] = next;
          localStorage.setItem(key, JSON.stringify(saved));
        } catch (err) {}
      };
    });
  }

  function serviceUrl(port, https) {
    return (https ? "https" : "http") + "://127.0.0.1:" + String(port || "").trim();
  }

  function originJson(card) {
    var body = {};
    card.querySelectorAll("[data-origin]").forEach(function (input) {
      var key = input.getAttribute("data-origin");
      if (input.type === "checkbox") {
        if (input.checked) body[key] = true;
        return;
      }
      if (input.value.trim()) body[key] = input.value.trim();
    });
    return JSON.stringify(body);
  }

  function mount(root) {
    if (!root || root.getAttribute("data-ready") === "1") return;
    ensureStyle();
    enlargeHostDialog();
    setTimeout(enlargeHostDialog, 50);
    setTimeout(enlargeHostDialog, 300);
    root.setAttribute("data-ready", "1");
    root.innerHTML = [
      section("steps", "Steps", [
        '<ol class="cf-steps">',
        '<li>Install cloudflared once (button hides after install).</li>',
        '<li>Create a custom API token: My Profile → API Tokens → Create Token → Custom token. Permissions: <b>Account → Cloudflare Tunnel → Edit</b>, <b>Zone → DNS → Edit</b>, <b>Zone → Zone → Read</b>. Include your account and zone. Paste the secret under Accounts. If asked, paste the Account ID from the Cloudflare dashboard overview.</li>',
        '<li>Skip Browser login. Choose the account under Named tunnel, enter a name, click <b>Create</b>, then <b>Use</b>.</li>',
        '<li>Hostname: public name (<code>abc.com</code> or <code>www.abc.com</code>), port (1234), leave HTTPS unchecked for plain HTTP. For the root domain, tick <b>Replace existing A/AAAA</b> if Cloudflare still has an A record, then click <b>Add</b>.</li>',
        '<li>Service → <b>Install and start</b> until status is active.</li>',
        '</ol>',
        '<p class="cf-note">Browser login is optional and often fails on servers. Prefer the API token with Cloudflare Tunnel Edit. The Authorize alert does not download cert.pem.</p>',
      ].join(""), true),
      section("cloudflared", "cloudflared", [
        '<p class="cf-note" data-status>Checking…</p>',
        '<p class="cf-msg" data-msg="cloudflared"></p>',
        '<button class="cf-btn" type="button" data-install>Install pinned cloudflared</button>',
      ].join(""), false),
      section("accounts", "Accounts", [
        '<p class="cf-note">Custom API token needs Cloudflare Tunnel Edit + DNS Edit. aaPanel’s saved token is listed read-only and cannot create tunnels here.</p>',
        '<p class="cf-msg" data-msg="accounts"></p>',
        '<div class="cf-row"><input class="cf-grow" data-profile placeholder="Account name"><input class="cf-grow" data-token type="password" placeholder="API token" autocomplete="off">',
        '<input class="cf-grow" data-cf-account placeholder="Account ID, for an account token" autocomplete="off">',
        '<button class="cf-btn" type="button" data-add-profile>Add account</button></div><div data-profiles></div>',
      ].join(""), false),
      section("tunnel", "Named tunnel", [
        '<p class="cf-msg" data-msg="tunnel"></p>',
        '<div class="cf-row"><select class="cf-select" data-tunnel-profile></select><input class="cf-grow" data-tunnel-name placeholder="Tunnel name">',
        '<button class="cf-btn" type="button" data-create-tunnel>Create</button>',
        '<button class="cf-btn alt" type="button" data-reload-tunnels>Refresh</button></div>',
        '<p class="cf-note">Only use this box if Browser login never becomes “saved” and your browser actually downloaded a cert.pem file. Choose the same account in the dropdown first.</p>',
        '<textarea class="cf-cert" data-origin-cert spellcheck="false" placeholder="-----BEGIN ARGO TUNNEL TOKEN-----"></textarea>',
        '<button class="cf-btn alt" type="button" data-save-cert>Save certificate</button><div data-tunnels></div>',
      ].join(""), false),
      section("hostname", "Hostname", [
        '<p class="cf-note">Public name → 127.0.0.1 on this machine. Click Use on a tunnel first. Root domains usually need Replace existing A/AAAA.</p>',
        '<p class="cf-msg" data-msg="hostname"></p>',
        '<div class="cf-row"><input class="cf-grow" data-host placeholder="app.example.com or example.com"><input class="cf-port" data-port placeholder="Port" inputmode="numeric">',
        '<label class="cf-check"><input type="checkbox" data-https> HTTPS origin</label>',
        '<label class="cf-check"><input type="checkbox" data-replace-dns> Replace existing A/AAAA</label>',
        '<button class="cf-btn" type="button" data-add-host>Add</button></div>',
        '<div class="cf-row"><select class="cf-select" data-zone><option value="">Match the zone from the hostname</option></select></div>',
        '<div class="cf-options">',
        '<label class="cf-check"><input type="checkbox" data-origin="noTLSVerify"> Skip origin certificate check</label>',
        '<label class="cf-check"><input type="checkbox" data-origin="http2Origin"> HTTP/2 to origin</label>',
        '<input data-origin="httpHostHeader" placeholder="Host header">',
        '<input data-origin="originServerName" placeholder="SNI name">',
        '<input data-origin="connectTimeout" placeholder="Connect timeout, 30s">',
        '<input data-origin="tlsTimeout" placeholder="TLS timeout, 10s"></div>',
        '<div data-hosts></div>',
      ].join(""), false),
      section("quick", "Quick link", [
        '<p class="cf-note">Temporary *.trycloudflare.com. No API token. Stays up until you stop it.</p>',
        '<p class="cf-msg" data-msg="quick"></p>',
        '<div class="cf-row"><input class="cf-port" data-quick-port placeholder="Port" inputmode="numeric">',
        '<button class="cf-btn" type="button" data-quick-start>Start</button>',
        '<button class="cf-btn stop" type="button" data-quick-stop>Stop</button></div>',
        '<p data-quick></p>',
      ].join(""), true),
      section("service", "Service", [
        '<p class="cf-note">After Hostname is added, click Install and start. Optional: paste a Zero Trust install token for connector-token mode.</p>',
        '<p class="cf-msg" data-msg="service"></p>',
        '<div class="cf-row"><input class="cf-grow" data-account-id placeholder="Account ID, optional" autocomplete="off">',
        '<input class="cf-grow" data-tunnel-token type="password" placeholder="Tunnel install token, optional" autocomplete="off">',
        '<button class="cf-btn" type="button" data-save-token>Save and start</button></div>',
        '<div class="cf-row"><button class="cf-btn" type="button" data-svc="install">Install and start</button>',
        '<button class="cf-btn alt" type="button" data-svc="restart">Restart</button>',
        '<button class="cf-btn stop" type="button" data-svc="stop">Stop</button>',
        '<button class="cf-btn alt" type="button" data-svc="start">Start</button>',
        '<button class="cf-btn alt" type="button" data-log-btn>Refresh log</button></div>',
        '<pre class="cf-log" data-log-out></pre>',
      ].join(""), false),
    ].join("");
    bindSections(root);

    function say(section, message, isError) {
      root.querySelectorAll("[data-msg]").forEach(function (node) {
        if (node.getAttribute("data-msg") !== section) {
          node.style.display = "none";
          node.textContent = "";
          node.classList.remove("err");
        }
      });
      var node = root.querySelector('[data-msg="' + section + '"]');
      if (!node) return;
      node.textContent = message || "";
      node.classList.toggle("err", !!isError);
      node.style.display = message ? "block" : "none";
    }

    function load() {
      post("get_status", {}).then(function (data) {
        var row = (data && data.data) || {};
        var line = "plugin " + (row.plugin_version || "1.6") + " · ";
        line += row.installed
          ? ("cloudflared " + (row.version || "installed") + " · service " + (row.service_active || "unknown")
            + (row.connector === "token" ? " · using tunnel token" : "")
            + (row.active_tunnel_name ? " · tunnel " + row.active_tunnel_name : ""))
          : "cloudflared is not installed. Use the install button below.";
        if (!data.status && data.msg) line = data.msg;
        if (row.dir_error) line += " Directory setup failed: " + row.dir_error;
        root.querySelector("[data-status]").textContent = line;
        root.querySelector("[data-install]").classList.toggle("cf-hidden", !!row.installed);
        if (row.service_hint) say("service", row.service_hint, true);
      }).catch(function (err) { say("cloudflared", String(err), true); });
      post("list_profiles", {}).then(function (data) {
        var host = root.querySelector("[data-profiles]");
        var select = root.querySelector("[data-tunnel-profile]");
        var previous = select.value;
        host.innerHTML = "";
        select.innerHTML = '<option value="">Choose an account</option>';
        var profiles = (data && data.data) || [];
        if (!data.status && data.msg) host.innerHTML = '<p class="cf-warn">' + esc(data.msg) + "</p>";
        else if (!profiles.length) host.innerHTML = '<p class="cf-empty">No accounts yet.</p>';
        profiles.forEach(function (profile) {
          var line = document.createElement("div");
          line.className = "cf-item";
          var label = profile.name + (profile.virtual ? " (from aaPanel, DNS only)" : "")
            + (profile.has_token ? " · token …" + (profile.tail || "") : " · no API token")
            + (profile.api_ready ? " · ready for tunnels" : "")
            + (profile.logged_in ? " · browser cert saved" : "");
          line.innerHTML = "<div>" + esc(label) + "</div>";
          if (!profile.virtual) {
            var login = document.createElement("button");
            login.className = "cf-btn alt";
            login.type = "button";
            login.textContent = profile.logged_in ? "Re-login" : "Browser login (optional)";
            login.onclick = function () { startLogin(profile.id); };
            var remove = document.createElement("button");
            remove.className = "cf-btn stop";
            remove.type = "button";
            remove.textContent = "Remove";
            remove.onclick = function () {
              post("delete_profile", { profile_id: profile.id }).then(load);
            };
            var actions = document.createElement("div");
            actions.className = "cf-actions";
            actions.appendChild(login);
            actions.appendChild(remove);
            line.appendChild(actions);
            var option = document.createElement("option");
            option.value = profile.id;
            option.textContent = profile.name + (profile.can_create_tunnels ? " (ready)" : " (needs Tunnel Edit token)");
            select.appendChild(option);
          }
          host.appendChild(line);
        });
        if (previous) select.value = previous;
      }).catch(function () {});
      post("list_zones", {}).then(function (data) {
        var select = root.querySelector("[data-zone]");
        var current = select.value;
        select.innerHTML = "";
        var blank = document.createElement("option");
        blank.value = "";
        blank.textContent = (!data.status && data.msg) ? data.msg : "Match the zone from the hostname";
        select.appendChild(blank);
        ((data && data.data) || []).forEach(function (zone) {
          var option = document.createElement("option");
          option.value = zone.id;
          option.textContent = zone.name + " (" + zone.profile_name + ")";
          select.appendChild(option);
        });
        select.value = current;
      }).catch(function () {});
      post("list_tunnels", {}).then(function (data) {
        var host = root.querySelector("[data-tunnels]");
        host.innerHTML = "";
        if (!data.status) {
          host.innerHTML = '<p class="cf-empty">' + esc(data.msg || "") + "</p>";
          if (data.msg) say("tunnel", data.msg, true);
          return;
        }
        if (!(data.data || []).length) host.innerHTML = '<p class="cf-empty">No tunnels yet. Enter a name and click Create.</p>';
        (data.data || []).forEach(function (tunnel) {
          var line = document.createElement("div");
          line.className = "cf-item";
          line.innerHTML = "<div>" + esc(tunnel.name + " · " + tunnel.profile_name + " · " + tunnel.connections + " connections") + "</div>";
          var use = document.createElement("button");
          use.className = "cf-btn";
          use.type = "button";
          use.textContent = "Use";
          use.onclick = function () {
            post("select_tunnel", { tunnel_id: tunnel.id, tunnel_name: tunnel.name, profile_id: tunnel.profile_id }).then(function (res) {
              say("tunnel", res.msg || "", !res.status);
              load();
            });
          };
          var remove = document.createElement("button");
          remove.className = "cf-btn stop";
          remove.type = "button";
          remove.textContent = "Delete";
          remove.onclick = function () {
            if (!window.confirm("Delete tunnel " + tunnel.name + "?")) return;
            post("delete_tunnel", { tunnel_id: tunnel.id, profile_id: tunnel.profile_id }).then(load);
          };
          var actions = document.createElement("div");
          actions.className = "cf-actions";
          actions.appendChild(use);
          actions.appendChild(remove);
          line.appendChild(actions);
          host.appendChild(line);
        });
      }).catch(function () {});
      post("get_ingress", {}).then(function (data) {
        var host = root.querySelector("[data-hosts]");
        host.innerHTML = "";
        var items = (data && data.data) || [];
        if (!items.length) host.innerHTML = '<p class="cf-empty">No hostnames yet.</p>';
        items.forEach(function (item) {
          var line = document.createElement("div");
          line.className = "cf-item";
          line.innerHTML = "<div>" + esc(item.hostname + " → " + item.service) + "</div>";
          var remove = document.createElement("button");
          remove.className = "cf-btn stop";
          remove.type = "button";
          remove.textContent = "Remove";
          remove.onclick = function () {
            post("remove_ingress", { hostname: item.hostname, delete_dns: "1" }).then(load);
          };
          line.appendChild(remove);
          host.appendChild(line);
        });
      }).catch(function () {});
      post("quick_status", {}).then(function (data) {
        var row = (data && data.data) || {};
        root.querySelector("[data-quick]").textContent = row.running
          ? ("Live: " + (row.url || "waiting for the address"))
          : "Quick tunnel is stopped.";
      }).catch(function () {});
    }

    function startLogin(profileId) {
      var select = root.querySelector("[data-tunnel-profile]");
      if (profileId) select.value = profileId;
      say("accounts", "Starting Cloudflare login…");
      post("cf_login_start", { profile_id: profileId }).then(function (data) {
        if (!data.status) { say("accounts", data.msg || "Login failed.", true); return; }
        if (data.data && data.data.logged_in) {
          say("accounts", "Browser login saved. Choose the account under Named tunnel, create a tunnel, then Use it.");
          load();
          return;
        }
        var url = data.data && data.data.url;
        if (url) window.open(url, "_blank", "noopener");
        say("accounts", data.msg || "Approve the zone in Cloudflare. Leave this page open until it says the login is saved.");
        var tries = 0;
        var timer = setInterval(function () {
          tries += 1;
          post("cf_login_status", { profile_id: profileId }).then(function (res) {
            if (res.data && res.data.logged_in) {
              clearInterval(timer);
              say("accounts", "Browser login saved. Choose the account under Named tunnel, create a tunnel, then Use it.");
              load();
            } else if (res.data && res.data.detail) {
              say("accounts", res.data.detail, true);
              say("tunnel", res.data.detail, true);
            } else if (tries > 40) {
              clearInterval(timer);
              say("accounts", "Cloudflare finished in the browser, but this server has not stored the certificate yet. Click Browser login again and keep this page open for about two minutes. Do not expect a cert.pem download unless your browser actually saved one.", true);
            }
          });
        }, 3000);
      });
    }

    root.querySelector("[data-save-token]").onclick = function () {
      say("service", "Saving the tunnel token…");
      post("set_tunnel_token", {
        account_id: root.querySelector("[data-account-id]").value,
        tunnel_token: root.querySelector("[data-tunnel-token]").value,
      }).then(function (data) {
        say("service", data.msg || "", !data.status);
        root.querySelector("[data-tunnel-token]").value = "";
        load();
      });
    };
    root.querySelector("[data-install]").onclick = function () {
      say("cloudflared", "Downloading cloudflared…");
      post("install_cloudflared", {}).then(function (data) {
        say("cloudflared", data.msg || "", !data.status);
        load();
      });
    };
    root.querySelector("[data-add-profile]").onclick = function () {
      post("add_profile", {
        profile_name: root.querySelector("[data-profile]").value,
        token: root.querySelector("[data-token]").value,
        cf_account_id: root.querySelector("[data-cf-account]").value,
      }).then(function (data) {
        say("accounts", data.msg || "", !data.status);
        root.querySelector("[data-token]").value = "";
        load();
      });
    };
    root.querySelector("[data-save-cert]").onclick = function () {
      var profileId = root.querySelector("[data-tunnel-profile]").value;
      if (!profileId) {
        say("tunnel", "Choose the account in the dropdown first.", true);
        return;
      }
      say("tunnel", "Saving certificate…");
      post("save_origin_cert", {
        profile_id: profileId,
        origin_cert: root.querySelector("[data-origin-cert]").value,
      }).then(function (data) {
        say("tunnel", data.msg || "", !data.status);
        if (data.status) root.querySelector("[data-origin-cert]").value = "";
        load();
      });
    };
    root.querySelector("[data-create-tunnel]").onclick = function () {
      post("create_tunnel", {
        profile_id: root.querySelector("[data-tunnel-profile]").value,
        tunnel_name: root.querySelector("[data-tunnel-name]").value,
      }).then(function (data) {
        say("tunnel", data.msg || "", !data.status);
        load();
      });
    };
    root.querySelector("[data-reload-tunnels]").onclick = load;
    root.querySelector("[data-add-host]").onclick = function () {
      post("add_ingress", {
        hostname: root.querySelector("[data-host]").value,
        service: serviceUrl(root.querySelector("[data-port]").value, root.querySelector("[data-https]").checked),
        zone_id: root.querySelector("[data-zone]").value,
        auto_dns: "1",
        proxied: "1",
        replace_dns: root.querySelector("[data-replace-dns]").checked ? "1" : "0",
        origin_request_json: originJson(root),
      }).then(function (data) {
        say("hostname", data.msg || "", !data.status);
        load();
      });
    };
    root.querySelector("[data-quick-start]").onclick = function () {
      say("quick", "Starting quick tunnel…");
      post("quick_start", { port: root.querySelector("[data-quick-port]").value }).then(function (data) {
        var url = data.data && data.data.url;
        root.querySelector("[data-quick]").textContent = url ? ("Live: " + url) : (data.msg || "");
        say("quick", data.msg || "", !data.status);
      });
    };
    root.querySelector("[data-quick-stop]").onclick = function () {
      post("quick_stop", {}).then(function (data) {
        say("quick", data.msg || "Quick tunnel stopped.");
        load();
      });
    };
    root.querySelectorAll("[data-svc]").forEach(function (button) {
      button.onclick = function () {
        post("service_action", { act: button.getAttribute("data-svc") }).then(function (data) {
          say("service", data.msg || "", !data.status);
          load();
        });
      };
    });
    root.querySelector("[data-log-btn]").onclick = function () {
      post("get_log", {}).then(function (data) {
        var row = (data && data.data) || {};
        root.querySelector("[data-log-out]").textContent = (row.log || "") + (row.quick_log ? "\n\n-- quick --\n" + row.quick_log : "");
      });
    };
    load();
  }

  function boot() {
    var root = document.getElementById("cftunnel-app");
    if (root) mount(root);
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot);
  else boot();
  var observer = new MutationObserver(boot);
  observer.observe(document.documentElement, { childList: true, subtree: true });
  global.CfTunnel = { mount: mount };
})(window);
