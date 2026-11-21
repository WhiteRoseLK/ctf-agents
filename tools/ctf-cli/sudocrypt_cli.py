#!/usr/bin/env python3
"""
Sudocrypt CLI - dedicated connector for the Sudocrypt v16 CTF engine.

Sudocrypt is a bespoke, server-rendered platform (not CTFd/HTB/RootMe), so it
gets its own client instead of being forced into ctf_cli.py.

Auth model (reverse-engineered from /components/js/play.js):
  - Session  : cookie `session_id`
  - CSRF     : server sets cookie `csrf` on any GET; mutating requests echo it
               back in the `X-CSRF-Token` header (credentials included).
API:
  - GET  /play                         -> HTML, embeds <script id="__PLAY__"> state (dots list)
  - GET  /api/levels/{id}?type={type}  -> {"level": {...}}   (NOT server-side gated)
  - POST /api/submit?type={type}       -> body: answer, type, levelId   (needs CSRF)
"""

import argparse
import html as _html
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ctf_cli  # noqa: E402

BASE_URL = "https://sudocrypt.com"
CONFIG_FILE = os.path.expanduser("~/.claude/ctf/sudocrypt_config.json")
UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")

_CTX = ctf_cli.default_ssl_context()


def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE) as f:
            return json.load(f)
    return {}


def save_config(cfg):
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=2)
    os.chmod(CONFIG_FILE, 0o600)


def _session():
    cfg = load_config()
    sid = cfg.get("session_id")
    if not sid:
        sys.exit("Not connected. Run: sudocrypt_cli.py connect --session <session_id>")
    return sid


def request(path, method="GET", body=None, sid=None, csrf=None, accept_json=True):
    """Low-level request. Returns (status, headers, parsed_or_text)."""
    url = BASE_URL + path
    headers = {"User-Agent": UA}
    headers["Accept"] = "application/json" if accept_json else "text/html,*/*"
    cookies = []
    if sid:
        cookies.append(f"session_id={sid}")
    if csrf:
        cookies.append(f"csrf={csrf}")
        headers["X-CSRF-Token"] = csrf
        # Mutating requests are rejected (403) without a same-origin Origin/Referer.
        headers["Origin"] = BASE_URL
        headers["Referer"] = BASE_URL + "/play"
    if cookies:
        headers["Cookie"] = "; ".join(cookies)

    data = None
    if body is not None:
        if isinstance(body, dict):
            data = urllib.parse.urlencode(body).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        else:
            data = body.encode() if isinstance(body, str) else body

    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        resp = ctf_cli.open_url(req, 30, _CTX)
    except urllib.error.HTTPError as e:
        resp = e
    raw = resp.read().decode("utf-8", errors="replace")
    ct = resp.headers.get("content-type", "")
    parsed = raw
    if "application/json" in ct:
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            parsed = {"raw": raw}
    return resp.status, resp.headers, parsed


def fetch_csrf(sid):
    """GET /play and return the csrf cookie the server issues for this session."""
    status, hdrs, _ = request("/play", sid=sid, accept_json=False)
    for _k, v in hdrs.items():
        if _k.lower() == "set-cookie" and "csrf=" in v:
            m = re.search(r"csrf=([0-9a-fA-F]+)", v)
            if m:
                return m.group(1)
    # fall back: maybe already in a prior cookie — re-request headers list
    raise RuntimeError("Could not obtain csrf cookie (session may be invalid)")


def get_play_state(sid):
    """Return the embedded __PLAY__ game state (dots list, current level, etc.)."""
    status, _hdrs, html = request("/play", sid=sid, accept_json=False)
    if isinstance(html, dict):
        html = html.get("raw", "")
    m = re.search(r'<script id="__PLAY__"[^>]*>(.*?)</script>', html, re.S)
    if not m:
        if "Redirecting" in html or "login" in html.lower():
            sys.exit("Session invalid or expired. Re-run connect with a fresh session_id.")
        raise RuntimeError("Could not find __PLAY__ state on /play")
    return json.loads(_html.unescape(m.group(1).strip()))


# --- commands ---------------------------------------------------------------

def cmd_connect(args):
    sid = args.session.strip()
    cfg = load_config()
    cfg["session_id"] = sid
    save_config(cfg)
    try:
        state = get_play_state(sid)
    except SystemExit:
        raise
    except Exception as e:
        sys.exit(f"Connected but could not read game state: {e}")
    dots = state.get("dots", [])
    user = state.get("display") or state.get("title") or "?"
    print(f"Connected to Sudocrypt. {len(dots)} challenges visible across "
          f"{len({d.get('type') for d in dots})} tracks.")
    print(f"Config saved to {CONFIG_FILE} (chmod 600).")


def cmd_list(args):
    sid = _session()
    state = get_play_state(sid)
    dots = state.get("dots", [])
    rows = []
    for d in dots:
        lid, typ = d.get("id"), d.get("type")
        try:
            _s, _h, body = request(
                f"/api/levels/{urllib.parse.quote(lid)}?type={urllib.parse.quote(typ)}",
                sid=sid)
            lvl = (body or {}).get("level", {}) if isinstance(body, dict) else {}
        except Exception:
            lvl = {}
        rows.append({
            "id": lid, "type": typ,
            "title": lvl.get("title", ""),
            "points": lvl.get("points", ""),
            "solves": lvl.get("solves", ""),
            "difficulty": lvl.get("difficulty", ""),
        })
    if args.json:
        print(json.dumps(rows, indent=2))
        return
    print(f"{'ID':<14}{'TYPE':<10}{'PTS':>5}{'SOLVES':>8}  TITLE")
    print("-" * 70)
    for r in rows:
        print(f"{r['id']:<14}{r['type']:<10}{str(r['points']):>5}"
              f"{str(r['solves']):>8}  {r['title']}")


def cmd_get(args):
    sid = _session()
    typ = args.type or args.id.rsplit("-", 1)[0]
    _s, _h, body = request(
        f"/api/levels/{urllib.parse.quote(args.id)}?type={urllib.parse.quote(typ)}",
        sid=sid)
    lvl = body.get("level", body) if isinstance(body, dict) else body
    print(json.dumps(lvl, indent=2))


def cmd_submit(args):
    sid = _session()
    typ = args.type or args.id.rsplit("-", 1)[0]
    csrf = fetch_csrf(sid)
    body = {"answer": args.flag, "type": typ, "levelId": args.id}
    status, _h, resp = request(
        f"/api/submit?type={urllib.parse.quote(typ)}",
        method="POST", body=body, sid=sid, csrf=csrf)
    if isinstance(resp, dict):
        err = resp.get("error")
        if status == 200 and resp.get("success") is True:
            print(f"[+] CORRECT: {json.dumps(resp)}")
        elif err:
            print(f"[-] ERROR (http {status}): {err}")
        else:
            print(f"[-] INCORRECT (http {status}): {json.dumps(resp)}")
    else:
        print(f"[http {status}] {resp}")


def main():
    p = argparse.ArgumentParser(prog="sudocrypt_cli.py")
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("connect"); c.add_argument("--session", required=True)
    c.set_defaults(func=cmd_connect)

    c = sub.add_parser("list"); c.add_argument("--json", action="store_true")
    c.set_defaults(func=cmd_list)

    c = sub.add_parser("get"); c.add_argument("id"); c.add_argument("--type")
    c.set_defaults(func=cmd_get)

    c = sub.add_parser("submit"); c.add_argument("id"); c.add_argument("flag")
    c.add_argument("--type")
    c.set_defaults(func=cmd_submit)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
