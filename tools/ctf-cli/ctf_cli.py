#!/usr/bin/env python3
"""
CTF Platform CLI - Handles API interactions with CTFd, HTB, and RootMe platforms.
Used by Claude Code skills to automate CTF challenge workflows.
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.request
import urllib.parse
import urllib.error
import ssl
import shutil
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

CONFIG_FILE = os.path.expanduser("~/.claude/ctf/config.json")
WORK_DIR = os.path.expanduser("~/.claude/ctf/workspace")


def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE) as f:
            return json.load(f)
    return {}


def save_config(config):
    """Écrit la config (contient des tokens) en 0600, dossier en 0700."""
    config_dir = os.path.dirname(CONFIG_FILE)
    os.makedirs(config_dir, mode=0o700, exist_ok=True)
    os.chmod(config_dir, 0o700)
    fd = os.open(CONFIG_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.fchmod(fd, 0o600)  # corrige un fichier préexistant en 644
    with os.fdopen(fd, "w") as f:
        json.dump(config, f, indent=2)


def get_ctfd_csrf_nonce(base_url, session_cookie):
    for path in ("/challenges", "/"):
        try:
            body = subprocess.check_output(
                [
                    "curl", "-ksS",
                    "-b", f"session={session_cookie}",
                    f"{base_url}{path}",
                ],
                text=True,
                timeout=15,
            )
            match = re.search(r"csrfNonce':\s*\"([0-9a-f]+)\"", body)
            if match:
                return match.group(1)
        except Exception:
            pass

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    headers = {
        "Cookie": f"session={session_cookie}",
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }

    for path in ("/challenges", "/"):
        req = urllib.request.Request(f"{base_url}{path}", headers=headers)
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            body = resp.read().decode("utf-8", errors="replace")
        match = re.search(r"csrfNonce':\s*\"([0-9a-f]+)\"", body)
        if match:
            return match.group(1)

    raise RuntimeError("Unable to extract CTFd CSRF nonce")


def api_request(url, method="GET", data=None, headers=None, token=None, platform="ctfd"):
    if headers is None:
        headers = {}

    if token:
        if platform == "ctfd":
            # Support session cookie auth (when API tokens aren't available)
            config = load_config()
            if config.get("auth_type") == "session_cookie":
                headers["Cookie"] = f"session={token}"
                if method != "GET":
                    headers["CSRF-Token"] = get_ctfd_csrf_nonce(config.get("url") or config.get("active", {}).get("url"), token)
            else:
                headers["Authorization"] = f"Token {token}"
            headers["Content-Type"] = "application/json"
        elif platform == "htb":
            headers["Authorization"] = f"Bearer {token}"
            headers["Content-Type"] = "application/json"
        elif platform == "rootme":
            headers["Cookie"] = f"spip_session={token}"

    headers.setdefault("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
    headers.setdefault("Accept", "application/json")

    if data and isinstance(data, dict):
        data = json.dumps(data).encode("utf-8")

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
            body = resp.read().decode("utf-8")
            try:
                return json.loads(body)
            except json.JSONDecodeError:
                return {"raw": body}
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        print(f"HTTP {e.code}: {body}", file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"Connection error: {e.reason}", file=sys.stderr)
        sys.exit(1)


# ─── CTFd ────────────────────────────────────────────────────────────────

def ctfd_list(base_url, token, category=None, solved=None):
    resp = api_request(f"{base_url}/api/v1/challenges", token=token, platform="ctfd")
    challenges = resp.get("data", [])
    if category:
        challenges = [c for c in challenges if c.get("category", "").lower() == category.lower()]
    if solved is not None:
        challenges = [c for c in challenges if c.get("solved_by_me", False) == solved]
    return challenges


def ctfd_info(base_url, token, challenge_id):
    resp = api_request(f"{base_url}/api/v1/challenges/{challenge_id}", token=token, platform="ctfd")
    return resp.get("data", resp)


def ctfd_download(base_url, token, challenge_id, dest_dir):
    info = ctfd_info(base_url, token, challenge_id)
    files = info.get("files", [])
    os.makedirs(dest_dir, exist_ok=True)

    # Save challenge metadata
    with open(os.path.join(dest_dir, "challenge.json"), "w") as f:
        json.dump(info, f, indent=2)

    downloaded = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for file_url in files:
        if file_url.startswith("/"):
            file_url = f"{base_url}{file_url}"
        elif not file_url.startswith("http"):
            file_url = f"{base_url}/files/{file_url}"

        filename = file_url.split("/")[-1].split("?")[0]
        filepath = os.path.join(dest_dir, filename)

        req = urllib.request.Request(file_url)
        if token:
            config = load_config()
            if config.get("auth_type") == "session_cookie":
                req.add_header("Cookie", f"session={token}")
            else:
                req.add_header("Authorization", f"Token {token}")
        with urllib.request.urlopen(req, context=ctx, timeout=60) as resp:
            with open(filepath, "wb") as f:
                shutil.copyfileobj(resp, f)
        downloaded.append(filepath)

    return {"info": info, "files": downloaded}


def ctfd_submit(base_url, token, challenge_id, flag):
    data = {"challenge_id": int(challenge_id), "submission": flag}
    resp = api_request(f"{base_url}/api/v1/challenges/attempt", method="POST", data=data, token=token, platform="ctfd")
    return resp


# ─── HTB ─────────────────────────────────────────────────────────────────

HTB_API = "https://labs.hackthebox.com/api/v4"
HTB_API_V5 = "https://labs.hackthebox.com/api/v5"  # machine/own n'existe qu'en v5

def htb_categories(token):
    """Fetch and cache HTB category id->name mapping."""
    resp = api_request(f"{HTB_API}/challenge/categories/list", token=token, platform="htb")
    return {cat["id"]: cat["name"] for cat in resp.get("info", [])}


def htb_list(token, category=None, solved=None, retired=False):
    url = f"{HTB_API}/challenge/list"
    resp = api_request(url, token=token, platform="htb")
    challenges = resp.get("challenges", [])

    # Enrich with category names
    cat_map = htb_categories(token)
    for c in challenges:
        c["category_name"] = cat_map.get(c.get("challenge_category_id"), "Unknown")

    if category:
        challenges = [c for c in challenges if c.get("category_name", "").lower() == category.lower()]
    if solved is not None:
        if solved:
            challenges = [c for c in challenges if c.get("authUserSolve")]
        else:
            challenges = [c for c in challenges if not c.get("authUserSolve")]
    return challenges


def htb_info(token, challenge_id):
    resp = api_request(f"{HTB_API}/challenge/info/{challenge_id}", token=token, platform="htb")
    return resp.get("challenge", resp)


def htb_download(token, challenge_id, dest_dir):
    os.makedirs(dest_dir, exist_ok=True)
    info = htb_info(token, challenge_id)

    with open(os.path.join(dest_dir, "challenge.json"), "w") as f:
        json.dump(info, f, indent=2)

    if not info.get("download", False):
        return {"info": info, "files": [], "note": "No downloadable files or requires instance spawn"}

    # HTB download endpoint returns binary directly via GET
    download_url = f"{HTB_API}/challenge/download/{challenge_id}"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    filename = info.get("file_name", f"challenge_{challenge_id}.zip")
    filepath = os.path.join(dest_dir, filename)
    req = urllib.request.Request(download_url)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36")
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=120) as r:
            with open(filepath, "wb") as f:
                shutil.copyfileobj(r, f)
        return {"info": info, "files": [filepath]}
    except Exception as e:
        return {"info": info, "files": [], "error": str(e)}


def htb_submit(token, challenge_id, flag, difficulty=50):
    data = {"challenge_id": int(challenge_id), "flag": flag, "difficulty": difficulty}
    resp = api_request(f"{HTB_API}/challenge/own", method="POST", data=data, token=token, platform="htb")
    return resp


# ─── HTB machines (boxes) ────────────────────────────────────────────────

def _htb_token_call(token, path, method="GET", data=None, base=HTB_API):
    return api_request(f"{base}/{path}", method=method, data=data, token=token, platform="htb")


def _htb_trusted_url(url):
    """Refuse de suivre une URL de pagination hors HTB : le token y serait envoyé."""
    if url:
        parts = urllib.parse.urlparse(url)
        if parts.scheme != "https" or parts.hostname != urllib.parse.urlparse(HTB_API).hostname:
            raise ValueError(f"Untrusted pagination URL refused: {url}")
    return url


def htb_machines_list(token, os_name=None, difficulty=None, solved=None, retired=False):
    """List boxes (active or retired), following API pagination.

    `solved` refers to root ownership.
    """
    path = "machine/list/retired/paginated" if retired else "machine/paginated"
    url = f"{HTB_API}/{path}?per_page=100"
    machines = []
    while url:
        resp = api_request(url, token=token, platform="htb")
        machines.extend(resp.get("data", []))
        url = _htb_trusted_url((resp.get("links") or {}).get("next"))

    if os_name:
        machines = [m for m in machines if (m.get("os") or "").lower() == os_name.lower()]
    if difficulty:
        machines = [m for m in machines if (m.get("difficultyText") or "").lower() == difficulty.lower()]
    if solved is not None:
        machines = [m for m in machines if bool(m.get("authUserInRootOwns")) == solved]
    return machines


def htb_machine_info(token, name):
    resp = _htb_token_call(token, f"machine/profile/{urllib.parse.quote(name, safe='')}")
    return resp.get("info", resp)


def htb_machine_spawn(token, machine_id):
    return _htb_token_call(token, "vm/spawn", method="POST", data={"machine_id": int(machine_id)})


def htb_machine_active(token):
    """Return the running box (with its IP), or None."""
    return _htb_token_call(token, "machine/active").get("info")


def htb_machine_submit(token, machine_id, flag, difficulty=50):
    data = {"id": int(machine_id), "flag": flag, "difficulty": difficulty}
    # Une seule route pour user et root : HTB déduit le type de flag soumis.
    return _htb_token_call(token, "machine/own", method="POST", data=data, base=HTB_API_V5)


# ─── RootMe ──────────────────────────────────────────────────────────────

ROOTME_API = "https://api.www.root-me.org"

def rootme_list(token, category=None, lang="fr"):
    challenges = []
    page = 1
    while True:
        url = f"{ROOTME_API}/challenges?debut_challenges={(page-1)*50}"
        if category:
            url += f"&categorie={urllib.parse.quote(category)}"
        resp = api_request(url, token=token, platform="rootme")
        items = resp if isinstance(resp, list) else resp.get("challenges", resp.get("data", []))
        if not items:
            break
        challenges.extend(items if isinstance(items, list) else [items])
        if len(items) < 50:
            break
        page += 1
        if page > 10:
            break
    return challenges


def rootme_info(token, challenge_id):
    resp = api_request(f"{ROOTME_API}/challenges/{challenge_id}", token=token, platform="rootme")
    return resp


def rootme_submit(token, challenge_id, flag):
    data = {"flag": flag}
    resp = api_request(
        f"{ROOTME_API}/challenges/{challenge_id}/submit",
        method="POST", data=data, token=token, platform="rootme"
    )
    return resp


# ─── Sudocrypt ───────────────────────────────────────────────────────────

def sudocrypt_list(token, category=None, solved=None):
    from sudocrypt_cli import get_play_state, request
    import urllib.parse
    state = get_play_state(token)
    dots = state.get("dots", [])
    pos_by_type = state.get("posByType", {})
    challenges = []
    type_counts = {}
    for d in dots:
        lid, typ = d.get("id"), d.get("type")
        idx = type_counts.get(typ, 0)
        type_counts[typ] = idx + 1
        is_solved = pos_by_type.get(typ, 0) > idx

        if category and category.lower() not in (typ or "").lower():
            continue
        if solved is not None and is_solved != solved:
            continue

        try:
            _s, _h, body = request(
                f"/api/levels/{urllib.parse.quote(lid)}?type={urllib.parse.quote(typ)}",
                sid=token,
            )
            lvl = (body or {}).get("level", {}) if isinstance(body, dict) else {}
        except Exception:
            lvl = {}

        challenges.append({
            "id": lid,
            "name": lvl.get("title") or lid,
            "category": typ,
            "value": lvl.get("points") or 0,
            "difficulty": lvl.get("difficulty") or "",
            "solved_by_me": is_solved,
            "solves": lvl.get("solves") or 0,
        })
    return challenges


def sudocrypt_info(token, challenge_id):
    from sudocrypt_cli import request
    import urllib.parse
    typ = challenge_id.rsplit("-", 1)[0]
    _s, _h, body = request(
        f"/api/levels/{urllib.parse.quote(challenge_id)}?type={urllib.parse.quote(typ)}",
        sid=token,
    )
    return body.get("level", body) if isinstance(body, dict) else body


def sudocrypt_submit(token, challenge_id, flag):
    from sudocrypt_cli import request, fetch_csrf
    import urllib.parse
    typ = challenge_id.rsplit("-", 1)[0]
    csrf = fetch_csrf(token)
    body = {"answer": flag, "type": typ, "levelId": challenge_id}
    status, _h, resp = request(
        f"/api/submit?type={urllib.parse.quote(typ)}",
        method="POST", body=body, sid=token, csrf=csrf,
    )
    if isinstance(resp, dict):
        err = resp.get("error")
        if status == 200 and resp.get("success") is True:
            return {"status": "correct", "message": "Correct flag!", "response": resp}
        else:
            return {"status": "incorrect", "message": err or json.dumps(resp), "response": resp}
    return {"status": "error", "message": str(resp)}


# ─── CLI ─────────────────────────────────────────────────────────────────

def cmd_connect(args):
    config = load_config()
    profile = {
        "platform": args.platform,
        "url": args.url.rstrip("/") if args.url else None,
        "token": args.token,
    }
    config["active"] = profile
    save_config(config)

    # Test connection
    try:
        if args.platform == "ctfd":
            challs = ctfd_list(profile["url"], profile["token"])
            print(json.dumps({"status": "connected", "platform": "ctfd", "challenges_count": len(challs)}))
        elif args.platform == "htb":
            challs = htb_list(profile["token"])
            print(json.dumps({"status": "connected", "platform": "htb", "challenges_count": len(challs)}))
        elif args.platform == "rootme":
            challs = rootme_list(profile["token"])
            print(json.dumps({"status": "connected", "platform": "rootme", "challenges_count": len(challs)}))
        elif args.platform == "sudocrypt":
            from sudocrypt_cli import get_play_state, save_config as save_sudo_cfg
            state = get_play_state(profile["token"])
            dots = state.get("dots", [])
            save_sudo_cfg({"session_id": profile["token"]})
            print(json.dumps({"status": "connected", "platform": "sudocrypt", "challenges_count": len(dots)}))
    except Exception as e:
        print(json.dumps({"status": "error", "message": str(e)}))
        sys.exit(1)


def cmd_list(args):
    config = load_config()
    profile = config.get("active")
    if not profile:
        print("Not connected. Run: ctf connect first", file=sys.stderr)
        sys.exit(1)

    solved = None
    if args.solved == "true":
        solved = True
    elif args.solved == "false":
        solved = False

    if profile["platform"] == "ctfd":
        challs = ctfd_list(profile["url"], profile["token"], category=args.category, solved=solved)
    elif profile["platform"] == "htb":
        challs = htb_list(profile["token"], category=args.category, solved=solved)
    elif profile["platform"] == "rootme":
        challs = rootme_list(profile["token"], category=args.category)
    elif profile["platform"] == "sudocrypt":
        challs = sudocrypt_list(profile["token"], category=args.category, solved=solved)

    # Normalize output
    output = []
    for c in challs:
        entry = {
            "id": c.get("id"),
            "name": c.get("name") or c.get("titre"),
            "category": c.get("category") or c.get("category_name") or c.get("rubrique"),
            "points": c.get("value") or c.get("points") or c.get("score"),
            "difficulty": c.get("difficulty") or c.get("difficulte"),
            "solved": c.get("solved_by_me") or bool(c.get("authUserSolve")) or c.get("validee", False),
            "solves": c.get("solves") or c.get("authUserSolveCount", 0),
        }
        output.append(entry)

    if args.sort == "points":
        output.sort(key=lambda x: x.get("points") or 0)
    elif args.sort == "solves":
        output.sort(key=lambda x: x.get("solves") or 0, reverse=True)
    elif args.sort == "difficulty":
        output.sort(key=lambda x: str(x.get("difficulty") or ""))

    print(json.dumps(output, indent=2))


def cmd_info(args):
    config = load_config()
    profile = config.get("active")
    if not profile:
        print("Not connected.", file=sys.stderr)
        sys.exit(1)

    if profile["platform"] == "ctfd":
        info = ctfd_info(profile["url"], profile["token"], args.id)
    elif profile["platform"] == "htb":
        info = htb_info(profile["token"], args.id)
    elif profile["platform"] == "rootme":
        info = rootme_info(profile["token"], args.id)
    elif profile["platform"] == "sudocrypt":
        info = sudocrypt_info(profile["token"], args.id)

    print(json.dumps(info, indent=2))


def cmd_download(args):
    config = load_config()
    profile = config.get("active")
    if not profile:
        print("Not connected.", file=sys.stderr)
        sys.exit(1)

    dest = args.dest or os.path.join(WORK_DIR, f"challenge_{args.id}")

    if profile["platform"] == "ctfd":
        result = ctfd_download(profile["url"], profile["token"], args.id, dest)
    elif profile["platform"] == "htb":
        result = htb_download(profile["token"], args.id, dest)
    elif profile["platform"] == "rootme":
        info = rootme_info(profile["token"], args.id)
        os.makedirs(dest, exist_ok=True)
        with open(os.path.join(dest, "challenge.json"), "w") as f:
            json.dump(info, f, indent=2)
        result = {"info": info, "files": [], "note": "RootMe challenges are typically web-based"}
    elif profile["platform"] == "sudocrypt":
        info = sudocrypt_info(profile["token"], args.id)
        os.makedirs(dest, exist_ok=True)
        with open(os.path.join(dest, "challenge.json"), "w") as f:
            json.dump(info, f, indent=2)
        result = {"info": info, "files": [], "note": "Sudocrypt challenges info saved"}

    print(json.dumps({"dest": dest, "files": result.get("files", []), "info": result.get("info", {})}, indent=2, default=str))


def cmd_submit(args):
    config = load_config()
    profile = config.get("active")
    if not profile:
        print("Not connected.", file=sys.stderr)
        sys.exit(1)

    if profile["platform"] == "ctfd":
        result = ctfd_submit(profile["url"], profile["token"], args.id, args.flag)
    elif profile["platform"] == "htb":
        result = htb_submit(profile["token"], args.id, args.flag)
    elif profile["platform"] == "rootme":
        result = rootme_submit(profile["token"], args.id, args.flag)
    elif profile["platform"] == "sudocrypt":
        result = sudocrypt_submit(profile["token"], args.id, args.flag)

    print(json.dumps(result, indent=2))


def cmd_status(args):
    config = load_config()
    profile = config.get("active")
    if not profile:
        print(json.dumps({"connected": False}))
    else:
        safe_profile = dict(profile)
        token = safe_profile.get("token")
        if token:
            safe_profile["token"] = "sha256:" + hashlib.sha256(token.encode()).hexdigest()[:8]
        print(json.dumps({"connected": True, **safe_profile}))


def _htb_profile():
    profile = load_config().get("active")
    if not profile or profile.get("platform") != "htb":
        print("Not connected to HTB. Run: ctf connect --platform htb first", file=sys.stderr)
        sys.exit(1)
    return profile


def cmd_machines(args):
    token = _htb_profile()["token"]
    action = args.action

    if action == "list":
        solved = {"true": True, "false": False}.get(args.solved)
        machines = htb_machines_list(token, os_name=args.os, difficulty=args.difficulty,
                                     solved=solved, retired=args.retired)
        result = [
            {
                "id": m.get("id"),
                "name": m.get("name"),
                "os": m.get("os"),
                "difficulty": m.get("difficultyText"),
                "points": m.get("points"),
                "user_owned": bool(m.get("authUserInUserOwns")),
                "root_owned": bool(m.get("authUserInRootOwns")),
                "release": m.get("release"),
            }
            for m in machines
        ]
    elif action == "info":
        result = htb_machine_info(token, args.name)
    elif action == "spawn":
        result = htb_machine_spawn(token, args.id)
    elif action == "active":
        result = htb_machine_active(token) or {"active": False}
    elif action == "submit":
        result = htb_machine_submit(token, args.id, args.flag)

    print(json.dumps(result, indent=2))


def main():
    parser = argparse.ArgumentParser(description="CTF Platform CLI")
    sub = parser.add_subparsers(dest="command")

    # connect
    p_conn = sub.add_parser("connect")
    p_conn.add_argument("--platform", choices=["ctfd", "htb", "rootme", "sudocrypt"], required=True)
    p_conn.add_argument("--url", help="Platform base URL (required for ctfd)")
    p_conn.add_argument("--token", required=True, help="API token")

    # list
    p_list = sub.add_parser("list")
    p_list.add_argument("--category", help="Filter by category")
    p_list.add_argument("--solved", choices=["true", "false"], help="Filter by solved status")
    p_list.add_argument("--sort", choices=["points", "solves", "difficulty"], default="points")

    # info
    p_info = sub.add_parser("info")
    p_info.add_argument("--id", required=True, help="Challenge ID")

    # download
    p_dl = sub.add_parser("download")
    p_dl.add_argument("--id", required=True, help="Challenge ID")
    p_dl.add_argument("--dest", help="Destination directory")

    # submit
    p_sub = sub.add_parser("submit")
    p_sub.add_argument("--id", required=True, help="Challenge ID")
    p_sub.add_argument("--flag", required=True, help="Flag to submit")

    # machines (HTB boxes)
    p_mach = sub.add_parser("machines", help="HTB boxes: list, info, spawn, active, submit")
    p_mach.add_argument("action", choices=["list", "info", "spawn", "active", "submit"])
    p_mach.add_argument("--os", help="list: filter by OS (Linux, Windows...)")
    p_mach.add_argument("--difficulty", help="list: filter by difficulty (Easy, Medium, Hard, Insane)")
    p_mach.add_argument("--solved", choices=["true", "false"], help="list: filter by root ownership")
    p_mach.add_argument("--retired", action="store_true", help="list: retired boxes instead of active ones")
    p_mach.add_argument("--name", help="info: box name")
    p_mach.add_argument("--id", type=int, help="spawn/submit: box ID")
    p_mach.add_argument("--flag", help="submit: user or root flag")

    # status
    sub.add_parser("status")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)
    if args.command == "machines":
        needs = {"info": "name", "spawn": "id", "submit": "id"}.get(args.action)
        if needs and not getattr(args, needs):
            parser.error(f"machines {args.action} requires --{needs}")
        if args.action == "submit" and not args.flag:
            parser.error("machines submit requires --flag")

    {
        "connect": cmd_connect,
        "list": cmd_list,
        "info": cmd_info,
        "download": cmd_download,
        "submit": cmd_submit,
        "status": cmd_status,
        "machines": cmd_machines,
    }[args.command](args)


if __name__ == "__main__":
    main()
