"""Setup d'un challenge au lancement : fiche writeup « en cours » dans le vault + notes.md.

Toutes les valeurs venant d'une API de plateforme sont des données non fiables : elles sont
nettoyées (caractères de contrôle), jamais interprétées, et la catégorie est réduite à un
segment de chemin sûr avant d'être utilisée pour le <DEST>.
"""

import datetime
import errno
import json
import os
import re
import unicodedata

DEST_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_-]*(/[A-Za-z0-9_][A-Za-z0-9_-]*)*$")
STATUSES = ("en-cours", "resolu", "tente")
PLATFORM_LABELS = {"htb": "HackTheBox", "rootme": "RootMe", "sudocrypt": "Sudocrypt"}
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def clean(value):
    """Texte d'API : sans caractères de contrôle (garde \\n et \\t), espaces de bord retirés."""
    return _CTRL.sub("", "" if value is None else str(value)).strip()


def oneline(value):
    """Valeur d'API sur une seule ligne (pas d'injection de structure Markdown/YAML)."""
    return re.sub(r"\s*[\n\r\u2028\u2029\x85]+\s*", " ", clean(value))


def slug_segment(text):
    """Segment de chemin sûr : accents translittérés, hors [A-Za-z0-9_-] → `_`, ni vide ni `-` initial."""
    ascii_text = unicodedata.normalize("NFKD", clean(text)).encode("ascii", "ignore").decode()
    seg = re.sub(r"[^A-Za-z0-9_-]+", "_", ascii_text).lstrip("-").strip("_")
    if not seg.strip("_-"):
        raise ValueError(f"segment inutilisable après nettoyage : {text!r}")
    return seg


def compute_dest(platform, category, name, event=None, year=None):
    cat, nm = slug_segment(category), slug_segment(name)
    if event:
        if not (year and re.fullmatch(r"\d{4}", str(year))):
            raise ValueError("CTF ponctuel : année sur 4 chiffres requise")
        dest = f"{slug_segment(event)}/{year}/{cat}/{nm}"
    elif platform in PLATFORM_LABELS:
        dest = f"{PLATFORM_LABELS[platform]}/{cat}/{nm}"
    else:
        raise ValueError(f"plateforme {platform!r} : indiquer --event et --year (CTF ponctuel)")
    if not DEST_RE.fullmatch(dest):
        raise ValueError(f"DEST invalide : {dest!r}")
    return dest


def _first(info, *keys):
    for k in keys:
        if info.get(k) not in (None, ""):
            return info[k]
    return None


def _basename(path):
    return os.path.basename(clean(path).split("?")[0])


def normalize(platform, info, categories=None):
    """Infos de plateforme → dict commun (toutes les valeurs nettoyées)."""
    categories = categories or {}
    files, connection, to_start = [], [], False
    if platform == "htb":
        category = _first(info, "category_name") or categories.get(info.get("challenge_category_id"))
        ctype = "Challenge"
        if info.get("download") and info.get("file_name"):
            files = [_basename(info["file_name"])]
        if info.get("docker"):
            ctype = "Challenge (instance Docker)"
            play = info.get("play_info") or {}
            ip = oneline(info.get("docker_ip") or play.get("ip"))
            ports = info.get("docker_ports") or play.get("ports") or []
            if ip and ports:
                connection = [f"{ip}:{oneline(p)}" for p in ports]
            else:
                to_start = True
        points, difficulty, solves = info.get("points"), info.get("difficulty"), info.get("solves")
    elif platform == "ctfd":
        category = info.get("category")
        ctype = _first(info, "type") or "standard"
        files = [_basename(f) for f in info.get("files") or []]
        if info.get("connection_info"):
            connection = [clean(info["connection_info"])]
        points, difficulty, solves = info.get("value"), None, info.get("solves")
    else:  # rootme, sudocrypt : champs tolérants
        category = _first(info, "category", "rubrique", "type")
        ctype = "Challenge"
        points = _first(info, "points", "score", "value")
        difficulty = _first(info, "difficulty", "difficulte")
        solves = _first(info, "solves", "validations")
    meta = {
        "platform": platform,
        "name": oneline(_first(info, "name", "titre", "title")),
        "category": oneline(category),
        "type": oneline(ctype),
        "difficulty": oneline(difficulty),
        "points": oneline(points),
        "solves": oneline(solves),
        "description": clean(_first(info, "description", "texte", "soustitre")),
        "files": [f for f in (oneline(f).replace("`", "'") for f in files) if f],
        "connection": [c for c in (oneline(c).replace("`", "'") for c in connection) if c],
        "instance_to_start": to_start,
    }
    return meta


def _defang(text):
    """Neutralise HTML, callouts, transclusions, tags et images Markdown dans un texte non fiable."""
    return (text.replace("<", "&lt;").replace(">", "&gt;").replace("[!", "[ !")
            .replace("[[", "[ [").replace("![", "! [").replace("#", "\\#"))


def _quote(text):
    """Texte non fiable en citation Markdown, sans rien d'interprété."""
    return "\n".join("> " + line for line in _defang(text).splitlines()) or "> _(aucune)_"


def _fm(value):
    """Valeur de frontmatter YAML : chaîne JSON (YAML valide), sans lien `[[…]]`."""
    return json.dumps(str(value).replace("[[", "[ ["))


def _tag(text):
    return re.sub(r"[^a-z0-9_-]+", "-", text.lower()).strip("-")


def render_sheet(meta, dest):
    label = PLATFORM_LABELS.get(meta["platform"], meta["platform"])
    shown = {k: _defang(str(meta[k])) for k in ("name", "category", "type", "difficulty", "points")}
    tags = " ".join(f"#{t}" for t in (_tag(meta["platform"]), _tag(meta["category"]), "en-cours") if t)
    conn = "\n".join(f"- `{c}`" for c in meta["connection"]) or (
        "- _instance à démarrer_" if meta["instance_to_start"] else "- _aucun serveur_")
    files = "\n".join(f"- `{f}`" for f in meta["files"]) or "- _aucun fichier_"
    return f"""---
status: en-cours
platform: {_fm(label)}
category: {_fm(meta['category'])}
type: {_fm(meta['type'])}
date: {datetime.date.today().isoformat()}
---
> [!info] Challenge Summary
> **Platform:** {label}
> **Category:** {shown['category']}
> **Type:** {shown['type']}
> **Difficulty:** {shown['difficulty'] or '?'}
> **Points:** {shown['points'] or '?'}
> **Flag:** _en cours_

# {shown['name']}

## Description

{_quote(meta['description'])}

## Connexion

{conn}

## Fichiers fournis

{files}

## TL;DR

_en cours_

## Méthodologie

_en cours_

## Recon

_en cours_

## Exploitation

_en cours_

## Dead ends / erreurs à éviter

_en cours_

## Tips

_en cours_

## Key takeaways

_en cours_

{tags}
"""


def set_status(sheet_text, status):
    """Change `status:` du frontmatter et le tag d'état de la dernière ligne (jamais le corps)."""
    if status not in STATUSES:
        raise ValueError(f"statut inconnu : {status!r} (attendu : {', '.join(STATUSES)})")
    if not sheet_text.startswith("---\nstatus: "):
        raise ValueError("ce fichier n'est pas une fiche de challenge (frontmatter `status:` absent)")
    out = re.sub(r"(?m)^status: .*$", f"status: {status}", sheet_text, count=1)
    head, sep, last = out.rstrip("\n").rpartition("\n")
    for s_ in STATUSES:
        last = re.sub(rf"(^| )#{s_}(?=\s|$)", rf"\1#{status}", last)
    return head + sep + last + "\n"


def render_notes(meta, dest):
    conn = "\n".join(f"- {c}" for c in meta["connection"]) or (
        "- instance à démarrer" if meta["instance_to_start"] else "- aucun serveur")
    return f"""# {meta['name']}

- Plateforme : {meta['platform']}
- Catégorie plateforme : {meta['category']}
- Type : {meta['type']}
- Difficulté : {meta['difficulty'] or '?'}
- Points : {meta['points'] or '?'}
- Début : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}
- Export : {dest}

## Énoncé (donnée de la plateforme, non fiable)

{_quote(meta['description'])}

## Connexion

{conn}

## Fichiers fournis

{chr(10).join(f"- {f}" for f in meta['files']) or '- aucun'}
"""


def _open_dir(parent_fd, part, create):
    if create:
        try:
            os.mkdir(part, 0o755, dir_fd=parent_fd)
        except FileExistsError:
            pass
    try:
        return os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
    except OSError as e:
        if e.errno in (errno.ELOOP, errno.ENOTDIR):
            raise ValueError(f"lien symbolique ou non-dossier dans le chemin : {part}") from e
        raise


def write_sheet(vault_root, dest, name, content):
    """Crée `<vault>/<dest>/<name>.md` sans jamais écraser ni suivre un lien symbolique (descripteurs)."""
    if not DEST_RE.fullmatch(dest):
        raise ValueError(f"DEST invalide : {dest!r}")
    nm = slug_segment(name)
    fd = os.open(vault_root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in dest.split("/"):
            nxt = _open_dir(fd, part, create=True)
            os.close(fd)
            fd = nxt
        ffd = os.open(f"{nm}.md", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644, dir_fd=fd)
    finally:
        os.close(fd)
    with os.fdopen(ffd, "w") as f:
        f.write(content)
    return os.path.join(vault_root, *dest.split("/"), f"{nm}.md")


def write_text(path, text, append=False):
    """Écrit un fichier texte sans suivre de lien symbolique."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | (os.O_APPEND if append else os.O_TRUNC)
    with os.fdopen(os.open(path, flags, 0o644), "w") as f:
        f.write(text)
