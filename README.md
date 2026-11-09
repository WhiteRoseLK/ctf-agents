# CTF Multi-Agent Workspace

Workspace multi-agent (Claude Code par défaut) pour résoudre des challenges CTF (HackTheBox, Root-Me, CTFd…).
C'est une **couche d'orchestration + mémoire** par-dessus une suite de skills CTF vendorés :
les agents orchestrent, les skills fournissent la technique, et chaque challenge alimente
une knowledge base qui sert aux suivants.

## Prérequis

- **Claude Code** (`npm install -g @anthropic-ai/claude-code`), plan Max recommandé.
- **Docker**, **Exegol** (environnement d'exécution des outils) et **Obsidian** (vault des writeups).
- *(Optionnel)* **OpenCodex** pour faire tourner les agents sur plusieurs providers (voir § OpenCodex).
  → `install.sh` tente d'installer ce qui manque (Homebrew sur macOS ; sur Linux : pipx pour
  Exegol, script officiel pour Docker). Sur Linux, Obsidian (appli GUI) reste manuel (AppImage/flatpak).

Les outils d'attaque (nmap, pwntools, ghidra, binwalk…) **ne s'installent pas sur l'hôte** :
ils vivent dans Exegol.

## Setup

```bash
git clone https://github.com/WhiteRoseLK/ctf-agents.git
cd ctf-agents
./install.sh            # installe les deps + symlinke skills/ et le CLI (idempotent)
claude                  # puis, dans Claude Code :  /ctf-connect htb <TOKEN>
```

`install.sh` ne touche jamais à un `config.json`/token existant. Options : `--no-deps`, `--yes`, `--opencodex` (installe OpenCodex : app, CLI `ocx`, workers et raccourci zsh ; OAuth manuel via `ocx setup`).
Les secrets (tokens, config plateforme) ne sont **jamais versionnés** (voir `.gitignore`).

### OpenCodex (optionnel, multi-provider)

`./install.sh --opencodex` installe et configure [OpenCodex](https://opencodex.me), un proxy qui
répartit les agents entre plusieurs providers (Anthropic et Google Antigravity) :

1. **App desktop** (runtime du proxy, macOS, via `brew install --cask opencodex`) et **CLI `ocx`**
   (`npm install -g @bitkyc08/opencodex`, Node.js requis).
2. **Connexion des providers** : manuelle, par OAuth → lancer `ocx setup` (le script signale ceux
   qui ne sont pas connectés).
3. **Workers en failover** déclarés comme sous-agents délégables : `flash`→`haiku`, `haiku`→`flash`,
   `sonnet`→`argon`, `argon`→`sonnet`, `opus`→`argon` (si le premier modèle est indisponible, le
   second prend le relais).
4. **Raccourci zsh** (sur confirmation, bloc délimité dans `~/.zshrc`) : `ocx claude` lance
   l'orchestrateur sur `claude-sonnet-5-5` (variable `OCX_MODEL` d'`install.sh`), sauf si un
   `--model` est passé. `claude` seul n'est pas affecté. Pour le retirer : supprimer le bloc.

Relancer `./install.sh --opencodex` est sans effet de bord (combos mis à jour, raccourci non dupliqué).

## Comment ça marche

- **Exécution dans Exegol.** Les commandes d'attaque tournent dans un conteneur dédié au
  challenge (`challenges/<nom>/work/` monté sur `/workspace`). Un **hook** impose cette règle :
  toute commande hors orchestration lancée sur l'hôte demande une acceptation expresse.
- **Technique = skills.** `solve-challenge` (dispatcher) route vers `ctf-web`, `ctf-pwn`,
  `ctf-reverse`, `ctf-crypto`, `ctf-forensics`, `ctf-malware`, `ctf-osint`, `ctf-misc`, `ctf-ai-ml`.
  On ne duplique jamais une technique de skill dans le repo.
- **Mémoire.** `knowledge-base/` (journal expérientiel) + `retrospectives/`, interrogés par
  pertinence via `tools/kb-search/kb_search.py "<mots-clés>"` (TF-IDF, zéro dépendance).
- **Travail local, export du writeup.** Chaque challenge se résout dans `challenges/<nom>/`
  (gitignoré : ce repo est public). Seule l'étape writeup exporte writeup + notes, logs, flag et
  solveur vers un **repo CTF privé** séparé (`~/Documents/CTF/CTF`, aussi vault Obsidian) :
  `<Plateforme>/<Catégorie>/<Nom>/`, ou `<Événement>/<Année>/…` avec un `README.md` de synthèse
  par édition (gabarit : `templates/writeup-template.md`).

## Workflow

**Mode** (`/ctf-mode`, défaut `training`) : en **entraînement**, après un flag l'orchestrateur enchaîne
automatiquement writeup + review approfondie (méthodo, pièges, respect du cadre) — la boucle d'amélioration.
En **compétition**, il s'arrête à la soumission (writeup différé, review sautée) pour économiser les tokens ;
le record committé reste complet et régénérable.

1. `/ctf-connect <plateforme> <token>` — se connecter (puis `/ctf-list`, `/ctf-solve` au besoin).
2. `/ctf-start <plateforme> <challenge> [cible]` — démarre le **worker Orca** du challenge
   (worktree dédié + conteneur Exegol, via `ocx claude`) ; le worker structure le challenge,
   consulte la mémoire, puis résout.
3. **Recon** — l'agent `recon` charge `solve-challenge`, triage, produit `recon-report.md`
   (avec la catégorie détectée). Aucune exploitation.
4. **Exploit** — l'agent `exploit` charge le skill `ctf-<catégorie>`, attaque, logge tout dans
   `exploit-log.md`, extrait le flag.
5. `/ctf-submit <challenge> <flag>` — archive + soumet + sauve le solveur dans `challenges/<nom>/solution/`.
6. **Selon le mode** — training : **Writeup** (agent `writeup` → export vers le repo CTF privé, avec méthodo/tips/erreurs) +
   `/ctf-retro` (agent `review` approfondi → KB + post-mortem) ; competition : différés.

> **Plusieurs challenges en parallèle** : l'orchestrateur global démarre un worker Orca par
> challenge (`orca orchestration worker-start`), chacun dans son worktree + Exegol, et les dirige
> par le bus Orca. L'utilisateur peut entrer dans le chat d'un worker pour aider. Cf. ADR
> `docs/adr/0001`.

## Structure

```
ctf-agents/
├── CLAUDE.md                 # instructions du workspace
├── install.sh                # bootstrap : deps + symlinks skills/CLI
├── skills/                   # skills CTF vendorés (solve-challenge, ctf-*, intégration plateforme)
├── tools/
│   ├── ctf-cli/              # CLI plateforme : ctf_cli.py + sudocrypt_cli.py + config.example.json
│   ├── kb-search/            # recherche mémoire TF-IDF
│   └── hooks/                # enforce_exegol.py (politique d'exécution)
├── templates/                # gabarit de writeup (vault)
├── .claude/
│   ├── agents/               # recon, exploit, writeup, review
│   ├── commands/             # ctf-start, ctf-submit, ctf-retro
│   └── settings.json         # permissions, hook, MCP git
├── knowledge-base/           # mémoire : techniques.md, lessons-learned.md
├── challenges/<nom>/         # travail local (gitignoré) : notes, recon, exploit-log, flag, solution/, work/
└── retrospectives/           # post-mortems <date>-<challenge>.md

~/Documents/CTF/CTF/          # repo CTF privé (= vault Obsidian), alimenté par l'étape writeup
```

## Amélioration continue

Après chaque challenge, `/ctf-retro` fait tourner l'agent `review` qui enrichit
`knowledge-base/techniques.md`, `lessons-learned.md` et `retrospectives/`. Plus on joue,
plus la mémoire sert — les agents la consultent (`kb-search`) avant chaque phase.
