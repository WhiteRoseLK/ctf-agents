# CTF Multi-Agent Workspace

## Contexte

Ce workspace est dédié à la résolution de challenges CTF sur HackTheBox et Root-Me.
Nous travaillons en équipe multi-agent avec des rôles spécialisés.
Chaque action doit être documentée pour produire un writeup et alimenter l'amélioration continue.

## Agents disponibles

- **recon** : Reconnaissance et énumération (scans, fingerprinting, OSINT)
- **exploit** : Exploitation de vulnérabilités, privesc, extraction de flags
- **writeup** : Rédaction du writeup final pédagogique et reproductible
- **review** : Retrospective, analyse de performance, mise à jour knowledge base

## Couche skills (moteur technique)

Les techniques CTF viennent des skills vendorés dans `skills/` (installés via `install.sh`) :
- `solve-challenge` : dispatcher — triage puis routage vers la bonne catégorie
- `ctf-web`, `ctf-pwn`, `ctf-crypto`, `ctf-reverse`, `ctf-forensics`, `ctf-malware`,
  `ctf-osint`, `ctf-misc`, `ctf-ai-ml` : références profondes par catégorie
- `ctf-connect` / `ctf-list` / `ctf-solve` / `ctf-submit` / `ctf-writeup` : intégration plateforme

**Les agents orchestrent, les skills fournissent la technique.** On ne duplique jamais
une technique de skill dans un agent ou dans la knowledge base.

## Rôle de l'agent principal — ORCHESTRATEUR (il ne résout pas)

L'agent principal **orchestre, il ne résout jamais lui-même**. Il écoute l'utilisateur et délègue
via le skill **`orchestration`** d'Orca (cf. ADR `docs/adr/0001`) :

- Il **démarre un worker Orca par challenge** (`orca orchestration worker-start --worktree
  new-top-level --agent claude`), dans son propre worktree + conteneur Exegol, lancé via
  **`ocx claude`** (routage multi-provider). Le worker mène la résolution et délègue en interne à
  ses sous-agents `recon` puis `exploit` (spécialisés par catégorie via `ctf-<catégorie>`).
- **Il dirige chaque worker par le bus Orca** : `orca orchestration send --to dispatch:<id>` (jamais
  le `SendMessage` de Claude, jamais le terminal du worker). Il est réveillé par leurs `worker_done`.
- **Plusieurs challenges = plusieurs workers Orca en parallèle.** L'orchestrateur supervise et
  **reste disponible** pour de nouvelles instructions de l'utilisateur. L'utilisateur peut entrer
  dans le chat d'un worker (`--keep-open`) pour aider sans casser l'orchestration.
- Il ne lance **JAMAIS** lui-même une commande de recon/exploitation (pas de `docker exec` d'outils,
  pas de solveur inline, pas d'analyse de binaire). Si l'envie de « juste résoudre » surgit : **déléguer**.
- Il ne garde en propre que : l'init (`/ctf-start`), la **soumission** (`/ctf-submit`), et le
  **déclenchement** des sous-agents `writeup` et `review`.

## Mode : entraînement / compétition

Le workspace a deux modes, dans `.ctf-mode` (gitignoré, perso) ; **défaut = `training` si absent**.
Bascule : `/ctf-mode training|competition`. Lecture : `MODE=$(cat .ctf-mode 2>/dev/null || echo training)`.

- **`training`** (défaut) — boucle d'entraînement complète : après un flag validé, l'orchestrateur
  enchaîne **automatiquement** writeup + **review approfondie** (post-mortem méthodo/pièges/cadre).
- **`competition`** — vitesse/économie de tokens : l'orchestrateur **s'arrête après la soumission**
  (flag + record conservés en local dans `challenges/<nom>/`) ; writeup **différé** et review **sautée** (régénérables depuis les logs plus tard).

## Workflow standard (tout est délégué par l'orchestrateur)

1. **Init** → l'orchestrateur lance `/ctf-start <plateforme> <challenge>` : démarre le **worker Orca** du challenge (`worker-start`, worktree + conteneur Exegol via `ocx claude`) et lui passe le brief
2. **Phase Recon** → **dans le worker**, délégation au sous-agent `recon` : charge `solve-challenge`, triage, produit `recon-report.md` avec la **catégorie détectée**
3. **Phase Exploit** → **dans le worker**, délégation au sous-agent `exploit` : charge le skill `ctf-<catégorie>`, attaque dans le conteneur Exegol, produit `exploit-log.md` + `flag.txt` + solveur dans `challenges/<nom>/solution/`
4. **Soumission** → l'orchestrateur lance `/ctf-submit <challenge> <flag>` (archive + soumet + sauve le solveur dans `challenges/<nom>/solution/`)
5. **Writeup** (⚙ training : auto · competition : différé) → sous-agent `writeup` → **export** du writeup + record vers `<DEST>` (repo CTF privé = vault Obsidian), jamais dans ce repo. Inclut **méthodo + tips + erreurs à éviter**, pas que la solution.
6. **Review** (⚙ training uniquement) → `/ctf-retro <challenge>` → sous-agent `review` en mode approfondi (KB/rétro **+ post-mortem process/cadre**). En compétition : sautée.
7. **Fin de cycle & cleanup** → voir ci-dessous.

## Fin de cycle & cleanup

Les workers sont lancés **sans `--keep-open`** : un worker se **ferme tout seul** après son
`worker_done` (le chat reste ouvert pendant le travail pour que l'utilisateur puisse aider).
Une fois le challenge **complètement terminé**, l'orchestrateur nettoie :

```bash
# <nom> = slug du challenge, STRICTEMENT [A-Za-z0-9_-] — à valider avant interpolation (frontière
# de confiance : le nom vient de la plateforme/utilisateur). Rejeter tout autre caractère ou un `-` initial.
WT=~/orca/workspaces/claude_ctf/ctf-<nom>              # worktree du worker
bash "$WT/challenges/<nom>/cleanup.sh"                 # docker rm -f exegol-ctf-<nom> + rm -rf work/
orca worktree rm --worktree name:ctf-<nom> --force    # ferme le worker + supprime le worktree
```

**Étape de vérification OBLIGATOIRE avant tout `orca worktree rm`** (suppression irréversible) :
prouver que le record est sauvé — en `training`, le commit writeup est présent dans le repo privé ;
en `competition`, `challenges/<nom>/` a été archivé hors du worktree. **Sans cette preuve lue au
préalable, ne rien supprimer.**

**Quand nettoyer, selon le mode :**
- **`training`** : après writeup **et** review — le record est déjà exporté dans le repo privé, donc
  supprimer le worktree ne perd rien.
- **`competition`** : le writeup est **différé** → le record (`challenges/<nom>/solution/`, logs) vit
  dans le worktree. **Ne pas `orca worktree rm` tant que le writeup différé n'est pas fait**, ou
  d'abord **archiver** `challenges/<nom>/` hors du worktree. Sinon on perd le record.

> ⚠ Jamais de `orca worktree rm` d'un challenge dont le record n'est ni exporté ni archivé.

## Conventions obligatoires

### Documentation
- **Chaque commande exécutée** doit être loggée avec son output dans `exploit-log.md`
- **Chaque découverte** va dans `recon-report.md` avec la commande qui l'a produite
- Les timestamps sont obligatoires pour mesurer le temps par phase

### Knowledge Base
- **TOUJOURS** consulter la mémoire par pertinence avant de tenter une technique :
  `python3 tools/kb-search/kb_search.py "<mots-clés>"` (indexe KB + rétros, TF-IDF, zéro dépendance ; les writeups exportés ne sont pas indexés)
- Compléter au besoin par la lecture de `knowledge-base/techniques.md` et `lessons-learned.md`
- La KB est un **journal expérientiel** (ce qu'on a appris), pas une copie des skills
- Après chaque challenge, mettre à jour ces fichiers (via `/ctf-retro`)

### Git
- `challenges/` est **gitignoré** (repo public) : le record d'un challenge n'est jamais commité ici.
  Ce repo ne reçoit que KB, rétros et outillage (commit `[retro]`).
- Seule l'étape **writeup** commit (+ push) dans le repo CTF privé (`[writeup] <nom>: …`).
- Messages de commit : `[phase] challenge-name: description`
- Exemples : `[recon] Keeper: scan initial nmap`, `[exploit] Keeper: privesc via CVE-2023-xxxxx`

## Structure des challenges

**Tout le travail se fait en local, dans ce repo** : `challenges/<nom>/` (gitignoré). Init, recon,
exploit, soumission et rétro ne dépendent **d'aucun autre repo**.

```
challenges/<nom-challenge>/
├── notes.md            # Notes libres de l'orchestrateur
├── recon-report.md     # Rapport de reconnaissance structuré
├── exploit-log.md      # Journal chronologique des tentatives
├── flag.txt            # Le flag extrait
├── solution/           # Solveur(s) finaux (repro même après cleanup de work/)
├── cleanup.sh          # Supprime le conteneur Exegol et work/ (garde le reste)
└── work/               # Fichiers de travail temporaires (montés dans Exegol sur /workspace)
```

> ⚠ `challenges/` n'est versionné nulle part tant que le writeup n'est pas exporté (mode
> compétition = writeup différé) : ne jamais supprimer un dossier de challenge à la main.

### Export writeup → repo CTF privé (seule dépendance externe)

L'étape **writeup** (agent `writeup` + skill `ctf-writeup`) est la **seule** à écrire hors de ce
repo : dans le repo privé `WhiteRoseLK/ctf-writeups`, cloné sur `~/Documents/CTF/CTF` (= vault
Obsidian). Destination **`<DEST>`** :
- plateforme permanente : `<HackTheBox|RootMe>/<Catégorie>/<Nom>/`
- CTF ponctuel : `<Événement>/<Année>/<Catégorie>/<Nom>/` (ex. `THCon/2026/Web/<Nom>/`)

(catégorie de la plateforme, `<Nom>` avec underscores). L'orchestrateur note `Export : <DEST>`
dans `challenges/<nom>/notes.md` et y copie (`cp -R`) `notes.md`, `recon-report.md`,
`exploit-log.md`, `flag.txt`, `solution/` (jamais `work/`) ; l'agent `writeup` y écrit `<Nom>.md`.
**CTF ponctuel** : l'agent `writeup` met à jour la synthèse `<Événement>/<Année>/README.md` (date, score, tableau
challenge | catégorie | points | statut ✅ / ⚠️ tenté / ❌ | lien writeup), `<Événement>/README.md`
(éditions) et le tableau du `README.md` racine. Puis commit `[writeup] <nom>: …` + `git push`
dans le repo CTF, faits par l'orchestrateur (étape writeup de `/ctf-submit`).

## Environnement d'exécution — Exegol

**Les sous-agents recon/exploit pilotent depuis l'hôte macOS ; les outils CTF tournent dans
un conteneur Exegol dédié au challenge** (c'est là que vivent nmap, pwntools, ghidra, binwalk, john…).
L'hôte macOS n'a pas ces outils → ne pas lancer les commandes d'attaque directement dessus.

> **Un challenge = un worker Orca = un worktree.** Le conteneur Exegol et le dossier
> `challenges/<nom>/` d'un challenge vivent dans le **worktree du worker** (`orca orchestration
> worker-start`, cf. ADR `docs/adr/0001`), pas dans le worktree principal. L'orchestrateur global
> ne crée ni conteneur ni solveur : il démarre le worker et le dirige par `orchestration send`.

> **Politique (hook `PreToolUse`, liste noire — autorise par défaut)** : l'orchestration et
> l'inspection (git, grep, find, sed, awk, cat, docker, exegol, outils du repo…) passent **sans
> friction**. Seule une commande de **résolution/attaque lancée sur l'hôte** (outil CTF : nmap,
> binwalk, radare2, gdb, wine, nc… ; exécution d'un binaire/artefact ; script de solve) déclenche
> une demande d'acceptation expresse — le réflexe étant de la lancer dans Exegol (`docker exec
> exegol-ctf-<nom> …`). Hook : `tools/hooks/enforce_exegol.py`. Chargé au **démarrage de session** ;
> si modifié en cours de session, le recharger via `/hooks` (ou relancer `claude`).

### Cycle de vie du conteneur (un par challenge)

```bash
# Démarrage (fait par /ctf-start) — work/ monté sur /workspace
# `yes '' |` : Exegol affiche encore un prompt « Press ENTER » (notice de MAJ) MÊME avec
#   --offline ; sans stdin il quitte sans créer le conteneur. On acquitte en alimentant des
#   newlines. --accept-eula couvre l'EULA. Image : toujours `free` (les autres sont payantes).
yes '' | exegol start "ctf-<nom>" free --offline --accept-eula \
  --workspace "$(pwd)/challenges/<nom>/work" \
  --disable-X11 -s bash
# + --vpn ~/htb.ovpn  si le challenge a une cible réseau HTB (sinon omettre)

# Vérifier
docker ps --filter "name=ctf-<nom>" --format "{{.Names}}\t{{.Status}}"
```

En non-interactif, `exegol start` affiche « cannot attach stdin to a TTY-enabled container » :
c'est **sans conséquence**, le conteneur est créé et tourne — on interagit via `docker exec`.
Si `exegol start` échoue sur « Unable to connect to docker » : `open -a Docker` puis
`until docker info >/dev/null 2>&1; do sleep 3; done` avant de réessayer.

**Image `free` uniquement** (les images `full`/`ad` sont payantes). Si un outil manque du
conteneur (ex. binwalk, ghidra, john), l'installer dedans à la volée
(`docker exec exegol-ctf-<nom> bash -c "apt-get install -y <pkg> || pipx install <pkg>"`)
ou le réimplémenter en Python — **ne pas changer d'image**.

### Lancer une commande dans le conteneur

Le nom Docker réel est `exegol-ctf-<nom>`. Aucun `exegol-mcp` n'est configuré → on passe par :

```bash
docker exec exegol-ctf-<nom> bash -c "cd /workspace && <commande>"
```

Écrire un fichier pour le conteneur : l'écrire dans `challenges/<nom>/work/` (monté sur
`/workspace`). En fin de challenge, `cleanup.sh` supprime le conteneur via
`docker rm -f exegol-ctf-<nom>` (fiable, sans prompt — `exegol stop/remove` bute sur le
prompt de MAJ) puis supprime `work/`.

### Apple Silicon
Conteneur aarch64 + binaire x86 → `qemu-user-static` (`qemu-x86_64-static -L <sysroot> ./bin`),
**uniquement pour valider la logique** ; revérifier toute adresse de gadget avec `ropper`/`ROPgadget`
sur le vrai binaire. (détails : skill `ctf-pwn`)
