Initialise un nouveau challenge CTF en démarrant son **worker Orca dédié**.

Arguments attendus : `<plateforme> <nom-du-challenge> [cible]`
Exemple : `/ctf-start htb Keeper 10.10.11.227`
Exemple : `/ctf-start rootme "SQL Injection - Authentication" https://challenge.root-me.org/...`

> Modèle : **1 challenge = 1 worker Orca = 1 worktree** (cf. ADR `docs/adr/0001`). L'orchestrateur
> global **démarre le worker et le dirige par le bus Orca** ; toute la résolution (structure,
> download, Exegol, recon, exploit) se fait **dans le worktree du worker**.

## Côté orchestrateur global

1. **Déterminer** plateforme, nom, cible, et (CTF ponctuel) événement + année.
2. **Récupérer le repoId** : `orca repo list --json` (ce repo = `claude_ctf`).
3. **Démarrer le worker** du challenge, avec le brief ci-dessous comme `--spec` :
   ```bash
   orca orchestration worker-start \
     --worktree new-top-level --repo id:<repoId> --name "ctf-<nom>" \
     --agent claude \
     --spec "<brief self-contained : plateforme, nom, cible, objectif = flag, livrable>" --json
   ```
   **Par défaut (sans `--keep-open`), le worker se ferme tout seul après `worker_done`.** Le chat
   reste ouvert **pendant** le travail (l'utilisateur peut y entrer pour aider). Ajouter
   `--keep-open` **uniquement** si l'utilisateur veut garder le chat ouvert après la fin.
4. **Rester disponible** : plusieurs challenges = plusieurs `worker-start` en parallèle. Diriger
   chaque worker par `orca orchestration send --to dispatch:<id>` ; être réveillé par `worker_done`.
5. Ne **pas** créer de conteneur Exegol ni de structure ici : c'est le worker qui le fait.
6. **Fin de cycle** : après la soumission (et, en `training`, writeup + review), l'orchestrateur
   **nettoie** le challenge — cf. CLAUDE.md § « Fin de cycle & cleanup ».

## Brief du worker (ce que le worker exécute dans son worktree)

1. **Créer la structure du challenge en local** (gitignoré, aucun autre repo touché) :
   ```
   challenges/<nom>/
   ├── notes.md
   ├── recon-report.md
   ├── exploit-log.md
   ├── flag.txt
   ├── cleanup.sh       # supprime le conteneur Exegol (docker rm -f) + work/
   └── work/            # fichiers du challenge (monté sur /workspace dans Exegol)
   ```

2. **Initialiser notes.md** : plateforme, nom, cible, date de début, catégorie si connue ;
   pour un CTF ponctuel, événement + année (servira à l'export du writeup).

3. **Consulter la knowledge base par pertinence** :
   ```bash
   python3 tools/kb-search/kb_search.py "<nom-du-challenge> <catégorie si connue> <mots-clés>"
   ```
   Remonte techniques, leçons et rétros les plus proches. Compléter si besoin par
   `knowledge-base/techniques.md` et `lessons-learned.md`. Résumer dans notes.md.

4. **Télécharger les fichiers du challenge dans `work/`** (si le challenge en a) :
   ```bash
   python3 ~/.claude/ctf/ctf_cli.py download --id <ID>     # dépose dans ~/.claude/ctf/workspace/
   ```
   **Bug connu HTB** : le CLI renvoie souvent `"files": []` (HTTP 400). Contournement direct :
   ```bash
   TOKEN=$(python3 -c "import json;print(json.load(open('$HOME/.claude/ctf/config.json'))['active']['token'])")
   # Token passé par substitution de process (-K <(...)), JAMAIS en argv (sinon lisible par `ps aux`).
   # Ne jamais logger cette commande après expansion dans exploit-log.md : logger `$TOKEN` littéral.
   curl -sL -A "Mozilla/5.0" \
     -K <(printf 'header = "Authorization: Bearer %s"\n' "$TOKEN") \
     -o challenges/<nom>/work/challenge.zip \
     "https://labs.hackthebox.com/api/v4/challenge/download/<ID>"
   ```
   Beaucoup de zips HTB sont protégés par le mot de passe `hackthebox`. L'archive est **non
   fiable** → l'extraire et l'analyser dans le conteneur Exegol, jamais sur l'hôte. Un challenge
   « container-only » (pas de download) n'a pas de fichier : attaquer l'instance live directement.

5. **Démarrer le conteneur Exegol** (environnement d'exécution — cf. CLAUDE.md § Exegol) :
   ```bash
   docker info >/dev/null 2>&1 || { open -a Docker; until docker info >/dev/null 2>&1; do sleep 3; done; }
   # `yes '' |` indispensable : Exegol bute encore sur un prompt « Press ENTER » (notice MAJ)
   # même avec --offline ; sans stdin il quitte sans créer le conteneur.
   yes '' | exegol start "ctf-<nom>" free --offline --accept-eula \
     --workspace "$(pwd)/challenges/<nom>/work" --disable-X11 -s bash
   # ajouter  --vpn ~/htb.ovpn  si cible réseau HTB
   # l'erreur « cannot attach stdin to a TTY » est normale : le conteneur tourne quand même
   docker ps --filter "name=ctf-<nom>" --format "{{.Names}}\t{{.Status}}"
   ```
   Générer `cleanup.sh` qui fait `docker rm -f exegol-ctf-<nom>` (pas `exegol stop`, qui bute
   sur le prompt de MAJ) puis `rm -rf work/`.

6. **Pas de commit** : `challenges/` est gitignoré (repo public).

7. **Résoudre** : phase Recon (sous-agent `recon` → `solve-challenge`) puis Exploit (sous-agent
   `exploit` → skill `ctf-<catégorie>`). Rapporter le flag à l'orchestrateur par `worker_done`
   (questions/blocages → `orca orchestration ask`).
