Soumet un flag à la plateforme CTF connectée et l'archive localement.

Arguments attendus : `<nom-du-challenge> <flag>`
Exemple : `/ctf-submit SpookyPass HTB{...}`

Pour une soumission par ID de challenge sur la plateforme active, utilise directement
le skill `ctf-submit` (qui appelle `~/.claude/ctf/ctf_cli.py submit --id <id> --flag <flag>`).

## Actions à réaliser

1. **Archiver le flag en local** dans `challenges/<nom-du-challenge>/flag.txt`
   (juste le flag, une ligne, pas de formatage). `challenges/` est gitignoré.

2. **Soumettre à la plateforme** si une connexion est active. Vérifie d'abord :
   ```bash
   python3 ~/.claude/ctf/ctf_cli.py status
   ```
   - Si connecté et que le challenge a un ID connu → délègue au skill `ctf-submit`.
   - Sinon, archive seulement en local et signale qu'aucune plateforme n'est connectée
     (l'utilisateur peut lancer `/ctf-connect`).

3. **Avertir** si le format du flag paraît inhabituel (pas de wrapper type `HTB{...}`),
   mais soumettre quand même si l'utilisateur confirme.

4. **Sauver le solveur dans le record** (avant tout cleanup) : copier le(s) script(s) de solve
   de `work/` vers `challenges/<nom>/solution/` pour que le writeup reste reproductible
   même différé et après suppression de `work/`. Pas de commit (gitignoré).

6. **Clôturer selon le MODE** — uniquement si la soumission est un succès (flag confirmé correct).
   Lire le mode :
   ```bash
   MODE=$(cat .ctf-mode 2>/dev/null || echo training)   # défaut : training
   ```
   - **`training`** (défaut) → **enchaîner automatiquement** (sans redemander, c'est la boucle d'entraînement) :
     a. **Writeup + export** (quel que soit le mode quand on le lance ; cf. CLAUDE.md § Export) :
        lire `<DEST>` dans `Export :` de `challenges/<nom>/notes.md` — fixé et validé au **setup**
        (`ctf_cli.py setup`) ; la fiche `<DEST>/<Nom>.md` existe déjà dans le vault avec le statut `en-cours`.
        *(Challenge lancé avant le setup : relancer `ctf_cli.py setup` pour créer la fiche, ou à défaut fixer
        `<DEST>` à la main : catégorie plateforme réduite à un segment sûr, cf. `setup_challenge.compute_dest`.)*
        Contrôler que `<DEST>` matche `^[A-Za-z0-9_-]+(/[A-Za-z0-9_-]+)*$` (pas de `..`), sinon s'arrêter ;
        copier le record (`cp -RP` notes, recon-report, exploit-log, flag, solution/ — pas work/) vers
        `~/Documents/CTF/CTF/<DEST>/` et refuser l'export si `find <DEST> -type l` trouve un lien ;
        puis déléguer le sous-agent `writeup` (il **complète la fiche existante** + synthèse d'édition) en lui passant
        `challenges/<nom>/` et `<DEST>`. Passer la fiche à `resolu` :
        `python3 ~/.claude/ctf/ctf_cli.py sheet-status --sheet ~/Documents/CTF/CTF/<DEST>/<Nom>.md --status resolu`.
        Enfin vérifier les fichiers exportés et `git -C ~/Documents/CTF/CTF add <DEST> … && commit
        "[writeup] <nom>: …" && push` ;
     b. puis `/ctf-retro <nom-du-challenge>` → sous-agent `review` en **mode approfondi**
        (post-mortem méthodo/pièges/cadre + propositions, en plus de la KB/rétro).
   - **`competition`** → **s'arrêter là** : flag + record conservés en local dans `challenges/<nom>/`
     (recon-report + exploit-log + flag + solution/, non versionnés : ne pas les supprimer). **Pas de writeup, pas de review** (réservés pour plus tard, économie de tokens).
     Signaler : « writeup différé + review sautée (mode compétition) ; régénérables via les logs ».
     **Plus tard** (writeup différé) : relancer l'étape 6a ci-dessus pour ce challenge, puis
     éventuellement `/ctf-retro`.
