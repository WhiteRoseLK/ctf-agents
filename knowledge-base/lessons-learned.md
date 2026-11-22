# Lessons Learned — CTF

> Erreurs et pièges rencontrés, pour ne pas les répéter. Mis à jour par `/ctf-retro`.
> **Consulter avant chaque challenge.**

Format : **Date** / **Challenge** — **Problème** → **Cause** → **Solution** → **Règle**

---

## Leçons

### 2026-03-15 — GameLoader
- **Problème** : un scan brute-force de la clé AES dans tout le PE (42 Mo) a renvoyé 0 résultat,
  alors que la clé était bien dans le binaire.
- **Cause** : le critère de validation déchiffrait en **AES-ECB** (défaut Godot), mais le
  challenge utilisait un template patché en **AES-CFB avec IV**. Le bon mode n'était pas celui supposé.
- **Solution** : reverser `open_and_parse` d'abord pour établir le format/mode exact, PUIS
  localiser la clé via le pointeur global (plus fiable que le scan octet par octet).
- **Règle** : **confirmer le mode/format de chiffrement par reverse AVANT tout brute-force.**
  Un brute-force qui valide avec le mauvais mode ne converge jamais.

### 2026-03-15 — EtherTag
- **Problème** : `nmap --script enip-info` prévu dans le plan, mais `nmap` absent de la machine.
- **Cause** : poste macOS sans outils de pentest Linux installés.
- **Solution** : probe EtherNet/IP réimplémenté en **sockets Python** (List Identity, Register
  Session, ReadTag) — aucun outil externe requis.
- **Règle** : **vérifier la disponibilité d'un outil avant de bâtir un plan dessus** ; sinon
  réimplémenter le protocole en Python plutôt que de rester bloqué. (cf. [[techniques]] § Méta)

### 2026-03-15 — SpookyPass
- **Problème** : temps passé à envisager un bypass d'auth (strcmp patch) alors que le flag
  était extractible sans jamais exécuter le binaire.
- **Cause** : réflexe « crackme → patcher le saut » au lieu de vérifier d'abord le stockage statique.
- **Solution** : sur un binaire non strippé, lire `.rodata`/`.data` en premier (`strings`, `nm`).
- **Règle** : **commencer par l'analyse statique la moins coûteuse** ; l'exécution/patch est un recours, pas un réflexe.

### 2026-10-30 — NoiseCodex
- **Problème** : un LLL réimplémenté en pur-Python (`Fraction`) a dépassé 120 s sur une base de
  dim 11 avec des entiers de 3072 bits ; le solveur fpylll a ensuite résolu en 0,05 s.
- **Cause** : l'image Exegol `free` n'a pas fpylll/sage/pip, et on a appliqué à la lettre la règle
  « réimplémenter en Python » (EtherTag). Or le LLL recalculait tout le Gram-Schmidt à chaque
  étape sur des rationnels énormes. Pourtant `apt` fonctionnait dans le conteneur.
- **Solution** : `docker exec exegol-ctf-<nom> apt-get install -y python3-fpylll`.
- **Règle** : **si l'outil est installable (apt/pip) dans le conteneur, l'installer plutôt que de
  le réimplémenter.** Réimplémenter n'est valable que pour du simple (protocole, parsing), pas
  pour du calcul lourd (LLL, factorisation, Gröbner). Tester `apt-get install` en premier (1 min).
- **Process** : `recon-report.md` a été laissé vide (« à compléter ») car le triage était rapide.
  **Remplir recon-report.md même si le triage est court** (artefacts, analyse de la source,
  hypothèse de vecteur) : sert à l'agent exploit et à la rétro.

### 2026-10-31 — PartialEncryption
- **Problème 1 (process)** : le ZIP du challenge était protégé, le CLI HTB annonçait
  `file_password: None`, l'extraction a échoué et la recon a été bloquée jusqu'à confirmation
  manuelle du mot de passe (`hackthebox`).
- **Ce qu'on aurait dû faire** : tester directement `hackthebox` (mot de passe standard des archives HTB).
- **Règle** : **ne pas se fier à `file_password: None`** ; essayer `hackthebox` d'office avant de bloquer.
- **Problème 2 (technique)** : les instructions **AES-NI** (`aesenc`/`aesdec`/`aesdeclast`/
  `aeskeygenassist`) sont du « crypto maison », pas un XOR trivial. `rabin2 -I` disait `crypto false`
  (pas de constantes détectées) : cet indicateur est trompeur avec AES-NI.
- **Règle** : repérer `aes*` dans le désassemblage, puis réimplémenter en Python (S-box, RotWord=ROR8,
  InvShiftRows) plutôt que d'exécuter le binaire. Voir [[techniques]] § Reverse.
- **Problème 3 (leurres)** : 3 routines sur 4 ne font qu'imprimer un message d'usage via `putchar`.
  Le flag se lit dans les `cmp argv[1][i]` du vrai checker.
- **Règle** : **vérifier quel code est réellement atteint / compare l'entrée** ; ne pas supposer que la
  sortie `putchar` contient le flag.

### 2026-10-31 — SuspiciousThreat (Forensics, HTB #746)
- **Problème 1 (plateforme)** : le téléchargement du challenge a donné un faux « zip » (JSON d'erreur
  « Challenge file not found »). Le challenge est container-only (`play_methods: ["container"]`).
- **Ce qu'on aurait dû faire** : ne pas télécharger ; spawner via `POST /api/v4/container/start`
  (headers `Origin`/`Referer` = app.hackthebox.com) puis lire host/port/mot de passe (`hackthebox`).
- **Règle** : challenge sans fichier = spawn API, pas de download.
- **Problème 2 (outil)** : `objdump` d'Exegol est aarch64 (« can't disassemble for architecture
  UNKNOWN ») sur une lib x86-64. `strings`/`nm -D`/`objdump -s -j .rodata` ont suffi.
- **Règle** : sur binaire x86, ne pas compter sur `objdump -d` ; `strings`, `nm`, `readelf`, ou capstone Python.
- **Problème 3 (sécurité)** : `ctf_cli.py status` affiche le token HTB ; IP:port et identifiants de
  l'instance ont été écrits dans recon-report/notes committés.
- **Règle** : ne jamais lancer/logguer `status` ; placeholders `<HOST>:<PORT>` dans les fichiers committés.
- **Technique** : rootkit LD_PRELOAD qui hooke `readdir` = on ne désarme pas, on lit par chemin
  direct ou on réénumère en `getdents64`. Voir [[techniques]] § Forensics.
- **Process** : recon-report complet (règle NoiseCodex tenue), délégation et Exegol respectés.
  **Règle** : remplir `notes.md` « Mémoire pertinente » avec la sortie de kb-search dès l'init,
  même quand la KB ne remonte rien (noter « aucune entrée pertinente »).

### 2026-11-01 — APKey (Mobile/Android, HTB #240)
- **Ce qui s'est passé** : 1er agent recon arrêté par l'utilisateur, bloqué sur `jadx` absent
  (`apt-get install jadx` échoue dans l'image free). Relancé, il a utilisé `apktool`/smali et a trouvé
  en 4 min que le Toast de succès ne dépend pas du mot de passe. Exploit : 1 tentative.
- **Ce qu'on aurait dû faire** : prévoir `apktool` + smali d'office pour les APK (un seul essai d'install de
  jadx, avec timeout, puis repli) au lieu de s'acharner sur l'outil manquant.
- **Règle** : APK login : vérifier si la sortie de succès dépend de l'entrée avant tout crack. Voir
  [[techniques]] § Reverse (APK).
- **Process (bon)** : le recon a marqué ses index « lecture rapide non vérifiée » ; l'exploit les a
  revérifiés dans le smali avant le solveur. À garder : toute valeur non vérifiée est signalée comme telle.
- **Process (défaut)** : catégorie HTB « Mobile » inconnue des consignes du writeup, classé `HTB/Reversing`
  alors que l'orchestrateur demandait `HackTheBox/Mobile` ; Description de l'énoncé absente (non récupérée à
  l'init). **Règle** : passer au writeup le chemin vault exact et le texte de l'énoncé.
- **Outillage** : conteneur sans pycryptodome ni pip : `cryptography` est là. Écrire le solveur avec
  `cryptography` dès le départ.

### 2026-11-18 — Connected (Machine Linux / Web, HTB #906)
- **Problème 1 (plateforme, temps perdu)** : le user flag lu sur disque (`/home/asterisk/user.txt`) était
  refusé « Incorrect » à la soumission. L'équipe s'est acharnée (reconnexion root, hexdump, comparaison des
  mtime user/root, hypothèse de respawn) alors que **le root flag de la même instance était accepté** → la
  box était bien la bonne, la valeur on-disk exacte.
- **Cause** : sur une box HTB **déjà possédée (owned)** par le compte, l'API refuse une re-soumission du
  flag déjà validé. Le bon contrôle est l'état de possession, pas de resoumettre en boucle.
- **Solution** : vérifier `authUserInUserOwns` / l'état *owned* via l'API HTB **avant** de suspecter la
  lecture ou l'instance. Si déjà owned → ne pas resoumettre, c'est un succès.
- **Règle** : flag refusé mais disque cohérent et autre flag de l'instance accepté → **vérifier l'état owned
  (authUserInUserOwns) avant de s'acharner** ; ne pas enchaîner relectures/respawn.
- **Problème 2 (process, blocage modèle)** : les modèles **Claude 5.5 (Opus ET Sonnet)** ont déclenché un
  **faux positif de refus « cyber »** sur recon/exploit/writeup d'une box pourtant légitime (HTB, lab isolé),
  bloquant la chaîne.
- **Solution** : pinner **`claude-opus-4-8`** (override model) pour les sous-agents recon/exploit/writeup des
  challenges offensifs ; documenté dans `notes.md`.
- **Règle** : sur un refus « cyber » manifestement erroné en contexte CTF autorisé, **pinner opus-4-8** plutôt
  que de reformuler indéfiniment ; noter l'override dans `notes.md`.
- **Problème 3 (1re box réseau, hygiène)** : première machine réseau de l'équipe (vs challenges fichier).
  Risque de **placeholders IP/creds oubliés** dans le solveur exporté et de fuite d'IP d'instance.
- **Règle** : boxes réseau : le solveur final prend cible/VPN **en argument** (pas d'IP/creds en dur ni de
  placeholder `<HOST>` non résolu laissé actif) ; aucune IP d'instance ni credential réel dans les fichiers
  committés/exportés (cf. règle 12). `challenges/` reste gitignoré.
- **Process (bon)** : recon-report complet et priorisé (CVE-2025-57819 en vecteur #1, confirmée), foothold en
  1 vecteur, privesc trouvée après énumération méthodique. Exegol respecté (`exegol-ctf-connected`), rôle
  orchestrateur tenu. Impasse GPG (sysadmin_manager) proprement diagnostiquée et consignée.
- **Technique** : FreePBX endpoint unauth → auth-bypass → SQLi stackée → RCE (cron_jobs/scheduler) ; privesc
  modprobe.d writable + directive `install` déclenchée en root par un trigger incron non signé. Voir
  [[techniques]] §§ Web, Privilege Escalation (Linux).

---

## Règles accumulées (consultation rapide)

1. Confirmer le mode/format de chiffrement par reverse **avant** tout brute-force (GameLoader).
2. Vérifier la dispo d'un outil avant d'en dépendre ; sinon l'**installer** dans le conteneur
   (`apt install …`, ex. `python3-fpylll`), et ne réimplémenter en Python que le simple (protocole,
   parsing : EtherTag). En particulier **jamais de LLL/calcul lourd en pur-Python** (NoiseCodex : >120 s
   vs 0,05 s avec fpylll).
3. Analyse statique la moins coûteuse d'abord ; exécution/patch en recours (SpookyPass).
4. Un flag est souvent un tableau d'entiers (1 entier = 1 char ASCII) : vérifier `.data` / les tags.
5. Toujours charger le skill `ctf-<catégorie>` avant d'attaquer — ne pas réinventer la technique.
6. Remplir `recon-report.md` même quand le triage est rapide (NoiseCodex).
7. Archive protégée : essayer `hackthebox` d'office, ne pas croire `file_password: None` du CLI HTB (PartialEncryption).
8. Instructions `aes*` (AES-NI) dans un binaire = crypto maison : les réimplémenter en Python, ne pas exécuter (PartialEncryption).
9. Code décrypté au runtime : se méfier des routines leurres ; le flag peut être dans les `cmp argv[1][i]` du vrai checker.

10. Challenge HTB container-only (pas de fichier) : spawn via `POST /api/v4/container/start` (Origin/Referer), pas de download (SuspiciousThreat).
11. `objdump` d'Exegol = aarch64 : inutilisable sur du x86 ; `strings`/`nm -D`/`readelf` (SuspiciousThreat).
12. Jamais de token/IP/identifiants d'instance dans les fichiers committés ; ne pas lancer `ctf_cli.py status` (fuite du token).
13. Rootkit userland (hook `readdir`) : lire par chemin absolu ou `getdents64` brut, sans modifier la cible.
14. APK : `jadx` absent de l'image free, partir directement sur `apktool` + smali ; un seul essai d'install (timeout) (APKey).
15. Login/vérif : avant de cracker, vérifier si la sortie de succès dépend de l'entrée ; sinon recalculer statiquement (APKey).
16. Python Exegol : pas de pycryptodome/pip, utiliser `cryptography` pour AES (APKey).
17. Writeup : transmettre chemin vault exact (catégorie HTB « Mobile » incluse) et texte de l'énoncé (APKey).
18. Flag HTB refusé mais disque cohérent / autre flag de l'instance accepté → vérifier l'état *owned*
    (authUserInUserOwns) avant de s'acharner ; ne pas resoumettre ni respawn en boucle (Connected).
19. Refus « cyber » erroné des modèles 5.5 (Opus/Sonnet) sur un CTF autorisé → pinner `claude-opus-4-8`
    pour les sous-agents offensifs, noter l'override dans `notes.md` (Connected).
20. Box réseau : cible/VPN en argument du solveur, aucun placeholder IP/creds laissé actif, aucune IP
    d'instance ni credential réel dans les fichiers exportés (Connected ; cf. règle 12).
21. Privesc Linux : préférer un déclencheur root **non signé** (incron legacy, systemd) à un chemin à
    hooks GPG ; valider le trigger avec `pgrep -x <daemon>`, pas `ps|grep` (Connected).

---

_Dernière mise à jour : 2026-11-18 (Connected)_
