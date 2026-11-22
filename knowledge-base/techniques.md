# Techniques éprouvées — Knowledge Base

> **Journal expérientiel**, pas une encyclopédie. Les techniques génériques vivent dans
> les skills `ctf-*` (`skills/`). Ici on consigne UNIQUEMENT ce qu'on a réellement
> appliqué sur un challenge : le piège clé, l'astuce qui a débloqué, et le skill à charger.
> Mis à jour par l'agent `review` / `/ctf-retro` après chaque challenge.
> **Consulter avant chaque recon et exploit.**

Format d'une entrée :
- **Technique** — nom court
- **Catégorie / skill** — quel skill `ctf-*` couvre le détail
- **Challenge(s)** — où ça a servi
- **Insight clé** — le truc non évident qui a fait gagner (ou perdre) du temps
- **Approche** — commande / méthode condensée

---

## Reverse Engineering

### Extraction statique de flag/mot de passe en clair (`.rodata` / `.data`)
- **Catégorie / skill** : reverse → `ctf-reverse`
- **Challenge(s)** : SpookyPass (HTB)
- **Insight clé** : sur un binaire **not stripped** et non obfusqué, le flag peut être un
  tableau d'`int32` dans `.data` (un entier = un caractère ASCII), reconstruit par une
  boucle `buffer[i] = (char)parts[i]`. Inutile d'exécuter : `strings` + parsing des sections suffit.
- **Approche** : `file`, `strings`, `nm` pour repérer les symboles (`main`, `parts`) → parser
  `.data` à l'offset fichier pour lire le tableau. Sur macOS, pas d'`objdump`/`gdb` ELF :
  parsing ELF + désassemblage via **Python (pwntools/capstone)**.

### Déchiffrement d'un PCK Godot (FileAccessEncrypted) — attention au mode AES
- **Catégorie / skill** : reverse + crypto → `ctf-reverse`, `ctf-crypto`
- **Challenge(s)** : GameLoader (HTB)
- **Insight clé** : Godot chiffre le PCK en **AES-256-ECB** par défaut, MAIS un challenge peut
  avoir **patché le template** pour utiliser **CFB avec un IV de 16 octets** inséré après
  `MD5(16) + plaintext_size(8)`. Un brute-force de clé qui valide avec le *mauvais mode*
  échoue toujours → **toujours confirmer le mode en reversant `open_and_parse` avant de bruteforcer**.
- **Approche** : localiser la clé via le pointeur global dans `.data` (suivre le `mov r14, [rip+...]`
  qui référence la clé lors du check magique `GDPC`). Puis `AES.new(key, MODE_CFB, iv, segment_size=128)`,
  vérifier via le MD5 du répertoire. Décompilation : **GDRETools / gdsdecomp**.

### Déobfuscation GDScript (tableaux d'entiers → base64 → texte)
- **Catégorie / skill** : malware → `ctf-malware`
- **Challenge(s)** : GameLoader (HTB) — flag en 2 parties concaténées
- **Insight clé** : l'obfuscation = variables à noms aléatoires contenant des tableaux
  d'entiers (mix décimal/hex/binaire), assemblés en chaîne puis décodés base64. Le flag
  et les IOC (domaine C2, chemin de payload) sont tous encodés pareil. Reconstituer les
  concaténations de variables (`loap = zbxp + qiro`) avant de décoder.
- **Approche** : extraire chaque tableau → `''.join(chr(c))` → `base64.b64decode`.

### Partial runtime decryption via AES-NI (blobs `.data` déchiffrés à l'exécution)
- **Catégorie / skill** : reverse → `ctf-reverse`
- **Challenge(s)** : PartialEncryption (HTB #306, PE64 x86-64)
- **Quand l'utiliser** : PE sans chaînes, `.data` anormalement grosse (0xa00 pour 13 Ko), imports
  `VirtualAlloc`/`VirtualProtect`, `main` qui passe `putchar`/`exit`/`argv` à des routines.
- **Insight clé** : un déchiffreur commun fait `VirtualAlloc(RW)` → transfo par bloc de 16 o →
  `VirtualProtect(RX)` → appel du shellcode. La transfo n'est pas un XOR mais des instructions
  **AES-NI** : `result = aesdeclast(block XOR aeskeygenassist(key,0x10), aeskeygenassist(key,0x00))`,
  avec `key16` = octet d'index du bloc broadcasté. Un seul tour, clé triviale → **réimplémentable
  sans exécuter le PE** (ni wine, ni debug, anti-debug sans objet).
- **Approche** :
  1. `r2 -q -c 'aaa; pdf @ main'` puis `pdf` du déchiffreur et de la primitive → repérer `aes*`.
  2. Dumper `.data` : `r2 -q -c 's 0x140004000; wtf /workspace/data.bin 0xa00' bin.exe`.
  3. Python : S-box AES + inverse, `aeskeygenassist` (SubWord, RotWord = **ROR 8**, xor rcon),
     `aesdeclast` = InvShiftRows (col-major) + InvSubBytes + xor roundkey.
  4. Déchiffrer chaque blob, désassembler (`r2 -a x86 -b 64 -c 'pd 300' blob.bin`).
  5. Extraire les constantes du vrai checker (`cmp eax, <char>` sur `argv[1][index]`).
- **Pièges** : certains blobs sont des **leurres** (message d'usage via `putchar`) ; le flag est
  dans les `cmp`, pas dans la sortie. Valider la transfo : tous les blobs doivent donner du x86 valide.

---

### APK Android "login" : secret constant déchiffré hors-ligne depuis le smali (sans jadx)
- **Catégorie / skill** : reverse (HTB « Mobile ») → `ctf-reverse`
- **Challenge(s)** : APKey (HTB #240, Easy) : flag en ~5 min, 1 tentative
- **Quand l'utiliser** : APK avec formulaire login dont le succès affiche un Toast/texte déchiffré.
- **Insight clé** : se demander si le message de succès dépend de l'entrée. Ici `Toast(b.a(g.a()))`
  n'a aucun argument issu du formulaire : clé AES et ciphertext sont des constantes. Le mot de passe
  (MD5 comparé) n'a jamais besoin d'être cracké. À noter aussi : un hex fabriqué par
  `Integer.toHexString(b & 0xff)` perd les zéros de tête (30 hex au lieu de 32), donc non crackable
  via tables MD5 standard.
- **Approche (outillage)** : `apktool` suffit si `jadx` est indisponible (`apt-get install jadx` échoue
  dans l'image Exegol free). Lire `onClick` (`MainActivity$a.smali`), puis les classes de génération.
  Obfuscation « listes de chaînes leurres + index fixe » : regex sur `const-string` et sur l'index
  `const/4` précédant `ArrayList->get`, puis assemblage.
- **Pièges** : registres smali réutilisés (`vN` change de valeur) : suivre les affectations dans l'ordre pour
  l'ordre des `charAt`. `Cipher.getInstance("AES")` = AES/ECB/PKCS5 sous Android. Validation : padding
  PKCS5 valide + texte lisible. Python Exegol : pas de pycryptodome ni pip, utiliser `cryptography`
  (`Cipher(algorithms.AES(k), modes.ECB())`).
- **Alternative lourde (non testée)** : Frida / émulateur pour appeler `b.a(g.a())`.

## Crypto

### Approximate-GCD (ACD) par SDA + LLL
- **Catégorie / skill** : crypto → `ctf-crypto`
- **Challenge(s)** : Noise Codex (HTB #1419, Easy) — flag en 0,05 s une fois fpylll installé
- **Insight clé** : chiffrement bit par bit `c = p*distortion + 2*entropy + b` avec `p` (premier
  1024 bits) NON fourni. Comme `2*entropy + b < 2^514 ≪ p`, on a `c mod p = bruit` donc
  `b = (c mod p) & 1`. Tout le problème se réduit à retrouver `p` : c'est de l'approximate-GCD
  (`c_i = p*q_i + r_i`, `r_i` petit). Signal de reconnaissance : un « bruit » additif borné
  très inférieur à un modulus secret + plusieurs centaines d'échantillons.
- **Approche** : attaque SDA (simultaneous Diophantine approximation). Avec `x0..xt` échantillons
  et `ρ` = taille du bruit (514), base de dimension t+1 :
  ligne 0 = `[2^(ρ+1), x1, …, xt]`, ligne i = `-x0` en colonne i. LLL → le vecteur court
  `v[0] = q0*2^(ρ+1)` donne `q0 = |v[0]| / 2^(ρ+1)` puis `p = x0 // q0`. t=11 (dim 12) = marge
  large (le gap est assuré dès t>4). Vérifier : `p` fait 1024 bits et `c_i % p < 2^514`.
  Puis les 328 bits `b_i` → 41 caractères ASCII.
- **Piège outillage** : image Exegol `free` sans fpylll/sage → `apt-get install -y python3-fpylll`
  (cf. [[lessons-learned]] 2026-10-30). Un LLL pur-Python sur `Fraction` n'est pas viable
  (>120 s, vs 0,05 s en C).

---

## Forensics

### Rootkit userland LD_PRELOAD (`/etc/ld.so.preload`) — hook `readdir`
- **Catégorie / skill** : forensics (machine live) → `ctf-forensics`
- **Challenge(s)** : SuspiciousThreat (HTB #746)
- **Symptômes de l'énoncé** : « erreurs de linking de libs », dossiers « manquants » alors que leur existence est confirmée → penser LD_PRELOAD/ld.so.preload d'office.
- **Insight clé** : le hook ne filtre que les **listings** (`readdir`/`readdir64`) et `fopen`. `open()`, `stat()`, `cat` par **chemin absolu** ne sont pas interceptés. Donc inutile de désarmer le rootkit : si on devine/déduit le chemin, `cat` suffit. Le nom caché (`pr3l04d_`) est lisible dans `strings` de la lib.
- **Approche** :
  1. `cat /etc/ld.so.preload` (lisible alors que `ls /etc` ne le liste pas), `env | grep LD_`.
  2. Récupérer la lib par `scp` (visible dans `ls`), puis `nm -D` (exports `readdir/readdir64/fopen`), `strings` (motifs filtrés), `objdump -s -j .rodata`. Pas besoin de désassembler.
  3. Réénumérer avec un `getdents64` brut (Python `ctypes.syscall(217, fd, buf, n)`, **x86_64 seulement**, parser `ino,off,reclen,type,name`) : révèle les entrées masquées.
  4. Lire par chemin direct (`cat /var/pr3l04d_/flag.txt`). Dans un dossier caché, les fichiers dont le nom ne contient pas le motif restent listables.
- **À éviter** : modifier la cible (`mv /etc/ld.so.preload`) sans nécessité. `objdump` d'Exegol est aarch64, donc inutilisable sur la lib x86-64 (voir [[lessons-learned]]).

---

## ICS / Systèmes industriels

### Lecture non authentifiée de tag EtherNet/IP (CIP)
- **Catégorie / skill** : misc/réseau industriel → `ctf-misc` (+ recherche CVE)
- **Challenge(s)** : EtherTag (HTB) — Allen-Bradley 1756-L61/B
- **Insight clé** : EtherNet/IP v1/v2 **n'a aucune authentification** (CIP Security seulement
  en v3.21+). Le flag était dans un tag `flag` (INT[100], 1 entier = 1 caractère ASCII),
  lisible via service CIP **ReadTag (0x4c)**. Réf : CVE-2012-6435, ICSA-12-146-01.
- **Approche** : `Register Session (0x65)` → `SendRRData (0x6f)` + ReadTag avec path ANSI
  Extended Symbolic `\x91\x04flag\x00`, count=100. Outil dédié : **pycomm3** / **cpppo**
  (`CIPDriver(ip).get_tag_list()`), mais ici fait à la main en sockets Python.
- **Fingerprint** : `List Identity (0x63)` donne vendor/device/révision du PLC.

---

## Web (foothold applicatif)

### FreePBX : endpoint non authentifié → auth-bypass → SQLi stackée → RCE
- **Catégorie / skill** : web (foothold machine Linux) → `ctf-web`
- **Challenge(s)** : Connected (HTB #906, Easy) — 1re box réseau de l'équipe, foothold en 1 vecteur
- **Quand l'utiliser** : cible FreePBX/Sangoma (frontend Asterisk, souvent CentOS 7, Apache+PHP) dont
  le framework est **antérieur au correctif 16.0.89 / 15.0.66 / 17.0.3** et expose le module commercial
  `endpoint`. Fingerprint : `/admin` redirige, page « FreePBX Administration » avec `load_version=…`,
  `config.php?display=endpoint` → 200.
- **Insight clé** : CVE-2025-57819 (CISA KEV, CVSS 4.0 = 10.0) enchaîne trois primitives — (1)
  **auth-bypass** en passant le module via son chemin de classe (`module=FreePBX\modules\endpoint\ajax`)
  pour atteindre le code du module sans session ; (2) **SQLi stackée** sur le paramètre `brand` de
  `admin/ajax.php`, qui permet un `INSERT` ; (3) **RCE** en insérant une tâche dans la table `cron_jobs`,
  exécutée ~toutes les 60 s par le **scheduler DAG** de FreePBX (utilisateur `asterisk`) → dépôt d'un
  webshell PHP dans `/var/www/html`. Shell obtenu : `uid=asterisk`.
- **Approche** : partir du PoC public watchTowr (`watchTowr-vs-FreePBX-CVE-2025-57819`), l'adapter au
  vhost en HTTPS auto-signé (`-k`). Vérifier l'auth-bypass d'abord (une erreur 500 « array offset on
  value of type bool » dans `modules/endpoint/views/model.php` prouve qu'on atteint le code du module).
- **Pièges** : le `+` d'un payload base64 devient espace dans l'URL → encoder `+`→`%2b` sinon le webshell
  est corrompu. Attendre le passage du scheduler (jusqu'à ~60 s) avant de tester le webshell. Post-foothold :
  creds MySQL dans `/etc/freepbx.conf`, secrets dans `freepbx_settings` (aucun n'a marché en SSH ici).

## Privilege Escalation (Linux)

### `/etc/modprobe.d/*.conf` writable + directive `install` déclenchée en root au chargement d'un module
- **Catégorie / skill** : privesc Linux → `ctf-web` (workflow machine) / recherche locale
- **Challenge(s)** : Connected (HTB #906, Easy) — asterisk → root
- **Quand l'utiliser** : compte de service peu privilégié, `/etc/modprobe.d/<x>.conf` **writable** par ce
  compte (vérifier chaque fichier, pas que le dossier), et un **module non chargé** qu'un processus root
  peut (re)charger. Chercher un **déclencheur root** du `modprobe` : service systemd, init-script, ou ici
  un watch incron.
- **Insight clé** : une ligne `install <module> <commande>` dans un fichier modprobe.d fait exécuter
  `<commande>` **par kmod en root** à la place du chargement du module, à chaque `modprobe <module>`. Il
  suffit donc d'un chemin root qui invoque `modprobe`. Payload gagnant = **commande inline unique**
  (`install <mod> /usr/bin/install -m 6755 /bin/bash /chemin/RB` → bash setuid root), **pas un script
  wrapper** (`install <mod> /bin/bash /tmp/p.sh` n'a rien produit).
- **Approche** : écrire la directive dans le `.conf` writable, déclencher le chargement root, puis
  `./RB -p -c 'id; cat /root/root.txt'` (euid 0).
- **Pièges** :
  - **Choisir le bon déclencheur root.** Ici deux watches incron coexistaient : le watch `legacy`
    (`/var/spool/asterisk/sysadmin/dahdi_restart` IN_CLOSE_WRITE → `sysadmin_dahdi_restart` → `/etc/init.d/dahdi
    restart` → `modprobe dahdi`) **sans vérif GPG** = le bon ; le watch `sysadmin_manager` (chemin à hooks
    **signés GPG**) = impasse (cf. ci-dessous). Toujours préférer le chemin root **sans signature**.
  - **Vérifier que le trigger a bien lieu en root** avec `pgrep -x asterisk` (le daemon s'arrête un instant),
    **pas** `ps|grep asterisk` (apache tourne sous l'**utilisateur** asterisk → compteur faussé).
  - L'init-script peut être redirigé vers **systemd** ; `modprobe` s'exécute alors en root dans le service
    (PPID 1), pas dans le shell de l'init-script.

### Impasse à connaître : hook « signé GPG » dont le keyring dépend de `getpwuid(uid)`
- **Catégorie / skill** : privesc Linux (anti-pattern) → note expérientielle
- **Challenge(s)** : Connected (HTB #906) — Tentative 3, ~40 min perdues
- **Insight clé** : le watch incron `sysadmin_manager` termine par `system("$hookfile $params")`. L'injection
  de **pipe** marche (`|` absent de la blacklist `[ ' " $ > < & ; ]`, et la magie `CONTENTS` fait lire les
  params depuis le contenu d'un fichier → autorise `/` et espaces). MAIS la classe GPG (ionCube) résout son
  homedir via **`getpwuid(uid courant)`**, pas via `$HOME`. Lancé en root par incrond, elle cherche
  `/root/.gnupg` (pas de clé FreePBX) → `checkSig` échoue → « Module tampered » → `exit` **avant** `system()`.
  L'injection ne « marche » qu'invoquée manuellement en tant qu'asterisk → inutile pour la privesc.
- **Règle** : un chemin root « protégé par signature » dont le keyring se résout par `getpwuid` est
  inexploitable si le compte bas-privilège ne peut pas peupler `/root/.gnupg`. Tester tôt
  (`env -i HOME=/tmp/x …` montre que `$HOME` est ignoré) et basculer sur un déclencheur **non signé**.

## Méta / environnement

### macOS sans outils Linux natifs → sockets & parsing Python
- **Challenge(s)** : SpookyPass, EtherTag, GameLoader
- **Insight clé** : sur ce poste macOS, `nmap`, `objdump` ELF, `gdb` ne sont pas dispo.
  Ne pas bloquer : **réimplémenter en Python** (parsing ELF/PE, sockets bruts pour
  EtherNet/IP, capstone pour le désassemblage). Toujours vérifier la dispo d'un outil
  avant de baser un plan dessus.

---

_Dernière mise à jour : 2026-11-18 (Connected : FreePBX CVE-2025-57819 + privesc modprobe.d/install)_
