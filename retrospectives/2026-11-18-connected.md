# Retrospective — Connected (2026-11-18)

## Score global : B+

Première **box réseau** de l'équipe (HTB #906, Linux Easy), user + root obtenus. Chaîne techniquement
propre : foothold en 1 vecteur (CVE-2025-57819, annoncé #1 au recon), privesc root trouvée après
énumération méthodique. La note est tempérée par trois frictions **process** coûteuses : un blocage
« cyber » des modèles 5.5, une impasse privesc de ~40 min (hook GPG), et un acharnement inutile sur un
user flag refusé alors que la box était déjà *owned*.

## Métriques
| Métrique | Valeur | Tendance vs. précédent |
|----------|--------|----------------------|
| Catégorie | Web (foothold FreePBX) → Machine Linux (user+root) | nouvelle catégorie (1re box réseau) |
| Temps total | recon 17:58 → root ~20:00 UTC ≈ 2 h (dont ~1 h de trou 18:03→19:06, probable blocage modèle/setup) | n/a (incomparable aux challenges fichier) |
| Temps par phase | recon 17:58–18:03 (~5 min) · exploit foothold ~19:06–19:12 · privesc ~19:20–20:00 | n/a |
| Tentatives exploit | foothold : 1 vecteur (1 correctif `+`→`%2b`) · privesc : 5 tentatives dont 1 impasse (hook GPG) | n/a |
| Recon accuracy | Excellent : CVE-2025-57819 en vecteur #1, confirmée ; user `asterisk` prédit | → (tenue) |

Note : les horodatages exploit ont un trou d'~1 h entre la fin du recon (18:03) et la 1re tentative
(~19:06), non expliqué dans le log — probablement le blocage modèle et le setup du PoC.

## Ce qui a bien marché
- **Recon chirurgical** : fingerprint FreePBX 16.0.40.7 + module `endpoint` → CVE-2025-57819 (CISA KEV)
  identifiée et priorisée #1, avec surface confirmée (`config.php?display=endpoint` 200) et PoC public repéré.
- **Foothold en 1 vecteur** : auth-bypass vérifié avant d'aller plus loin (erreur 500 « array offset »
  prouvant qu'on atteint le code du module), SQLi stackée, RCE via `cron_jobs`/scheduler. Reproductible.
- **Diagnostic d'impasse rigoureux** : la piste GPG `sysadmin_manager` a été abandonnée sur **cause racine
  prouvée** (`getpwuid(uid)` → `/root/.gnupg` sans clé), pas sur un abandon vague. Désambiguïsation par
  `env -i HOME=…` pour montrer que `$HOME` est ignoré.
- **Privesc finale solide** : chaîne modprobe.d writable + directive `install` + trigger incron `legacy`
  non signé, validée par preuves intermédiaires (`CPTEST`, bascule chargé/non-chargé selon la directive).
- **Cadre respecté** : Exegol dédié (`exegol-ctf-connected`), rôle orchestrateur tenu, recon-report et
  notes.md remplis, solveur + README dans `solution/`.

## Ce qui peut être amélioré
- **Acharnement sur le user flag refusé** : au lieu de vérifier l'état *owned* (authUserInUserOwns) via
  l'API HTB, l'équipe a multiplié reconnexions root, hexdump, comparaison de mtime et envisagé un respawn.
  Le root flag de l'instance étant accepté, la box était la bonne : le contrôle *owned* aurait tranché
  immédiatement.
- **Blocage modèle 5.5 non anticipé** : faux positif « cyber » (Opus ET Sonnet 5.5) sur recon/exploit/writeup
  d'une box légitime. Contourné par un pin `claude-opus-4-8`, mais découvert à chaud, d'où le trou horaire.
- **Impasse GPG coûteuse (~40 min)** : la piste `sysadmin_manager` (hooks signés) a été poussée loin
  (injection de pipe via `CONTENTS`) avant de constater qu'elle ne s'exécute qu'en tant qu'asterisk. Le
  réflexe « préférer le trigger non signé » aurait économisé ce détour.
- **Pièges d'énumération** : `ps|grep asterisk` trompeur (apache tourne sous l'utilisateur asterisk) ;
  `install dahdi <script wrapper>` muet alors que l'inline marche. Redécouverts en live.

## Patterns récurrents (vs rétros précédentes)
- **Plomberie plateforme = faiblesse n°1 de l'équipe** : après SuspiciousThreat (token/IP, spawn API) et
  APKey (catégorie vault, énoncé), Connected ajoute le non-usage d'authUserInUserOwns. Le technique est fort,
  la mécanique HTB (soumission, état owned, spawn) reste mal maîtrisée.
- **Faux amis / pistes poussées trop loin** : récurrent (GameLoader mode AES, PartialEncryption leurres
  putchar, ici hook GPG). L'équipe sait diagnostiquer la cause racine, mais tard — manque un critère d'arrêt
  précoce (« ce chemin est-il seulement atteignable dans le bon contexte d'exécution ? »).
- **Nouveauté bien absorbée** : 1re box réseau, chaîne web→privesc menée proprement malgré l'absence
  d'expérience antérieure en KB. La discipline recon-report / notes.md tient depuis NoiseCodex.

## §6 Post-mortem process / cadre
- **Rôle orchestrateur** : respecté. Recon puis exploit délégués aux sous-agents ; init/soumission gardées.
  La gestion worker Orca par challenge (worktree + Exegol dédiés) a fonctionné ; le conteneur manuel
  (`exegol-ctf-connected-manual`) a bien été distingué du conteneur piloté.
- **Exegol / hook** : toutes les commandes d'attaque dans `exegol-ctf-connected` (webshell, énumération,
  solveur). Aucune commande offensive hôte rapportée. Politique du hook tenue.
- **Pièges rencontrés** : (1) refus « cyber » 5.5 → pin opus-4-8 ; (2) impasse hook GPG (contexte root ≠
  contexte asterisk) ; (3) `ps|grep` vs `pgrep -x` ; (4) `install` inline vs wrapper ; (5) `+`→`%2b` dans
  l'URL base64 ; (6) user flag refusé = box déjà owned, pas une erreur de lecture.
- **Sorties de périmètre** : aucune majeure. Le recon a aussi esquissé le post-exploit (creds MySQL,
  pistes privesc) — utile et dans son rôle d'analyse.
- **Coût** : ~1 h de trou (blocage modèle + setup PoC), ~40 min sur l'impasse GPG, et un temps non chiffré
  d'acharnement sur le user flag. Pas d'outil réinstallé inutilement ; PoC watchTowr réutilisé.

## Actions pour le prochain challenge
- [ ] Box HTB : après lecture d'un flag refusé, **vérifier l'état owned (authUserInUserOwns) avant tout**
      resubmit/respawn ; si owned → succès, on arrête.
- [ ] Challenges offensifs : pinner `claude-opus-4-8` d'emblée pour recon/exploit/writeup ; ne pas perdre de
      temps à reformuler un refus « cyber » erroné.
- [ ] Privesc Linux : énumérer les déclencheurs root **non signés** (incron legacy, systemd, cron) avant un
      chemin à hooks GPG ; valider un trigger daemon avec `pgrep -x`, pas `ps|grep`.
- [ ] Box réseau : solveur paramétré (cible/VPN en argument), zéro placeholder IP/creds laissé actif, zéro
      IP/credential réel exporté.
- [ ] Horodater le début/fin réels de chaque phase (le trou 18:03→19:06 n'est pas documenté).

## Modifications suggérées aux agents
- **exploit** : ajouter au workflow « machine Linux » une checklist privesc priorisant les **triggers root
  non signés** (modprobe.d `install`, init/systemd, cron, incron legacy) et un garde-fou « avant de pousser
  un chemin, vérifier qu'il est atteignable dans le contexte d'exécution root visé » (ex. keyring GPG résolu
  par `getpwuid`). Rappeler `pgrep -x` vs `ps|grep` et « payload inline, pas de wrapper » pour `install`.
- **review / orchestrateur (soumission)** : avant de traiter un flag comme « refusé », interroger
  `authUserInUserOwns` ; documenter la règle dans `/ctf-submit`.
- **orchestrateur / `/ctf-start`** : pour un challenge offensif, pinner `claude-opus-4-8` sur les sous-agents
  par défaut (le refus « cyber » 5.5 est désormais un pattern connu), et le consigner dans `notes.md`.
- **recon** : pour une cible applicative à CVE connue (FreePBX, etc.), fournir au recon le lien PoC + la
  version de correctif, comme fait ici — à garder comme standard.

## KB mise à jour
- `techniques.md` § Web : FreePBX endpoint unauth → auth-bypass → SQLi stackée → RCE (CVE-2025-57819).
- `techniques.md` § Privilege Escalation (Linux) : modprobe.d writable + directive `install` déclenchée en
  root ; + impasse « hook signé GPG via getpwuid ».
- `lessons-learned.md` : leçon Connected (authUserInUserOwns, pin opus-4-8, hygiène box réseau), règles 18 à 21.
