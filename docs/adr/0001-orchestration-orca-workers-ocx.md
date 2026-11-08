# ADR 0001 — Orchestration CTF via workers Orca routés ocx

- **Statut** : Accepté
- **Date** : 2026-11-08
- **Décideurs** : WhiteRose (validé en session par tests réels)

## Contexte

L'orchestration CTF reposait sur un orchestrateur unique (la session principale) qui lançait
des sous-agents `recon`/`exploit` en tâche de fond, un jeu par challenge. Deux limites :

- les sous-agents de fond ne sont **pas interactifs** : impossible pour l'utilisateur d'entrer
  dans la résolution d'un challenge pour aider ou aiguiller ;
- aucun moyen propre d'isoler le travail de plusieurs challenges en parallèle.

L'environnement dispose d'**Orca** (ADE : 1 git worktree + 1 agent par tâche, workers parallèles,
sous-système d'orchestration natif) et d'**ocx/opencodex** (proxy multi-provider : anthropic +
google-antigravity/Gemini).

## Décision

Architecture à **3 niveaux**, un point d'entrée unique :

1. **Orchestrateur global** (session principale) — utilise le skill **`orchestration`** d'Orca.
   Par challenge : `orca orchestration worker-start --worktree new-top-level --agent <claude>`.
   Il dirige chaque worker par `orca orchestration send --to dispatch:<id>` et est réveillé par
   leurs `worker_done`. Il ne résout jamais lui-même.
2. **Worker Orca** (1 par challenge) — session Claude dans son propre worktree + conteneur Exegol
   dédié. **Ouvrable directement par l'utilisateur** (chat du worker, `--keep-open`). Il mène la
   résolution et délègue en interne à ses sous-agents.
3. **Sous-agents** `recon` / `exploit` (+ `writeup` / `review`) — inchangés, internes au worker.

Deux choix techniques actés :

- **Canal coordinateur↔worker = bus Orca** (`orchestration send` / `ask` / `reply` / `worker_done`),
  **jamais** le `SendMessage` inter-sessions de Claude ni le pilotage par terminal.
- **Workers lancés via `ocx claude`** (commande d'agent Orca), pour router les modèles par le proxy
  ocx et basculer de provider au besoin.

## Justification (validé en session)

- `orchestration send` est **livré sans mise en attente** ; aller-retour `send → worker_done`
  prouvé de bout en bout. Les workers tournent en `bypass permissions` : le bus Orca ignore les
  modes de permission de Claude.
- Routage ocx confirmé : un worker rapporte `ANTHROPIC_BASE_URL=http://127.0.0.1:10100`.

## Conséquences

**Positives**
- L'utilisateur peut entrer dans n'importe quel worker pour aider, sans casser l'orchestration.
- Isolation réelle par challenge (worktree + Exegol + branche dédiés).
- Multi-provider via ocx, bascule selon quota/pertinence.

**Négatives / coûts**
- Dépendance à Orca (app desktop) et à ocx (proxy) pour le cycle complet.
- La commande d'agent `ocx claude` est un **réglage GUI d'Orca** (pas de flag CLI) → étape humaine,
  couverte par `tools/orca-ocx-setup.sh`.

## Alternatives écartées

- **`SendMessage` Claude inter-sessions** : retenu puis expiré quand les modes de permission
  diffèrent (coordinateur en auto mode, worker Orca en bypass). Non fiable.
- **Alignement des modes de permission / `crossSessionInbound: accept`** : rendu inutile par le
  bus Orca ; complexité en moins.
- **Pilotage d'un worker par son terminal** : explicitement interdit par le guide `orchestration`.

## À préciser à l'implémentation

- Répartition `/ctf-start` : l'orchestrateur démarre le worker (worktree) ; la mise en place
  Exegol + structure `challenges/<nom>/` se fait **dans le worktree du worker**.
- Spec de `worker-start` : brief self-contained (plateforme, nom, cible, objectif = flag, livrable).
