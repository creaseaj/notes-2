# Pentest Notes — Searchable Command Index

Markdown notes in, a filterable/searchable command index out. Push to GitHub and
it publishes to GitHub Pages automatically.

## Layout

```
reference/        Reusable playbook — canonical, copy-ready commands (placeholders like TARGET/USER)
  recon.md, smb-enumeration.md, credential-access.md, general-commands.md, ...
  tools/          Per-tool references (nmap, netcat, bbot, metasploit, nessus)
walkthroughs/     Engagement / box narratives (GOAD, HTB boxes) — real invocations + evidence
assets/           Images referenced by notes
scripts/build_index.py   Parser: markdown -> site/index.json
viewer/index.html        The filterable UI
site/                    Build output (index.json + index.html), served by Pages
.searchindexignore       Globs excluded from the index (course admin, quizzes, scratch)
```

**Reference vs walkthrough** is the core split. A reference entry is the clean,
reusable version you copy mid-engagement (`nxc smb TARGET -u USER -H NTHASH --ntds`).
A walkthrough entry is the real thing you ran, with its output kept as evidence.
The viewer tags each with a `REFERENCE` / `WALKTHROUGH` badge, so filtering to
e.g. *credential-access* shows both the playbook command and how it actually went.

## Writing notes

Every file starts with frontmatter that all its snippets inherit:

```yaml
---
kind: walkthrough        # walkthrough | reference
platform: goad           # goad | htb | generic ...
target: sevenkingdoms    # optional
scope: internal          # internal | external
os: windows              # windows | linux | mixed
tags: [active-directory]
index: true              # set false to skip the file entirely
---
```

A **command** is a fenced block preceded by a meta comment. You usually only need
`technique=` — tool, phase, scope, os, platform are auto-detected or inherited:

````
<!-- meta: technique=user-enumeration -->
```bash
nxc smb dcs.txt -u '' -p '' --users
```
````

**Output/evidence** goes in a fence right after, marked `<!-- output -->`. It is
attached to the command above as a collapsible block, not indexed separately:

````
<!-- output -->
```
SMB  10.2.10.11  WINTERFELL  Administrator ...
```
````

That command/output split is what makes the copy button copy *just* the command,
and keeps search matching techniques instead of hostnames.

## Auto-tagging

You rarely tag by hand. The parser derives:

- **tool** — from the command (nxc, ffuf, impacket, nmap, hashcat, bloodhound, ...).
- **technique** — from command content (`--ntds` → ntds-dump, `GetUserSPNs` →
  kerberoasting, `-M coerce_plus` → coercion, ...). An explicit `technique=` wins.
- **phase** — kill-chain stage the technique belongs to (recon → initial-access →
  enumeration → credential-access → lateral-movement → privesc → persistence → exfil).

Anything it can't place lands in `misc` / `untagged` so you can find and backfill
it. Extend the maps at the top of `scripts/build_index.py` as your kit grows.

Exact-duplicate commands across files are collapsed into one entry; the extra
source files show as `+N` on the card.

## Deploy (one-time)

1. Push to a **public** GitHub repo.
2. Settings → Pages → Source: **GitHub Actions**.
3. Push to `main`. Every push rebuilds `index.json` and redeploys the viewer to
   `https://<user>.github.io/<repo>/`.

## Local preview

```bash
python scripts/build_index.py . site/index.json
cp viewer/index.html site/index.html && cp -r assets site/assets
cd site && python3 -m http.server 8000   # open http://localhost:8000
```

## Using the viewer

Filter rows for **phase / tool / technique / scope / kind** (multi-select; AND
across rows, OR within a row) plus free-text search over command + context.
Results group under colour-coded kill-chain phases. Each card copies the command
alone; **Copy visible** grabs every command currently shown — handy for assembling
a command list for a specific engagement phase.

## Before pushing (public repo hygiene)

- The HTB notes had live-looking secrets (a Zabbix DB password, session IDs) — those
  are redacted in `htb-watcher.md`. Keep that habit for anything client-identifiable.
- HTB restricts published writeups for **active** boxes; check a box is retired
  (or a VL/lab box) before this goes public.
- GOAD/Metasploitable creds are intentionally public lab defaults — fine to keep.

## What was skipped

Course admin, quizzes, Excalidraw, exam/CPD/law notes and empty stubs from the
original vault aren't reusable pentest content, so they were left out of this pass.
Drop new technical notes into `reference/` or `walkthroughs/` and they're picked
up automatically.
