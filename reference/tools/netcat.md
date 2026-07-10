---
kind: reference
platform: generic
os: mixed
tags: [netcat]
---

# Netcat

Flags: `-u` UDP, `-v`/`-vv` verbose, `-l` listen, `-n` numeric only (no DNS).
Useful for banner grabbing.

<!-- meta: technique=service-discovery -->
```bash
nc -nv TARGET PORT
```
