---
kind: reference
platform: generic
os: mixed
tags: [bbot, recon]
---

# bbot

Scope control with `--whitelist` / `--blacklist` (same format as target files).
Docs: https://www.blacklanternsecurity.com/bbot/Stable/scanning/#scope

<!-- meta: technique=subdomain-enumeration -->
```bash
bbot -t tesla.com -p subdomain-enum
bbot -t tesla.com -p subdomain-enum -rf passive
```

<!-- meta: technique=osint -->
```bash
bbot -t tesla.com -p email-enum
```

Filter URL output: `| grep '[URL]' | cut -f2`
