---
kind: reference
platform: generic
os: mixed
tags: [nessus, vuln-scanning]
index: true
---

# Nessus — Scan Configuration Notes

Advanced scan, most options. Key choices:

- **Host discovery:** disable "ping the remote host". Avoid scanning network
  printers (they may print) and OT devices (can break them).
- **Port scanning:** range = all; no UDP port scanning.
- **Assessment / brute force:** uncheck "only use credentials provided by the
  user" (can lock out accounts).
- **Web apps:** off (personal choice).
- **Report:** uncheck "show missing patches superseded"; designate hosts by DNS name.
- **Credentials:** paste passwords from notepad to be sure they're correct.
  SSH: consider privilege elevation. Windows: enable remote registry, admin
  shares, server service; UAC registry hack to let non-DAs scan Windows hosts.
