---
kind: reference
platform: generic
os: mixed
tags: [nmap, scanning]
---

# Nmap

## Flag reference

- `-sS --top-ports 1000` — default as root (SYN scan)
- `-sn` — ping sweep, no port scan (ICMP/TCP/ARP; needs sudo for Windows hosts)
- `-Pn` — skip host discovery, treat as up
- `-sU` — UDP ports
- `-sV` — service version detection
- `-A` — OS + version + scripts + traceroute (`-O -sCV --traceroute`)
- `-oA file` — output all three formats (normal/xml/greppable)
- `-T3` standard, `-T5` most aggressive
- `-p0-` — **always** use this for all-ports so port 0 is included

Run two scans as a sanity check: `-sn` for ping-sweep discovery and `-sS` for
open-port discovery.

## Canonical scans

<!-- meta: technique=port-scanning -->
```bash
nmap -sSCV -p0- -T4 -oA tcp_full TARGET
nmap -sUCV --top-ports 1000 -T4 -oA udp_1k TARGET
```
