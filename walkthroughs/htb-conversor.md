---
kind: walkthrough
platform: htb
target: conversor
scope: external
os: linux
tags: [htb, xxe]
---

# HTB — Conversor

Linux box. Web app processes XML with lxml/xslt — points toward XXE. *(In progress.)*

## Recon

<!-- meta: technique=port-scanning -->
```bash
nmap --privileged -sSCV -p0- -T4 -oA tcp_full 10.129.7.119
nmap --privileged -sUV --top-ports 100 -T4 -oA udp_quick 10.129.7.119
```
<!-- output -->
```
22/tcp  open  ssh   OpenSSH 8.9p1 Ubuntu
80/tcp  open  http  Apache 2.4.52  -> redirects to http://conversor.htb/
UDP: all top-100 in ignored states
```

## Notes

Source downloaded from the site uses lxml and XSLT — all roads point to XXE. Exploitation TBD.
