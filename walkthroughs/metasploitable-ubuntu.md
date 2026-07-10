---
kind: walkthrough
platform: generic
target: metasploitable-ubuntu
scope: internal
os: linux
tags: [metasploitable, lab]
---

# Metasploitable — Ubuntu

## Services

| Port | Service | Comments |
| --- | --- | --- |
| 21 | FTP | ProFTPD |
| 22 | SSH | OpenSSH |
| 80 | HTTP | Apache |
| 445 | SMB | Samba |
| 631 | ipp | CUPS |
| 3306 | MySQL | - |
| 3500 | http | WEBrick |
| 6697 | irc | UnrealIRCd |
| 8080 | http | Jetty |

## Findings

### RCE — UnrealIRCd backdoor

MSF module: `unreal_ircd_3281_backdoor`. The outdated UnrealIRCd instance allows
remote code execution, giving a shell as `boba_fett`. The account password
couldn't be recovered, but an SSH key was added to the profile to establish a
persistent foothold over SSH.

<!-- meta: technique=remote-exec -->
```bash
msf6 > use exploit/unix/irc/unreal_ircd_3281_backdoor
```
