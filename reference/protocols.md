---
kind: reference
platform: generic
os: mixed
tags: [protocols, ports]
---

# Protocols & Services

## Common ports

| Port | Service | Port | Service |
| --- | --- | --- | --- |
| 21 | FTP | 1433 | MSSQL |
| 53 | DNS | 3306 | MySQL |
| 443 | HTTPS | 3389 | RDP |
| 445 | SMB | 5985 | WinRM |
| 500 | IKE (UDP) | 8080 | HTTP proxy |

## Notes

- **ARP (L2):** resolves IP↔MAC via broadcast; MACs are swapped in.
- **FTP (21):** active = server-initiated; passive = client-initiated (firewall-friendly).
- **DNS (53):** records A/AAAA/PTR/MX/TXT/NS/SOA/SRV. Zone transfers should be
  IP allow-listed; see recon playbook for `dig axfr` / `fierce`.
- **DHCP (67 UDP):** IPs handed out from a pool.
- **SMB (445):** file shares + interactive sessions.
- **IKE (500 UDP):** aggressive mode sends crackable hashes (see HTB Expressway).
