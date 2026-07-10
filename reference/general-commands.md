---
kind: reference
platform: generic
scope: internal
os: linux
tags: [shell, networking, kali]
---

# General Commands

## Fixed IP via CLI

```bash
ifconfig ethX down
ifconfig ethX x.x.x.x netmask x.x.x.x up
route add default gw x.x.x.x ethX
echo nameserver 10.0.0.1 > /etc/resolv.conf
```

## Networking quick checks

```bash
ip a    # ip breakdown
ip r    # route, default gateways
systemctl stop NetworkManager
```

## Output redirection

```bash
| tee newfile.txt     # console + save to file
| tee -a file.txt     # console + append
nmap -oA out          # oN human, oX xml, oG greppable
```

## Log every terminal to ~/scripts with timestamps

Add to `~/.zshrc` (needs `bsdutils` and a `~/scripts` dir):

```bash
test "$(ps -ocommand= -p $PPID | awk '{print $1}')" == 'script' || (script -f $HOME/scripts/$(date +"%d-%b-%y_%H-%M-%S")_shell.log -T $HOME/scripts/$(date +"%d-%b-%y_%H-%M-%S")_time.log)
```

## Find files

```bash
updatedb
locate *.nse | grep tftp
```

## Nmap XML to HTML

<!-- meta: technique=port-scanning -->
```bash
xsltproc scan.xml -o out.html
```

## Initial scans

<!-- meta: technique=port-scanning -->
```bash
nmap -iL scope.txt -sSCV -p0- -T5 -oA full_tcp_scan -Pn
nmap -iL scope.txt -sUCV -p0- -T5 -oA full_udp_scan -Pn
```

## File transfer over HTTP

<!-- meta: technique=file-transfer -->
```bash
python -m http.server 8080
droopy --dl
```

## Firewall

```bash
iptables -A OUTPUT -d 10.0.0.2 -j DROP
iptables -L
```
