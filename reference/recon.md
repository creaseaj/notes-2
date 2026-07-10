---
kind: reference
platform: generic
scope: external
os: mixed
tags: [recon, osint, dns, subdomains]
---

# Recon Playbook

## Passive / OSINT

Location and job info, employee photos (desks, badges, screens). Useful sources:
hunter.io (email patterns), https://phonebook.cz, Clearbit Connect (Chrome).

Target validation: WHOIS, nslookup, dnsrecon — confirm scope is valid before touching anything.

## Subdomain enumeration

<!-- meta: technique=subdomain-enumeration -->
```bash
sublist3r -d tesla.com -t 40
```

crt.sh — enter `%.tesla.com` for all certs associated with the domain.

### bbot

<!-- meta: technique=subdomain-enumeration -->
```bash
bbot -t tesla.com -p subdomain-enum
bbot -t tesla.com -p subdomain-enum -rf passive
```

<!-- meta: technique=osint -->
```bash
bbot -t tesla.com -p email-enum
```

## DNS zone transfers

<!-- meta: technique=zone-transfer -->
```bash
dig axfr domain @nameserver
host -l domain nameserver
fierce --domain DOMAIN
```

`fierce` is useful when the domain resists straight zone transfers.

## Web fingerprinting

<!-- meta: technique=web-fingerprinting -->
```bash
whatweb https://tesla.com
```

Also: wappalyzer, https://builtwith.com, netcat banner grabs, wafw00f.

## Content discovery

<!-- meta: technique=content-discovery -->
```bash
ffuf -u http://TARGET/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302
```

## Vhost fuzzing

<!-- meta: technique=subdomain-enumeration -->
```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://TARGET -H "Host: FUZZ.domain" -fs SIZE
```
