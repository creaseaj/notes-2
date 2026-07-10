#!/usr/bin/env python3
"""
Build index.json from refactored pentest notes.

Conventions this parser understands
------------------------------------
1. YAML-ish frontmatter at the top of each file, inherited by every snippet:

   ---
   kind: walkthrough        # walkthrough | reference
   platform: goad           # goad | htb | generic ...
   target: sevenkingdoms    # optional free text
   scope: internal          # internal | external
   os: windows              # windows | linux | mixed
   tags: [active-directory] # optional list
   index: true              # set false to skip this file
   ---

2. A runnable command is a fenced block immediately preceded by a meta comment.
   Only `technique` is usually needed per-snippet; everything else is inherited.

   <!-- meta: technique=user-enumeration -->
   ```bash
   nxc smb dcs.txt -u '' -p '' --users
   ```

3. Console output / evidence for the previous command goes in a fence directly
   preceded by an <!-- output --> marker. It is attached to that command as
   collapsible context, NOT indexed as its own snippet.

   <!-- output -->
   ```
   SMB  10.2.10.11  445  WINTERFELL  Administrator ...
   ```

Tool, technique and kill-chain phase are auto-detected from the command text.
An explicit `technique=` in meta always wins; its phase is looked up in
TECHNIQUE_PHASE. Bare (meta-less) fenced blocks are still captured with a
best-effort auto tag so nothing is silently lost.

Usage: python build_index.py <notes_root> <output_json_path>
"""
import sys
import re
import json
import hashlib
from pathlib import Path

# ---------------------------------------------------------------------------
# Kill-chain phases, in the order you actually move through an engagement.
# The viewer uses this order for grouping.
# ---------------------------------------------------------------------------
PHASE_ORDER = [
    "recon",
    "initial-access",
    "enumeration",
    "credential-access",
    "lateral-movement",
    "privesc",
    "persistence",
    "exfil",
    "misc",
]

# technique -> phase. Extend freely; unknown techniques fall back to 'misc'
# (or the file's frontmatter default phase if present).
TECHNIQUE_PHASE = {
    "port-scanning": "recon",
    "service-discovery": "recon",
    "host-discovery": "recon",
    "vuln-scanning": "recon",
    "content-discovery": "recon",
    "subdomain-enumeration": "recon",
    "dns-recon": "recon",
    "zone-transfer": "recon",
    "web-fingerprinting": "recon",
    "osint": "recon",
    "ike-enumeration": "recon",
    "hostfile-generation": "recon",
    "user-enumeration": "enumeration",
    "share-enumeration": "enumeration",
    "ad-enumeration": "enumeration",
    "data-discovery": "enumeration",
    "kerberoasting": "credential-access",
    "asreproasting": "credential-access",
    "hash-cracking": "credential-access",
    "ntds-dump": "credential-access",
    "lsass-dump": "credential-access",
    "dpapi-looting": "credential-access",
    "psk-cracking": "credential-access",
    "password-spraying": "credential-access",
    "pass-the-hash": "lateral-movement",
    "remote-exec": "lateral-movement",
    "delegation-abuse": "lateral-movement",
    "coercion": "lateral-movement",
    "sudo-exploit": "privesc",
    "kernel-exploit": "privesc",
    "privesc-enum": "privesc",
    "add-domain-admin": "persistence",
    "add-user": "persistence",
    "file-transfer": "exfil",
}

# Tool detection: first matching pattern against the command's first line.
TOOL_PATTERNS = [
    (r"^\s*(sudo\s+)?nxc\b", "nxc"),
    (r"^\s*(sudo\s+)?crackmapexec\b", "nxc"),
    (r"^\s*(sudo\s+)?ffuf\b", "ffuf"),
    (r"^\s*(sudo\s+)?gobuster\b", "gobuster"),
    (r"^\s*(sudo\s+)?impacket-\w+", "impacket"),
    (r"^\s*(sudo\s+)?bloodhound(-ce)?-python\b", "bloodhound"),
    (r"^\s*(sudo\s+)?nmap\b", "nmap"),
    (r"^\s*(sudo\s+)?hashcat\b", "hashcat"),
    (r"^\s*(sudo\s+)?evil-winrm\b", "evil-winrm"),
    (r"^\s*(sudo\s+)?ike-scan\b", "ike-scan"),
    (r"^\s*(sudo\s+)?psk-crack\b", "psk-crack"),
    (r"^\s*(sudo\s+)?sublist3r\b", "sublist3r"),
    (r"^\s*(sudo\s+)?bbot\b", "bbot"),
    (r"^\s*(sudo\s+)?nuclei\b", "nuclei"),
    (r"^\s*(sudo\s+)?whatweb\b", "whatweb"),
    (r"^\s*(sudo\s+)?wafw00f\b", "wafw00f"),
    (r"^\s*(sudo\s+)?fierce\b", "fierce"),
    (r"^\s*(sudo\s+)?dig\b", "dig"),
    (r"^\s*host\s+-l\b", "host"),
    (r"^\s*(sudo\s+)?snaffler", "snaffler"),
    (r"^\s*\.?\\?snaffler", "snaffler"),
    (r"^\s*(sudo\s+)?\.?/?linpeas", "linpeas"),
    (r"^\s*(sudo\s+)?xsltproc\b", "xsltproc"),
    (r"^\s*net\s+(user|group)\b", "net"),
    (r"^\s*(msf6?|msfconsole)\b", "metasploit"),
    (r"^\s*(sudo\s+)?nc\b", "netcat"),
    (r"^\s*(sudo\s+)?ncat\b", "netcat"),
    (r"^\s*ssh\b", "ssh"),
    (r"^\s*python[23]?\s+-m\s+http\.server", "python"),
    (r"^\s*(sed|grep|cut|awk)\b", "shell"),
    (r"^\s*(ip|ifconfig|route|iptables)\b", "shell"),
    (r"^\s*(cat|chmod|chown|tee|echo|updatedb|locate|systemctl)\b", "shell"),
]

# Ordered technique rules matched against the FULL command text (not just line 1).
# First hit wins, so put the most specific patterns first.
TECHNIQUE_RULES = [
    (r"GetUserSPNs|-m\s*13100", "kerberoasting"),
    (r"--asreproast|-m\s*18200", "asreproasting"),
    (r"--ntds\b", "ntds-dump"),
    (r"-M\s*lsassy|lsass", "lsass-dump"),
    (r"--dpapi\b", "dpapi-looting"),
    (r"getST.*-impersonate|-altservice|delegation", "delegation-abuse"),
    (r"-M\s*(coerce_plus|petitpotam|printerbug|coerce)", "coercion"),
    (r"-M\s*(zerologon|smbghost|nopac|ms17)", "vuln-scanning"),
    (r"psk-crack", "psk-cracking"),
    (r"hashcat", "hash-cracking"),
    (r"--generate-hosts-file", "hostfile-generation"),
    (r"--shares\b", "share-enumeration"),
    (r"--users\b", "user-enumeration"),
    (r"-H\s+[0-9a-fA-F]{32}", "pass-the-hash"),
    (r"bloodhound(-ce)?-python", "ad-enumeration"),
    (r"\bffuf\b|\bgobuster\b", "content-discovery"),
    (r"\bsublist3r\b|subdomains?-", "subdomain-enumeration"),
    (r"axfr|host\s+-l\b|zone.?transfer", "zone-transfer"),
    (r"\bdig\b|\bfierce\b|dnsrecon", "dns-recon"),
    (r"\bwhatweb\b|wappalyzer|builtwith", "web-fingerprinting"),
    (r"ike-scan", "ike-enumeration"),
    (r"\bnmap\b.*-sU", "port-scanning"),
    (r"\bnmap\b.*-sn", "host-discovery"),
    (r"\bnmap\b.*-sV", "service-discovery"),
    (r"\bnmap\b", "port-scanning"),
    (r"snaffler", "data-discovery"),
    (r"net\s+group\s+\"?Domain Admins\"?.*/add", "add-domain-admin"),
    (r"net\s+user\s+/add|net\s+user\s+\w+\s+\w+\s+/add", "add-user"),
    (r"sudo-chwoot|CVE-2025-32463|sudo\s+version", "sudo-exploit"),
    (r"linpeas|linenum", "privesc-enum"),
    (r"evil-winrm", "remote-exec"),
    (r"python[23]?\s+-m\s+http\.server|droopy", "file-transfer"),
    (r"nxc\s+\w+\s+\S+\s+-u\s+\S+\s+-p\s+\S+\s+--continue-on-success", "password-spraying"),
]

META_CMD_RE = re.compile(
    r"<!--\s*meta:\s*(?P<meta>[^>]*?)\s*-->\s*\n```(?P<lang>[\w+-]*)\n(?P<code>.*?)```",
    re.DOTALL,
)
OUTPUT_RE = re.compile(
    r"\A\s*<!--\s*output\s*-->\s*\n```[\w+-]*\n(?P<out>.*?)```",
    re.DOTALL,
)
ANY_FENCE_RE = re.compile(r"```(?P<lang>[\w+-]*)\n(?P<code>.*?)```", re.DOTALL)
HEADING_RE = re.compile(r"^#{1,6}\s+(.*)$", re.MULTILINE)


def parse_frontmatter(text):
    fm = {}
    body = text
    if text.startswith("---"):
        end = text.find("\n---", 3)
        if end != -1:
            block = text[3:end].strip()
            body = text[end + 4:]
            for line in block.splitlines():
                if ":" not in line:
                    continue
                k, v = line.split(":", 1)
                k, v = k.strip(), v.strip()
                if v.startswith("[") and v.endswith("]"):
                    v = [x.strip() for x in v[1:-1].split(",") if x.strip()]
                fm[k] = v
    return fm, body


def parse_meta_fields(meta_str):
    fields = {}
    for part in meta_str.split(","):
        if "=" in part:
            k, v = part.split("=", 1)
            fields[k.strip()] = v.strip()
    return fields


def detect_tool(code):
    first = code.strip().splitlines()[0] if code.strip() else ""
    for pat, tool in TOOL_PATTERNS:
        if re.search(pat, first, re.IGNORECASE):
            return tool
    return "unknown"


def detect_technique(code):
    for pat, tech in TECHNIQUE_RULES:
        if re.search(pat, code, re.IGNORECASE):
            return tech
    return "untagged"


def phase_for(technique, fm):
    if technique in TECHNIQUE_PHASE:
        return TECHNIQUE_PHASE[technique]
    return fm.get("phase", "misc")


def nearest_heading(text, pos):
    best = ""
    for m in HEADING_RE.finditer(text):
        if m.start() > pos:
            break
        best = m.group(1).strip()
    return best


def make_entry(code, lang, technique, fm, rel_path, heading, output=""):
    tool = detect_tool(code)
    subtool = ""
    if tool == "impacket":
        m = re.search(r"impacket-(\w+)", code)
        if m:
            subtool = m.group(1)
    phase = phase_for(technique, fm)
    uid = hashlib.sha1((rel_path + code).encode()).hexdigest()[:10]
    return {
        "id": uid,
        "kind": fm.get("kind", "reference"),
        "source_file": rel_path,
        "platform": fm.get("platform", ""),
        "target": fm.get("target", ""),
        "scope": fm.get("scope", "unspecified"),
        "os": fm.get("os", ""),
        "tool": tool,
        "subtool": subtool,
        "technique": technique,
        "phase": phase,
        "lang": lang or "text",
        "command": code.strip(),
        "output": output.strip(),
        "context": heading,
        "tags": fm.get("tags", []) if isinstance(fm.get("tags", []), list) else [fm.get("tags")],
    }


def process_file(path, notes_root):
    raw = path.read_text(encoding="utf-8", errors="ignore")
    fm, body = parse_frontmatter(raw)
    if str(fm.get("index", "true")).lower() == "false":
        return []
    rel_path = str(path.relative_to(notes_root))

    entries = []
    consumed = []  # spans already handled, so the bare-fence pass skips them

    for m in META_CMD_RE.finditer(body):
        meta = parse_meta_fields(m.group("meta"))
        code = m.group("code")
        # explicit technique wins; else auto-detect
        technique = meta.get("technique") or detect_technique(code)
        # allow per-snippet overrides of inherited fields
        local_fm = dict(fm)
        for k in ("scope", "os", "platform", "target", "phase"):
            if k in meta:
                local_fm[k] = meta[k]

        # look for an attached output block right after this command
        tail = body[m.end():]
        out_m = OUTPUT_RE.match(tail)
        output = ""
        span_end = m.end()
        if out_m:
            output = out_m.group("out")
            span_end = m.end() + out_m.end()

        heading = nearest_heading(body, m.start())
        entries.append(make_entry(code, m.group("lang"), technique, local_fm, rel_path, heading, output))
        consumed.append((m.start(), span_end))

    # Bare fenced blocks with no meta comment: still capture, best-effort tag.
    for m in ANY_FENCE_RE.finditer(body):
        if any(s <= m.start() < e for s, e in consumed):
            continue
        code = m.group("code")
        if not code.strip():
            continue
        # skip obvious pure-output / data blocks (no recognisable tool AND multi-line noise)
        tool = detect_tool(code)
        if tool == "unknown" and len(code.strip().splitlines()) > 3:
            continue
        technique = detect_technique(code)
        if tool == "unknown" and technique == "untagged":
            continue
        heading = nearest_heading(body, m.start())
        entries.append(make_entry(code, m.group("lang"), technique, fm, rel_path, heading))

    return entries


def main():
    if len(sys.argv) != 3:
        print("Usage: build_index.py <notes_root> <output_json_path>")
        sys.exit(1)

    notes_root = Path(sys.argv[1])
    output_path = Path(sys.argv[2])
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # read optional ignore file (glob patterns, one per line)
    ignore_globs = []
    ignore_file = notes_root / ".searchindexignore"
    if ignore_file.exists():
        ignore_globs = [l.strip() for l in ignore_file.read_text().splitlines()
                        if l.strip() and not l.startswith("#")]

    all_entries = []
    scanned = 0
    for md in sorted(notes_root.rglob("*.md")):
        rel = md.relative_to(notes_root)
        if any(rel.match(g) for g in ignore_globs):
            continue
        if "site" in rel.parts or "scripts" in rel.parts or "viewer" in rel.parts:
            continue
        scanned += 1
        all_entries.extend(process_file(md, notes_root))

    # Collapse exact-duplicate commands (same command string appearing in
    # multiple files). Keep one, prefer kind=reference, and record the others
    # under 'also_in' so nothing is hidden.
    by_cmd = {}
    for e in all_entries:
        key = e["command"].strip()
        if key not in by_cmd:
            by_cmd[key] = e
        else:
            keep = by_cmd[key]
            other = e
            # prefer a reference entry as the canonical one
            if keep["kind"] != "reference" and other["kind"] == "reference":
                keep, other = other, keep
                by_cmd[key] = keep
            also = set(keep.get("also_in", []))
            if other["source_file"] != keep["source_file"]:
                also.add(other["source_file"])
            keep["also_in"] = sorted(also)
    all_entries = list(by_cmd.values())

    # stable sort: phase order, then tool, then technique
    phase_idx = {p: i for i, p in enumerate(PHASE_ORDER)}
    all_entries.sort(key=lambda e: (phase_idx.get(e["phase"], 99), e["tool"], e["technique"]))

    payload = {
        "generated_from": str(notes_root),
        "phase_order": PHASE_ORDER,
        "count": len(all_entries),
        "entries": all_entries,
    }
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"Indexed {len(all_entries)} commands from {scanned} files -> {output_path}")


if __name__ == "__main__":
    main()
