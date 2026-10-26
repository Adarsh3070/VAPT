# VAPT-Toolkit

A Python-based automation framework for **Vulnerability Assessment and
Penetration Testing** — built for the college VAPT project. It wraps
Nmap, Exploit-DB (`searchsploit`), and the Metasploit Framework into a
single guided workflow, and outputs a formatted HTML report.

> ⚠️ **Authorized use only.** Run this only against systems you own or
> have explicit written permission to test — your own lab VMs
> (Metasploitable 2, DVWA), or an authorized CTF/HTB/THM target.
> Unauthorized scanning/exploitation is illegal under India's IT Act
> (Section 43/66) and equivalent laws elsewhere. The tool itself
> refuses to run unless you pass `--i-have-authorization`.

## What it does

1. **Recon** — Nmap scan (host discovery, open ports, service/version
   detection), parsed into structured Python objects.
2. **Vulnerability detection** — runs Nmap's `vuln` NSE script
   category and flags anything reported `VULNERABLE` or tied to a
   CVE.
3. **Exploit-DB cross-reference** — looks up each detected
   service/version against the local Exploit-DB mirror
   (`searchsploit`) to list known, catalogued exploits (metadata
   only — this tool does not embed or generate exploit code).
4. **Metasploit integration (optional)** — connects to `msfrpcd` and
   searches loaded MSF modules matching each service. Nothing is
   ever auto-executed: you're shown the module, then asked to
   confirm viewing its options, then asked again to confirm before
   it actually runs. Two separate y/N prompts.
5. **Reporting** — generates a single `vapt_report.html` with host
   inventory, service banners, and a findings table (color-coded by
   severity).

## Setup (in Kali VM)

```bash
# System tools (Kali ships with most of these already)
sudo apt update
sudo apt install nmap exploitdb metasploit-framework -y

# Python deps
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

If you want the Metasploit integration, start the RPC daemon first:

```bash
msfrpcd -P yourpassword -S -a 127.0.0.1 -p 55553
```

## Usage

```bash
# Basic scan + HTML report
> **Note:** Replace the example IP address with the IP address of your
> authorized lab target. Ensure the target is reachable from your Kali VM.
python main.py --target 192.168.56.101 --ports 1-1000 --i-have-authorization

# + vuln NSE scripts + Exploit-DB lookup
python main.py --target 192.168.56.101 --vuln --exploitdb --i-have-authorization

# + Metasploit module search (interactive confirmation before any exploit runs)
python main.py --target 192.168.56.101 --vuln --exploitdb --msf \
    --msf-password yourpassword --i-have-authorization
```

Open `vapt_report.html` in a browser to see the formatted report.

## Recommended lab targets (for testing/demo)

- **Metasploitable 2** — A deliberately vulnerable Linux virtual
  machine suitable for practicing network reconnaissance and
  vulnerability assessment in an isolated lab.
- **DVWA (Damn Vulnerable Web Application)** — A practice environment
  for web application security testing and future toolkit extensions.

## Project structure

```
vapt-toolkit/
├── main.py                    # CLI entry point
├── requirements.txt
├── vapt_toolkit/
│   ├── __init__.py
│   ├── recon.py               # Nmap scanning + XML parsing
│   ├── vuln_scan.py           # NSE vuln scripts + searchsploit lookup
│   ├── msf_integration.py     # Metasploit RPC (search + confirm-to-run)
│   ├── report.py              # HTML report generation
│   └── templates/
│       └── report.html.j2
```

## Suggested report/demo structure (for submission)

1. **Objective** — as per assignment: identify vulnerabilities in a
   simulated environment and perform penetration testing.
2. **Environment** — Kali VM (attacker) + Metasploitable 2 VM (target)
   on an isolated host-only VMware network (screenshot your VM
   network settings to show it's isolated).
3. **Methodology** — recon → vuln scan → exploit-DB cross-reference →
   (optional) exploitation via Metasploit → reporting.
4. **Results** — paste/screenshot the generated `vapt_report.html`.
5. **Skills demonstrated** — vulnerability scanning, exploitation
   techniques, ethical hacking methodology, and secure automation
   design (confirmation gates before any exploit runs).

## Extending it further

- Add a Burp Suite / OWASp ZAP module for web app scanning (maps to
  the "web application").
- Add Nessus API integration (`.nessus` XML parsing) alongside Nmap
  for a second vulnerability data source.
- Add CVSS scoring lookup (NVD API) to auto-rank findings by
  severity instead of the current simple heuristic.
