#!/usr/bin/env python3
"""
VAPT-Toolkit — main CLI

Usage examples:
    # Basic scan + report
    python main.py --target 192.168.56.101 --ports 1-1000

    # Scan + vuln NSE scripts + Exploit-DB catalog lookup
    python main.py --target 192.168.56.101 --ports 1-1000 --vuln --exploitdb

    # Also search Metasploit for matching modules (requires msfrpcd running)
    python main.py --target 192.168.56.101 --vuln --exploitdb --msf --msf-password yourpass

IMPORTANT: Only run this against systems you own or are explicitly
authorized to test (e.g. Metasploitable2, DVWA, your own lab VMs,
or an authorized CTF/HTB/THM target). Unauthorized scanning or
exploitation of systems is illegal.
"""

import argparse
import sys

from vapt_toolkit import recon, vuln_scan, report

try:
    from vapt_toolkit import msf_integration
except ImportError:
    msf_integration = None


def confirm(prompt: str) -> bool:
    resp = input(f"{prompt} [y/N]: ").strip().lower()
    return resp == "y"


def main():
    parser = argparse.ArgumentParser(description="VAPT-Toolkit: authorized VAPT automation")
    parser.add_argument("--target", required=True, help="Target IP / hostname / CIDR")
    parser.add_argument("--ports", default="1-1000", help="Port range (default 1-1000)")
    parser.add_argument("--vuln", action="store_true", help="Run nmap NSE vuln scripts")
    parser.add_argument("--exploitdb", action="store_true", help="Look up matching Exploit-DB entries")
    parser.add_argument("--msf", action="store_true", help="Search Metasploit for matching modules")
    parser.add_argument("--msf-password", default=None, help="msfrpcd password (required if --msf)")
    parser.add_argument("--msf-host", default="127.0.0.1")
    parser.add_argument("--msf-port", type=int, default=55553)
    parser.add_argument("--report", default="vapt_report.html", help="Output HTML report path")
    parser.add_argument("--i-have-authorization", action="store_true",
                         help="Confirm you are authorized to test this target (required)")
    args = parser.parse_args()

    if not args.i_have_authorization:
        print("[!] Refusing to scan without --i-have-authorization.")
        print("    Only use this tool against systems you own or are explicitly")
        print("    authorized to test (lab VMs, CTF targets, written pentest scope).")
        sys.exit(1)

    print(f"=== VAPT-Toolkit: {args.target} ===\n")

    # --- Recon ---
    xml_path = recon.run_scan(args.target, ports=args.ports)
    hosts = recon.parse_scan(xml_path)
    recon.print_summary(hosts)

    if not hosts:
        print("[!] No live hosts found in range, stopping.")
        sys.exit(0)

    findings = []

    # --- Vulnerability scripts ---
    if args.vuln:
        raw = vuln_scan.run_vuln_scripts(args.target, args.ports)
        for h in hosts:
            findings += vuln_scan.parse_vuln_output(raw, h.ip)

    # --- Exploit-DB catalog lookup ---
    if args.exploitdb:
        findings += vuln_scan.enrich_with_exploitdb(hosts)

    print(f"\n[+] Total findings: {len(findings)}")
    for f in findings:
        print(f"    [{f.severity.upper()}] {f.host}:{f.port} ({f.service}) - {f.title}")

    # --- Metasploit module search (search only, no auto-exploit) ---
    if args.msf:
        if msf_integration is None or not msf_integration.HAVE_MSFRPC:
            print("\n[!] pymetasploit3 not installed — skipping MSF integration.")
            print("    Install with: pip install pymetasploit3")
        elif not args.msf_password:
            print("\n[!] --msf-password required for --msf. Skipping.")
        else:
            client = msf_integration.connect(args.msf_password, args.msf_host, args.msf_port)
            if client:
                print("\n[*] Searching Metasploit modules for matching services...")
                for h in hosts:
                    for s in h.services:
                        if not s.product:
                            continue
                        matches = msf_integration.search_modules(client, s.name, s.product)
                        for m in matches:
                            print(f"    {h.ip}:{s.port} -> {m.get('fullname')} ({m.get('name')})")

                            if confirm(f"    View options / consider running {m.get('fullname')}?"):
                                mod = msf_integration.show_module_options(client, m.get('fullname'))
                                if mod and confirm(f"    Set RHOSTS={h.ip} RPORT={s.port} and EXECUTE this module?"):
                                    msf_integration.run_module_with_confirmation(
                                        client, m.get('fullname'),
                                        {"RHOSTS": h.ip, "RPORT": s.port}
                                    )

    # --- Report ---
    report.generate_report(args.target, hosts, findings, out_path=args.report)


if __name__ == "__main__":
    main()
