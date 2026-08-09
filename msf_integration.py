"""
msf_integration.py
Talks to a running Metasploit RPC daemon (msfrpcd) to search for
modules matching discovered services, and — only with explicit
per-module confirmation from the operator — launch a chosen module.

This module never writes or embeds exploit code itself; it only
drives the existing, vetted modules that ship with the Metasploit
Framework, exactly as msfconsole would.

Setup (in your Kali VM):
    msfrpcd -P yourpassword -S -a 127.0.0.1 -p 55553
"""

import time

try:
    from pymetasploit3.msfrpc import MsfRpcClient
    HAVE_MSFRPC = True
except ImportError:
    HAVE_MSFRPC = False


def connect(password: str, host: str = "127.0.0.1", port: int = 55553):
    if not HAVE_MSFRPC:
        print("[!] pymetasploit3 not installed. Run: pip install pymetasploit3")
        return None
    try:
        client = MsfRpcClient(password, server=host, port=port, ssl=True)
        return client
    except Exception as e:
        print(f"[!] Could not connect to msfrpcd: {e}")
        print("    Make sure msfrpcd is running: msfrpcd -P <password> -S -a 127.0.0.1 -p 55553")
        return None


def search_modules(client, service_name: str, product: str = "") -> list:
    """Searches loaded MSF modules by service/product keyword."""
    if client is None:
        return []
    query = product if product else service_name
    if not query:
        return []
    try:
        results = client.modules.search(query)
    except Exception as e:
        print(f"[!] Module search failed: {e}")
        return []
    # keep only exploit modules, cap results
    exploits = [r for r in results if r.get("type") == "exploit"]
    return exploits[:10]


def show_module_options(client, module_fullname: str):
    """Fetches and prints required options for a given module."""
    if client is None:
        return None
    mtype, mname = module_fullname.split("/", 1)
    try:
        mod = client.modules.use(mtype, mname)
        print(f"\n[*] Options for {module_fullname}:")
        for opt, info in mod.options.items():
            required = "(required)" if info in mod.required else ""
            print(f"    {opt} {required}")
        return mod
    except Exception as e:
        print(f"[!] Could not load module: {e}")
        return None


def run_module_with_confirmation(client, module_fullname: str, options: dict):
    """
    Launches a module ONLY after the caller has explicitly supplied
    options and this function has printed a confirmation prompt.
    The actual go/no-go decision must happen in the calling code
    (main.py) via an interactive y/N prompt — this function assumes
    that confirmation has already been obtained.
    """
    if client is None:
        return None
    mtype, mname = module_fullname.split("/", 1)
    try:
        mod = client.modules.use(mtype, mname)
        for k, v in options.items():
            mod[k] = v
        print(f"[*] Executing {module_fullname} ...")
        job = mod.execute(payload=mod.payloads[0] if hasattr(mod, "payloads") and mod.payloads else None)
        time.sleep(2)
        return job
    except Exception as e:
        print(f"[!] Module execution failed: {e}")
        return None


def list_active_sessions(client):
    if client is None:
        return {}
    try:
        return client.sessions.list
    except Exception:
        return {}
