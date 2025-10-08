#!/usr/bin/env python3
# Executable Name: ariesgad

import os
import sys
import time
import datetime
import subprocess
import argparse
import json
import re
import socket
import logging
import ipaddress
from urllib.parse import urlparse
import traceback 
import io
import concurrent.futures # Explicitly imported for ThreadPoolExecutor

# --- External Library Imports (Required for Options 1, 2, 3, 4, 5) ---
try:
    import requests
    from colorama import init as colorama_init, Fore, Style
    from bs4 import BeautifulSoup
    import concurrent.futures
    import dns.resolver
    import dns.reversename
    import urllib3
    from tqdm import tqdm # Library used for progress bar
    import asyncio
    import aiohttp
    import websockets
    import ssl
    from aiohttp import ClientConnectorCertificateError, ClientConnectorError
except ImportError as e:
    print(f"Error: Missing required Python library: {e.name}")
    print(f"Please install it using: pip install {e.name}")
    sys.exit(1)

# Disable insecure request warnings shown when verify=False (Option 1, 4)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
colorama_init(autoreset=True)

# --- Configuration & Global Variables ---

# Author Name: ♈️AriesGad♈️

# API Keys (Placeholders - **MUST BE UPDATED BY USER**)
VT_API_KEY = "11ae53bcdcfa8d42d47347073f0ddbe342180f9f5d0ddbe342180f9f5d219d8d1e2df30db14103e2"
SHODAN_API_KEY = "s35jHyUC1RO0riYFS4B9yQQ66KppWtiD"
SECURITYTRAILS_API_KEY = "lvO0DQkpeNZeRBfxAriEzE3R4yt-1oFJ"
CENSYS_UID = None
CENSYS_SECRET = None

# Option Configs
DEFAULT_TIMEOUT = 8
O1_DEFAULT_WORKERS = 20
O1_DEFAULT_PORTS = [80, 443, 8080, 8443]
O1_USER_AGENT = "revagg/1.2 (AriesGad) - polite-recon"
O1_HEADERS = {"User-Agent": O1_USER_AGENT}
O1_SLEEP_BETWEEN_QUERIES = 1.0

O2_COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "dev", "admin", "api", "cdn", "beta", "test", "docs", "staging", "app"
]

O4_CLOUDFLARE_IPS = []
O4_CDN_PATTERNS = [
    r'cloudflare', r'akamai', r'fastly', r'aws|amazon', r'google|GFE',
    r'nginx/1\.[0-9]+\.([0-9]+) \(nginx-cloudflare\)', r'CDN77', r'KeyCDN', r'BunnyCDN'
]

# Fixed Output File Names
OUTPUT_FILES = {
    1: "Reverselookup.txt",
    2: "Subdomains.txt",
    3: "Zero-rate.txt",
    4: "SNI_SSL.txt",
    5: "CIDR.txt",
    6: "Wordlist_DNS_Results.txt" # New output file for Option 6
}

# Setup logging for Option 1 and 4 debug
# We keep the basic logging config and add a handler in run_option_1
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def get_timestamp_filename(option):
    """Returns the fixed, requested filename for the given option."""
    return OUTPUT_FILES.get(option, "output.txt")


# ==============================================================================
# ----------------------------- BANNER & MENU LOGIC ----------------------------
# ==============================================================================

MAIN_BANNER = r"""
···············································································
:     _               __                            ___                   _   :
:    /.\      _ ___   LJ    ____      ____        ,"___".    ___ _     ___FJ  :
:   //_\\    J '__ ",      F __ J    F ___J       FJ---L]   F __` L   F __  L :
:  / ___ \   | |__|-J FJ  | _____J  | '----_     J |  [""L | |--| |  | |--| | :
: / L___J \  F L  `-'J  L F L___--. )-____  L    | \___] | F L__J J  F L__J J :
:J__L   J__LJ__L     J__LJ\______/FJ\______/F    J\_____/FJ\____,__LJ\____,__L:
:|__L   J__||__L     |__| J______F  J______F      J_____F  J____,__F J____,__F:
···············································································
"""

# UPDATED MENU OPTIONS: 6 is Wordlist Scan, 7 is Exit
MENU_OPTIONS = {
    1: "Reverse IP/Host LookUp",
    2: "Subdomains Enumeration",
    3: "ISP Zero-Rated Check",
    4: "WS/SSL/HTTP/SNI/CDN Check",
    5: "CIDR IP+Name Resolve",
    6: "Wordlist DNS Scan", # New Option
    7: "Exit"              # Exit moved to 7
}

def display_menu():
    """Prints the main menu and prompts for choice."""
    os.system('cls' if os.name == 'nt' else 'clear')
    print(Fore.CYAN + MAIN_BANNER + Style.RESET_ALL)
    print(Fore.YELLOW + "====================================================================================" + Style.RESET_ALL)
    print(Fore.YELLOW + f"                          AriesGad Scanner (Author: ♈️AriesGad♈️)" + Style.RESET_ALL)
    print(Fore.YELLOW + "====================================================================================" + Style.RESET_ALL)
    
    # Iterate through all keys up to 7
    for key in sorted(MENU_OPTIONS.keys()):
        value = MENU_OPTIONS[key]
        if key == 7: # Special case for Exit
            print(Fore.RED + f"  [{key}] " + Fore.WHITE + f"{value}" + Style.RESET_ALL)
        else:
            filename = OUTPUT_FILES.get(key, "N/A")
            print(Fore.GREEN + f"  [{key}] " + Fore.WHITE + f"{value} ({filename})" + Style.RESET_ALL)
            
    print(Fore.YELLOW + "====================================================================================" + Style.RESET_ALL)
    return input(Fore.MAGENTA + "Enter your option (1-7): " + Style.RESET_ALL).strip()


def load_targets(target_input):
    """Loads a list of targets from a file or returns the single target."""
    targets = []
    if os.path.isfile(target_input):
        try:
            with open(target_input, "r") as f:
                targets.extend([line.strip() for line in f if line.strip() and not line.startswith('#')])
        except FileNotFoundError:
            print(Fore.RED + f"Error: Target file '{target_input}' not found." + Style.RESET_ALL)
            return []
    elif target_input:
        targets.append(target_input)
    return targets

def prompt_and_execute(option, prompt_text, exec_function, wordlist_required=False):
    """
    Handles the user prompt, execution, and return to menu.
    """
    os.system('cls' if os.name == 'nt' else 'clear')
    output_file = get_timestamp_filename(option)
    
    print(Fore.YELLOW + f"--- {MENU_OPTIONS[option]} ---" + Style.RESET_ALL)
    
    # Target input
    target = input(Fore.CYAN + prompt_text + Style.RESET_ALL).strip()
    if not target:
        print(Fore.RED + "Target input cannot be empty." + Style.RESET_ALL)
        input(Fore.YELLOW + "Press ENTER to return to the main menu..." + Style.RESET_ALL)
        return
        
    wordlist_path = None
    if wordlist_required:
        wordlist_path = input(Fore.CYAN + "Enter path to wordlist file (e.g., /path/to/seclists.txt): " + Style.RESET_ALL).strip()
        if not wordlist_path or not os.path.exists(wordlist_path):
            print(Fore.RED + f"Error: Wordlist file not found at '{wordlist_path}'." + Style.RESET_ALL)
            input(Fore.YELLOW + "Press ENTER to return to the main menu..." + Style.RESET_ALL)
            return

    # Output message
    if option == 5:
        print(Fore.BLUE + f"[*] NOTE: Final aligned output will be saved to: {output_file.replace('.txt', '_resolved.txt')}" + Style.RESET_ALL)
    else:
        print(Fore.BLUE + f"[*] NOTE: Output will overwrite the file: {output_file}" + Style.RESET_ALL)

    print(Fore.BLUE + f"[*] Starting scan..." + Style.RESET_ALL)
    time.sleep(1)

    try:
        if option == 4:
            asyncio.run(exec_function(target, output_file))
        elif option == 6:
            exec_function(target, wordlist_path, output_file) # Option 6 takes 3 arguments
        else:
            exec_function(target, output_file)
    except Exception as e:
        print(Fore.RED + f"\n[CRITICAL ERROR] Failed to execute Option {option}: {e}" + Style.RESET_ALL)
        traceback.print_exc() 

    print(Fore.YELLOW + "\n====================================================================================" + Style.RESET_ALL)
    
    final_filename = output_file
    if option == 5:
        final_filename = output_file.replace('.txt', '_resolved.txt')

    print(Fore.GREEN + f"Scan finished. Results saved to {final_filename}. " + Style.RESET_ALL)
    input(Fore.YELLOW + "Press ENTER to return to the main menu..." + Style.RESET_ALL) 


# ==============================================================================
# ------------------------------- OPTION 1: REVAGG -----------------------------
# ==============================================================================

# ... (run_option_1 and its helpers are unchanged) ...

def o1_resolve_ip(host):
    """Resolve host to IP."""
    try:
        return socket.gethostbyname(host)
    except Exception:
        return "0.0.0.0"

def o1_probe_one(host, port, timeout=DEFAULT_TIMEOUT):
    """Probe host:port with GET, return dict or None."""
    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{host}:{port}/"
    try:
        r = requests.get(url, headers=O1_HEADERS, timeout=timeout, verify=False, allow_redirects=True)
        code = r.status_code
        server = r.headers.get("Server", "") or r.headers.get("server", "")
        ip = o1_resolve_ip(host)
        return {
            "Method": "GET", "Code": str(code), "Server": server,
            "Port": str(port), "IP": ip, "Host": host
        }
    except Exception:
        return None

def o1_bulk_probe(hosts, ports, max_workers, timeout):
    """Concurrently probe hosts x ports."""
    results = []
    tasks = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        for h in hosts:
            for p in ports:
                tasks.append(ex.submit(o1_probe_one, h, p, timeout))
        for fut in concurrent.futures.as_completed(tasks):
            try:
                r = fut.result()
            except Exception as e:
                logging.error(f"O1 probe task exception: {e}")
                r = None
            if r:
                results.append(r)
    return results

def o1_color_for_code(code_str):
    """Get color for status code."""
    try:
        code = int(code_str)
    except Exception:
        return Fore.WHITE
    if 200 <= code < 300: return Fore.GREEN
    if 300 <= code < 400: return Fore.CYAN
    if 400 <= code < 500: return Fore.YELLOW
    if 500 <= code < 600: return Fore.RED
    return Fore.WHITE

def o1_print_table(rows, log_file, cand_output_file):
    """Prints results as an ALIGNED table to stdout and CSV to file."""
    
    all_hosts = [r.get("Host", "") for r in rows]
    host_max = max(len(h) for h in all_hosts) if all_hosts else 30
    host_max = max(host_max, 30)
    
    widths = {
        'Method': 6, 'Code': 4, 'Server': 20, 'Port': 5, 'IP': 15, 'Host': host_max
    }
    
    col_sep = "  " 
    hdr = (f"{'Method':<{widths['Method']}}{col_sep}{'Code':<{widths['Code']}}{col_sep}"
           f"{'Server':<{widths['Server']}}{col_sep}{'Port':>{widths['Port']}}{col_sep}"
           f"{'IP':<{widths['IP']}}{col_sep}{'Host':<{widths['Host']}}")
           
    sep_len = sum(widths.values()) + (len(col_sep) * (len(widths) - 1))
    sep = '-' * sep_len
    
    print(Fore.MAGENTA + hdr + Style.RESET_ALL)
    print(Fore.MAGENTA + sep + Style.RESET_ALL)
    
    log_file.write(f"--- Live Probe Results ---\n")
    log_file.write(f"Source Candidates: {os.path.basename(cand_output_file)}\n")
    log_file.write("Method,Code,Server,Port,IP,Host\n")

    for r in rows:
        server = (r.get("Server", "") or "").strip()
        host = r.get("Host", "")
        code = r.get("Code", "")
        color = o1_color_for_code(code)
        
        server_display = server[:widths['Server']-1] + '…' if len(server) > widths['Server'] else server
        
        line = (f"{r.get('Method',''):<{widths['Method']}}{col_sep}{code:<{widths['Code']}}{col_sep}"
                f"{server_display:<{widths['Server']}}{col_sep}{r.get('Port',''):>{widths['Port']}}{col_sep}"
                f"{r.get('IP',''):<{widths['IP']}}{col_sep}{host:<{widths['Host']}}")
                
        print(color + line + Style.RESET_ALL)

        server_csv = server.replace(",", " ")
        log_line = (f"{r.get('Method','')},{r.get('Code','')},{server_csv},"
                    f"{r.get('Port','')},{r.get('IP','')},{r.get('Host','')}\n")
        log_file.write(log_line)

# --- O1 Source Functions (Adapted) ---
def o1_query_hackertarget(ip):
    """Reverse IP Lookup from HackerTarget (Quick but limited free tier)."""
    results = set()
    try:
        url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
        r = requests.get(url, headers=O1_HEADERS, timeout=DEFAULT_TIMEOUT)
        if r.status_code == 200 and "No records" not in r.text:
            results.update(line.strip() for line in r.text.splitlines() if line.strip() and not line.startswith("error"))
    except Exception as e: logging.error(f"hackertarget error for {ip}: {e}")
    return results

def o1_query_viewdns(ip):
    """Reverse IP Lookup by scraping ViewDNS.info (More domains found)."""
    results = set()
    try:
        # Using a reliable scraping URL for ViewDNS that returns a full list
        url = f"https://viewdns.info/reverseip/?host={ip}&t=1" 
        r = requests.get(url, headers=O1_HEADERS, timeout=DEFAULT_TIMEOUT)
        if r.status_code == 200:
            soup = BeautifulSoup(r.text, "html.parser")
            # The results are usually in a table with border=1
            table = soup.find("table", attrs={"border": "1"})
            if table:
                rows = table.find_all("tr")
                for row in rows[1:]: # Skip header row
                    cols = row.find_all("td")
                    if len(cols) >= 1:
                        hostname = cols[0].get_text(strip=True)
                        if hostname and hostname != "-" and hostname.lower() != "host":
                            results.add(hostname)
            else:
                # Fallback for cases where the table isn't found
                logging.warning(f"ViewDNS table not found for {ip}. Check HTML structure.")
    except Exception as e: logging.error(f"viewdns error for {ip}: {e}")
    return results

def o1_query_crtsh_for_domain(domain):
    """Certificate Transparency lookup for related domains."""
    results = set()
    try:
        q = f"%25.{domain}"
        url = f"https://crt.sh/?q={q}&output=json"
        r = requests.get(url, headers=O1_HEADERS, timeout=DEFAULT_TIMEOUT)
        if r.status_code == 200:
            try:
                # crt.sh returns JSON (sometimes with a leading newline, hence the strip/loads)
                data = json.loads(r.text.strip())
                for item in data:
                    name = item.get("name_value")
                    if name:
                        # Common names can be space-separated or comma-separated lists
                        results.update(n.strip().rstrip(".") for n in re.split(r"[\s,]+", name) if n)
            except json.JSONDecodeError as e: 
                logging.error(f"crt.sh JSON parse error for {domain}: {e}")
            except Exception as e: 
                logging.error(f"crt.sh generic parse error for {domain}: {e}")
    except Exception as e: logging.error(f"crt.sh error for {domain}: {e}")
    return results


def run_option_1(target, live_output_file):
    """Main logic for Option 1: Reverse IP/Host LookUp (revagg)."""
    
    cand_output_file = "ReverseIP_Candidates.txt" 
    debug_log_file = "ReverseIP_debug.log"
    
    file_handler = logging.FileHandler(debug_log_file, mode='w')
    file_handler.setFormatter(logging.Formatter('%(asctime)s: %(message)s'))
    logging.getLogger().addHandler(file_handler)

    print(f"[*] Aggregating candidates from various sources...")
    ips = set()
    domain = None
    
    # Target is an IP or a domain
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", target):
        ips.add(target)
    else:
        domain = target
        try:
            ip = socket.gethostbyname(domain)
            ips.add(ip)
        except Exception:
            pass
            
    # Target is a file containing IPs/Domains
    if os.path.isfile(target):
        for line in load_targets(target):
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", line):
                ips.add(line)
            else:
                domain = line # We'll only use the last domain from the file for crt.sh to keep it simple

    if not ips and not domain:
        print(Fore.RED + "No valid IP or domain to scan." + Style.RESET_ALL)
        logging.getLogger().removeHandler(file_handler)
        return

    all_candidates = set()

    for ip in ips:
        print(f"  [+] Inspecting IP: {ip}")
        # PTR lookup
        try:
            ptr = dns.reversename.from_address(ip).to_text().rstrip(".")
            all_candidates.add(ptr)
        except Exception:
            pass
            
        # Use both sources for better coverage
        all_candidates.update(o1_query_hackertarget(ip)) # Quick source
        all_candidates.update(o1_query_viewdns(ip))      # More verbose source
        
        time.sleep(O1_SLEEP_BETWEEN_QUERIES)

    if domain:
        print(f"  [+] Inspecting Domain: {domain}")
        all_candidates.update(o1_query_crtsh_for_domain(domain))
        time.sleep(O1_SLEEP_BETWEEN_QUERIES)

    with open(cand_output_file, "w") as f:
        for h in sorted(all_candidates):
            f.write(h + "\n")

    print(Fore.YELLOW + f"\n[+] Aggregation complete. {len(all_candidates)} candidates written to {cand_output_file}" + Style.RESET_ALL)

    if not all_candidates:
        print(Fore.RED + "[*] No candidate hosts to probe." + Style.RESET_ALL)
        logging.getLogger().removeHandler(file_handler)
        return

    print(f"\n[*] Starting HTTP/HTTPS probes (Workers: {O1_DEFAULT_WORKERS})...")
    candidates_list = sorted(all_candidates)

    rows = o1_bulk_probe(candidates_list, ports=O1_DEFAULT_PORTS, max_workers=O1_DEFAULT_WORKERS, timeout=DEFAULT_TIMEOUT)

    rows_sorted = sorted(rows, key=lambda x: (x.get("Host",""), int(x.get("Port","0"))))

    with open(live_output_file, "w") as f:
        print(Fore.GREEN + f"\n[+] Live hits written to {live_output_file} (CSV rows)." + Style.RESET_ALL)
        o1_print_table(rows_sorted, f, cand_output_file)

    logging.getLogger().removeHandler(file_handler)

# ==============================================================================
# ------------------------- OPTION 2: SUBDOMAIN ENUMERATION --------------------
# ==============================================================================

# ... (run_option_2 and its helpers are unchanged) ...

def o2_resolve_domain(full_domain):
    """Resolve the domain to IP if possible."""
    try:
        ip = socket.gethostbyname(full_domain)
        return ip
    except socket.gaierror:
        return None

# --- API-DEPENDENT SOURCES (Skipped if placeholder key is used) ---

def o2_get_subdomains_from_virustotal(domain):
    """Fetch subdomains from VirusTotal API v3."""
    if VT_API_KEY == "11ae53bcdcfa8d42d47347073f0ddbe342180f9f5d0ddbe342180f9f5d219d8d1e2df30db14103e2": 
        print(f"{Fore.YELLOW}  [INFO] Skipping VirusTotal: API key is a placeholder.{Style.RESET_ALL}")
        return []
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
    headers = {"Authorization": f"Bearer {VT_API_KEY}"}
    subdomains = set()
    try:
        response = requests.get(url, headers=headers, timeout=DEFAULT_TIMEOUT)
        if response.status_code == 200:
            data = response.json().get('data', [])
            subdomains.update(item['id'] for item in data)
        elif response.status_code in [401, 403]:
             print(f"{Fore.RED}  [ERROR] VirusTotal returned Status {response.status_code}: API Key is invalid or expired.{Style.RESET_ALL}")
        else: print(f"  [ERROR] VT Error: Status {response.status_code}")
    except Exception as e: print(f"  [ERROR] Error fetching from VirusTotal: {e}")
    return list(subdomains)

def o2_get_subdomains_from_securitytrails(domain):
    """Fetch subdomains from SecurityTrails API."""
    if SECURITYTRAILS_API_KEY == "lvO0DQkpeNZeRBfxAriEzE3R4yt-1oFJ": 
        print(f"{Fore.YELLOW}  [INFO] Skipping SecurityTrails: API key is a placeholder.{Style.RESET_ALL}")
        return []
    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    headers = {"APIKEY": SECURITYTRAILS_API_KEY}
    subdomains = set()
    try:
        response = requests.get(url, headers=headers, timeout=DEFAULT_TIMEOUT)
        if response.status_code == 200:
            data = response.json()
            full_domains = [f"{sub}.{domain}" for sub in data.get('subdomains', [])]
            subdomains.update(full_domains)
        elif response.status_code in [401, 403]:
             print(f"{Fore.RED}  [ERROR] SecurityTrails returned Status {response.status_code}: API Key is invalid or expired.{Style.RESET_ALL}")
    except Exception: pass
    return list(subdomains)

def o2_get_subdomains_from_shodan(domain):
    """Fetch subdomains from Shodan API."""
    if SHODAN_API_KEY == "s35jHyUC1RO0riYFS4B9yQQ66KppWtiD": 
        print(f"{Fore.YELLOW}  [INFO] Skipping Shodan: API key is a placeholder.{Style.RESET_ALL}")
        return []
    url = "https://api.shodan.io/shodan/host/search"
    params = {"key": SHODAN_API_KEY, "query": f'hostname:"*.{domain}"'}
    subdomains = set()
    try:
        response = requests.get(url, params=params, timeout=DEFAULT_TIMEOUT)
        if response.status_code == 200:
            data = response.json()
            for match in data.get('matches', []):
                hostnames = match.get('hostnames', [])
                for hostname in hostnames:
                    if hostname.endswith('.' + domain) and hostname != domain:
                        subdomains.add(hostname)
        elif response.status_code in [401, 403]:
             print(f"{Fore.RED}  [ERROR] Shodan returned Status {response.status_code}: API Key is invalid or expired.{Style.RESET_ALL}")
    except Exception: pass
    return list(subdomains)


# --- PASSIVE SOURCES (NO API KEY REQUIRED) ---

def o2_get_subdomains_from_crtsh(domain):
    """Fetch subdomains from crt.sh (Certificate Transparency Log)."""
    print(f"  [+] Querying crt.sh...")
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    subdomains = set()
    try:
        response = requests.get(url, timeout=DEFAULT_TIMEOUT)
        if response.status_code == 200:
            data = json.loads(response.text.strip())
            for entry in data:
                if 'name_value' in entry:
                    # Split by newline and handle comma/space separated entries
                    names = re.split(r"[\s,]+", entry['name_value'])
                    for name in names:
                        name = name.strip().lstrip('*.').rstrip('.')
                        if name.endswith(domain) and name != domain:
                            subdomains.add(name)
    except Exception as e: 
        print(f"  [ERROR] crt.sh failed: {e}")
    return list(subdomains)

def o2_get_subdomains_from_certspotter(domain):
    """Fetch subdomains from Certspotter (Certificate Transparency Log)."""
    print(f"  [+] Querying Certspotter...")
    # This endpoint is a public API and does not typically require an API key
    url = f"https://certspotter.com/api/v0/certs?domain={domain}&expand=dns_names&include=subdomains"
    subdomains = set()
    try:
        response = requests.get(url, timeout=DEFAULT_TIMEOUT)
        if response.status_code == 200:
            data = response.json()
            for cert in data:
                for dns in cert.get('dns_names', []):
                    dns = dns.rstrip('.')
                    if dns.endswith(domain) and dns != domain:
                        subdomains.add(dns)
    except Exception as e:
        print(f"  [ERROR] Certspotter failed: {e}")
    return list(subdomains)

def o2_get_subdomains_from_rapiddns(domain):
    """Fetches subdomains from RapidDNS by attempting to scrape the result page."""
    print(f"  [+] Querying RapidDNS (Scraping)...")
    subdomains = set()
    try:
        # RapidDNS search page URL
        url = f"https://rapiddns.io/subdomain/{domain}?full=1#result"
        headers = {'User-Agent': O1_USER_AGENT}
        response = requests.get(url, headers=headers, timeout=DEFAULT_TIMEOUT)

        if response.status_code == 200:
            # Simple regex to find the subdomains in the resulting HTML table
            pattern = re.compile(r'<td>([a-zA-Z0-9.-]+\.' + re.escape(domain) + r')</td>')
            found = pattern.findall(response.text)
            subdomains.update(sub.lower().strip() for sub in found)
        
        elif response.status_code == 403:
            print("  [INFO] RapidDNS returned 403 (might be rate-limited or blocked).")
        
    except requests.exceptions.RequestException as e:
        print(f"  [ERROR] RapidDNS scraping failed: {e}")
    return list(subdomains)

def o2_get_subdomains_from_hackertarget_passive(domain):
    """Fetches subdomains from HackerTarget's public hostsearch tool."""
    print(f"  [+] Querying HackerTarget (Hostsearch)...")
    subdomains = set()
    try:
        # This endpoint is generally reliable for a small number of queries
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        response = requests.get(url, timeout=DEFAULT_TIMEOUT)
        
        if response.status_code == 200:
            for line in response.text.splitlines():
                parts = line.split(',')
                # Hostname is typically the first column
                if parts and len(parts) > 0 and f".{domain}" in parts[0]:
                    subdomains.add(parts[0].lower().strip())
        else:
            print(f"  [ERROR] HackerTarget failed with status code: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"  [ERROR] HackerTarget failed: {e}")
    return list(subdomains)

def o2_get_subdomains_from_alienvault_otx(domain):
    """Fetches subdomains from AlienVault OTX (Open Threat Exchange) passive DNS."""
    print(f"  [+] Querying AlienVault OTX...")
    subdomains = set()
    try:
        # Public API endpoint for domain passive DNS
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        response = requests.get(url, timeout=DEFAULT_TIMEOUT)

        if response.status_code == 200:
            data = response.json()
            for record in data.get('passive_dns', []):
                hostname = record.get('hostname')
                if hostname and f".{domain}" in hostname:
                    subdomains.add(hostname.lower().strip())
        else:
            print(f"  [ERROR] AlienVault OTX failed with status code: {response.status_code}")
    except Exception as e:
        print(f"  [ERROR] AlienVault OTX failed: {e}")
    return list(subdomains)


def o2_get_subdomains_from_anubis(domain):
    """Fetches subdomains from a public AnubisDB repository (if available)."""
    print(f"  [+] Querying AnubisDB...")
    subdomains = set()
    try:
        # Anubis often provides a public data link for its scan results as a JSON array
        url = f"https://jonlu.ca/anubis/subdomains/{domain}" 
        response = requests.get(url, timeout=DEFAULT_TIMEOUT)

        if response.status_code == 200:
            data = response.json()
            # Expecting a list of strings
            for sub in data:
                if isinstance(sub, str) and f".{domain}" in sub:
                    subdomains.add(sub.lower().strip())
        else:
            print(f"  [ERROR] AnubisDB failed with status code: {response.status_code}")
    except Exception as e:
        print(f"  [ERROR] AnubisDB failed: {e}")
    return list(subdomains)


def run_option_2(target_input, output_file):
    """Main logic for Option 2: Subdomains Enumeration (Hardened Passive Sources)."""

    domains = load_targets(target_input)
    all_found = []

    # List of all passive sources that generally don't require an API key
    passive_sources = [
        o2_get_subdomains_from_crtsh,
        o2_get_subdomains_from_certspotter,
        o2_get_subdomains_from_rapiddns,
        o2_get_subdomains_from_hackertarget_passive,
        o2_get_subdomains_from_alienvault_otx,
        o2_get_subdomains_from_anubis
    ]
    
    # List of API sources (only run if API key is not default)
    api_sources = [
        o2_get_subdomains_from_virustotal,
        o2_get_subdomains_from_securitytrails,
        o2_get_subdomains_from_shodan
    ]

    for domain in domains:
        print(Fore.YELLOW + f"\n[*] Scanning domain: {domain}" + Style.RESET_ALL)
        
        candidates = set(f"{p}.{domain}" for p in O2_COMMON_SUBDOMAINS)
        
        # 1. Run all PASSIVE Sources
        print(Fore.CYAN + "  Fetching from passive sources (No API Key Required)..." + Style.RESET_ALL)
        for source_func in passive_sources:
            candidates.update(source_func(domain))
        
        # 2. Run API Sources (Only if key is set)
        print(Fore.CYAN + "  Fetching from API sources (If Keys are configured)..." + Style.RESET_ALL)
        for source_func in api_sources:
            candidates.update(source_func(domain))

        candidates.add(domain)

        full_domains = sorted(list(candidates))
        
        print(Fore.CYAN + f"  Found {len(full_domains)} unique candidates. Starting DNS resolution..." + Style.RESET_ALL)
        
        found_current = []
        # Use a higher number of workers for parallel DNS resolution
        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
            future_to_domain = {executor.submit(o2_resolve_domain, d): d for d in full_domains}
            
            with tqdm(total=len(full_domains), desc="Resolving", colour='GREEN', unit=" hosts") as pbar:
                for future in concurrent.futures.as_completed(future_to_domain):
                    domain_name = future_to_domain[future]
                    try:
                        ip = future.result()
                        if ip:
                            found_current.append((domain_name, ip))
                    except Exception:
                        pass
                    pbar.update(1)

        all_found.extend(found_current)

    if all_found:
        host_max = max(len(sub) for sub, _ in all_found) if all_found else 30
        host_max = max(host_max, 30)
        ip_width = 15
        
        col_sep = " - "
        header_text = f"{'Host':<{host_max}}{col_sep}{'IP':<{ip_width}}"
        sep = "-" * len(header_text)

        print("\n" + Fore.YELLOW + "=" * len(sep) + Style.RESET_ALL)
        
        print(Fore.BLUE + f"{'Host':<{host_max}}" + Style.RESET_ALL + col_sep + Fore.GREEN + f"{'IP':<{ip_width}}" + Style.RESET_ALL)
        print(sep)

        with open(output_file, "w") as f:
            f.write(header_text + "\n")
            f.write(sep + "\n")
            
            for sub, ip in sorted(all_found):
                tqdm.write(Fore.BLUE + f"{sub:<{host_max}}" + Style.RESET_ALL + col_sep + Fore.GREEN + f"{ip:<{ip_width}}" + Style.RESET_ALL)
                f.write(f"{sub:<{host_max}}{col_sep}{ip:<{ip_width}}\n")
    else:
        print(Fore.RED + "No subdomains found or resolved." + Style.RESET_ALL)


# ==============================================================================
# ------------------------- OPTION 3: ISP ZERO-RATED CHECK ---------------------
# ==============================================================================

# ... (run_option_3 and its helpers are unchanged) ...

def o3_resolve_domain(domain, resolver="8.8.8.8"):
    """Resolve domain to IPv4 and IPv6 addresses using a specific resolver."""
    ipv4s = set()
    ipv6s = set()
    try:
        resolver_obj = dns.resolver.Resolver(configure=False)
        resolver_obj.nameservers = [resolver]
        
        # A records (IPv4)
        try:
            answers = resolver_obj.resolve(domain, 'A')
            ipv4s.update(str(r) for r in answers)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
            pass

        # AAAA records (IPv6)
        try:
            answers = resolver_obj.resolve(domain, 'AAAA')
            ipv6s.update(str(r) for r in answers)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
            pass
            
        return list(ipv4s), list(ipv6s)
    except Exception:
        return [], []

def o3_check_zero_rate_python(ip, domain, proto, timeout=DEFAULT_TIMEOUT):
    """Probes the domain/IP combination and checks for zero-rate indicators."""
    port = 443 if proto == 'https' else 80
    url = f"{proto}://{domain}:{port}/"
    zero_rate = False
    http_ok = False

    # Define common zero-rate keywords
    ZERO_RATE_KEYWORDS = ["free data", "zero-rated", "whitelist", "portal", "digicel", "add credit", "out of data"]

    try:
        # Use requests with specific IP binding if possible (requires advanced networking setup, simplified here)
        
        r = requests.get(url, headers={'Host': domain, 'User-Agent': O1_USER_AGENT}, 
                         timeout=timeout, verify=False, allow_redirects=True)
        
        # Check HTTP status
        if 200 <= r.status_code < 400:
            http_ok = True
        
        # Check Zero-Rate Indicators in Headers or Body
        resp_text = r.text.lower() if r.text else ""
        resp_headers = str(r.headers).lower()
        
        if any(keyword in resp_text for keyword in ZERO_RATE_KEYWORDS):
            zero_rate = True
        if any(keyword in resp_headers for keyword in ZERO_RATE_KEYWORDS):
            zero_rate = True
            
    except requests.exceptions.Timeout:
        pass
    except requests.exceptions.RequestException:
        pass
    except Exception as e:
        # print(f"  [Error] {proto} probe on {domain} failed: {e}")
        pass

    return http_ok, zero_rate

def o3_get_verdict(sys_dns_ok, http4_ok, https4_ok, http6_ok, https6_ok, env_zero_flag, zero_rate_detected):
    """Determine the final verdict based on results."""
    
    if not sys_dns_ok:
        return Fore.RED + "DNS filtered" + Style.RESET_ALL, "DNS filtered"
    
    total_ok = http4_ok + https4_ok + http6_ok + https6_ok
    
    if total_ok == 0:
        return Fore.RED + "Fully blocked" + Style.RESET_ALL, "Fully blocked"
    elif env_zero_flag:
        return Fore.GREEN + "Likely Zero-Rated (loads despite control fail)" + Style.RESET_ALL, "Likely Zero-Rated"
    elif zero_rate_detected:
        return Fore.YELLOW + "Zero indicators detected" + Style.RESET_ALL, "Zero indicators detected"
    else:
        return Fore.GREEN + "Accessible (may require data)" + Style.RESET_ALL, "Accessible"


def run_option_3(target_input, output_file):
    """Main logic for Option 3: ISP Zero-Rated Check (Pure Python)."""
    
    domains = load_targets(target_input)
    if not domains: return

    RESOLVERS = ["8.8.8.8", "1.1.1.1"]
    CONTROL_SITE = "google.com"
    
    # 1. Baseline Control Check
    print(Fore.BLUE + f"Baseline Check: Testing {Fore.YELLOW}{CONTROL_SITE}{Style.RESET_ALL} (non-zero-rated)...")
    control_ipv4s, _ = o3_resolve_domain(CONTROL_SITE, RESOLVERS[0])
    control_http4_ok = False
    control_https4_ok = False
    control_zero_rate = False
    
    for ip in control_ipv4s:
        http_ok, http_zero = o3_check_zero_rate_python(ip, CONTROL_SITE, 'http')
        https_ok, https_zero = o3_check_zero_rate_python(ip, CONTROL_SITE, 'https')
        if http_ok: control_http4_ok = True
        if https_ok: control_https4_ok = True
        if http_zero or https_zero: control_zero_rate = True
        if control_http4_ok and control_https4_ok and control_zero_rate: break
        
    print(Fore.GREEN + f"Control: IPv4 HTTP/HTTPS: {int(control_http4_ok)}/{int(control_https4_ok)} | Zero Indicators: {int(control_zero_rate)}" + Style.RESET_ALL)
    
    all_results = []
    
    # 2. Main Scan Loop
    for domain in tqdm(domains, desc="Scanning Domains", colour='GREEN'):
        
        http4_ok, https4_ok, http6_ok, https6_ok = False, False, False, False
        zero_rate_detected = False
        sys_dns_ok = False
        
        ipv4s, ipv6s = [], []
        
        for r in RESOLVERS:
            # Check for generic DNS resolution (not filtered by the ISP)
            i4, i6 = o3_resolve_domain(domain, r)
            if i4 or i6: sys_dns_ok = True
            ipv4s.extend(i4)
            ipv6s.extend(i6)
            if sys_dns_ok: break 

        # Check IPv4
        for ip in set(ipv4s):
            http_ok, http_zero = o3_check_zero_rate_python(ip, domain, 'http')
            https_ok, https_zero = o3_check_zero_rate_python(ip, domain, 'https')
            
            if http_ok: http4_ok = True
            if https_ok: https4_ok = True
            if http_zero or https_zero: zero_rate_detected = True
        
        # Check IPv6 (Simplified: uses the same Python function)
        for ip in set(ipv6s):
            http_ok, http_zero = o3_check_zero_rate_python(ip, domain, 'http')
            https_ok, https_zero = o3_check_zero_rate_python(ip, domain, 'https')
            
            if http_ok: http6_ok = True
            if https_ok: https6_ok = True
            if http_zero or https_zero: zero_rate_detected = True

        # Environment Zero-Flag: Loads successfully when control site failed
        env_zero_flag = 0
        if not control_http4_ok and (http4_ok or https4_ok): env_zero_flag = 1
        
        # Final Verdict
        verdict_colored, verdict_clean = o3_get_verdict(sys_dns_ok, http4_ok, https4_ok, http6_ok, https6_ok, env_zero_flag, zero_rate_detected)
        
        # Console Summary Output
        tqdm.write(Fore.BLUE + f"\n[SUMMARY] {Fore.YELLOW}{domain}{Style.RESET_ALL}")
        printf_format = "%-20s %-12s"
        
        tqdm.write(printf_format % ("IPv4 HTTP:", Fore.GREEN + "OK" + Style.RESET_ALL if http4_ok else Fore.RED + "BLOCKED" + Style.RESET_ALL))
        tqdm.write(printf_format % ("IPv4 HTTPS:", Fore.GREEN + "OK" + Style.RESET_ALL if https4_ok else Fore.RED + "BLOCKED" + Style.RESET_ALL))
        tqdm.write(printf_format % ("IPv6 HTTP:", Fore.GREEN + "OK" + Style.RESET_ALL if http6_ok else Fore.RED + "BLOCKED" + Style.RESET_ALL))
        tqdm.write(printf_format % ("IPv6 HTTPS:", Fore.GREEN + "OK" + Style.RESET_ALL if https6_ok else Fore.RED + "BLOCKED" + Style.RESET_ALL))
        tqdm.write(printf_format % ("Zero Indicators:", Fore.YELLOW + "YES" + Style.RESET_ALL if zero_rate_detected else Fore.GREEN + "NO" + Style.RESET_ALL))
        tqdm.write(printf_format % ("Env Zero-Flag:", Fore.YELLOW + "YES" + Style.RESET_ALL if env_zero_flag else Fore.GREEN + "NO" + Style.RESET_ALL))

        tqdm.write(Fore.BLUE + f"\n[VERDICT]{Style.RESET_ALL}")
        tqdm.write(f"%-12s %-12s" % ("", verdict_colored))
        tqdm.write("-" * 50)
        
        all_results.append({
            "Domain": domain,
            "HTTPv4": "OK" if http4_ok else "BLOCK",
            "HTTPSv4": "OK" if https4_ok else "BLOCK",
            "HTTPv6": "OK" if http6_ok else "BLOCK",
            "HTTPSv6": "OK" if https6_ok else "BLOCK",
            "Zero Flags": str(int(zero_rate_detected) + env_zero_flag),
            "Verdict": verdict_clean
        })

    # 3. Final File Output (Aligned)
    if all_results:
        with open(output_file, "w") as f:
            
            # Column widths for file output
            w = {k: max(len(r.get(k, '')) for r in all_results) for k in all_results[0].keys()}
            w['Domain'] = max(w['Domain'], 30)
            
            # Separator function
            def separator_line(char='-'):
                return (f"{char*w['Domain']:<{w['Domain']}} | {char*w['HTTPv4']:<{w['HTTPv4']}} | "
                        f"{char*w['HTTPSv4']:<{w['HTTPSv4']}} | {char*w['HTTPv6']:<{w['HTTPv6']}} | "
                        f"{char*w['HTTPSv6']:<{w['HTTPSv6']}} | {char*w['Zero Flags']:<{w['Zero Flags']}} | "
                        f"{char*w['Verdict']}\n")

            # Write Header
            header_line = (f"{'Domain':<{w['Domain']}} | {'HTTPv4':<{w['HTTPv4']}} | "
                           f"{'HTTPSv4':<{w['HTTPSv4']}} | {'HTTPv6':<{w['HTTPv6']}} | "
                           f"{'HTTPSv6':<{w['HTTPSv6']}} | {'Zero Flags':<{w['Zero Flags']}} | "
                           f"{'Verdict'}\n")
            f.write(header_line)
            f.write(separator_line())
            
            # Write Rows
            for r in all_results:
                line = (f"{r['Domain']:<{w['Domain']}} | {r['HTTPv4']:<{w['HTTPv4']}} | "
                        f"{r['HTTPSv4']:<{w['HTTPSv4']}} | {r['HTTPv6']:<{w['HTTPv6']}} | "
                        f"{r['HTTPSv6']:<{w['HTTPSv6']}} | {r['Zero Flags']:<{w['Zero Flags']}} | "
                        f"{r['Verdict']}\n")
                f.write(line)


# ==============================================================================
# ------------------------- OPTION 4: WS/SSL/HTTP/SNI/CDN CHECK ----------------
# ==============================================================================

# ... (run_option_4 and its helpers are unchanged) ...

def o4_get_cloudflare_ip_ranges():
    global O4_CLOUDFLARE_IPS
    if O4_CLOUDFLARE_IPS: return
    try:
        response = requests.get('https://www.cloudflare.com/ips-v4', timeout=5)
        if response.status_code == 200:
            O4_CLOUDFLARE_IPS = [ipaddress.ip_network(cidr.strip()) for cidr in response.text.splitlines()]
    except Exception as e: logging.error(f"Failed to fetch Cloudflare IP ranges: {e}")

async def o4_get_ip(host, timeout=5):
    try:
        loop = asyncio.get_event_loop()
        addr_info = await asyncio.wait_for(loop.run_in_executor(None, socket.gethostbyname, host), timeout)
        return addr_info
    except (socket.gaierror, asyncio.TimeoutError): return "N/A"

async def o4_check_http(host, port=80, timeout=5):
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f'http://{host}:{port}/', timeout=timeout) as response: return response.status == 200
    except: return False

async def o4_check_https(host, port=443, timeout=5):
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f'https://{host}:{port}/', timeout=timeout) as response: return response.status == 200
    except ClientConnectorCertificateError:
        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
                async with session.get(f'https://{host}:{port}/', timeout=timeout) as response: return response.status == 200
        except: return False
    except ClientConnectorError:
        return False
    except: return False

async def o4_check_websocket(host, port=80, secure=False, timeout=5, retries=2):
    scheme = 'wss' if secure else 'ws'
    port = 443 if secure and port == 80 else port
    for attempt in range(retries):
        try:
            ssl_context = ssl.create_default_context()
            if secure: ssl_context.check_hostname = False; ssl_context.verify_mode = ssl.CERT_NONE
            
            async with websockets.connect(
                f'{scheme}://{host}:{port}/',
                ssl=ssl_context if secure else None, timeout=timeout
            ) as ws:
                await ws.ping(); return True
        except:
            if attempt < retries - 1: await asyncio.sleep(1)
            continue
    return False

async def o4_check_cdn_via_headers_and_ip(host, ip, timeout=5):
    is_cdn = False
    
    # 1. Check Headers
    try:
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
            for proto in ['http', 'https']:
                try:
                    async with session.get(f'{proto}://{host}/', timeout=timeout) as response:
                        headers = {k.lower(): v.lower() for k, v in response.headers.items()}
                        server = headers.get('server', '')
                        
                        if any(re.search(pattern, server) for pattern in O4_CDN_PATTERNS): is_cdn = True; break
                        if any(cdn in headers.get(h, '') for h in ['x-cache', 'via', 'cf-ray', 'x-cdn', 'x-served-by'] for cdn in ['cloudfront', 'akamai', 'fastly', 'cloudflare', 'bunnycdn']): is_cdn = True; break
                except: continue
    except: pass
    
    if is_cdn: return True

    # 2. Check IP 
    if ip != "N/A":
        try:
            ip_addr = ipaddress.ip_address(ip)
            if ip_addr.is_private: return False
            for net in O4_CLOUDFLARE_IPS:
                if ip_addr in net: return True
        except ValueError: pass
        
    return False

async def o4_scan_host(host, semaphore):
    async with semaphore:
        ip_task = o4_get_ip(host)
        ip_result = await ip_task
        
        http_task = o4_check_http(host)
        https_task = o4_check_https(host)
        websocket_task = o4_check_websocket(host, secure=False)
        websocket_secure_task = o4_check_websocket(host, 443, secure=True)
        cdn_task = o4_check_cdn_via_headers_and_ip(host, ip_result)
        
        http_result, https_result, ws_result, wss_result, cdn_result = await asyncio.gather(
            http_task, https_task, websocket_task, websocket_secure_task, cdn_task,
            return_exceptions=True
        )
        
        results = {
            'host': host,
            'ip': ip_result if not isinstance(ip_result, Exception) else "N/A",
            'http': http_result if not isinstance(http_result, Exception) else False,
            'https': https_result if not isinstance(https_result, Exception) else False,
            'websocket': (ws_result or wss_result) if not isinstance(ws_result, Exception) and not isinstance(wss_result, Exception) else False,
            'sni_ssl_tls': https_result if not isinstance(https_result, Exception) else False,
            'cdn': cdn_result if not isinstance(cdn_result, Exception) else False
        }
        return results


async def run_option_4(target_input, output_file):
    """Main logic for Option 4: WS/SSL/HTTP/SNI/CDN Check (Async Python)."""

    o4_get_cloudflare_ip_ranges()
    hosts = load_targets(target_input)

    col_widths = {'host': 30, 'ip': 15, 'http': 10, 'https': 10, 'websocket': 12, 'sni_ssl_tls': 15, 'cdn': 10}
    total_width = sum(col_widths.values())
    
    def get_colored_field(text, width, color):
        return f"{color}{text:<{width}}{Style.RESET_ALL}"
    
    header_console = (f"{get_colored_field('Host', col_widths['host'], Fore.BLUE)}"
                      f"{get_colored_field('IP', col_widths['ip'], Fore.GREEN)}"
                      f"{get_colored_field('HTTP', col_widths['http'], Fore.YELLOW)}"
                      f"{get_colored_field('HTTPS', col_widths['https'], Fore.CYAN)}"
                      f"{get_colored_field('WebSocket', col_widths['websocket'], Fore.MAGENTA)}"
                      f"{get_colored_field('SNI/SSL/TLS', col_widths['sni_ssl_tls'], Fore.WHITE)}"
                      f"{get_colored_field('CDN', col_widths['cdn'], Fore.RED)}")

    print("\n" + Fore.YELLOW + "=" * total_width + Style.RESET_ALL)
    print(header_console)
    print("-" * total_width)
    
    header_file = (f"{'Host':<{col_widths['host']}}"
                   f"{'IP':<{col_widths['ip']}}"
                   f"{'HTTP':<{col_widths['http']}}"
                   f"{'HTTPS':<{col_widths['https']}}"
                   f"{'WebSocket':<{col_widths['websocket']}}"
                   f"{'SNI/SSL/TLS':<{col_widths['sni_ssl_tls']}}"
                   f"{'CDN':<{col_widths['cdn']}}")
    
    semaphore = asyncio.Semaphore(50)
    tasks = [o4_scan_host(host, semaphore) for host in hosts]
    
    with open(output_file, "w") as f:
        f.write(header_file + "\n")
        f.write("-" * total_width + "\n")
        
        for task in tqdm(asyncio.as_completed(tasks), total=len(tasks), desc="Scanning", unit=" hosts"):
            result = await task
            
            if isinstance(result, Exception): continue
            
            def get_status_text(value):
                return 'YES' if value else 'NO'

            host_disp = result['host'][:col_widths['host']-1]
            ip_disp = result['ip'][:col_widths['ip']-1]

            row_console = (
                f"{get_colored_field(host_disp, col_widths['host'], Fore.BLUE)}"
                f"{get_colored_field(ip_disp, col_widths['ip'], Fore.GREEN)}"
                f"{get_colored_field(get_status_text(result['http']), col_widths['http'], Fore.YELLOW)}"
                f"{get_colored_field(get_status_text(result['https']), col_widths['https'], Fore.CYAN)}"
                f"{get_colored_field(get_status_text(result['websocket']), col_widths['websocket'], Fore.MAGENTA)}"
                f"{get_colored_field(get_status_text(result['sni_ssl_tls']), col_widths['sni_ssl_tls'], Fore.WHITE)}"
                f"{get_colored_field(get_status_text(result['cdn']), col_widths['cdn'], Fore.RED)}"
            )
            tqdm.write(row_console)

            row_file = (f"{host_disp:<{col_widths['host']}}"
                        f"{ip_disp:<{col_widths['ip']}}"
                        f"{get_status_text(result['http']):<{col_widths['http']}}"
                        f"{get_status_text(result['https']):<{col_widths['https']}}"
                        f"{get_status_text(result['websocket']):<{col_widths['websocket']}}"
                        f"{get_status_text(result['sni_ssl_tls']):<{col_widths['sni_ssl_tls']}}"
                        f"{get_status_text(result['cdn']):<{col_widths['cdn']}}")
            f.write(row_file + "\n")


# ==============================================================================
# ------------------------- OPTION 5: CIDR RESOLUTION --------------------------
# ==============================================================================

# ... (run_option_5 and its helpers are unchanged) ...

def o5_resolve_cidr_range(cidr_range):
    """
    Scans a CIDR range, resolves PTR records for each IP, and returns
    a list of (IP, Hostname) tuples.
    """
    resolved_hosts = []
    
    # Manually configure a reliable DNS resolver
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ['8.8.8.8', '1.1.1.1'] 
    resolver.timeout = 5.0
    resolver.lifetime = 10.0
    
    try:
        network = ipaddress.ip_network(cidr_range, strict=False)
        total_ips = len(list(network.hosts()))
        
        print(Fore.CYAN + f"[*] Resolving PTR for {cidr_range} ({total_ips} addresses) using {resolver.nameservers}..." + Style.RESET_ALL)

        # Use tqdm for a progress bar
        with tqdm(network.hosts(), total=total_ips, desc="Resolving IPs", unit=" hosts", colour='BLUE') as pbar:
            for ip_obj in ipaddress.ip_network(cidr_range).hosts():
                ip = str(ip_obj)
                pbar.set_description(f"Current: {ip}")
                
                try:
                    # Perform reverse DNS lookup (PTR)
                    rev_name = dns.reversename.from_address(ip)
                    
                    # Use the configured resolver and set a robust lifetime (8.0 seconds)
                    answers = resolver.resolve(rev_name, 'PTR', lifetime=8.0) 
                    
                    # Get the hostname, cleaning up the trailing dot
                    hostname = str(answers[0]).rstrip('.')
                    
                    if hostname:
                        # Console output - Use pbar.write() to prevent progress bar interference
                        pbar.write(f"{Fore.GREEN}{ip:<15}{Style.RESET_ALL} -> {Fore.BLUE}{hostname}{Style.RESET_ALL}")
                        
                        # Store for file output
                        resolved_hosts.append((ip, hostname))
                    
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                    pass # Skip if no PTR record exists or timeout
                except Exception as e:
                    pass
                pbar.update(1) # Ensure update is called regardless of success/failure
        
    except ValueError:
        print(Fore.RED + f"Error: Invalid CIDR format: {cidr_range}" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"An error occurred during resolution: {e}" + Style.RESET_ALL)

    return resolved_hosts

def run_option_5(target_input, output_file):
    """Main logic for Option 5: CIDR IP+Name Resolve (Pure Python)."""

    cidrs = load_targets(target_input)
    if not cidrs:
        print(Fore.RED + "Invalid input. Please provide a CIDR (e.g., 1.1.1.0/24) or a list file." + Style.RESET_ALL)
        return

    all_resolved = []
    
    # Run the resolution for each CIDR block
    for cidr in cidrs:
        all_resolved.extend(o5_resolve_cidr_range(cidr))

    # The actual output file for the aligned results
    final_resolved_file = output_file.replace(".txt", "_resolved.txt")

    if all_resolved:
        # Determine max widths for alignment
        ip_max = max(len(ip) for ip, host in all_resolved) if all_resolved else 15
        host_max = max(len(host) for ip, host in all_resolved) if all_resolved else 30
        ip_max = max(ip_max, 15)
        host_max = max(host_max, 30)

        # Write to final aligned file
        with open(final_resolved_file, "w") as f:
            
            # Header
            header = f"{'IP':<{ip_max}} | {'Host':<{host_max}}"
            separator = f"{'-'*ip_max} | {'-'*host_max}"
            
            f.write(header + "\n")
            f.write(separator + "\n")
            
            # Rows (Sorted by IP)
            for ip, host in sorted(all_resolved, key=lambda x: ipaddress.ip_address(x[0])):
                line = f"{ip:<{ip_max}} | {host:<{host_max}}"
                f.write(line + "\n")

        # FIX FOR SYNTAXERROR: Changed f-string concatenation to a single print
        print(Fore.GREEN + "\n[+] Clean resolved list saved to " + final_resolved_file + Style.RESET_ALL)
    else:
        print(Fore.RED + "[-] No hosts with names found." + Style.RESET_ALL)


# ==============================================================================
# ------------------------- OPTION 6: WORDLIST DNS SCAN --------------------------
# ==============================================================================

def o6_check_domain_existence(entry, base_domain):
    """Checks if a wordlist entry is a resolvable domain/subdomain."""
    entry = entry.strip()
    if not entry:
        return None

    if "." in entry:
        # If the wordlist entry is a full domain (e.g., mail.example.com), check it directly
        full_domain = entry
    else:
        # Otherwise, assume it is a subdomain (e.g., www, mail, blog)
        full_domain = f"{entry}.{base_domain}"

    try:
        # Attempt to resolve the A record
        # Note: Using dns.resolver is better for parallel lookups than socket.gethostbyname
        answers = dns.resolver.resolve(full_domain, 'A', lifetime=DEFAULT_TIMEOUT)
        
        # If resolution is successful, return the domain and its IP
        ip_address = str(answers[0])
        return full_domain, ip_address

    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
        return None
    except Exception:
        return None

def run_option_6(base_domain, wordlist_path, output_file):
    """
    Performs a concurrent DNS scan using a wordlist against a base domain.
    The base_domain is the 'target' input. The wordlist_path is the second input.
    """
    
    print(Fore.YELLOW + f"[*] Target Base Domain: {base_domain}" + Style.RESET_ALL)
    print(Fore.YELLOW + f"[*] Wordlist Path: {wordlist_path}" + Style.RESET_ALL)

    try:
        with open(wordlist_path, 'r') as f:
            entries = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(Fore.RED + f"Error: Failed to read wordlist: {e}" + Style.RESET_ALL)
        return

    print(Fore.CYAN + f"[*] Loaded {len(entries)} entries from the wordlist." + Style.RESET_ALL)
    
    found_hosts = []
    
    # Use ThreadPoolExecutor for concurrent DNS queries
    with concurrent.futures.ThreadPoolExecutor(max_workers=O1_DEFAULT_WORKERS) as executor:
        # Submit tasks for each entry
        future_to_entry = {
            executor.submit(o6_check_domain_existence, entry, base_domain): entry
            for entry in entries
        }
        
        # Use tqdm for a progress bar
        for future in tqdm(concurrent.futures.as_completed(future_to_entry), 
                           total=len(future_to_entry), desc="Resolving", colour='BLUE'):
            
            result = future.result()
            if result:
                found_hosts.append(result)

    # Output Results
    if found_hosts:
        try:
            with open(output_file, 'w') as f:
                f.write("Host,IP_Address\n") # CSV Header
                
                print(Fore.GREEN + f"\n[+] Scan complete. {len(found_hosts)} live hosts found." + Style.RESET_ALL)
                
                # Determine max widths for alignment
                host_max = max(len(h) for h, ip in found_hosts) if found_hosts else 30
                ip_max = max(len(ip) for h, ip in found_hosts) if found_hosts else 15
                
                header_text = f"{'Host':<{host_max}} | {'IP Address':<{ip_max}}"
                separator = "-" * len(header_text)
                
                print(separator)
                print(Fore.CYAN + header_text + Style.RESET_ALL)
                print(separator)

                for host, ip in sorted(found_hosts):
                    f.write(f"{host},{ip}\n")
                    print(f"{host:<{host_max}} | {ip:<{ip_max}}")
                
            print(Fore.GREEN + f"\n[+] Results written to {output_file}." + Style.RESET_ALL)

        except Exception as e:
            print(Fore.RED + f"Error: Failed to write output file: {e}" + Style.RESET_ALL)
    else:
        print(Fore.RED + "[-] No live hosts found from the wordlist." + Style.RESET_ALL)


# ==============================================================================
# ------------------------------ MAIN EXECUTION LOOP ---------------------------
# ==============================================================================

def main_menu_loop():
    """The main application loop."""
    while True:
        choice = display_menu()

        if choice == '1':
            prompt_and_execute(1, "Enter domain/IP to lookup (e.g., example.com or 8.8.8.8): ", run_option_1)
        elif choice == '2':
            prompt_and_execute(2, "Enter domain or list file path to enumerate: ", run_option_2)
        elif choice == '3':
            prompt_and_execute(3, "Enter domain or list file path to scan: ", run_option_3)
        elif choice == '4':
            prompt_and_execute(4, "Enter domain or list file path to scan: ", run_option_4)
        elif choice == '5':
            # Note: The output_file is "CIDR.txt" but the function writes to "CIDR_resolved.txt"
            prompt_and_execute(5, "Enter a CIDR (e.g., 1.1.1.0/24) or a list file path: ", run_option_5)
        elif choice == '6':
            # NEW OPTION 6: Wordlist DNS Scan. Requires the base domain and the wordlist path.
            prompt_and_execute(6, "Enter BASE domain to scan against (e.g., google.com): ", run_option_6, wordlist_required=True)
        elif choice == '7':
            # EXIT moved to 7
            print(Fore.GREEN + "\nExiting script. Goodbye!" + Style.RESET_ALL)
            sys.exit(0)
        else:
            print(Fore.RED + "Invalid choice. Please enter a number between 1 and 7." + Style.RESET_ALL)
            time.sleep(1)

if __name__ == "__main__":
    try:
        main_menu_loop()
    except KeyboardInterrupt:
        print(Fore.RED + "\nScan interrupted by user (Ctrl+C). Exiting." + Style.RESET_ALL)
        sys.exit(1)
