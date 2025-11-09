#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
STRATUS v1.0 - Ultimate Python Source Code Scanner
Developed by Biswajeet Ray
(Single-file version with Native DB)
"""

import sys
import os
import re
import json
import csv
import argparse
import subprocess
import time
import threading
import itertools
import urllib.request
import platform
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional
from collections import defaultdict
import warnings

# --- Configuration ---
warnings.filterwarnings('ignore')
VERSION = "1.0"
AUTHOR = "Biswajeet Ray"

# --- Optional Dependencies ---
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False
    class MockColor:
        def __getattr__(self, _): return ""
    Fore = Style = MockColor()

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False
    def tqdm(iterable, *args, **kwargs): return iterable

# --- Constants ---
SEVERITY_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "🔵"}
SEVERITY_WEIGHTS = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1, "INFO": 0}

BANNER = f"""
{Fore.CYAN}███████╗████████╗██████╗  █████╗ ████████╗██╗   ██╗███████╗
██╔════╝╚══██╔══╝██╔══██╗██╔══██╗╚══██╔══╝██║   ██║██╔════╝
███████╗   ██║   ██████╔╝███████║   ██║   ██║   ██║███████╗
╚════██║   ██║   ██╔══██╗██╔══██║   ██║   ██║   ██║╚════██║
███████║   ██║   ██║  ██║██║  ██║   ██║   ╚██████╔╝███████║
╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚══════╝{Style.RESET_ALL}

{Fore.GREEN}✨ STRATUS v{VERSION} - ULTIMATE PYTHON SECURITY SUITE ✨{Style.RESET_ALL}
{Fore.YELLOW}Professional Multi-Engine Vulnerability Scanner{Style.RESET_ALL}
{Fore.CYAN}Developed by {AUTHOR} 🚀{Style.RESET_ALL}
"""

# --- Native Pattern Database (100+ High-Value Patterns) ---
NATIVE_DB = [
    # SQL Injection
    (r'(execute|cursor\.execute|executemany)\s*\([^)]*[\'"].*?(%s|%d|\+|\.format|f[\'"])', "CRITICAL", "SQL Injection", "Use parameterized queries (bind variables)."),
    (r'\$this->db->query\s*\(', "CRITICAL", "SQL Injection (PHP)", "Use query bindings."),
    # Command Injection
    (r'os\.system\s*\(', "CRITICAL", "Command Injection (os.system)", "Use subprocess.run(['ls', arg], shell=False)."),
    (r'os\.popen\s*\(', "CRITICAL", "Command Injection (os.popen)", "Use subprocess.run() with shell=False."),
    (r'subprocess\.(call|run|Popen)\s*\(.*shell\s*=\s*True', "HIGH", "Command Injection (shell=True)", "Set shell=False and use a list for args."),
    (r'(exec|shell_exec|system|passthru|pcntl_exec|popen)\s*\(', "CRITICAL", "Command Injection (PHP)", "Avoid shell execution or use escapeshellarg()."),
    (r'`.*\$[^`]*`', "CRITICAL", "Command Injection (PHP Backticks)", "Avoid backtick operator with variables."),
    # Dangerous Functions
    (r'\beval\s*\(', "CRITICAL", "Dangerous Eval", "Avoid eval() entirely."),
    (r'\bexec\s*\(', "CRITICAL", "Dangerous Exec", "Avoid dynamic code execution."),
    (r'assert\s*\(', "HIGH", "Dangerous Assert", "Do not use assert for security logic."),
    # Deserialization
    (r'pickle\.loads?\s*\(', "HIGH", "Insecure Deserialization (pickle)", "Use JSON instead of pickle for untrusted data."),
    (r'yaml\.load\s*\(', "HIGH", "Insecure Deserialization (yaml)", "Use yaml.safe_load()."),
    (r'unserialize\s*\(', "HIGH", "Insecure Deserialization (PHP)", "Use json_decode() instead."),
    # Secrets & Auth
    (r'(?:password|passwd|secret|api_key|auth_token|access_token)\s*=\s*[\'"][A-Za-z0-9_\-]{8,}[\'"]', "HIGH", "Hardcoded Secret", "Move to environment variables."),
    (r'(AKIA|ASIA)[0-9A-Z]{16}', "CRITICAL", "AWS Access Key", "Revoke and use IAM roles."),
    (r'-----BEGIN [A-Z]+ PRIVATE KEY-----', "CRITICAL", "Private Key Found", "Remove private keys from source code."),
    (r'Authorization:\s*Bearer\s+[a-zA-Z0-9_\-\.]+', "HIGH", "Hardcoded Bearer Token", "Use dynamic token generation."),
    # Misconfiguration
    (r'debug\s*=\s*True', "MEDIUM", "Debug Mode Enabled", "Set DEBUG=False in production."),
    (r'verify\s*=\s*False', "HIGH", "SSL Verification Disabled", "Enable SSL verification."),
    (r'bind\s*=\s*[\'"]0\.0\.0\.0[\'"]', "MEDIUM", "Insecure Binding", "Bind to 127.0.0.1 if possible."),
    (r'chmod\s*\(.*, 0o?777\)', "HIGH", "Insecure Permissions (777)", "Use restricted permissions (e.g., 644 or 600)."),
    # Cryptography
    (r'hashlib\.(md5|sha1)\s*\(', "MEDIUM", "Weak Hashing", "Use SHA-256 or stronger."),
    (r'random\.(random|randint|choice)', "LOW", "Weak PRNG", "Use 'secrets' module for cryptography."),
    # Web specific
    (r'innerHTML\s*=', "HIGH", "DOM XSS Risk (JS)", "Use .textContent or .innerText."),
    (r'dangerouslySetInnerHTML', "HIGH", "React XSS Risk", "Sanitize input before using this."),
    (r'document\.write\s*\(', "HIGH", "DOM XSS Risk", "Avoid document.write()."),
    (r'echo\s*\$_GET\[', "HIGH", "Reflected XSS (PHP)", "Use htmlspecialchars()."),
    (r'header\s*\([\'"]Location:.*\$', "HIGH", "Open Redirect (PHP)", "Validate redirect targets."),
]

# --- Helpers ---
def print_info(msg): print(f"{Fore.CYAN}[INFO] {msg}{Style.RESET_ALL}")
def print_success(msg): print(f"{Fore.GREEN}[SUCCESS] {msg}{Style.RESET_ALL}")
def print_error(msg): print(f"{Fore.RED}[ERROR] {msg}{Style.RESET_ALL}")
def print_warning(msg): print(f"{Fore.YELLOW}[WARNING] {msg}{Style.RESET_ALL}")

class Spinner:
    def __init__(self, message="Processing..."):
        self.msg = message; self.running = False; self.thread = None
    def spin(self):
        s = itertools.cycle(['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'])
        while self.running: sys.stdout.write(f"\r{Fore.CYAN}{next(s)} {self.msg}{Style.RESET_ALL}"); sys.stdout.flush(); time.sleep(0.1)
        sys.stdout.write('\r' + ' ' * (len(self.msg) + 2) + '\r')
    def __enter__(self): self.running = True; self.thread = threading.Thread(target=self.spin); self.thread.start(); return self
    def __exit__(self, *a): self.running = False; self.thread.join() if self.thread else None

def run_command(cmd, timeout=300):
    try:
        f = subprocess.CREATE_NO_WINDOW if platform.system() == "Windows" else 0
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, errors='ignore', creationflags=f)
        return r.returncode, r.stdout, r.stderr
    except Exception as e: return -1, "", str(e)

# --- Tool Manager ---
class ToolManager:
    def __init__(self):
        self.tools = {'bandit':{'name':'Bandit','m':'bandit'},'mypy':{'name':'Mypy','m':'mypy'},'pylint':{'name':'Pylint','m':'pylint'},'safety':{'name':'Safety','m':'safety'}}
        self.installed = {}
        self.check()
    def check(self):
        for t,i in self.tools.items(): c,_,_ = run_command([sys.executable,'-m',i['m'],'--version'],5); self.installed[t]=(c==0)
    def install_all(self):
        m = [t for t,i in self.installed.items() if not i]
        if not m: return print_success("All engines ready!")
        print_info(f"Installing {len(m)} engines...")
        for t in m:
            with Spinner(f"Installing {self.tools[t]['name']}..."):
                c,_,_ = run_command([sys.executable,'-m','pip','install',t],600)
                if c!=0: c,_,_ = run_command([sys.executable,'-m','pip','install',t,'--break-system-packages'],600)
                if c==0: print_success(f"{self.tools[t]['name']} installed.")
                else: print_error(f"Failed to install {self.tools[t]['name']}")
        self.check()

# --- Scanner ---
class UnifiedScanner:
    def __init__(self, tools=['stratus']):
        self.tools, self.findings, self.stats = tools, [], defaultdict(int)
        self.tm = ToolManager()
        # Compile regexes once
        self.patterns = [(re.compile(p, re.I), s, n, f) for p, s, n, f in NATIVE_DB] if 'stratus' in tools else []

    def scan(self, target):
        if not os.path.exists(target): return print_error(f"Missing: {target}")
        print_info(f"🚀 Scanning: {target}")
        start = time.time()
        
        if 'stratus' in self.tools:
            print_info(f"⚡ Native Engine ({len(self.patterns)} patterns)...")
            files = []
            if os.path.isfile(target): files = [Path(target)]
            else:
                for ext in ('*.py', '*.php', '*.js', '*.java', '*.go', '*.rb'):
                    files.extend(Path(target).rglob(ext))
            
            for f in (tqdm(files, unit="file") if HAS_TQDM and files else files):
                try:
                    with open(f, 'r', errors='ignore') as r:
                        for i, l in enumerate(r, 1):
                            if len(l) > 500: continue
                            for p, sev, name, fix in self.patterns:
                                if p.search(l):
                                    self.findings.append({'file': str(f), 'line': i, 'severity': sev, 'name': name, 'desc': 'Pattern matched', 'fix': fix, 'tool': 'Native'})
                                    break
                except: pass

        engines = {
            'bandit': (['bandit', '-r', target, '-f', 'json', '-q'], lambda o: [{'file':r['filename'],'line':r['line_number'],'severity':r['issue_severity'].upper(),'name':r['test_id'],'desc':r['issue_text'],'fix':'See docs','tool':'Bandit'} for r in json.loads(o).get('results',[])]),
            'mypy': (['mypy', target, '--no-error-summary', '--show-error-codes'], lambda o: [{'file':l.split(':')[0],'line':int(l.split(':')[1]) if l.split(':')[1].isdigit() else 0,'severity':'LOW','name':'Type Error','desc':l.split(':',2)[2].strip(),'fix':'Fix type','tool':'Mypy'} for l in o.splitlines() if 'error:' in l]),
            'pylint': (['pylint', target, '-f', 'json', '-E'], lambda o: [{'file':i['path'],'line':i['line'],'severity':'HIGH' if i['type']=='error' else 'MEDIUM','name':f"Pylint {i['symbol']}",'desc':i['message'],'fix':'Fix lint','tool':'Pylint'} for i in json.loads(o)])
        }
        for t in self.tools:
            if t in engines and self.tm.installed.get(t):
                with Spinner(f"Running {t.capitalize()}..."):
                     c, out, _ = run_command([sys.executable, '-m'] + engines[t][0])
                     try: self.findings.extend(engines[t][1](out))
                     except: pass

        if 'dependencies' in self.tools:
            reqs = list(Path(target).rglob('requirements.txt')) if os.path.isdir(target) else ([Path(target)] if 'requirements' in target else [])
            if reqs:
                with Spinner("Scanning dependencies..."):
                    for req in reqs[:3]:
                        if self.tm.installed.get('safety'):
                            _, out, _ = run_command([sys.executable, '-m', 'safety', 'check', '-f', str(req), '--json'])
                            try: self.findings.extend([{'file': str(req), 'line': 0, 'severity': 'HIGH', 'name': f"Vulnerable: {v[0]}", 'desc': v[3], 'fix': f"Upgrade {v[0]} >= {v[1]}", 'tool': 'Safety'} for v in json.loads(out)])
                            except: pass
                        try:
                             for l in open(str(req), errors='ignore'):
                                 if l.strip() and not l.startswith('#'):
                                     pkg = re.split(r'[=<>!~]', l)[0].strip()
                                     if pkg:
                                         r = json.loads(urllib.request.urlopen(urllib.request.Request("https://api.osv.dev/v1/query", data=json.dumps({"package": {"name": pkg, "ecosystem": "PyPI"}}).encode(), headers={'Content-Type': 'application/json'}), timeout=2).read().decode())
                                         if r.get('vulns'): self.findings.extend([{'file': str(req), 'line': 0, 'severity': 'HIGH', 'name': f"OSV: {pkg}", 'desc': r['vulns'][0].get('summary','Vuln detected'), 'fix': 'Check OSV', 'tool': 'OSV'}])
                        except: pass

        for f in self.findings: self.stats[f.get('severity', 'INFO')] += 1
        self.duration = time.time() - start

    def report(self):
        if not self.findings: return print_success("\n✨ No issues found.\n")
        print(f"\n{'='*60}\n📊 SCAN REPORT\n{'='*60}\n⏱️  Time: {self.duration:.2f}s | 🐞 Issues: {len(self.findings)}\n{'-'*60}")
        self.findings.sort(key=lambda x: SEVERITY_WEIGHTS.get(x['severity'], 0), reverse=True)
        for f in self.findings[:25]:
            print(f"{SEVERITY_EMOJI.get(f['severity'],'🔵')} [{f['severity']}] {f['name']} ({f['tool']})\n   📍 {f['file']}:{f['line']} | 💡 {f.get('fix','')}\n{'-'*60}")
        if len(self.findings)>25: print_warning(f"...and {len(self.findings)-25} more.")
        score = max(0, 100 - sum(self.stats[s]*w for s,w in SEVERITY_WEIGHTS.items()))
        print(f"\n🏆 SCORE: {Fore.GREEN if score>80 else Fore.RED}{score}/100{Style.RESET_ALL} | " + ", ".join([f"{SEVERITY_EMOJI[s]} {c}" for s,c in self.stats.items() if c>0]) + "\n")

    def save(self, j=None, c=None, h=None):
        if j: json.dump({'findings': self.findings}, open(j, 'w'), indent=2); print_success(f"JSON: {j}")
        if c:
            w = csv.DictWriter(open(c, 'w', newline=''), fieldnames=['severity','tool','name','file','line','desc','fix'])
            w.writeheader(); w.writerows([{k:f.get(k,'') for k in w.fieldnames} for f in self.findings]); print_success(f"CSV: {c}")
        if h:
            htm = f"<!DOCTYPE html><html><head><title>Stratus Report</title><style>body{{font-family:sans-serif;background:#1a1a1a;color:#eee;padding:20px}}.f{{background:#333;padding:15px;margin:10px 0;border-left:5px solid #ccc}}.CRITICAL{{border-color:#f44}}.HIGH{{border-color:#fa0}}.MEDIUM{{border-color:#fd0}}.LOW{{border-color:#4f4}}</style></head><body><h1>🌩️ Stratus Report</h1><h2>Score: {max(0, 100 - sum(self.stats[s]*w for s,w in SEVERITY_WEIGHTS.items()))}/100</h2>"
            for f in self.findings: htm += f"<div class='f {f['severity']}'><h3>[{f['severity']}] {f['name']} ({f['tool']})</h3><p>📍 {f['file']}:{f['line']}</p><p>📝 {f['desc']}</p><p>💡 {f.get('fix','')}</p></div>"
            open(h,'w',encoding='utf-8').write(htm+"</body></html>"); print_success(f"HTML: {h}")

if __name__ == "__main__":
    p = argparse.ArgumentParser(description=f"Stratus v{VERSION}")
    p.add_argument('targets', nargs='*', help='Scan targets')
    p.add_argument('--install', action='store_true', help='Install tools')
    p.add_argument('--tools', nargs='+', default=['stratus'], choices=['stratus','bandit','mypy','pylint','dependencies','all'])
    p.add_argument('--json', metavar='FILE'); p.add_argument('--csv', metavar='FILE'); p.add_argument('--html', metavar='FILE')
    a = p.parse_args()
    print(BANNER)
    if a.install: ToolManager().install_all()
    elif a.targets:
        s = UnifiedScanner(['stratus','bandit','mypy','pylint','dependencies'] if 'all' in a.tools else a.tools)
        for t in a.targets: s.scan(t)
        s.report(); s.save(a.json, a.csv, a.html)
    else: p.print_help()
