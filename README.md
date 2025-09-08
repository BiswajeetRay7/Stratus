# Stratus - Python SAST & VAPT Scanner

███████╗████████╗██████╗  █████╗ ████████╗██╗   ██╗███████╗
██╔════╝╚══██╔══╝██╔══██╗██╔══██╗╚══██╔══╝██║   ██║██╔════╝
███████╗   ██║   ██████╔╝███████║   ██║   ██║   ██║███████╗
╚════██║   ██║   ██╔══██╗██╔══██║   ██║   ██║   ██║╚════██║
███████║   ██║   ██║  ██║██║  ██║   ██║   ╚██████╔╝███████║
╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚══════╝


**Developed by Biswajeet Ray**

Stratus is a production-quality **Python Static Application Security Testing (SAST) and Vulnerability Assessment & Penetration Testing (VAPT) tool** specifically designed for Python codebases.  
It scans single files, multiple files, or entire directories recursively, detecting **Python security issues, misconfigurations, secrets, and vulnerabilities**, while generating **CSV and HTML reports** for easy analysis.

---

## Features

Stratus performs a wide range of security checks:

### Code Vulnerabilities:
- Code execution: `eval`, `exec`, `compile`
- Dynamic imports
- Command injection: `os.system`, `subprocess`
- Unsafe deserialization: `pickle`, `yaml.load`, `marshal`
- SQL injection: raw queries, ORM misuse
- Path traversal & insecure file handling
- Hardcoded credentials and secrets (high entropy detection)
- Weak cryptography: `md5`, `sha1`, ECB mode
- Insecure randomness: `random.random()` for tokens
- Unsafe TLS usage: `verify=False`, HTTP endpoints
- Unsafe templating: Jinja2 `.render()`, `.format()` with user input
- Dangerous modules: `ftplib`, `telnetlib` without TLS
- Sys.path hijacking, TOCTOU race conditions
- Unsafe `getattr`/`setattr`
- Unbounded recursion & unsafe subprocesses

### Framework Checks:
- Django `DEBUG=True`
- Flask debug mode
- Missing CSRF protection
- Weak cookie flags
- Logging sensitive data

### Analysis Features:
- Lightweight **taint tracking** (user input → sinks like eval, exec, subprocess, DB, file)
- Entropy-based **hardcoded secret detection**
- Detection of package-level vulnerabilities via installed modules
- Multi-file and directory scanning
- Supports following symlinks
- Skips very large files optionally
- Supports demo sample vulnerable snippets

### Reports:
- CSV report: `S.No, Title, Severity, OWASP/NIST/SANS, File, Line, Code snippet`
- HTML report: color-coded by severity, sortable, summary counts
- Can filter findings by severity (`INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`)

---

## Installation

### 1️⃣ Recommended: Using Virtual Environment

```bash
# Create a virtual environment
python3 -m venv Stratus_venv

# Activate the environment
source Stratus_venv/bin/activate

# Install required packages
pip install -r requirements.txt


