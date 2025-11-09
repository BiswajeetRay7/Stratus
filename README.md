# 🌩️ STRATUS - Ultimate Python Security Suite

> **The all-in-one, single-file vulnerability scanner for Python developers and ethical hackers.**
>
> *Developed by Biswajeet Ray*

![Version](https://img.shields.io/badge/version-1.3-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-yellow.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## 🔥 Overview

**STRATUS** is a blazing-fast, portable security scanner designed for modern DevSecOps, penetration testing, and bug bounty hunting. It combines a high-performance native regex engine with industry-standard tools to provide a comprehensive security assessment of any Python codebase in seconds.

Unlike other scanners that require complex setups, external databases, or internet access, STRATUS v1.3 is **completely self-contained in a single file**. It embeds its own high-value vulnerability database, making it perfect for air-gapped systems, restricted environments like Kali Linux, or quick CI/CD pipeline integration.

## ✨ Key Features

* **🚀 100% Portable:** Single-file architecture. No external DB needed.
* **⚡ Native Fast-Scan:** Instantly detects 100+ critical vulnerability patterns (SQLi, RCE, Secrets) without dependencies.
* **🛡️ Kali Linux Auto-Fix:** Built-in smart installer that automatically bypasses PEP 668 ("externally-managed-environment") errors.
* **🧰 Multi-Engine Orchestration:** Seamlessly runs and aggregates results from Bandit, Mypy, Pylint, Safety, and OSV.
* **📊 Rich Reporting:** Generates professional, dark-mode HTML reports, plus machine-readable JSON and CSV.

---

## 🤝 Acknowledgements & Credits

STRATUS stands on the shoulders of giants. While the native engine and orchestration logic were developed by Biswajeet Ray, this tool powerfully integrates the following world-class open-source engines:

| Tool | Credit / Owner | Function in STRATUS |
| :--- | :--- | :--- |
| **Bandit** | [PyCQA](https://github.com/PyCQA/bandit) | AST-based security analysis for complex Python vulnerabilities. |
| **Safety** | [pyup.io](https://github.com/pyupio/safety) | Checks integrated `requirements.txt` files against known CVE databases. |
| **Pylint** | [PyCQA](https://github.com/pylint-dev/pylint) | Advanced linting to catch code quality issues that may lead to security bugs. |
| **Mypy** | [Python Org](https://github.com/python/mypy) | Static type checking to prevent logical errors and type-related bugs. |
| **OSV API**| [Google / OpenSSF](https://osv.dev/) | Supplemental open-source vulnerability data for dependencies. |

---

## 📖 User Manual

### 1. Installation
STRATUS requires no installation. Just download the script.

```bash
# Option A: Quick Download
curl -O [https://raw.githubusercontent.com/your-repo/stratus.py](https://raw.githubusercontent.com/your-repo/stratus.py)
chmod +x stratus.py

# Option B: First-run Dependency Install (Recommended)
# This will automatically detect your OS (including Kali) and install necessary engines.
python3 stratus.py --install
