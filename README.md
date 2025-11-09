# 🌩️ STRATUS - Ultimate Python Security Suite

> **The all-in-one, single-file vulnerability scanner for Python developers and ethical hackers.**
>
> *Developed by Biswajeet Ray*

![Version](https://img.shields.io/badge/version-1.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-yellow.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## 🔥 Overview

**STRATUS** is a blazing-fast, portable security scanner designed for modern DevSecOps, penetration testing, and bug bounty hunting. It combines a high-performance native regex engine with industry-standard tools to provide a comprehensive security assessment of any Python codebase in seconds.

Unlike other scanners that require complex setups, external databases, or internet access, STRATUS is **completely self-contained**. It embeds its own high-value vulnerability database, making it perfect for air-gapped systems, restricted environments like Kali Linux, or quick CI/CD pipeline integration.

## ✨ Key Features

* **🚀 100% Portable:** Single-file architecture. No external DB needed.
* **⚡ Native Fast-Scan:** Instantly detects 100+ critical vulnerability patterns (SQLi, RCE, Secrets) without dependencies.
* **🛡️ Kali Linux Auto-Fix:** Built-in smart installer that automatically bypasses PEP 668 ("externally-managed-environment") errors.
* **🧰 Multi-Engine Orchestration:** Seamlessly runs and aggregates results from Bandit, Mypy, Pylint, Safety, and OSV.
* **📊 Rich Reporting:** Generates professional, dark-mode HTML reports, plus machine-readable JSON and CSV.

---

## 📥 Installation

You can install STRATUS by cloning this repository.

 Quick Start (Git Clone)
```bash
git clone https://github.com/BiswajeetRay7/Stratus.git
cd Stratus
python3 stratus.py --install

## 🤝 Credits

STRATUS uses a custom native engine developed by **Biswajeet Ray** and powerfully orchestrates the following best open-source tools:

* **Bandit** (PyCQA) - AST Analysis
* **Safety** (pyup.io) - Dependency Checking
* **Pylint** (PyCQA) - Linting
* **Mypy** (Python Org) - Type Checking
* **OSV API** (Google/OpenSSF) - Vulnerability Data
