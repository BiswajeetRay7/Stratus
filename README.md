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

1.  Quick Start (Git Clone)
```bash
git clone https://github.com/BiswajeetRay7/Stratus.git
cd Stratus
python3 stratus.py --install

## 2. ⚡ Basic Scanning (Native Engine)

By default, **STRATUS** uses its **Native Engine**.  
This is instant and has zero dependencies — perfect for quick checks.

### Scan a Single File:
```bash
python3 stratus.py my_script.py
```

### Scan an Entire Project Folder:
```bash
python3 stratus.py /home/user/projects/my_app
```

### Scan the Current Directory:
```bash
python3 stratus.py .
```

---

## 3. 🔍 Deep Scanning (Multi-Engine)

For a complete security audit, use the `--tools` argument to activate external engines.

### 🧩 Recommended Audit Scan (Fast & Effective)
Uses **Native + Bandit (SAST) + Dependency Checks**

```bash
python3 stratus.py . --tools stratus bandit dependencies
```

### 🧠 Full Deep Scan (Maximum Coverage)
Runs **everything**.  
This may take longer but provides the deepest analysis.

```bash
python3 stratus.py . --tools all
```

---

## 4. 📊 Generating Reports

Don't just read results in the terminal — generate **professional reports** for sharing or analysis.

### Generate ALL Report Formats at Once:
```bash
python3 stratus.py . --tools all --html scan_report.html --csv scan_results.csv --json pipeline.json
```

| Format | Best Use Case |
|:-------|:---------------|
| **HTML** | Human review. Open `scan_report.html` in your browser for a color-coded, interactive view. |
| **CSV**  | Spreadsheets. Open `scan_results.csv` in Excel/Sheets to filter and track fixes. |
| **JSON** | Automation. Use `pipeline.json` in CI/CD tools (Jenkins, GitLab) to fail builds if critical bugs are found. |

---

## 5. 🧾 Command Reference Cheat Sheet

| **Flag** | **Description** | **Example** |
|:----------|:----------------|:-------------|
| `TARGET` | The file or folder to scan. | `python3 stratus.py my_project/` |
| `--install` | Installs/updates required tools. | `python3 stratus.py --install` |
| `--tools` | Specify which engines to run. | `--tools stratus bandit` |
| `--html` | Save output to an HTML file. | `--html report.html` |
| `--csv` | Save output to a CSV file. | `--csv data.csv` |
| `--json` | Save output to a JSON file. | `--json data.json` |

---

## 6. 🚨 How to Read Results

**STRATUS** ranks findings by severity.  
Use this to prioritize your fixes effectively:

| **Severity** | **Meaning** | **Example** |
|:--------------|:------------|:-------------|
| 🔴 **[CRITICAL]** | Stop what you are doing and fix immediately. | Hardcoded AWS keys, SQL Injection |
| 🟠 **[HIGH]** | Fix before the next release. | High risk of exploitation |
| 🟡 **[MEDIUM]** | Add to your bug tracker. | Vulnerable under specific conditions |
| 🟢 **[LOW]** | Best practice issue or code quality improvement | Minor security hygiene issues |

---

**Author:** *Biswajeet Ray*  
**Version:** 1.0.0  

## 🤝 Credits

STRATUS uses a custom native engine developed by **Biswajeet Ray** and powerfully orchestrates the following best open-source tools:

* **Bandit** (PyCQA) - AST Analysis
* **Safety** (pyup.io) - Dependency Checking
* **Pylint** (PyCQA) - Linting
* **Mypy** (Python Org) - Type Checking
* **OSV API** (Google/OpenSSF) - Vulnerability Data
  
**Dedicated to my VS7**
