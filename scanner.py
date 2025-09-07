#!/usr/bin/env python3
# scanner.py
"""
Stratus - Python SAST Scanner
Developed by Biswajeet Ray
"""

import argparse
import os
import sys
from reports import generate_csv_report, generate_html_report
from py_ast_checks import scan_python_file
from secrets import scan_secrets_file
from package_scan import scan_installed_packages
from sample_vulns import sample_findings
from utils import print_banner

def scan_path(path, skip_dirs=None, follow_symlinks=False, severity_filter="INFO"):
    """
    Scan a file or directory recursively for vulnerabilities.
    """
    all_findings = []

    if os.path.isfile(path):
        findings = scan_file(path)
        all_findings.extend(findings)
    elif os.path.isdir(path):
        for root, dirs, files in os.walk(path, followlinks=follow_symlinks):
            if skip_dirs:
                dirs[:] = [d for d in dirs if d not in skip_dirs]
            for f in files:
                if f.endswith(".py"):
                    file_path = os.path.join(root, f)
                    findings = scan_file(file_path)
                    all_findings.extend(findings)
    else:
        print(f"Path not found: {path}")

    # Apply severity filter
    severity_levels = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    min_index = severity_levels.index(severity_filter.upper())
    all_findings = [f for f in all_findings if severity_levels.index(f.get('severity','INFO')) >= min_index]

    return all_findings

def scan_file(file_path):
    """
    Scan a single Python file for code and secrets vulnerabilities.
    """
    findings = []
    try:
        findings.extend(scan_python_file(file_path))
        findings.extend(scan_secrets_file(file_path))
    except Exception as e:
        print(f"Error scanning {file_path}: {e}")
    return findings

def main():
    print_banner()

    parser = argparse.ArgumentParser(description="Stratus v5 - Python SAST & VAPT Scanner")
    parser.add_argument("paths", nargs="*", help="File(s) or directory to scan")
    parser.add_argument("--csv", help="CSV output file")
    parser.add_argument("--html", help="HTML output file")
    parser.add_argument("--full-scan", action="store_true", help="Scan code + packages + secrets")
    parser.add_argument("--scan-packages", action="store_true", help="Scan installed Python packages")
    parser.add_argument("--severity", default="INFO", help="Minimum severity filter (INFO, LOW, MEDIUM, HIGH, CRITICAL)")
    parser.add_argument("--skip-dirs", nargs="*", help="Directories to skip during scan")
    parser.add_argument("--follow-symlinks", action="store_true", help="Follow symbolic links")
    parser.add_argument("--list-rules", action="store_true", help="List all implemented rules")
    parser.add_argument("--sample", action="store_true", help="Run built-in sample vulnerable snippets")
    parser.add_argument("--version", action="version", version="Stratus v5.0.0")

    args = parser.parse_args()

    all_findings = []

    if args.list_rules:
        from rules import list_all_rules
        list_all_rules()
        sys.exit(0)

    if args.sample:
        all_findings.extend(sample_findings())
    elif args.paths:
        for path in args.paths:
            all_findings.extend(scan_path(path, skip_dirs=args.skip_dirs, follow_symlinks=args.follow_symlinks, severity_filter=args.severity))

    if args.full_scan:
        all_findings.extend(scan_installed_packages())

    print(f"\nTotal Findings (Severity ≥ {args.severity.upper()}): {len(all_findings)}")

    if args.csv:
        generate_csv_report(all_findings, args.csv)
        print(f"CSV report saved: {args.csv}")

    if args.html:
        generate_html_report(all_findings, args.html)
        print(f"HTML report saved: {args.html}")

if __name__ == "__main__":
    main()
