#!/usr/bin/env python3
"""
Stratus - Python Source Code Scanner
Developed by Biswajeet Ray
"""

import argparse
import sys
from pathlib import Path
from py_ast_checks import analyze_path
from package_scan import scan_packages
from reports import generate_csv_report, generate_html_report
from utils import colored_banner, filter_findings_by_severity
from sample_vulns import sample_vulnerable_snippets

VERSION = "5.0.0"
SEVERITY_LEVELS = ["INFO","LOW","MEDIUM","HIGH","CRITICAL"]

def main():
    parser = argparse.ArgumentParser(description="Stratus v5 - Python SAST & VAPT + Package Scanner")
    parser.add_argument("paths", nargs="*", help="Files or directories to scan")
    parser.add_argument("--csv", help="CSV report filename")
    parser.add_argument("--html", help="HTML report filename")
    parser.add_argument("--severity", choices=SEVERITY_LEVELS, default="INFO", help="Minimum severity to report")
    parser.add_argument("--skip-dirs", nargs="*", default=[], help="Directories to skip")
    parser.add_argument("--follow-symlinks", action="store_true", help="Follow symlinks")
    parser.add_argument("--list-rules", action="store_true", help="List detection rules")
    parser.add_argument("--sample", action="store_true", help="Run sample vulnerable snippets")
    parser.add_argument("--scan-packages", action="store_true", help="Scan installed Python packages for known vulnerabilities")
    parser.add_argument("--full-scan", action="store_true", help="Run full scan including code + packages + runtime/framework checks")
    parser.add_argument("--version", action="version", version=f"Stratus v5 {VERSION}")

    args = parser.parse_args()
    print(colored_banner("STRATUS v5"))

    findings = []

    # List rules
    if args.list_rules:
        from rules import RULES
        print("Detection Rules:")
        for idx, rule in enumerate(RULES, 1):
            print(f"{idx}. {rule['title']} | Severity:{rule['severity']} | OWASP:{rule.get('owasp')} | CWE/NIST:{rule.get('nist')}")
        sys.exit(0)

    # Sample vulnerable snippets
    if args.sample:
        findings.extend(sample_vulnerable_snippets())

    # Path scan
    if args.paths:
        findings.extend(analyze_path(args.paths, skip_dirs=args.skip_dirs, follow_symlinks=args.follow_symlinks))

    # Package scan
    if args.scan_packages or args.full_scan:
        findings.extend(scan_packages())

    # TODO: Future: Runtime / framework-specific checks
    # runtime_findings = runtime_checks(args.paths)
    # findings.extend(runtime_findings)

    # Filter by severity
    filtered = filter_findings_by_severity(findings, args.severity)
    print(f"\nTotal Findings (Severity ≥ {args.severity}): {len(filtered)}")

    # Generate reports
    if args.csv:
        generate_csv_report(filtered, args.csv)
        print(f"CSV report saved: {args.csv}")
    if args.html:
        generate_html_report(filtered, args.html)
        print(f"HTML report saved: {args.html}")

if __name__ == "__main__":
    main()
