#!/usr/bin/env python3
"""
Stratus v1 - Python SAST Scanner
Developed by Biswajeet Ray
"""

import argparse
import os
import sys
from utils import print_banner, Loader
from py_ast_checks import scan_python_file
from secrets import scan_secrets_file
from package_scan import scan_installed_packages
from reports import generate_csv_report, generate_html_report
from sample_vulns import sample_findings

def scan_file(file_path):
    """
    Scan a single Python file for vulnerabilities and secrets.
    """
    findings = []
    try:
        findings.extend(scan_python_file(file_path))
        findings.extend(scan_secrets_file(file_path))
    except Exception as e:
        print(f"Error scanning {file_path}: {e}")
    return findings

def scan_path(paths, skip_dirs=None, follow_symlinks=False, severity_filter="INFO"):
    """
    Scan files/directories recursively. Filter by severity.
    """
    all_findings = []
    for path in paths:
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

    # Filter by minimum severity
    severity_levels = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    min_index = severity_levels.index(severity_filter.upper())
    all_findings = [f for f in all_findings if severity_levels.index(f.get('severity','INFO')) >= min_index]
    return all_findings

def main():
    print_banner()

    parser = argparse.ArgumentParser(description="Stratus v5 - Python SAST & VAPT Scanner")
    parser.add_argument("paths", nargs="*", help="File(s) or directory to scan")
    parser.add_argument("--csv", help="CSV output file")
    parser.add_argument("--html", help="HTML output file")
    parser.add_argument("--severity", default="INFO", help="Minimum severity filter: INFO/LOW/MEDIUM/HIGH/CRITICAL")
    parser.add_argument("--skip-dirs", nargs="*", help="Directories to skip during scan")
    parser.add_argument("--follow-symlinks", action="store_true", help="Follow symbolic links")
    parser.add_argument("--full-scan", action="store_true", help="Run full scan including packages")
    parser.add_argument("--sample", action="store_true", help="Run built-in vulnerable sample scan")
    args = parser.parse_args()

    if args.sample:
        findings = sample_findings()
    else:
        # Count total files for loader progress
        total_files = 0
        for path in args.paths:
            if os.path.isfile(path) and path.endswith(".py"):
                total_files += 1
            elif os.path.isdir(path):
                for root, dirs, files in os.walk(path):
                    if args.skip_dirs:
                        dirs[:] = [d for d in dirs if d not in args.skip_dirs]
                    total_files += len([f for f in files if f.endswith(".py")])

        loader = Loader("Scanning files", total_steps=max(total_files,1))
        loader.start()
        findings = scan_path(args.paths, skip_dirs=args.skip_dirs, follow_symlinks=args.follow_symlinks, severity_filter=args.severity)
        # Update loader progress
        for i in range(len(findings)):
            loader.update(i+1)
        loader.stop()

    # Full scan for installed packages
    if args.full_scan:
        print("\n🔍 Scanning installed Python packages for known vulnerabilities...")
        pkg_findings = scan_installed_packages()
        findings.extend(pkg_findings)

    # Reports
    if args.csv:
        generate_csv_report(findings, args.csv)
        print(f"CSV report saved: {args.csv}")
    if args.html:
        generate_html_report(findings, args.html)
        print(f"HTML report saved: {args.html}")

    print(f"\nTotal Findings (Severity ≥ {args.severity}): {len(findings)}")

if __name__ == "__main__":
    main()
