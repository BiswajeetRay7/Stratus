import subprocess
import json

def scan_packages():
    findings = []
    try:
        result = subprocess.run(["safety","check","--json"], capture_output=True, text=True)
        if result.returncode == 0:
            vulns = json.loads(result.stdout)
            for v in vulns:
                findings.append({
                    "id": f"PKG-{v.get('package_name','N/A')}",
                    "title": f"Vulnerable Package {v.get('package_name')}",
                    "severity": "HIGH",
                    "owasp": "A9:2021",
                    "nist": "CWE-1109",
                    "line": 0,
                    "file": v.get("package_name"),
                    "snippet": f"Installed: {v.get('installed_version')}, Vulnerable: {v.get('vulnerable_spec')}"
                })
    except Exception as e:
        print("Package scan failed:", e)
    return findings
