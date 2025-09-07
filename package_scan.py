import subprocess
import json

def scan_installed_packages():
    """
    Scan installed Python packages for known vulnerabilities.
    Returns a list of dictionaries with package info.
    """
    try:
        result = subprocess.run(
            ["pip", "list", "--format=json"],
            capture_output=True, text=True, check=True
        )
        packages = json.loads(result.stdout)
        findings = []

        for pkg in packages:
            name = pkg.get('name')
            version = pkg.get('version')
            findings.append({
                'sno': len(findings)+1,
                'title': f'Installed package {name}',
                'severity': 'INFO',
                'owasp': 'N/A',
                'nist': 'CWE-1104',
                'file': 'N/A',
                'line': '',
                'snippet': f'{name}=={version}',
            })
        return findings

    except subprocess.CalledProcessError as e:
        print(f"Package scan failed: {e}")
        return []

    except json.JSONDecodeError as e:
        print(f"Package scan failed: Invalid JSON output from pip - {e}")
        return []

if __name__ == "__main__":
    pkgs = scan_installed_packages()
    print(f"Total packages found: {len(pkgs)}")
    for p in pkgs:
        print(f"{p['title']}: {p['snippet']} ({p['severity']})")
