# package_scan.py
import subprocess
import json

def scan_installed_packages():
    """
    Scan installed Python packages for known vulnerabilities.
    Returns a list of dictionaries with package info.
    """
    try:
        # Get JSON output of installed packages
        result = subprocess.run(
            ["pip", "list", "--format=json"],
            capture_output=True, text=True, check=True
        )
        packages = json.loads(result.stdout)
        findings = []

        for pkg in packages:
            # Basic detection placeholder: check for old version (example)
            name = pkg.get('name')
            version = pkg.get('version')

            # You can enhance this with Safety DB or other vulnerability DBs
            findings.append({
                'package': name,
                'version': version,
                'severity': 'INFO',
                'title': f'Installed package {name}',
                'description': f'Package {name} version {version} detected',
            })

        return findings

    except subprocess.CalledProcessError as e:
        print(f"Package scan failed: {e}")
        return []

    except json.JSONDecodeError as e:
        print(f"Package scan failed: Invalid JSON output from pip - {e}")
        return []

# Example usage
if __name__ == "__main__":
    pkgs = scan_installed_packages()
    print(f"Total packages found: {len(pkgs)}")
    for p in pkgs:
        print(f"{p['package']}=={p['version']} ({p['severity']})")
