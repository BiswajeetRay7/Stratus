import re

def scan_secrets_file(file_path):
    """
    Scan a file for hardcoded secrets like API keys or passwords.
    """
    findings = []
    secret_patterns = [r'API_KEY\s*=.*', r'PASSWORD\s*=.*', r'TOKEN\s*=.*']

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        for i, line in enumerate(lines, 1):
            for pattern in secret_patterns:
                if re.search(pattern, line):
                    findings.append({
                        'sno': len(findings)+1,
                        'title': 'Hardcoded secret detected',
                        'severity': 'CRITICAL',
                        'owasp': 'A2:2021',
                        'nist': 'CWE-798',
                        'file': file_path,
                        'line': i,
                        'snippet': line.strip()
                    })
    except Exception as e:
        print(f"Secret scan failed for {file_path}: {e}")

    return findings
