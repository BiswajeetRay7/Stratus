import re

SECRET_PATTERNS = [
    r"['\"](password|passwd|secret|api_key|token|jwt)['\"]\s*[:=]\s*['\"].+['\"]",
    r"AKIA[0-9A-Z]{16}", 
    r"(?i)-----BEGIN PRIVATE KEY-----",
    r"(?i)-----BEGIN RSA PRIVATE KEY-----"
]

def shannon_entropy(data):
    import math
    if not data: return 0
    entropy = 0
    for x in set(data):
        p_x = data.count(x)/len(data)
        entropy += -p_x*math.log2(p_x)
    return entropy

def detect_secrets(content, file_path):
    findings = []
    for pattern in SECRET_PATTERNS:
        for m in re.finditer(pattern, content):
            line_no = content[:m.start()].count("\n") + 1
            snippet = content.splitlines()[line_no-1].strip()
            if shannon_entropy(snippet) > 3.5:
                findings.append({
                    "id": "SECRET-001",
                    "title": "Hardcoded Secret Detected",
                    "severity": "CRITICAL",
                    "owasp": "A2:2021",
                    "nist": "CWE-798",
                    "line": line_no,
                    "file": str(file_path),
                    "snippet": snippet
                })
    return findings
