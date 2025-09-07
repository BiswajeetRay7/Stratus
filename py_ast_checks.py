import ast

def scan_python_file(file_path):
    """
    Scan a Python file using AST for common vulnerabilities.
    """
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            tree = ast.parse(f.read(), filename=file_path)

        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and hasattr(node.func, 'id') and node.func.id in ['eval','exec','compile']:
                findings.append({
                    'sno': len(findings)+1,
                    'title': f'Use of {node.func.id} detected',
                    'severity': 'HIGH',
                    'owasp': 'A1:2021',
                    'nist': 'CWE-94',
                    'file': file_path,
                    'line': node.lineno,
                    'snippet': f'{node.func.id} usage'
                })

            # Detect dangerous module usage
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in ['pickle','marshal','ftplib','telnetlib','yaml']:
                        findings.append({
                            'sno': len(findings)+1,
                            'title': f'Dangerous module {alias.name} imported',
                            'severity': 'MEDIUM',
                            'owasp': 'A6:2021',
                            'nist': 'CWE-502',
                            'file': file_path,
                            'line': node.lineno,
                            'snippet': f'import {alias.name}'
                        })
    except Exception as e:
        print(f"AST scan failed for {file_path}: {e}")
    return findings
