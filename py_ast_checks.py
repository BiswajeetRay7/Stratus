import ast
import os
import re
import math
from pathlib import Path
from rules import RULES
from secrets import detect_secrets

USER_SOURCES = ["input", "sys.argv", "os.environ", "request.args", "request.form", "request.data"]

def shannon_entropy(data):
    if not data: return 0
    entropy = 0
    for x in set(data):
        p_x = data.count(x)/len(data)
        entropy += -p_x * math.log2(p_x)
    return entropy

def analyze_file(file_path):
    findings = []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
            tree = ast.parse(content)
    except Exception as e:
        print(f"Parsing error {file_path}: {e}")
        return findings

    # Regex rule checks
    for rule in RULES:
        pattern = rule.get("pattern")
        negate = rule.get("negate", False)
        if pattern:
            matches = re.finditer(pattern, content)
            for m in matches:
                line_no = content[:m.start()].count("\n") + 1
                snippet = content.splitlines()[line_no-1].strip()
                if negate:
                    continue  # Skip positive matches for negated rules
                # Skip low-entropy secrets
                if "password" in rule['title'].lower() or "secret" in rule['title'].lower():
                    if shannon_entropy(snippet) < 3.5: continue
                findings.append({
                    "id": rule["id"],
                    "title": rule["title"],
                    "severity": rule["severity"],
                    "owasp": rule.get("owasp"),
                    "nist": rule.get("nist"),
                    "line": line_no,
                    "file": str(file_path),
                    "snippet": snippet
                })

    # AST analysis for eval, exec, subprocess, dynamic import
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func_name = ""
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                func_name = node.func.attr
            if func_name in ["eval","exec","compile","os.system","subprocess.call","subprocess.Popen","__import__"]:
                findings.append({
                    "id": f"AST-{func_name.upper()}",
                    "title": f"Dynamic/Command Execution ({func_name})",
                    "severity": "HIGH",
                    "owasp": "A1:2021",
                    "nist": "CWE-78",
                    "line": getattr(node, "lineno", 0),
                    "file": str(file_path),
                    "snippet": ast.get_source_segment(content, node)
                })

    # Secrets detection
    findings.extend(detect_secrets(content, file_path))
    return findings

def analyze_path(paths, skip_dirs=None, follow_symlinks=False, max_file_size=10*1024*1024):
    findings = []
    for path_str in paths:
        path = Path(path_str)
        if path.is_file() and path.suffix == ".py":
            if path.stat().st_size > max_file_size:
                print(f"Skipping large file: {path}")
                continue
            findings.extend(analyze_file(path))
        elif path.is_dir():
            for root, dirs, files in os.walk(path, followlinks=follow_symlinks):
                if skip_dirs:
                    dirs[:] = [d for d in dirs if d not in skip_dirs]
                for file in files:
                    if file.endswith(".py"):
                        file_path = Path(root)/file
                        if file_path.stat().st_size > max_file_size:
                            continue
                        findings.extend(analyze_file(file_path))
    return findings
