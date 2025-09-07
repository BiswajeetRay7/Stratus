RULES = [
    # Code Execution
    {"id":"R001","title":"Use of eval/exec/compile","severity":"HIGH","pattern":r"\b(eval|exec|compile)\b","owasp":"A1:2021","nist":"CWE-94"},
    {"id":"R002","title":"Command Injection via os.system/subprocess","severity":"HIGH","pattern":r"\b(os\.system|subprocess\.)","owasp":"A1:2021","nist":"CWE-78"},
    {"id":"R003","title":"Dynamic import usage","severity":"MEDIUM","pattern":r"__import__\(","owasp":"A1:2021","nist":"CWE-94"},

    # Secrets / Hardcoded credentials
    {"id":"R004","title":"Hardcoded password/secret","severity":"CRITICAL","pattern":r"(password|secret|api_key|token)\s*[:=]","owasp":"A2:2021","nist":"CWE-798"},

    # Cryptography
    {"id":"R005","title":"Weak cryptography (MD5/SHA1)","severity":"MEDIUM","pattern":r"\b(md5|sha1)\b","owasp":"A6:2021","nist":"CWE-327"},
    {"id":"R006","title":"Insecure randomness","severity":"MEDIUM","pattern":r"\brandom\.random\b","owasp":"A6:2021","nist":"CWE-338"},

    # Deserialization
    {"id":"R007","title":"Unsafe YAML/Pickle/Marshal deserialization","severity":"CRITICAL","pattern":r"\b(pickle|marshal|yaml\.load)\b","owasp":"A1:2021","nist":"CWE-502"},

    # TLS / HTTP
    {"id":"R008","title":"Insecure TLS (verify=False)","severity":"HIGH","pattern":r"verify\s*=\s*False","owasp":"A6:2021","nist":"CWE-295"},

    # Template injection
    {"id":"R009","title":"Jinja2 unsafe template rendering","severity":"HIGH","pattern":r"\.render\(","owasp":"A1:2021","nist":"CWE-74"},

    # Dangerous modules
    {"id":"R010","title":"Use of dangerous modules (ftplib, telnetlib)","severity":"HIGH","pattern":r"\b(ftplib|telnetlib)\b","owasp":"A9:2021","nist":"CWE-829"},

    # File handling
    {"id":"R011","title":"Path traversal / unsafe file handling","severity":"HIGH","pattern":r"(open\(|os\.remove|os\.rename)","owasp":"A5:2021","nist":"CWE-22"},

    # Logging
    {"id":"R012","title":"Logging sensitive information","severity":"MEDIUM","pattern":r"\blogging\.|print\(","owasp":"A3:2021","nist":"CWE-532"},

    # Framework-specific checks (Django/Flask)
    {"id":"R013","title":"Django DEBUG mode enabled","severity":"HIGH","pattern":r"DEBUG\s*=\s*True","owasp":"A6:2021","nist":"CWE-16"},
    {"id":"R014","title":"Flask debug mode enabled","severity":"HIGH","pattern":r"app\.debug\s*=\s*True","owasp":"A6:2021","nist":"CWE-16"},
    {"id":"R015","title":"Django CSRF middleware missing","severity":"HIGH","pattern":r"MIDDLEWARE\s*=\s*\[.*'django.middleware.csrf.CsrfViewMiddleware'.*\]","owasp":"A6:2021","nist":"CWE-16","negate":True},
    {"id":"R016","title":"Insecure cookie flags","severity":"HIGH","pattern":r"SESSION_COOKIE_SECURE\s*=\s*False|CSRF_COOKIE_SECURE\s*=\s*False","owasp":"A6:2021","nist":"CWE-16"}
]
