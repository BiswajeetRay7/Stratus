def list_all_rules():
    rules = [
        'eval/exec/compile detection',
        'Hardcoded secrets',
        'Use of pickle/marshal/yaml.load',
        'Command injection (os.system/subprocess)',
        'SQL injection via raw queries',
        'Path traversal and insecure file handling',
        'Weak cryptography (md5, sha1, ECB)',
        'Insecure randomness',
        'Insecure TLS usage',
        'Framework misconfigurations (Django DEBUG, Flask debug)',
        'Logging of sensitive data',
        'Unsafe templating',
        'Dangerous modules (ftplib, telnetlib)',
        'Sys.path hijacking',
        'TOCTOU race conditions',
        'Unsafe getattr/setattr',
        'Unbounded recursion or subprocesses'
    ]
    print("Implemented Detection Rules:")
    for i, r in enumerate(rules,1):
        print(f"{i}. {r}")
