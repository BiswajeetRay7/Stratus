def sample_vulnerable_snippets():
    snippets = [
        {"id":"S001","title":"Use of eval with user input","severity":"HIGH","owasp":"A1:2021","nist":"CWE-94","line":1,"file":"sample.py","snippet":"eval(input('Enter code: '))"},
        {"id":"S002","title":"Hardcoded secret","severity":"CRITICAL","owasp":"A2:2021","nist":"CWE-798","line":2,"file":"sample.py","snippet":"API_KEY='12345SECRET'"},
        {"id":"S003","title":"Insecure TLS usage","severity":"HIGH","owasp":"A6:2021","nist":"CWE-295","line":5,"file":"sample.py","snippet":"requests.get('https://example.com', verify=False)"},
    ]
    return snippets
