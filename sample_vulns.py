def sample_findings():
    return [
        {'sno':1,'title':'Sample eval usage','severity':'HIGH','owasp':'A1:2021','nist':'CWE-94','file':'sample.py','line':1,'snippet':'eval(input("Enter code:"))'},
        {'sno':2,'title':'Sample hardcoded API key','severity':'CRITICAL','owasp':'A2:2021','nist':'CWE-798','file':'sample.py','line':2,'snippet':'API_KEY="12345SECRET"'}
    ]
