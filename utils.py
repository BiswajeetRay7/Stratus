from termcolor import colored

def colored_banner(text):
    banner = f"""
███████╗████████╗██████╗  █████╗ ████████╗██╗   ██╗███████╗
██╔════╝╚══██╔══╝██╔══██╗██╔══██╗╚══██╔══╝██║   ██║██╔════╝
███████╗   ██║   ██████╔╝███████║   ██║   ██║   ██║███████╗
╚════██║   ██║   ██╔══██╗██╔══██║   ██║   ██║   ██║╚════██║
███████║   ██║   ██║  ██║██║  ██║   ██║   ╚██████╔╝███████║
╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚══════╝
                                                           
"""
    print(colored(banner, "cyan"))
    return banner

def filter_findings_by_severity(findings, min_severity):
    SEVERITY_ORDER = {"INFO":0,"LOW":1,"MEDIUM":2,"HIGH":3,"CRITICAL":4}
    threshold = SEVERITY_ORDER.get(min_severity, 0)
    return [f for f in findings if SEVERITY_ORDER.get(f.get("severity","INFO"),0) >= threshold]
