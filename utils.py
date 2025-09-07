import time
import sys
from datetime import datetime
import threading
import itertools

# ANSI color codes
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

def print_banner():
    """
    Prints a colorful, animated Stratus banner with date/time and developer credit.
    """
    banner = [
        f"{Colors.CYAN}███████╗████████╗██████╗  █████╗ ████████╗██╗   ██╗███████╗",
        f"{Colors.CYAN}██╔════╝╚══██╔══╝██╔══██╗██╔══██╗╚══██╔══╝██║   ██║██╔════╝",
        f"{Colors.GREEN}███████╗  ██║   ██████╔╝███████║   ██║   ██║   ██║███████╗",
        f"{Colors.GREEN}╚════██║  ██║   ██╔══██╗██╔══██║   ██║   ██║   ██║╚════██║",
        f"{Colors.YELLOW}███████║ ██║   ██║  ██║██║  ██║   ██║   ╚██████╔╝███████║",
        f"{Colors.YELLOW}╚══════╝ ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚══════╝{Colors.RESET}"
    ]

    for line in banner:
        for char in line:
            sys.stdout.write(char)
            sys.stdout.flush()
            time.sleep(0.002)
        print()
        time.sleep(0.05)

    now = datetime.now().strftime("%A, %d %B %Y %H:%M:%S")
    print(f"\n{Colors.BOLD}{Colors.BLUE}📅 Current Date & Time: {now}{Colors.RESET}\n")
    print(f"{Colors.BOLD}{Colors.CYAN}🌟 Welcome to Stratus Python SAST VAPT Scanner 🌟{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.GREEN}💻 Developed by Biswajeet Ray 💻{Colors.RESET}\n")


class Loader:
    """
    Colorful terminal loader with spinning animation and progress percentage.
    """
    def __init__(self, text="Scanning", total_steps=100):
        self.text = text
        self.done = False
        self.progress = 0
        self.total_steps = total_steps
        self._lock = threading.Lock()

    def start(self):
        threading.Thread(target=self._animate, daemon=True).start()

    def update(self, step):
        with self._lock:
            self.progress = step
            if self.progress >= self.total_steps:
                self.done = True

    def _animate(self):
        spinner = itertools.cycle([f'{Colors.RED}|{Colors.RESET}', 
                                    f'{Colors.YELLOW}/{Colors.RESET}', 
                                    f'{Colors.GREEN}-{Colors.RESET}', 
                                    f'{Colors.CYAN}\\{Colors.RESET}'])
        while not self.done:
            with self._lock:
                percent = int((self.progress / self.total_steps) * 100)
            sys.stdout.write(f'\r{self.text} {next(spinner)} [{percent}%]')
            sys.stdout.flush()
            time.sleep(0.1)
        sys.stdout.write(f'\r{Colors.GREEN}✅ {self.text} Completed! 100%{Colors.RESET}\n')

    def stop(self):
        self.done = True
