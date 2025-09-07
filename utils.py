import time
import sys
from datetime import datetime
import threading
import itertools

def print_banner():
    banner = [
        "███████╗████████╗██████╗  █████╗ ████████╗██╗   ██╗███████╗",
        "██╔════╝╚══██╔══╝██╔══██╗██╔══██╗╚══██╔══╝██║   ██║██╔════╝",
        "███████╗   ██║   ██████╔╝███████║   ██║   ██║   ██║███████╗",
        "╚════██║   ██║   ██╔══██╗██╔══██║   ██║   ██║   ██║╚════██║",
        "███████║   ██║   ██║  ██║██║  ██║   ██║   ╚██████╔╝███████║",
        "╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚══════╝"
    ]
    for line in banner:
        for char in line:
            sys.stdout.write(char)
            sys.stdout.flush()
            time.sleep(0.002)
        print()
        time.sleep(0.05)

    now = datetime.now().strftime("%A, %d %B %Y %H:%M:%S")
    print(f"\n📅 Current Date & Time: {now}\n")
    print("🌟 Welcome to Stratus - Python SAST Scanner 🌟")
    print("💻 Developed by Biswajeet Ray 💻\n")


# Loader animation for scanning
class Loader:
    def __init__(self, text="Scanning"):
        self.text = text
        self.done = False

    def start(self):
        threading.Thread(target=self._animate, daemon=True).start()

    def _animate(self):
        for c in itertools.cycle(['|', '/', '-', '\\']):
            if self.done:
                break
            sys.stdout.write(f'\r{self.text} {c}')
            sys.stdout.flush()
            time.sleep(0.1)
        sys.stdout.write('\r✅ Scan completed!    \n')

    def stop(self):
        self.done = True
