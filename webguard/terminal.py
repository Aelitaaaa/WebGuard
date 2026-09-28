import os
import sys

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
CYAN = "\033[36m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
GRAY = "\033[90m"

def supports_color():
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    return sys.stdout.isatty() or os.name == "nt"

def c(text, color):
    if not supports_color():
        return str(text)
    return f"{color}{text}{RESET}"

def banner(version):
    lines = [
        "╔══════════════════════════════════════════════════════════════╗",
        "║                         WEBGUARD                             ║",
        f"║                Security Assessment v{version:<22}║",
        "╚══════════════════════════════════════════════════════════════╝",
    ]
    print(c("\n".join(lines), CYAN))
    print(c("Authorized • Non-destructive • Developer-friendly", DIM))
    print()

def section(title):
    print()
    print(c(f"── {title} " + "─" * max(2, 55 - len(title)), BOLD))

def info(label, value):
    print(f"{c(label + ':', BLUE):18} {value}")

def success(text):
    print(c(f"✓ {text}", GREEN))

def warning(text):
    print(c(f"! {text}", YELLOW))

def error(text):
    print(c(f"✗ {text}", RED))

def status(text):
    print(c(f"→ {text}", CYAN))

def severity_label(severity):
    sev = severity.upper()
    colors = {
        "CRITICAL": MAGENTA,
        "HIGH": RED,
        "MEDIUM": YELLOW,
        "LOW": YELLOW,
        "INFO": BLUE,
    }
    return c(f"[{sev}]", colors.get(sev, GRAY))

def command(name, description):
    print(f"  {c(name, CYAN):38} {description}")
