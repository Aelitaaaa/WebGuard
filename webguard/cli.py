import argparse
from collections import Counter
from urllib.parse import urlsplit

from . import __version__
from .scanner import run_scan
from .reporter import default_report_paths, write_json, write_html
from .config import load_config
from .terminal import (
    banner, section, info, success, warning, error, status,
    severity_label, command, c, BOLD, DIM, CYAN
)

HELP_TOPICS = {
    "scan": """
SCAN — Memindai website yang sudah Anda miliki izin untuk diuji.

Contoh paling sederhana:
  webguard scan https://example.com --authorized

Contoh dengan batas 20 halaman:
  webguard scan https://example.com --authorized --max-pages 20

Contoh dengan safe-active CORS check:
  webguard scan https://example.com --authorized --safe-active

Contoh scope host tambahan:
  webguard scan https://example.com --authorized --scope-host api.example.com

Opsi penting:
  --authorized       Wajib. Konfirmasi bahwa target memang boleh diuji.
  --max-pages N      Maksimum halaman yang akan dikunjungi.
  --delay N          Jeda antar request dalam detik.
  --timeout N        Timeout request.
  --safe-active      Menjalankan benign CORS reflection check.
  --scope-host HOST  Menambahkan host yang memang termasuk scope.
  --ignore-robots    Abaikan robots.txt. Gunakan hanya jika scope mengizinkan.
  --report-dir DIR   Folder output report.
  --json FILE        Simpan report JSON ke path tertentu.
  --html FILE        Simpan report HTML ke path tertentu.
""",
    "wizard": """
WIZARD — Mode interaktif untuk user yang tidak ingin menghafal command.

Jalankan:
  webguard wizard

Wizard akan menanyakan:
  1. Target URL
  2. Konfirmasi izin
  3. Maksimum halaman
  4. Safe-active CORS check

Setelah selesai, report HTML dan JSON dibuat otomatis.
""",
    "gui": """
GUI — Membuka tampilan desktop WebGuard.

Jalankan:
  webguard gui

Cocok untuk user pemula. Masukkan URL, centang konfirmasi izin,
atur jumlah halaman, lalu klik Start Authorized Scan.
""",
    "doctor": """
DOCTOR — Mengecek apakah instalasi WebGuard lengkap.

Jalankan:
  webguard doctor

Pemeriksaan:
  - requests
  - beautifulsoup4
  - dnspython
  - tkinter
""",
    "reports": """
REPORTS — WebGuard menghasilkan dua format utama.

HTML:
  Mudah dibaca oleh developer atau pemilik website.

JSON:
  Cocok untuk automation, parsing, dan integrasi tooling.

Default:
  reports/webguard-<host>-<timestamp>.html
  reports/webguard-<host>-<timestamp>.json
""",
    "safety": """
SAFETY — Batas penggunaan WebGuard.

WebGuard v0.1 sengaja tidak melakukan:
  - brute force
  - SQL injection exploitation
  - XSS exploitation
  - SSRF exploitation
  - command execution
  - file upload exploitation
  - authentication bypass
  - penghapusan/perubahan data
  - pencurian credential

Gunakan hanya pada website milik sendiri atau website yang memberi izin eksplisit.
""",
}

def build_parser():
    p = argparse.ArgumentParser(
        prog="webguard",
        description="Authorized non-destructive web security scanner",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Contoh:\n"
            "  webguard wizard\n"
            "  webguard scan https://example.com --authorized\n"
            "  webguard help scan\n"
            "  webguard commands\n"
        ),
    )
    p.add_argument("--version", action="version", version=f"WebGuard {__version__}")
    sub = p.add_subparsers(dest="command")

    s = sub.add_parser(
        "scan",
        help="Jalankan authorized website security scan",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    s.add_argument("target", help="Target URL, contoh https://example.com")
    s.add_argument("--authorized", action="store_true", help="Konfirmasi bahwa target boleh diuji")
    s.add_argument("--config", help="Gunakan config JSON")
    s.add_argument("--max-pages", type=int, help="Maksimum halaman")
    s.add_argument("--delay", type=float, help="Jeda antar request (detik)")
    s.add_argument("--timeout", type=float, help="Timeout request (detik)")
    s.add_argument("--scope-host", action="append", default=[], help="Tambahkan host yang termasuk scope")
    s.add_argument("--safe-active", action="store_true", help="Aktifkan benign CORS reflection check")
    s.add_argument("--ignore-robots", action="store_true", help="Abaikan robots.txt jika scope mengizinkan")
    s.add_argument("--report-dir", default="reports", help="Folder report default")
    s.add_argument("--json", help="Path report JSON")
    s.add_argument("--html", help="Path report HTML")

    sub.add_parser("wizard", help="Mode interaktif termudah")
    sub.add_parser("gui", help="Buka desktop GUI")
    sub.add_parser("doctor", help="Cek instalasi dan dependency")
    sub.add_parser("commands", help="Lihat semua command WebGuard")

    h = sub.add_parser("help", help="Buka pusat bantuan WebGuard")
    h.add_argument("topic", nargs="?", choices=sorted(HELP_TOPICS), help="Topik bantuan")

    return p

def show_commands():
    banner(__version__)
    section("COMMANDS")
    command("webguard wizard", "Mode interaktif untuk pemula")
    command("webguard gui", "Buka aplikasi desktop")
    command("webguard scan <URL> --authorized", "Jalankan security scan")
    command("webguard doctor", "Cek dependency dan instalasi")
    command("webguard commands", "Lihat daftar command")
    command("webguard help", "Buka pusat bantuan")
    command("webguard help scan", "Bantuan lengkap command scan")
    command("webguard --version", "Lihat versi WebGuard")
    section("QUICK START")
    print("  1. " + c("webguard doctor", CYAN))
    print("  2. " + c("webguard wizard", CYAN))
    print("  3. Buka report HTML dari folder reports")
    print()

def show_help(topic=None):
    banner(__version__)
    if topic:
        section(f"HELP • {topic.upper()}")
        print(HELP_TOPICS[topic].strip())
        return

    section("HELP CENTER")
    print("WebGuard dibuat agar bisa digunakan tanpa harus menghafal semua command.")
    print()
    print(c("Topik bantuan:", BOLD))
    for name, desc in [
        ("scan", "Cara scan dan semua opsi scan"),
        ("wizard", "Cara menggunakan wizard"),
        ("gui", "Cara menggunakan GUI"),
        ("doctor", "Troubleshooting instalasi"),
        ("reports", "Penjelasan HTML/JSON report"),
        ("safety", "Batas keamanan penggunaan"),
    ]:
        command(f"webguard help {name}", desc)

    section("PALING MUDAH")
    print("  Jalankan:")
    print("  " + c("webguard wizard", CYAN))
    print()
    print(c("Tip:", BOLD), "Jika lupa command, gunakan", c("webguard commands", CYAN))
    print()

def summary(result):
    counts = Counter(f.severity.upper() for f in result.findings)
    banner(__version__)

    section("SCAN SUMMARY")
    info("Target", result.target)
    info("Pages scanned", len(result.pages_scanned))
    info("High", counts["HIGH"])
    info("Medium", counts["MEDIUM"])
    info("Low", counts["LOW"])
    info("Info", counts["INFO"])

    sec = result.disclosure.get("security_txt", {})
    info("security.txt", sec.get("url") or "not found")
    if sec.get("contacts"):
        info("Disclosure", ", ".join(sec["contacts"]))

    if not result.findings:
        section("RESULT")
        success("Tidak ada finding dari checks yang dijalankan.")
    else:
        section("FINDINGS")
        for i, f in enumerate(result.sorted_findings(), 1):
            print(f"{c(str(i).rjust(2) + '.', DIM)} {severity_label(f.severity)} {c(f.title, BOLD)}")
            print(f"    Code        : {f.code}")
            print(f"    Category    : {f.category}")
            print(f"    URL         : {f.url}")
            print(f"    Confidence  : {f.confidence}")
            print(f"    Evidence    : {f.evidence}")
            print(f"    Remediation : {f.remediation}")
            print()

    if result.errors:
        section("WARNINGS")
        for e in result.errors:
            warning(e)

def wizard():
    banner(__version__)
    section("INTERACTIVE WIZARD")
    print("Cara termudah menjalankan WebGuard.")
    print(c("Gunakan hanya pada sistem milik Anda atau dengan izin eksplisit.", DIM))
    print()

    target = input(c("Target URL", BOLD) + ": ").strip()
    confirm = input(c("Punya izin eksplisit? ketik YES", BOLD) + ": ").strip()
    if confirm != "YES":
        warning("Scan dibatalkan karena authorization belum dikonfirmasi.")
        raise SystemExit(2)

    raw_pages = input(c("Maksimum halaman [10]", BOLD) + ": ").strip()
    max_pages = int(raw_pages) if raw_pages else 10
    safe = input(c("Safe-active CORS check? [y/N]", BOLD) + ": ").strip().lower() == "y"

    section("SCAN START")
    status("Menjalankan authorized security scan...")
    result = run_scan(target, max_pages=max_pages, safe_active=safe)
    summary(result)

    host = urlsplit(result.target).hostname or "target"
    j, h = default_report_paths("reports", host)
    write_json(result, j)
    write_html(result, h)

    section("REPORTS")
    success(f"JSON : {j}")
    success(f"HTML : {h}")
    print()
    print(c("Tip:", BOLD), "buka HTML report untuk tampilan hasil yang paling mudah dibaca.")
    print()

def doctor():
    banner(__version__)
    section("INSTALLATION DOCTOR")
    checks = []

    try:
        import requests
        checks.append(("requests", requests.__version__, True))
    except Exception as e:
        checks.append(("requests", str(e), False))

    try:
        import bs4
        checks.append(("beautifulsoup4", bs4.__version__, True))
    except Exception as e:
        checks.append(("beautifulsoup4", str(e), False))

    try:
        import dns
        checks.append(("dnspython", getattr(dns, "__version__", "installed"), True))
    except Exception as e:
        checks.append(("dnspython", str(e), False))

    try:
        import tkinter
        checks.append(("tkinter", "available", True))
    except Exception as e:
        checks.append(("tkinter", str(e), False))

    failed = False
    for name, value, ok in checks:
        if ok:
            success(f"{name:<18} {value}")
        else:
            error(f"{name:<18} {value}")
            failed = True

    print()
    if failed:
        warning("Ada dependency yang bermasalah. Jalankan kembali setup.ps1.")
        return 1

    success("Instalasi WebGuard siap digunakan.")
    print(c("Selanjutnya:", BOLD), c("webguard wizard", CYAN))
    return 0

def main():
    p = build_parser()
    args = p.parse_args()

    if args.command == "help":
        show_help(args.topic)
        return

    if args.command == "commands":
        show_commands()
        return

    if args.command == "wizard":
        wizard()
        return

    if args.command == "gui":
        from .gui import launch
        launch()
        return

    if args.command == "doctor":
        raise SystemExit(doctor())

    if args.command != "scan":
        show_commands()
        return

    cfg = load_config(args.config)

    if args.max_pages is not None:
        cfg["max_pages"] = args.max_pages
    if args.delay is not None:
        cfg["delay"] = args.delay
    if args.timeout is not None:
        cfg["timeout"] = args.timeout
    if args.scope_host:
        cfg["scope_hosts"] = args.scope_host
    if args.safe_active:
        cfg["safe_active"] = True
    if args.ignore_robots:
        cfg["respect_robots"] = False

    if not args.authorized:
        error("Scan dibatalkan: --authorized wajib digunakan setelah memastikan Anda memiliki izin eksplisit.")
        print("Gunakan", c("webguard help scan", CYAN), "untuk bantuan.")
        raise SystemExit(2)

    banner(__version__)
    section("SCAN START")
    status(f"Target: {args.target}")
    status("Menjalankan pemeriksaan keamanan...")

    result = run_scan(
        args.target,
        max_pages=cfg["max_pages"],
        delay=cfg["delay"],
        timeout=cfg["timeout"],
        respect_robots=cfg["respect_robots"],
        safe_active=cfg["safe_active"],
        scope_hosts=cfg["scope_hosts"],
    )
    summary(result)

    host = urlsplit(result.target).hostname or "target"
    section("REPORTS")

    if args.json or args.html:
        if args.json:
            write_json(result, args.json)
            success(f"JSON : {args.json}")
        if args.html:
            write_html(result, args.html)
            success(f"HTML : {args.html}")
    else:
        j, h = default_report_paths(args.report_dir, host)
        write_json(result, j)
        write_html(result, h)
        success(f"JSON : {j}")
        success(f"HTML : {h}")

if __name__ == "__main__":
    main()
