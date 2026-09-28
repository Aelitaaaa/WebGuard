from urllib.parse import urlsplit
from ..models import Finding

def finding(code, title, severity, url, evidence, impact, remediation, confidence="High"):
    return Finding(code, title, severity, url, evidence, impact, remediation, confidence, "Headers")

def check_headers(url: str, headers) -> list[Finding]:
    out = []
    h = {k.lower(): v.strip() for k, v in headers.items()}
    csp = h.get("content-security-policy", "")

    if not csp:
        out.append(finding(
            "WG-HDR-001", "Content-Security-Policy tidak ditemukan", "LOW", url,
            "Header Content-Security-Policy tidak ditemukan.",
            "Browser tidak mendapat pembatasan sumber resource melalui CSP.",
            "Terapkan CSP yang sesuai aplikasi. Uji dengan Content-Security-Policy-Report-Only lebih dahulu.",
        ))

    if "frame-ancestors" not in csp.lower() and "x-frame-options" not in h:
        out.append(finding(
            "WG-HDR-002", "Proteksi clickjacking tidak terlihat", "LOW", url,
            "Tidak ada CSP frame-ancestors atau X-Frame-Options.",
            "Halaman mungkin dapat di-embed oleh origin lain bila tidak ada kontrol lain.",
            "Gunakan CSP frame-ancestors; X-Frame-Options dapat menjadi fallback.",
        ))

    if h.get("x-content-type-options", "").lower() != "nosniff":
        out.append(finding(
            "WG-HDR-003", "X-Content-Type-Options belum nosniff", "LOW", url,
            f"Nilai: {h.get('x-content-type-options', '<missing>')}",
            "MIME sniffing dapat terjadi pada kondisi tertentu.",
            "Kirim X-Content-Type-Options: nosniff.",
        ))

    if "referrer-policy" not in h:
        out.append(finding(
            "WG-HDR-004", "Referrer-Policy tidak ditemukan", "LOW", url,
            "Header Referrer-Policy tidak ditemukan.",
            "Informasi URL asal dapat dibagikan lebih luas daripada yang diinginkan.",
            "Gunakan kebijakan yang sesuai, misalnya strict-origin-when-cross-origin.",
        ))

    if "permissions-policy" not in h:
        out.append(finding(
            "WG-HDR-005", "Permissions-Policy tidak ditemukan", "INFO", url,
            "Header Permissions-Policy tidak ditemukan.",
            "Fitur browser tidak dibatasi secara eksplisit melalui header ini.",
            "Batasi fitur browser yang tidak diperlukan.",
        ))

    if urlsplit(url).scheme == "https" and "strict-transport-security" not in h:
        out.append(finding(
            "WG-HDR-006", "HSTS tidak ditemukan", "MEDIUM", url,
            "Header Strict-Transport-Security tidak ditemukan.",
            "Klien baru lebih bergantung pada redirect HTTP ke HTTPS.",
            "Setelah HTTPS stabil, terapkan HSTS dengan max-age yang sesuai.",
        ))

    server = h.get("server", "")
    if server and any(ch.isdigit() for ch in server):
        out.append(finding(
            "WG-INFO-001", "Banner server mengungkap detail versi", "INFO", url,
            f"Server: {server}",
            "Mempermudah fingerprinting. Ini bukan bukti eksploit.",
            "Kurangi detail versi jika platform memungkinkan.",
        ))

    powered = h.get("x-powered-by", "")
    if powered:
        out.append(finding(
            "WG-INFO-002", "X-Powered-By mengungkap teknologi", "LOW", url,
            f"X-Powered-By: {powered}",
            "Memberikan informasi fingerprinting tambahan.",
            "Nonaktifkan header X-Powered-By bila tidak diperlukan.",
        ))

    return out
