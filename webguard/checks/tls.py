import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlsplit
from ..models import Finding

def check_tls(url):
    p = urlsplit(url)
    if p.scheme != "https":
        return [Finding(
            "WG-TLS-000", "Target tidak menggunakan HTTPS", "HIGH", url,
            f"Skema target: {p.scheme}",
            "HTTP tidak memberi perlindungan TLS.",
            "Aktifkan HTTPS dan redirect HTTP ke HTTPS.",
            "High", "TLS",
        )], {}

    host = p.hostname
    port = p.port or 443
    info = {}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                info["protocol"] = ssock.version()
                info["cipher"] = ssock.cipher()[0] if ssock.cipher() else None
                info["subject"] = dict(x[0] for x in cert.get("subject", []))
                info["issuer"] = dict(x[0] for x in cert.get("issuer", []))
                info["notAfter"] = cert.get("notAfter")

                out = []
                not_after = cert.get("notAfter")
                if not_after:
                    expiry_ts = ssl.cert_time_to_seconds(not_after)
                    expiry = datetime.fromtimestamp(expiry_ts, tz=timezone.utc)
                    days = (expiry - datetime.now(timezone.utc)).total_seconds() / 86400
                    info["days_remaining"] = round(days, 1)

                    if days < 0:
                        sev, code, title = "HIGH", "WG-TLS-001", "Sertifikat TLS sudah kedaluwarsa"
                    elif days < 14:
                        sev, code, title = "MEDIUM", "WG-TLS-002", "Sertifikat TLS segera kedaluwarsa"
                    elif days < 30:
                        sev, code, title = "LOW", "WG-TLS-003", "Sertifikat TLS mendekati kedaluwarsa"
                    else:
                        return out, info

                    out.append(Finding(
                        code, title, sev, url,
                        f"Sisa masa berlaku sekitar {days:.1f} hari.",
                        "Sertifikat yang habis dapat menyebabkan kegagalan koneksi klien.",
                        "Perbarui sertifikat dan verifikasi otomatisasi renewal.",
                        "High", "TLS",
                    ))
                return out, info

    except ssl.SSLCertVerificationError as e:
        return [Finding(
            "WG-TLS-004", "Validasi sertifikat TLS gagal", "HIGH", url,
            str(e),
            "Klien normal dapat menolak koneksi HTTPS.",
            "Periksa hostname, chain, masa berlaku, CA, dan intermediate certificate.",
            "High", "TLS",
        )], info
    except (ssl.SSLError, socket.error, OSError) as e:
        return [Finding(
            "WG-TLS-005", "Pemeriksaan TLS gagal", "MEDIUM", url,
            str(e),
            "Scanner tidak dapat memverifikasi TLS endpoint.",
            "Periksa ketersediaan HTTPS dan konfigurasi TLS secara manual.",
            "Medium", "TLS",
        )], info
