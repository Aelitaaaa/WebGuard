from ..models import Finding

SENSITIVE_HINTS = ("session", "sess", "sid", "auth", "token", "jwt")

def _headers(response):
    try:
        values = response.raw.headers.getlist("Set-Cookie")
        if values:
            return list(values)
    except Exception:
        pass
    value = response.headers.get("Set-Cookie")
    return [value] if value else []

def check_cookies(url, response):
    out = []
    for raw in _headers(response):
        parts = [p.strip() for p in raw.split(";") if p.strip()]
        if not parts or "=" not in parts[0]:
            continue

        name = parts[0].split("=", 1)[0]
        attrs = {p.split("=", 1)[0].lower(): p for p in parts[1:]}
        sensitive = any(x in name.lower() for x in SENSITIVE_HINTS)

        def add(code, title, sev, evidence, impact, remediation):
            out.append(Finding(code, title, sev, url, evidence, impact, remediation, "High", "Cookies"))

        if url.lower().startswith("https://") and "secure" not in attrs:
            add("WG-CK-001", f"Cookie {name} tidak memakai Secure",
                "MEDIUM" if sensitive else "LOW",
                f"Cookie {name} tidak memiliki Secure.",
                "Cookie dapat terkirim lewat koneksi non-HTTPS jika alur aplikasi memungkinkan.",
                "Tambahkan atribut Secure.")

        if "httponly" not in attrs:
            add("WG-CK-002", f"Cookie {name} tidak memakai HttpOnly",
                "MEDIUM" if sensitive else "LOW",
                f"Cookie {name} tidak memiliki HttpOnly.",
                "Jika terjadi XSS, JavaScript dapat membaca cookie tersebut.",
                "Tambahkan HttpOnly jika JavaScript tidak membutuhkannya.")

        if "samesite" not in attrs:
            add("WG-CK-003", f"Cookie {name} tidak menetapkan SameSite", "LOW",
                f"Cookie {name} tidak memiliki SameSite.",
                "Perilaku cross-site bergantung pada default browser.",
                "Tetapkan SameSite=Lax atau Strict bila sesuai.")

    return out
