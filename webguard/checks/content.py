import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlsplit
from ..models import Finding

RESOURCE_ATTRS = {
    "script": "src", "img": "src", "iframe": "src", "link": "href",
    "audio": "src", "video": "src", "source": "src",
}

DEBUG_PATTERNS = [
    (re.compile(r"Traceback \(most recent call last\)", re.I), "Python traceback"),
    (re.compile(r"Stack trace:", re.I), "Stack trace"),
    (re.compile(r"Fatal error:.* on line \d+", re.I | re.S), "PHP fatal error"),
    (re.compile(r"Unhandled exception", re.I), "Unhandled exception"),
    (re.compile(r"System\.[A-Za-z.]+Exception", re.I), ".NET exception"),
]

def check_content(url, html):
    out = []
    soup = BeautifulSoup(html or "", "html.parser")

    if url.startswith("https://"):
        seen = set()
        for tag_name, attr in RESOURCE_ATTRS.items():
            for tag in soup.find_all(tag_name):
                value = (tag.get(attr) or "").strip()
                if not value:
                    continue
                absolute = urljoin(url, value)
                if absolute.startswith("http://") and absolute not in seen:
                    seen.add(absolute)
                    sev = "MEDIUM" if tag_name in {"script", "iframe"} else "LOW"
                    out.append(Finding(
                        "WG-CNT-001", "Mixed content ditemukan", sev, url,
                        f"{tag_name} memuat {absolute}",
                        "Resource HTTP pada halaman HTTPS menurunkan integritas atau kerahasiaan.",
                        "Muat resource melalui HTTPS atau hapus resource tersebut.",
                        "High", "Content",
                    ))

    for form in soup.find_all("form"):
        action = urljoin(url, (form.get("action") or url).strip())
        has_password = form.find("input", attrs={"type": re.compile("^password$", re.I)}) is not None

        if url.startswith("http://") and has_password:
            out.append(Finding(
                "WG-FORM-001", "Password form berada pada halaman HTTP", "HIGH", url,
                "Form mengandung input type=password pada halaman tanpa HTTPS.",
                "Kredensial dapat terekspos pada jaringan sebelum perlindungan TLS.",
                "Gunakan HTTPS untuk seluruh halaman autentikasi.",
                "High", "Forms",
            ))

        if has_password and action.startswith("http://"):
            out.append(Finding(
                "WG-FORM-002", "Password form mengirim ke HTTP", "HIGH", url,
                f"Form action: {action}",
                "Kredensial berpotensi dikirim melalui koneksi tanpa TLS.",
                "Ubah action form menjadi HTTPS dan paksa HTTPS.",
                "High", "Forms",
            ))

    text_sample = (html or "")[:500000]
    for pattern, label in DEBUG_PATTERNS:
        if pattern.search(text_sample):
            out.append(Finding(
                "WG-ERR-001", "Indikasi debug / stack trace terekspos", "MEDIUM", url,
                f"Pola terdeteksi: {label}",
                "Pesan debug dapat membocorkan path, framework, query, atau detail internal.",
                "Nonaktifkan debug di production dan gunakan error page generik.",
                "Medium", "Information Disclosure",
            ))
            break

    return out
