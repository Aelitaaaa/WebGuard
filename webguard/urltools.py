from urllib.parse import urljoin, urlsplit, urlunsplit

DANGEROUS_PATH_HINTS = (
    "logout", "log-out", "signout", "sign-out", "delete", "destroy",
    "remove", "unsubscribe", "reset", "deactivate", "terminate",
)

def normalize_target(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        raise ValueError("Target URL kosong.")
    if "://" not in raw:
        raw = "https://" + raw

    p = urlsplit(raw)
    if p.scheme not in {"http", "https"}:
        raise ValueError("Hanya http dan https yang didukung.")
    if not p.hostname:
        raise ValueError("Hostname tidak valid.")
    return urlunsplit((p.scheme, p.netloc, p.path or "/", p.query, ""))

def host(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()

def allowed_host(url: str, allowed_hosts: set[str]) -> bool:
    return host(url) in {x.lower() for x in allowed_hosts}

def safe_join(base: str, href: str) -> str | None:
    href = (href or "").strip()
    if not href or href.startswith(("#", "mailto:", "tel:", "javascript:", "data:")):
        return None

    joined = urljoin(base, href)
    p = urlsplit(joined)
    if p.scheme not in {"http", "https"}:
        return None

    lower_path = (p.path or "/").lower()
    if any(hint in lower_path for hint in DANGEROUS_PATH_HINTS):
        return None

    return urlunsplit((p.scheme, p.netloc, p.path or "/", p.query, ""))
