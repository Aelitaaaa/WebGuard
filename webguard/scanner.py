from datetime import datetime, timezone
from urllib.parse import urlsplit
import requests

from . import __version__
from .models import ScanResult, Finding
from .http_client import SafeHttpClient
from .crawler import crawl
from .urltools import normalize_target
from .checks.headers import check_headers
from .checks.cookies import check_cookies
from .checks.content import check_content
from .checks.tls import check_tls
from .checks.disclosure import fetch_disclosure
from .checks.cors import assess_cors, safe_active_reflection
from .checks.dns_checks import check_dns

def now():
    return datetime.now(timezone.utc).isoformat()

def run_scan(
    target,
    max_pages=10,
    delay=0.8,
    timeout=12,
    respect_robots=True,
    safe_active=False,
    scope_hosts=None,
):
    target = normalize_target(target)
    root_host = (urlsplit(target).hostname or "").lower()
    allowed_hosts = {root_host}
    for h in scope_hosts or []:
        if h:
            allowed_hosts.add(h.lower().strip())

    result = ScanResult(target=target, started_at=now(), version=__version__)
    result.metadata["scope_hosts"] = sorted(allowed_hosts)
    result.metadata["max_pages"] = max_pages
    result.metadata["delay"] = delay
    result.metadata["respect_robots"] = respect_robots
    result.metadata["safe_active"] = safe_active

    client = SafeHttpClient(allowed_hosts, delay=delay, timeout=timeout)

    tls_findings, tls_info = check_tls(target)
    for f in tls_findings:
        result.add(f)
    result.metadata["tls"] = tls_info

    try:
        dns_findings, dns_info = check_dns(target)
        for f in dns_findings:
            result.add(f)
        result.metadata["dns"] = dns_info
    except Exception as e:
        result.errors.append(f"DNS check: {e}")

    result.disclosure["security_txt"] = fetch_disclosure(client, target)

    if safe_active:
        for f in safe_active_reflection(client, target):
            result.add(f)

    try:
        for url, fetched in crawl(
            client,
            target,
            allowed_hosts,
            max_pages=max_pages,
            respect_robots=respect_robots,
        ):
            r = fetched.response
            result.pages_scanned.append(url)

            if fetched.redirect_blocked:
                result.add(Finding(
                    "WG-SCOPE-001", "Redirect keluar scope dihentikan", "INFO", url,
                    f"Redirect menuju {fetched.redirect_blocked}",
                    "WebGuard tidak mengikuti host yang belum tercantum dalam scope.",
                    "Tambahkan host tersebut secara eksplisit hanya jika memang termasuk scope izin.",
                    "High", "Scope",
                ))
                continue

            for f in check_headers(url, r.headers):
                result.add(f)
            for f in check_cookies(url, r):
                result.add(f)
            for f in assess_cors(url, r.headers):
                result.add(f)

            if "text/html" in r.headers.get("Content-Type", "").lower():
                for f in check_content(url, r.text):
                    result.add(f)

            if r.status_code >= 500:
                result.add(Finding(
                    "WG-HTTP-500", "Server mengembalikan error 5xx", "INFO", url,
                    f"HTTP status {r.status_code}",
                    "Endpoint mengalami server-side error pada request GET biasa.",
                    "Tinjau log server/aplikasi.",
                    "High", "HTTP",
                ))

    except requests.RequestException as e:
        result.errors.append(f"HTTP error: {e}")
    except Exception as e:
        result.errors.append(f"Scanner error: {e}")

    result.finished_at = now()
    return result
