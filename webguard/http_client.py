import time
from dataclasses import dataclass
from urllib.parse import urljoin

import requests

from .urltools import allowed_host

@dataclass
class FetchResult:
    response: requests.Response
    redirect_blocked: str | None = None

class SafeHttpClient:
    def __init__(self, allowed_hosts: set[str], delay=0.8, timeout=12.0):
        self.allowed_hosts = {h.lower() for h in allowed_hosts}
        self.delay = max(0.2, min(float(delay), 10.0))
        self.timeout = max(2.0, min(float(timeout), 30.0))
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "WebGuard-Audit/1.0 (+authorized-security-assessment)",
            "Accept": "text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.5",
        })
        self._last = 0.0

    def _throttle(self):
        wait = self.delay - (time.monotonic() - self._last)
        if wait > 0:
            time.sleep(wait)

    def get(self, url: str, headers=None, max_redirects=5) -> FetchResult:
        current = url
        for _ in range(max_redirects + 1):
            self._throttle()
            response = self.session.get(
                current,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=False,
                verify=True,
            )
            self._last = time.monotonic()

            if response.is_redirect or response.is_permanent_redirect:
                location = response.headers.get("Location")
                if not location:
                    return FetchResult(response)
                nxt = urljoin(current, location)
                if not allowed_host(nxt, self.allowed_hosts):
                    return FetchResult(response, redirect_blocked=nxt)
                current = nxt
                continue

            return FetchResult(response)

        raise requests.TooManyRedirects(f"Terlalu banyak redirect: {url}")
