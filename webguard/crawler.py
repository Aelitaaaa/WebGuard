from collections import deque
from urllib.robotparser import RobotFileParser
from urllib.parse import urlsplit, urlunsplit
from bs4 import BeautifulSoup

from .urltools import allowed_host, safe_join

def robots_url(url):
    p = urlsplit(url)
    return urlunsplit((p.scheme, p.netloc, "/robots.txt", "", ""))

def get_robot_parser(client, start_url):
    rp = RobotFileParser()
    rp.set_url(robots_url(start_url))
    try:
        fetched = client.get(rp.url)
        if not fetched.redirect_blocked and fetched.response.status_code == 200:
            rp.parse(fetched.response.text.splitlines())
            return rp
    except Exception:
        pass
    return None

def extract_links(base_url, html, allowed_hosts):
    soup = BeautifulSoup(html or "", "html.parser")
    out = []
    for a in soup.find_all("a", href=True):
        u = safe_join(base_url, a.get("href"))
        if u and allowed_host(u, allowed_hosts):
            out.append(u)
    return out

def crawl(client, start_url, allowed_hosts, max_pages=10, respect_robots=True):
    max_pages = max(1, min(int(max_pages), 50))
    queue = deque([start_url])
    queued = {start_url}
    visited = set()
    rp = get_robot_parser(client, start_url) if respect_robots else None

    while queue and len(visited) < max_pages:
        url = queue.popleft()
        if url in visited:
            continue

        if rp and not rp.can_fetch("WebGuard-Audit", url):
            visited.add(url)
            continue

        fetched = client.get(url)
        r = fetched.response
        visited.add(url)
        yield url, fetched

        if fetched.redirect_blocked:
            continue

        if "text/html" not in r.headers.get("Content-Type", "").lower():
            continue

        for link in extract_links(url, r.text, allowed_hosts):
            if link not in visited and link not in queued:
                queue.append(link)
                queued.add(link)
