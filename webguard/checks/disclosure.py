from urllib.parse import urlsplit, urlunsplit

def base(url):
    p = urlsplit(url)
    return urlunsplit((p.scheme, p.netloc, "", "", ""))

def parse_security_txt(text):
    data = {"contacts": [], "policy": [], "expires": None, "raw_fields": {}}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, value = line.split(":", 1)
        key, value = key.strip(), value.strip()
        data["raw_fields"].setdefault(key, []).append(value)
        if key.lower() == "contact":
            data["contacts"].append(value)
        elif key.lower() == "policy":
            data["policy"].append(value)
        elif key.lower() == "expires":
            data["expires"] = value
    return data

def fetch_disclosure(client, url):
    for candidate in [base(url) + "/.well-known/security.txt", base(url) + "/security.txt"]:
        try:
            fetched = client.get(candidate)
            if fetched.redirect_blocked:
                continue
            r = fetched.response
            if r.status_code == 200 and r.text.strip():
                data = parse_security_txt(r.text)
                data.update({"url": candidate, "status_code": 200})
                return data
        except Exception:
            pass
    return {"url": None, "contacts": [], "policy": [], "expires": None, "raw_fields": {}}
