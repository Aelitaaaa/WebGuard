from ..models import Finding

def assess_cors(url, headers):
    out = []
    origin = headers.get("Access-Control-Allow-Origin")
    creds = (headers.get("Access-Control-Allow-Credentials") or "").lower() == "true"

    if origin == "*":
        out.append(Finding(
            "WG-CORS-001", "CORS wildcard terdeteksi", "INFO", url,
            "Access-Control-Allow-Origin: *",
            "Resource dapat dibaca oleh origin mana pun jika tidak membutuhkan credential.",
            "Pastikan wildcard memang sesuai untuk resource publik.",
            "High", "CORS",
        ))

    if origin == "*" and creds:
        out.append(Finding(
            "WG-CORS-002", "Kombinasi CORS wildcard dan credentials", "MEDIUM", url,
            "ACAO=* dan Access-Control-Allow-Credentials=true.",
            "Konfigurasi CORS ini tidak konsisten dengan model credentialed CORS dan perlu ditinjau.",
            "Gunakan allowlist origin eksplisit untuk resource yang membutuhkan credential.",
            "High", "CORS",
        ))

    return out

def safe_active_reflection(client, url):
    marker = "https://webguard.invalid"
    try:
        fetched = client.get(url, headers={"Origin": marker})
        if fetched.redirect_blocked:
            return []
        h = fetched.response.headers
        if h.get("Access-Control-Allow-Origin") == marker:
            creds = (h.get("Access-Control-Allow-Credentials") or "").lower() == "true"
            sev = "MEDIUM" if creds else "LOW"
            return [Finding(
                "WG-CORS-003",
                "Origin CORS tampak direfleksikan", sev, url,
                f"Origin benign {marker} direfleksikan pada Access-Control-Allow-Origin.",
                "Origin arbitrer mungkin diizinkan. Dampak lebih tinggi bila endpoint sensitif menerima credential.",
                "Gunakan allowlist origin yang ketat dan validasi kebutuhan credential per endpoint.",
                "Medium", "CORS",
            )]
    except Exception:
        pass
    return []
