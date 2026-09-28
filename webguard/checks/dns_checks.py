from urllib.parse import urlsplit

import dns.resolver

from ..models import Finding

def _txt(name):
    values = []
    for rdata in dns.resolver.resolve(name, "TXT"):
        try:
            values.append("".join(
                s.decode() if isinstance(s, bytes) else str(s)
                for s in rdata.strings
            ))
        except Exception:
            values.append(rdata.to_text().strip('"'))
    return values

def check_dns(url):
    domain = urlsplit(url).hostname
    info = {"domain": domain, "A": [], "AAAA": [], "CAA": [], "SPF": [], "DMARC": []}
    findings = []

    for kind in ("A", "AAAA", "CAA"):
        try:
            info[kind] = [x.to_text() for x in dns.resolver.resolve(domain, kind)]
        except Exception:
            pass

    try:
        txt = _txt(domain)
        info["SPF"] = [x for x in txt if x.lower().startswith("v=spf1")]
    except Exception:
        pass

    try:
        info["DMARC"] = [x for x in _txt("_dmarc." + domain) if x.lower().startswith("v=dmarc1")]
    except Exception:
        pass

    if not info["CAA"]:
        findings.append(Finding(
            "WG-DNS-001", "CAA record tidak ditemukan", "INFO", url,
            f"Domain: {domain}",
            "Tidak ada pembatasan CA melalui CAA. Ini bukan bukti kelemahan eksploitabel.",
            "Pertimbangkan CAA bila organisasi ingin membatasi CA yang boleh menerbitkan sertifikat.",
            "High", "DNS",
        ))

    if not info["DMARC"]:
        findings.append(Finding(
            "WG-DNS-002", "DMARC tidak ditemukan", "LOW", url,
            f"_dmarc.{domain} tidak menghasilkan policy DMARC.",
            "Domain email lebih sulit menerapkan kebijakan anti-spoofing yang eksplisit.",
            "Konfigurasikan SPF, DKIM, dan DMARC sesuai sistem email organisasi.",
            "Medium", "DNS",
        ))

    return findings, info
