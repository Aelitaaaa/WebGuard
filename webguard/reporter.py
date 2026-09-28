import html
import json
from pathlib import Path
from collections import Counter
from datetime import datetime

from .models import ScanResult


def write_json(result: ScanResult, path):
    Path(path).write_text(
        json.dumps(result.to_dict(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def esc(value):
    return html.escape(str(value if value is not None else ""), quote=True)


def default_report_paths(report_dir, target_host):
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    safe_host = "".join(c if c.isalnum() or c in ".-_" else "_" for c in target_host)
    folder = Path(report_dir)
    folder.mkdir(parents=True, exist_ok=True)
    return (
        folder / f"webguard-{safe_host}-{stamp}.json",
        folder / f"webguard-{safe_host}-{stamp}.html",
    )


def _summary_state(counts):
    if counts.get("HIGH", 0):
        return (
            "Prioritas tinggi",
            "Ada temuan yang perlu diperiksa lebih dulu sebelum fokus ke hardening lain.",
            "danger",
        )
    if counts.get("MEDIUM", 0):
        return (
            "Perlu ditinjau",
            "Tidak ada temuan high, tetapi ada konfigurasi yang sebaiknya diperiksa.",
            "warning",
        )
    if counts.get("LOW", 0):
        return (
            "Perbaikan ringan",
            "Temuan saat ini terutama berupa hardening dan peningkatan konfigurasi.",
            "low",
        )
    return (
        "Tidak ada isu utama",
        "Checks yang dijalankan tidak menemukan masalah yang membutuhkan tindakan segera.",
        "good",
    )


def _human_severity(severity):
    return {
        "HIGH": "Prioritas tinggi",
        "MEDIUM": "Perlu ditinjau",
        "LOW": "Peningkatan",
        "INFO": "Informasi",
    }.get(severity.upper(), severity.title())


def _action_hint(severity):
    return {
        "HIGH": "Periksa lebih dulu",
        "MEDIUM": "Jadwalkan perbaikan",
        "LOW": "Tingkatkan hardening",
        "INFO": "Tidak mendesak",
    }.get(severity.upper(), "Tinjau")


def write_html(result: ScanResult, path):
    findings = result.sorted_findings()
    counts = Counter(f.severity.upper() for f in findings)
    state_title, state_text, state_class = _summary_state(counts)

    top_actions = [
        f for f in findings if f.severity.upper() in {"HIGH", "MEDIUM", "LOW"}
    ][:3]

    action_rows = []
    for f in top_actions:
        action_rows.append(f"""
        <li class="priority-item">
          <span class="severity-dot dot-{esc(f.severity.lower())}" aria-hidden="true"></span>
          <div>
            <div class="priority-title">{esc(f.title)}</div>
            <div class="priority-meta">{esc(_action_hint(f.severity))} · {esc(f.category)}</div>
          </div>
          <a href="#finding-{esc(f.code)}" class="text-link">Lihat</a>
        </li>
        """)

    finding_rows = []
    for f in findings:
        sev = f.severity.upper()
        search_blob = " ".join([
            f.code, f.title, f.category, f.url, f.evidence,
            f.impact, f.remediation, f.confidence, sev
        ]).lower()

        finding_rows.append(f"""
        <article
          class="finding"
          id="finding-{esc(f.code)}"
          data-severity="{esc(sev)}"
          data-search="{esc(search_blob)}"
        >
          <div class="finding-head">
            <div class="finding-title-wrap">
              <div class="eyebrow">
                <span class="severity severity-{esc(sev.lower())}">
                  {esc(_human_severity(sev))}
                </span>
                <span>{esc(f.category)}</span>
                <span>{esc(f.code)}</span>
              </div>
              <h3>{esc(f.title)}</h3>
            </div>
            <div class="confidence">
              <span>Confidence</span>
              <strong>{esc(f.confidence)}</strong>
            </div>
          </div>

          <div class="finding-grid">
            <section>
              <h4>Kenapa ini penting</h4>
              <p>{esc(f.impact)}</p>
            </section>
            <section>
              <h4>Apa yang perlu dilakukan</h4>
              <p>{esc(f.remediation)}</p>
            </section>
          </div>

          <details class="technical">
            <summary>Detail teknis</summary>
            <dl>
              <div>
                <dt>URL</dt>
                <dd><code>{esc(f.url)}</code></dd>
              </div>
              <div>
                <dt>Evidence</dt>
                <dd>{esc(f.evidence)}</dd>
              </div>
              <div>
                <dt>Finding ID</dt>
                <dd><code>{esc(f.code)}</code></dd>
              </div>
              <div>
                <dt>Confidence</dt>
                <dd>{esc(f.confidence)}</dd>
              </div>
            </dl>
          </details>
        </article>
        """)

    sec = result.disclosure.get("security_txt", {})
    contacts = "".join(
        f'<li><code>{esc(x)}</code></li>' for x in sec.get("contacts", [])
    ) or "<li>Tidak ditemukan</li>"
    policies = "".join(
        f'<li><code>{esc(x)}</code></li>' for x in sec.get("policy", [])
    ) or "<li>Tidak ditemukan</li>"

    errors = "".join(
        f"<li>{esc(x)}</li>" for x in result.errors
    ) or "<li>Tidak ada error scanner yang tercatat.</li>"

    if action_rows:
        priority_html = "".join(action_rows)
    else:
        priority_html = """
        <li class="priority-empty">
          Tidak ada temuan yang membutuhkan tindakan prioritas dari checks yang dijalankan.
        </li>
        """

    html_doc = f"""<!doctype html>
<html lang="id">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light">
<title>WebGuard security report — {esc(result.target)}</title>
<style>
:root {{
  --bg: #f6f7f9;
  --surface: #ffffff;
  --surface-soft: #f0f2f5;
  --ink: #16181d;
  --muted: #666d78;
  --faint: #8c939d;
  --line: #dfe3e8;
  --line-strong: #cdd2d9;
  --accent: #2457d6;
  --accent-soft: #eaf0ff;
  --high: #b42318;
  --high-soft: #fff0ee;
  --medium: #9a6700;
  --medium-soft: #fff7df;
  --low: #59636e;
  --low-soft: #eef1f4;
  --info: #2457d6;
  --info-soft: #edf3ff;
  --good: #137333;
  --good-soft: #eaf6ee;
  --radius: 10px;
}}

* {{ box-sizing: border-box; }}

html {{
  scroll-behavior: smooth;
  background: var(--bg);
}}

body {{
  margin: 0;
  background: var(--bg);
  color: var(--ink);
  font-family: "Segoe UI Variable", "Segoe UI", system-ui, -apple-system, BlinkMacSystemFont, sans-serif;
  font-size: 15px;
  line-height: 1.6;
  -webkit-font-smoothing: antialiased;
}}

button, input {{
  font: inherit;
}}

a {{
  color: inherit;
}}

code {{
  font-family: "Cascadia Code", "Cascadia Mono", Consolas, monospace;
  font-size: 0.92em;
  overflow-wrap: anywhere;
}}

.skip-link {{
  position: absolute;
  left: 16px;
  top: -60px;
  z-index: 100;
  background: var(--ink);
  color: white;
  padding: 10px 14px;
  border-radius: 6px;
}}

.skip-link:focus {{ top: 16px; }}

.shell {{
  width: min(1180px, calc(100% - 40px));
  margin: 0 auto;
}}

.topbar {{
  border-bottom: 1px solid var(--line);
  background: rgba(246,247,249,0.94);
}}

.topbar-inner {{
  min-height: 64px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 18px;
}}

.brand {{
  display: flex;
  align-items: baseline;
  gap: 10px;
}}

.brand strong {{
  font-size: 17px;
  letter-spacing: -0.02em;
}}

.brand span {{
  color: var(--muted);
  font-size: 13px;
}}

.report-type {{
  color: var(--muted);
  font-size: 13px;
}}

main {{
  padding: 52px 0 72px;
}}

.hero {{
  display: grid;
  grid-template-columns: minmax(0, 1.55fr) minmax(280px, 0.75fr);
  gap: 64px;
  align-items: end;
  padding-bottom: 42px;
  border-bottom: 1px solid var(--line-strong);
}}

.kicker {{
  margin: 0 0 12px;
  color: var(--accent);
  font-size: 12px;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}}

h1, h2, h3, h4, p {{ margin-top: 0; }}

h1 {{
  max-width: 14ch;
  margin-bottom: 18px;
  font-size: clamp(36px, 5vw, 62px);
  line-height: 0.98;
  letter-spacing: -0.055em;
  text-wrap: balance;
}}

.hero-copy {{
  max-width: 66ch;
  margin: 0;
  color: var(--muted);
  font-size: 17px;
  line-height: 1.7;
}}

.meta-list {{
  margin: 0;
}}

.meta-row {{
  display: grid;
  grid-template-columns: 110px 1fr;
  gap: 14px;
  padding: 9px 0;
  border-bottom: 1px solid var(--line);
}}

.meta-row:last-child {{
  border-bottom: 0;
}}

.meta-row dt {{
  color: var(--faint);
}}

.meta-row dd {{
  margin: 0;
  font-variant-numeric: tabular-nums;
  overflow-wrap: anywhere;
}}

.status-strip {{
  display: grid;
  grid-template-columns: minmax(250px, 1.5fr) repeat(4, minmax(90px, 0.55fr));
  margin-top: 28px;
  border-top: 1px solid var(--line-strong);
  border-bottom: 1px solid var(--line-strong);
}}

.status-copy, .metric {{
  padding: 18px 20px;
}}

.status-copy {{
  padding-left: 0;
}}

.metric {{
  border-left: 1px solid var(--line);
}}

.status-label {{
  display: inline-flex;
  align-items: center;
  gap: 8px;
  font-size: 13px;
  font-weight: 700;
}}

.status-label::before {{
  content: "";
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--accent);
}}

.status-label.danger::before {{ background: var(--high); }}
.status-label.warning::before {{ background: var(--medium); }}
.status-label.low::before {{ background: var(--low); }}
.status-label.good::before {{ background: var(--good); }}

.status-copy p {{
  margin: 5px 0 0;
  color: var(--muted);
}}

.metric strong {{
  display: block;
  font-family: "Cascadia Code", "Cascadia Mono", Consolas, monospace;
  font-size: 26px;
  font-variant-numeric: tabular-nums;
  letter-spacing: -0.03em;
}}

.metric span {{
  color: var(--muted);
  font-size: 12px;
}}

.layout {{
  display: grid;
  grid-template-columns: 260px minmax(0, 1fr);
  gap: 64px;
  margin-top: 48px;
}}

.aside {{
  position: sticky;
  top: 24px;
  align-self: start;
}}

.aside h2 {{
  margin-bottom: 14px;
  font-size: 13px;
  letter-spacing: 0.01em;
}}

.priority-list {{
  padding: 0;
  margin: 0;
  list-style: none;
}}

.priority-item {{
  display: grid;
  grid-template-columns: 10px minmax(0,1fr) auto;
  gap: 10px;
  align-items: start;
  padding: 14px 0;
  border-top: 1px solid var(--line);
}}

.priority-empty {{
  padding: 14px 0;
  border-top: 1px solid var(--line);
  color: var(--muted);
}}

.severity-dot {{
  width: 7px;
  height: 7px;
  margin-top: 8px;
  border-radius: 50%;
}}

.dot-high {{ background: var(--high); }}
.dot-medium {{ background: var(--medium); }}
.dot-low {{ background: var(--low); }}
.dot-info {{ background: var(--info); }}

.priority-title {{
  font-size: 13px;
  font-weight: 600;
  line-height: 1.45;
}}

.priority-meta {{
  margin-top: 3px;
  color: var(--faint);
  font-size: 11px;
}}

.text-link {{
  color: var(--accent);
  font-size: 12px;
  text-decoration: none;
}}

.text-link:hover {{ text-decoration: underline; }}

.aside-nav {{
  margin-top: 28px;
  padding-top: 18px;
  border-top: 1px solid var(--line);
}}

.aside-nav a {{
  display: block;
  padding: 5px 0;
  color: var(--muted);
  font-size: 13px;
  text-decoration: none;
}}

.aside-nav a:hover {{ color: var(--ink); }}

.content {{
  min-width: 0;
}}

.section-head {{
  display: flex;
  align-items: end;
  justify-content: space-between;
  gap: 24px;
  margin-bottom: 18px;
}}

.section-head h2 {{
  margin: 0;
  font-size: 24px;
  letter-spacing: -0.035em;
}}

.section-head p {{
  max-width: 52ch;
  margin: 0;
  color: var(--muted);
}}

.toolbar {{
  display: grid;
  grid-template-columns: minmax(220px, 1fr) auto;
  gap: 14px;
  margin-bottom: 12px;
}}

.search {{
  width: 100%;
  height: 42px;
  padding: 0 13px;
  border: 1px solid var(--line-strong);
  border-radius: 7px;
  background: var(--surface);
  color: var(--ink);
  outline: none;
}}

.search:focus {{
  border-color: var(--accent);
  box-shadow: 0 0 0 3px var(--accent-soft);
}}

.filters {{
  display: flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
}}

.filter {{
  height: 42px;
  padding: 0 12px;
  border: 1px solid var(--line-strong);
  border-radius: 7px;
  background: transparent;
  color: var(--muted);
  cursor: pointer;
}}

.filter:hover,
.filter.active {{
  border-color: var(--ink);
  background: var(--ink);
  color: white;
}}

.finding-list {{
  border-top: 1px solid var(--line-strong);
}}

.finding {{
  padding: 28px 0 30px;
  border-bottom: 1px solid var(--line-strong);
}}

.finding[hidden] {{ display: none; }}

.finding-head {{
  display: grid;
  grid-template-columns: minmax(0,1fr) auto;
  gap: 28px;
  align-items: start;
}}

.eyebrow {{
  display: flex;
  flex-wrap: wrap;
  gap: 9px;
  align-items: center;
  color: var(--faint);
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 0.025em;
}}

.severity {{
  display: inline-flex;
  align-items: center;
  min-height: 23px;
  padding: 1px 7px;
  border-radius: 4px;
  font-weight: 700;
}}

.severity-high {{ color: var(--high); background: var(--high-soft); }}
.severity-medium {{ color: var(--medium); background: var(--medium-soft); }}
.severity-low {{ color: var(--low); background: var(--low-soft); }}
.severity-info {{ color: var(--info); background: var(--info-soft); }}

.finding h3 {{
  margin: 8px 0 0;
  max-width: 28ch;
  font-size: 25px;
  line-height: 1.15;
  letter-spacing: -0.035em;
  text-wrap: balance;
}}

.confidence {{
  min-width: 96px;
  text-align: right;
}}

.confidence span {{
  display: block;
  color: var(--faint);
  font-size: 11px;
}}

.confidence strong {{
  font-size: 13px;
}}

.finding-grid {{
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 38px;
  margin-top: 24px;
}}

.finding-grid h4 {{
  margin-bottom: 7px;
  font-size: 12px;
  letter-spacing: 0.015em;
}}

.finding-grid p {{
  margin: 0;
  color: var(--muted);
  max-width: 62ch;
}}

.technical {{
  margin-top: 18px;
  color: var(--muted);
}}

.technical summary {{
  width: max-content;
  color: var(--accent);
  cursor: pointer;
  font-size: 13px;
  user-select: none;
}}

.technical summary:hover {{ text-decoration: underline; }}

.technical dl {{
  margin: 16px 0 0;
  padding: 16px 18px;
  border-left: 2px solid var(--line-strong);
  background: var(--surface-soft);
}}

.technical dl > div {{
  display: grid;
  grid-template-columns: 110px minmax(0,1fr);
  gap: 14px;
  padding: 6px 0;
}}

.technical dt {{
  color: var(--faint);
  font-size: 12px;
}}

.technical dd {{
  margin: 0;
  overflow-wrap: anywhere;
}}

.support-section {{
  padding: 34px 0;
  border-bottom: 1px solid var(--line-strong);
}}

.support-section h2 {{
  margin-bottom: 8px;
  font-size: 20px;
  letter-spacing: -0.025em;
}}

.support-section > p {{
  color: var(--muted);
  max-width: 68ch;
}}

.support-grid {{
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 36px;
  margin-top: 18px;
}}

.support-grid h3 {{
  font-size: 12px;
}}

.clean-list {{
  padding-left: 18px;
  color: var(--muted);
}}

.empty-result {{
  display: none;
  padding: 28px 0;
  color: var(--muted);
}}

.footer {{
  padding-top: 30px;
  color: var(--faint);
  font-size: 12px;
}}

.footer strong {{ color: var(--muted); }}

@media (max-width: 900px) {{
  .hero {{
    grid-template-columns: 1fr;
    gap: 28px;
  }}

  h1 {{ max-width: none; }}

  .status-strip {{
    grid-template-columns: 1fr 1fr;
  }}

  .status-copy {{
    grid-column: 1 / -1;
    padding-left: 0;
  }}

  .metric {{
    border-top: 1px solid var(--line);
  }}

  .layout {{
    grid-template-columns: 1fr;
    gap: 36px;
  }}

  .aside {{
    position: static;
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 24px;
  }}

  .aside-nav {{
    margin-top: 0;
    padding-top: 0;
    border-top: 0;
  }}
}}

@media (max-width: 680px) {{
  .shell {{
    width: min(100% - 28px, 1180px);
  }}

  .topbar-inner {{
    align-items: flex-start;
    flex-direction: column;
    justify-content: center;
    padding: 12px 0;
  }}

  main {{ padding-top: 34px; }}

  .status-strip {{
    grid-template-columns: 1fr 1fr;
  }}

  .metric:nth-of-type(odd) {{
    border-left: 0;
  }}

  .layout {{
    margin-top: 34px;
  }}

  .aside {{
    grid-template-columns: 1fr;
  }}

  .toolbar {{
    grid-template-columns: 1fr;
  }}

  .filters {{
    overflow-x: auto;
    flex-wrap: nowrap;
    padding-bottom: 4px;
  }}

  .finding-head,
  .finding-grid,
  .support-grid {{
    grid-template-columns: 1fr;
  }}

  .confidence {{
    text-align: left;
  }}

  .technical dl > div {{
    grid-template-columns: 1fr;
    gap: 2px;
  }}
}}

@media print {{
  :root {{
    --bg: #fff;
    --surface: #fff;
    --surface-soft: #f6f6f6;
  }}

  body {{
    background: #fff;
    font-size: 11pt;
  }}

  .shell {{
    width: 100%;
  }}

  .topbar,
  .toolbar,
  .aside-nav {{
    display: none;
  }}

  main {{
    padding: 0;
  }}

  .hero {{
    grid-template-columns: 1.5fr 1fr;
    padding-bottom: 20px;
  }}

  h1 {{
    font-size: 30pt;
  }}

  .layout {{
    grid-template-columns: 1fr;
    margin-top: 24px;
  }}

  .aside {{
    position: static;
  }}

  .technical {{
    display: block;
  }}

  .technical > * {{
    display: block;
  }}

  .finding {{
    break-inside: avoid;
  }}
}}
</style>
</head>
<body>
<a class="skip-link" href="#findings">Lewati ke temuan</a>

<header class="topbar">
  <div class="shell topbar-inner">
    <div class="brand">
      <strong>WebGuard</strong>
      <span>v{esc(result.version)}</span>
    </div>
    <div class="report-type">Authorized security assessment report</div>
  </div>
</header>

<main>
  <div class="shell">
    <section class="hero" aria-labelledby="report-title">
      <div>
        <p class="kicker">Security report</p>
        <h1 id="report-title">Apa yang perlu diperbaiki pada website ini?</h1>
        <p class="hero-copy">
          Laporan ini memisahkan hal yang perlu tindakan dari informasi teknis.
          Temuan hardening tidak otomatis berarti website dapat dieksploitasi.
        </p>
      </div>

      <dl class="meta-list">
        <div class="meta-row">
          <dt>Target</dt>
          <dd>{esc(result.target)}</dd>
        </div>
        <div class="meta-row">
          <dt>Halaman</dt>
          <dd>{len(result.pages_scanned)}</dd>
        </div>
        <div class="meta-row">
          <dt>Mulai</dt>
          <dd>{esc(result.started_at)}</dd>
        </div>
        <div class="meta-row">
          <dt>Selesai</dt>
          <dd>{esc(result.finished_at)}</dd>
        </div>
      </dl>
    </section>

    <section class="status-strip" aria-label="Ringkasan hasil">
      <div class="status-copy">
        <div class="status-label {esc(state_class)}">{esc(state_title)}</div>
        <p>{esc(state_text)}</p>
      </div>

      <div class="metric">
        <strong>{counts.get("HIGH", 0)}</strong>
        <span>Prioritas tinggi</span>
      </div>
      <div class="metric">
        <strong>{counts.get("MEDIUM", 0)}</strong>
        <span>Perlu ditinjau</span>
      </div>
      <div class="metric">
        <strong>{counts.get("LOW", 0)}</strong>
        <span>Peningkatan</span>
      </div>
      <div class="metric">
        <strong>{counts.get("INFO", 0)}</strong>
        <span>Informasi</span>
      </div>
    </section>

    <div class="layout">
      <aside class="aside" aria-label="Prioritas dan navigasi">
        <div>
          <h2>Mulai dari sini</h2>
          <ol class="priority-list">
            {priority_html}
          </ol>
        </div>

        <nav class="aside-nav">
          <h2>Isi laporan</h2>
          <a href="#findings">Semua temuan</a>
          <a href="#disclosure">Responsible disclosure</a>
          <a href="#limitations">Batasan scanner</a>
        </nav>
      </aside>

      <div class="content">
        <section id="findings">
          <div class="section-head">
            <div>
              <h2>Temuan</h2>
              <p>
                Gunakan pencarian atau filter untuk mempersempit hasil.
                Buka “Detail teknis” hanya saat Anda membutuhkannya.
              </p>
            </div>
          </div>

          <div class="toolbar" aria-label="Filter temuan">
            <input
              id="finding-search"
              class="search"
              type="search"
              placeholder="Cari judul, kategori, URL, atau finding ID"
              aria-label="Cari temuan"
            >
            <div class="filters" role="group" aria-label="Filter severity">
              <button class="filter active" type="button" data-filter="ALL">Semua</button>
              <button class="filter" type="button" data-filter="HIGH">High</button>
              <button class="filter" type="button" data-filter="MEDIUM">Medium</button>
              <button class="filter" type="button" data-filter="LOW">Low</button>
              <button class="filter" type="button" data-filter="INFO">Info</button>
            </div>
          </div>

          <div id="finding-list" class="finding-list">
            {''.join(finding_rows) if finding_rows else '<div class="finding"><h3>Tidak ada temuan</h3><p>Checks yang dijalankan tidak menghasilkan finding.</p></div>'}
          </div>

          <div id="empty-result" class="empty-result">
            Tidak ada temuan yang cocok dengan filter ini.
          </div>
        </section>

        <section id="disclosure" class="support-section">
          <h2>Responsible disclosure</h2>
          <p>
            Jika Anda mengaudit website milik pihak lain dengan izin,
            gunakan kontak dan policy resmi target sebelum mengirim laporan.
          </p>

          <div class="support-grid">
            <div>
              <h3>security.txt</h3>
              <ul class="clean-list">
                <li>{esc(sec.get("url") or "Tidak ditemukan")}</li>
              </ul>
            </div>
            <div>
              <h3>Kontak</h3>
              <ul class="clean-list">{contacts}</ul>
            </div>
            <div>
              <h3>Policy</h3>
              <ul class="clean-list">{policies}</ul>
            </div>
          </div>
        </section>

        <section id="limitations" class="support-section">
          <h2>Batasan scanner</h2>
          <p>
            WebGuard v{esc(result.version)} adalah scanner non-destruktif.
            Hasil perlu divalidasi sebelum dianggap sebagai kerentanan yang exploitable.
          </p>
          <ul class="clean-list">
            {errors}
          </ul>
        </section>

        <footer class="footer">
          <strong>WebGuard v{esc(result.version)}</strong><br>
          Generated for authorized, non-destructive security assessment.
        </footer>
      </div>
    </div>
  </div>
</main>

<script>
(() => {{
  const search = document.getElementById("finding-search");
  const buttons = Array.from(document.querySelectorAll(".filter"));
  const findings = Array.from(document.querySelectorAll(".finding[data-severity]"));
  const empty = document.getElementById("empty-result");

  let activeSeverity = "ALL";

  function applyFilters() {{
    const q = (search.value || "").trim().toLowerCase();
    let visible = 0;

    for (const item of findings) {{
      const severityOK = activeSeverity === "ALL" || item.dataset.severity === activeSeverity;
      const searchOK = !q || (item.dataset.search || "").includes(q);
      const show = severityOK && searchOK;
      item.hidden = !show;
      if (show) visible += 1;
    }}

    empty.style.display = visible === 0 ? "block" : "none";
  }}

  buttons.forEach((button) => {{
    button.addEventListener("click", () => {{
      activeSeverity = button.dataset.filter;
      buttons.forEach((b) => b.classList.toggle("active", b === button));
      applyFilters();
    }});
  }});

  search.addEventListener("input", applyFilters);
}})();
</script>
</body>
</html>
"""
    Path(path).write_text(html_doc, encoding="utf-8")
