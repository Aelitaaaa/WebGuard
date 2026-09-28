# WebGuard v0.1

WebGuard adalah scanner keamanan website untuk **authorized security assessment**. Versi **v0.1.1** adalah rilis awal yang sudah dapat digunakan, tetapi proyek masih aktif dikembangkan. Fokus utamanya adalah aman, dapat diaudit, mudah dipahami, dan menghasilkan temuan yang berguna untuk perbaikan.

## Prinsip keamanan

- hanya target yang Anda konfirmasi memiliki izin
- crawler same-origin secara default
- host tambahan harus dicantumkan eksplisit
- rate limit
- batas halaman
- GET sebagai metode utama
- tidak brute force
- tidak login otomatis
- tidak mengunggah file
- tidak mengubah / menghapus data
- tidak mengirim payload SQL injection, command injection, SSRF, RCE, atau file inclusion
- link berisiko seperti logout/delete/remove/reset tidak diikuti crawler
- optional safe-active check hanya melakukan request benign untuk memeriksa kebijakan CORS

## Fitur

### Web security baseline
- HTTPS / TLS
- masa berlaku sertifikat
- HSTS
- CSP
- clickjacking protection
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy
- Server / X-Powered-By exposure
- cookie Secure / HttpOnly / SameSite
- mixed content
- form sensitif melalui HTTP
- password form dengan target HTTP
- debug / stack-trace disclosure pasif
- CORS header assessment
- optional benign CORS reflection check

### Domain posture
- DNS A / AAAA
- CAA
- SPF
- DMARC

### Responsible disclosure
- /.well-known/security.txt
- /security.txt
- Contact
- Policy

### Reporting
- terminal summary
- JSON
- HTML profesional
- finding deduplication
- severity
- evidence
- impact
- remediation
- confidence
- scan metadata

### Ease of use
- interactive wizard
- Tkinter GUI
- Windows setup PowerShell
- one-command scan
- config JSON

## Instalasi Windows

Ekstrak ZIP, lalu:

```powershell
cd WebGuard_Final
powershell -ExecutionPolicy Bypass -File .\setup.ps1
```

Aktifkan environment:

```powershell
.\.venv\Scripts\Activate.ps1
```

## Cara termudah

Wizard:

```powershell
webguard wizard
```

GUI:

```powershell
webguard gui
```

Cek instalasi:

```powershell
webguard doctor
```

CLI:

```powershell
webguard scan https://example.com --authorized
```

Dengan laporan otomatis:

```powershell
webguard scan https://example.com --authorized --report-dir reports
```

Safe-active CORS check:

```powershell
webguard scan https://example.com --authorized --safe-active
```

Host tambahan yang memang masuk scope:

```powershell
webguard scan https://example.com --authorized --scope-host api.example.com --scope-host static.example.com
```

## Contoh config

```json
{
  "max_pages": 10,
  "delay": 0.8,
  "timeout": 12,
  "respect_robots": true,
  "safe_active": false,
  "scope_hosts": []
}
```

Gunakan:

```powershell
webguard scan https://example.com --authorized --config webguard.json
```

## Severity

- HIGH: kontrol utama gagal atau ada indikasi kuat risiko besar
- MEDIUM: kelemahan konfigurasi penting / indikasi yang perlu validasi
- LOW: hardening gap / defense in depth
- INFO: informasi audit

Tidak semua finding adalah vulnerability yang exploitable. Validasi manual tetap diperlukan sebelum mengirim laporan ke pemilik sistem.

## Batasan sengaja

WebGuard v0.1 tidak mengeksploitasi SQLi, XSS, IDOR/BOLA, auth bypass, SSRF, RCE, deserialization, command injection, file upload, atau business logic. Pengujian tersebut memerlukan scope dan prosedur yang lebih ketat daripada baseline scanner otomatis.


## Status rilis

**Current release: v0.1.1**

WebGuard masih berada pada fase pengembangan awal. Format `0.x` dipakai agar perubahan arsitektur, rule, tampilan, dan format report masih dapat berkembang sebelum menuju `1.0`.

Target pengembangan berikutnya antara lain:

- provider-aware DNS checks
- technology/CMS fingerprinting pasif
- better false-positive handling
- finding lifecycle: NEW / OPEN / FIXED / NOT APPLICABLE
- baseline dan scan comparison
- source-code scan untuk repository milik sendiri
- SARIF / CI integration
- guided remediation berdasarkan framework/hosting
- dashboard history dan retest workflow

## Filosofi proyek

WebGuard tidak mengejar jumlah finding sebanyak mungkin. Tujuannya adalah menghasilkan temuan yang:

1. relevan terhadap target,
2. memiliki evidence,
3. mudah dimengerti,
4. tidak melebih-lebihkan dampak,
5. memberikan remediation yang dapat dilakukan,
6. tetap berada dalam scope pengujian yang diizinkan.


## Bantuan di terminal

WebGuard memiliki help center bawaan:

```powershell
webguard help
```

Lihat semua command:

```powershell
webguard commands
```

Bantuan khusus:

```powershell
webguard help scan
webguard help wizard
webguard help gui
webguard help doctor
webguard help reports
webguard help safety
```

Jika `webguard` dijalankan tanpa command, daftar command utama akan ditampilkan otomatis.



## Design note

The HTML report redesign in v0.1.1 was informed by the public design-audit principles in
Leonxlnx/taste-skill, especially its guidance on reducing generic card-heavy layouts,
improving hierarchy, restrained color, readable typography, and redesigning existing UI
without changing product behavior. WebGuard's report implementation remains standalone
and dependency-free.
