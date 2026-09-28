$ErrorActionPreference = "Stop"

Write-Host "WebGuard v0.1 Setup" -ForegroundColor Cyan

if (-not (Get-Command py -ErrorAction SilentlyContinue) -and -not (Get-Command python -ErrorAction SilentlyContinue)) {
    throw "Python 3.10+ tidak ditemukan. Install Python lalu jalankan setup lagi."
}

$PythonCmd = if (Get-Command py -ErrorAction SilentlyContinue) { "py" } else { "python" }

& $PythonCmd -m venv .venv
& .\.venv\Scripts\python.exe -m pip install --upgrade pip
& .\.venv\Scripts\python.exe -m pip install -e .

Write-Host ""
Write-Host "Instalasi selesai." -ForegroundColor Green
Write-Host "Aktifkan dengan:"
Write-Host ".\.venv\Scripts\Activate.ps1"
Write-Host ""
Write-Host "Lalu jalankan:"
Write-Host "webguard wizard"
