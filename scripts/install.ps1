<#
 UNITECH Security Center V3 - installer (Windows, NO elevation required).
 Creates a Python venv inside the V3 folder, installs pinned dependencies, builds the web UI, runs DB migrations
 and creates the first admin. It never touches Production V2 / Canary V2, PostgreSQL, Docker or key-rotation scripts.
 Usage:  powershell -ExecutionPolicy Bypass -File scripts\install.ps1 -ApprovedRoot D:\Security\TestProjects
#>
param([Parameter(Mandatory=$true)][string[]]$ApprovedRoot, [string]$DataDir = "$PSScriptRoot\..\data")
$ErrorActionPreference = "Stop"
$root = Resolve-Path "$PSScriptRoot\.."
Write-Host "== UNITECH V3 install in $root (user-level, no admin rights)"
if (-not (Get-Command python -ErrorAction SilentlyContinue)) { throw "Python 3.11+ is required (install it yourself; this script will not elevate)." }
python -m venv "$root\.venv"
& "$root\.venv\Scripts\python.exe" -m pip install --upgrade pip
& "$root\.venv\Scripts\python.exe" -m pip install -r "$root\backend\requirements.txt"
if (Get-Command npm -ErrorAction SilentlyContinue) {
  Push-Location "$root\frontend"; npm ci --no-audit --no-fund; npm run build; Pop-Location
} else { Write-Warning "Node.js not found: skipping web build. Copy a prebuilt frontend\dist or install Node 20+." }
$env:UNITECH_V3_DATA_DIR = (New-Item -ItemType Directory -Force $DataDir).FullName
$env:PYTHONPATH = "$root\backend;$root\agent"
Push-Location "$root\backend"
& "$root\.venv\Scripts\python.exe" -m unitech_v3.cli migrate
Pop-Location
Write-Host "== Done. Start with: powershell -File scripts\start.ps1 -ApprovedRoot $($ApprovedRoot -join ',')"
Write-Host "   The first start prints the one-time admin password (change it at first login)."
