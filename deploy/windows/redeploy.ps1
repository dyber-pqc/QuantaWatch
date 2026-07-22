<#
.SYNOPSIS
  Redeploy the already-built QuantaWatch binary + dashboard to the running
  service. Run from an ELEVATED PowerShell after `cargo build --release
  -p qw-gateway` and `npm run build` (or let CI build them).

  This is the "I just want to see my changes" script: stop -> wait -> copy -> start.
#>
[CmdletBinding()]
param(
  [string]$Repo = "H:\quantawatch",
  [string]$InstallDir = "C:\Program Files\QuantaWatch",
  [string]$ServiceName = "QuantaWatch"
)
$ErrorActionPreference = "Stop"

$exe  = Join-Path $Repo "target\release\quantawatch.exe"
$dist = Join-Path $Repo "dashboard\dist"
if (-not (Test-Path $exe))  { throw "Missing $exe - run: cargo build --release -p qw-gateway" }
if (-not (Test-Path (Join-Path $dist 'index.html'))) { throw "Missing dashboard build - run: (cd dashboard) npm run build" }

Write-Host "Stopping $ServiceName..."
Stop-Service $ServiceName -Force -ErrorAction SilentlyContinue
$deadline = (Get-Date).AddSeconds(30)
while ((Get-Process quantawatch -ErrorAction SilentlyContinue) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 500 }
if (Get-Process quantawatch -ErrorAction SilentlyContinue) { throw "quantawatch.exe still running; close it and retry." }

Copy-Item $exe (Join-Path $InstallDir "quantawatch.exe") -Force
Remove-Item (Join-Path $InstallDir "dashboard") -Recurse -Force -ErrorAction SilentlyContinue
Copy-Item $dist (Join-Path $InstallDir "dashboard") -Recurse -Force

Start-Service $ServiceName
Start-Sleep -Seconds 8

$bytes = (Get-Item (Join-Path $InstallDir "quantawatch.exe")).Length
Write-Host "Deployed. exe = $bytes bytes"
try {
  $code = (Invoke-WebRequest "http://127.0.0.1:9091/" -UseBasicParsing -TimeoutSec 8).StatusCode
  Write-Host "Dashboard: http://localhost:9091  (HTTP $code)  - hard-refresh with Ctrl+F5"
} catch { Write-Warning "Service started but the dashboard did not answer: $_" }
