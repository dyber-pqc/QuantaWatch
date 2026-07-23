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

$destExe = Join-Path $InstallDir "quantawatch.exe"
$srcHash = (Get-FileHash $exe).Hash

# Copy the exe and VERIFY it actually replaced the old one. A running/locked
# target can leave the old binary in place while Copy-Item appears to succeed,
# silently deploying a stale build. Retry, then fail loudly on a hash mismatch
# instead of printing a false "Deployed".
$copied = $false
for ($i = 1; $i -le 5 -and -not $copied; $i++) {
  try {
    Copy-Item $exe $destExe -Force -ErrorAction Stop
  } catch {
    Write-Warning "copy attempt $i failed: $($_.Exception.Message)"
    Start-Sleep -Milliseconds 750
    continue
  }
  if ((Get-FileHash $destExe).Hash -eq $srcHash) { $copied = $true }
  else { Start-Sleep -Milliseconds 750 }
}
if (-not $copied) {
  throw "Failed to update $destExe - it does not match the source build. The old process may still hold the file locked; stop the service and retry."
}

Remove-Item (Join-Path $InstallDir "dashboard") -Recurse -Force -ErrorAction SilentlyContinue
Copy-Item $dist (Join-Path $InstallDir "dashboard") -Recurse -Force

Start-Service $ServiceName
Start-Sleep -Seconds 8

$bytes = (Get-Item $destExe).Length
Write-Host "Deployed & verified. exe = $bytes bytes (hash matches source build)"
try {
  $code = (Invoke-WebRequest "http://127.0.0.1:9091/" -UseBasicParsing -TimeoutSec 8).StatusCode
  Write-Host "Dashboard: http://localhost:9091  (HTTP $code)  - hard-refresh with Ctrl+F5"
} catch { Write-Warning "Service started but the dashboard did not answer: $_" }
