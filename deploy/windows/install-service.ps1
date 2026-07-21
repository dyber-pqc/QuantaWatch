<#
.SYNOPSIS
  Install QuantaWatch as a Windows service. Run from an ELEVATED PowerShell.

.DESCRIPTION
  Follows the standard Windows split:
    * binary  -> C:\Program Files\QuantaWatch   (admin-writable only, so a
                 non-admin cannot swap the exe of a SYSTEM service)
    * state   -> C:\ProgramData\QuantaWatch     (config, data/, keys/, audit/, logs)

  The service anchors its working directory to the config's directory, so the
  relative paths in quantawatch.yaml (./data, ./keys, ./audit) resolve there
  rather than under C:\Windows\System32.

.EXAMPLE
  .\install-service.ps1
  .\install-service.ps1 -SourceExe H:\quantawatch\target\release\quantawatch.exe
#>
[CmdletBinding()]
param(
  [string]$SourceExe = "$PSScriptRoot\..\..\target\release\quantawatch.exe",
  [string]$InstallDir = 'C:\Program Files\QuantaWatch',
  [string]$StateDir   = 'C:\ProgramData\QuantaWatch',
  [string]$ServiceName = 'QuantaWatch'
)

$ErrorActionPreference = 'Stop'

# --- must be elevated -------------------------------------------------------
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw "This script must be run from an elevated (Administrator) PowerShell."
}

if (-not (Test-Path $SourceExe)) {
  throw "Release binary not found at '$SourceExe'. Build it first: cargo build --release -p qw-gateway"
}
if (-not (Test-Path "$StateDir\quantawatch.yaml")) {
  throw "No config at '$StateDir\quantawatch.yaml'. Create the state dir and copy quantawatch.yaml (plus data/, keys/, audit/) there first."
}

# --- stop anything already running -----------------------------------------
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
  Write-Host "Existing service found - stopping and removing it first..."
  & "$InstallDir\quantawatch.exe" service uninstall 2>$null
  sc.exe delete $ServiceName 2>$null | Out-Null
  Start-Sleep -Seconds 2
}
Get-Process quantawatch -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 1

# --- install the binary to a stable, admin-only location --------------------
New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
Copy-Item $SourceExe "$InstallDir\quantawatch.exe" -Force
Write-Host "Binary installed: $InstallDir\quantawatch.exe"

# --- lock down the state dir (it holds the CA + gateway private keys) -------
# ProgramData grants BUILTIN\Users read+write by default; that would expose the
# CA signing key and the ML-DSA gateway seed to any local user.
icacls $StateDir /inheritance:r /T /C /Q | Out-Null
icacls $StateDir /grant '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' /T /C /Q | Out-Null
Write-Host "State dir hardened: $StateDir (SYSTEM + Administrators only)"

# --- register + start -------------------------------------------------------
& "$InstallDir\quantawatch.exe" service install "$StateDir\quantawatch.yaml"
if ($LASTEXITCODE -ne 0) { throw "service install failed (exit $LASTEXITCODE)" }

# Auto-restart so it genuinely stays up: 5s, 5s, then 30s; counter resets daily.
sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/5000/restart/30000 | Out-Null
# Also restart when the service stops with a non-zero exit code, not just on crash.
sc.exe failureflag $ServiceName 1 | Out-Null

sc.exe start $ServiceName | Out-Null
Start-Sleep -Seconds 6

# --- verify -----------------------------------------------------------------
$svc = Get-Service -Name $ServiceName
Write-Host "`nService '$ServiceName' is $($svc.Status) (StartType: $($svc.StartType))"
try {
  $code = (Invoke-WebRequest -Uri 'http://127.0.0.1:9091/api/health' -UseBasicParsing -TimeoutSec 10).StatusCode
  Write-Host "Admin API health: $code"
} catch {
  Write-Warning "Service started but the admin API did not answer: $_"
  Write-Warning "Check $StateDir\quantawatch-service.log"
}
Write-Host "`nLogs:  $StateDir\quantawatch-service.log"
Write-Host "Stop:  sc.exe stop $ServiceName"
Write-Host "Remove: `"$InstallDir\quantawatch.exe`" service uninstall"
