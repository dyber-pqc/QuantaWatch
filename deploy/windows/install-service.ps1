<#
.SYNOPSIS
  Install QuantaWatch as a Windows service. Run from an ELEVATED PowerShell.

.DESCRIPTION
  Standard Windows layout:
    * binary  -> C:\Program Files\QuantaWatch   (admin-writable only, so a
                 non-admin cannot swap the exe of a service)
    * state   -> C:\ProgramData\QuantaWatch     (config, data/, keys/, audit/, logs)

  The service runs as the per-service VIRTUAL ACCOUNT "NT SERVICE\QuantaWatch":
  Windows creates and manages it, there is no password to leak, and it is far
  less privileged than LocalSystem - it can only touch what it is granted.
  Pass -Account LocalSystem to fall back to the old behaviour.

  The service anchors its working directory to the config's directory, so the
  relative paths in quantawatch.yaml (./data, ./keys, ./audit) resolve there
  rather than under C:\Windows\System32.

.EXAMPLE
  .\install-service.ps1
  .\install-service.ps1 -Account LocalSystem
#>
[CmdletBinding()]
param(
  [string]$SourceExe   = "$PSScriptRoot\..\..\target\release\quantawatch.exe",
  [string]$InstallDir  = 'C:\Program Files\QuantaWatch',
  [string]$StateDir    = 'C:\ProgramData\QuantaWatch',
  [string]$ServiceName = 'QuantaWatch',
  [string]$Account     = ''      # empty => virtual account NT SERVICE\<ServiceName>
)

$ErrorActionPreference = 'Stop'

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw "This script must be run from an elevated (Administrator) PowerShell."
}
if (-not (Test-Path $SourceExe)) {
  throw "Release binary not found at '$SourceExe'. Build it: cargo build --release -p qw-gateway"
}
if (-not (Test-Path "$StateDir\quantawatch.yaml")) {
  throw "No config at '$StateDir\quantawatch.yaml'. Copy quantawatch.yaml (plus data/, keys/, audit/) there first."
}

$svcAccount = if ($Account) { $Account } else { "NT SERVICE\$ServiceName" }

# --- remove any previous install -------------------------------------------
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
  Write-Host "Removing existing service..."
  sc.exe stop $ServiceName  2>&1 | Out-Null
  Start-Sleep -Seconds 2
  sc.exe delete $ServiceName 2>&1 | Out-Null
  Start-Sleep -Seconds 2
}
Get-Process quantawatch -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 1

# --- binary -----------------------------------------------------------------
New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
Copy-Item $SourceExe "$InstallDir\quantawatch.exe" -Force
Write-Host "Binary installed: $InstallDir\quantawatch.exe"

# --- register (creates the virtual account) ---------------------------------
# Registration happens BEFORE the ACL grant so the NT SERVICE\<name> SID exists.
& "$InstallDir\quantawatch.exe" service install "$StateDir\quantawatch.yaml" $svcAccount
if ($LASTEXITCODE -ne 0) { throw "service install failed (exit $LASTEXITCODE)" }

# --- state dir permissions --------------------------------------------------
# ProgramData grants BUILTIN\Users read+write by default. keys\ holds the CA
# signing key and the ML-DSA gateway seed, so strip Users and grant only the
# service account (Modify) plus SYSTEM/Administrators.
#
# NOTE: remove the Users ACE specifically - do NOT use "/inheritance:r /T",
# which strips inherited ACEs from every child and can leave files with an
# EMPTY DACL that nothing (not even Administrators) can open.
icacls $StateDir /inheritance:d /C /Q | Out-Null                       # inherited -> explicit
icacls $StateDir /remove:g '*S-1-5-32-545' /T /C /Q | Out-Null          # BUILTIN\Users
icacls $StateDir /grant "${svcAccount}:(OI)(CI)M" /T /C /Q | Out-Null   # service account
icacls $StateDir /grant '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' /T /C /Q | Out-Null
Write-Host "State dir hardened: $StateDir (service account + SYSTEM + Administrators)"

# Sanity-check that we did not lock ourselves out again.
try { [void](Get-Content "$StateDir\quantawatch.yaml" -Raw -ErrorAction Stop) }
catch { throw "Config became unreadable after the ACL step - aborting: $_" }

# --- auto-restart so it genuinely stays up ----------------------------------
sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/5000/restart/30000 | Out-Null
sc.exe failureflag $ServiceName 1 | Out-Null   # restart on non-zero exit too, not just crashes

# --- start + verify ---------------------------------------------------------
sc.exe start $ServiceName | Out-Null
Start-Sleep -Seconds 8

$svc = Get-Service -Name $ServiceName
Write-Host "`nService '$ServiceName' is $($svc.Status) (StartType: $($svc.StartType))"
Write-Host "Running as: $((Get-CimInstance Win32_Service -Filter "Name='$ServiceName'").StartName)"
try {
  $code = (Invoke-WebRequest -Uri 'http://127.0.0.1:9091/api/health' -UseBasicParsing -TimeoutSec 10).StatusCode
  Write-Host "Admin API health: $code"
} catch {
  Write-Warning "Service started but the admin API did not answer: $_"
  Write-Warning "Check $StateDir\quantawatch-service.log"
}
Write-Host "`nLogs:   $StateDir\quantawatch-service.log"
Write-Host "Stop:   sc.exe stop $ServiceName"
Write-Host "Remove: `"$InstallDir\quantawatch.exe`" service uninstall"
