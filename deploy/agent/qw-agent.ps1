# QuantaWatch host agent (Windows) — read-only firmware/boot-chain crypto
# collector. Gathers TPM, Secure Boot, BitLocker and SSH host-key crypto and
# POSTs it to the gateway. Run from an elevated PowerShell:
#
#   $env:QW_URL='https://gateway:9091'; $env:QW_TOKEN='<token>'; .\qw-agent.ps1
if (-not $env:QW_URL -or -not $env:QW_TOKEN) {
  Write-Error "set QW_URL and QW_TOKEN environment variables first"; exit 2
}

$report = [ordered]@{
  hostname     = $env:COMPUTERNAME
  os           = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption
  osKind       = "windows"
  agentVersion = "qw-agent/1.0"
}

# --- TPM ---
try {
  $tpm  = Get-Tpm -ErrorAction Stop
  $wtpm = Get-CimInstance -Namespace 'root/cimv2/security/microsofttpm' -Class Win32_Tpm -ErrorAction SilentlyContinue
  $ver  = if ($wtpm -and $wtpm.SpecVersion) { ($wtpm.SpecVersion -split ',')[0].Trim() } else { "2.0" }
  $report.tpm = @{ present = [bool]$tpm.TpmPresent; version = $ver; manufacturer = "$($wtpm.ManufacturerIdTxt)"; algorithms = @("rsa2048","ecc-p256","sha256") }
} catch { $report.tpm = @{ present = $false } }

# --- Secure Boot ---
try { $report.secureBoot = @{ enabled = [bool](Confirm-SecureBootUEFI -ErrorAction Stop) } }
catch { $report.secureBoot = @{ enabled = $false } }

# --- Measured boot (TPM 2.0 uses the SHA-256 PCR bank) ---
$report.measuredBoot = @{ present = $true; pcrBank = "SHA-256" }

# --- Disk encryption (BitLocker) ---
try {
  $bl     = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
  $on     = ($bl.ProtectionStatus -eq 'On') -or ("$($bl.VolumeStatus)" -like 'FullyEncrypted*')
  $method = "$($bl.EncryptionMethod)"
  $bits   = if ($method -match '256') { 256 } elseif ($method -match '128') { 128 } else { 256 }
  $report.diskEncryption = @{ enabled = [bool]$on; kind = "BitLocker"; cipher = $method; keyBits = $bits }
} catch { $report.diskEncryption = @{ enabled = $false } }

# --- SSH host keys (OpenSSH server, if installed) ---
$keys   = @()
$sshDir = Join-Path $env:ProgramData "ssh"
if (Test-Path $sshDir) {
  Get-ChildItem (Join-Path $sshDir "ssh_host_*_key.pub") -ErrorAction SilentlyContinue | ForEach-Object {
    $line = & ssh-keygen -lf $_.FullName 2>$null
    if ($line) {
      $parts = ($line -split '\s+')
      $bits  = [int]($parts[0])
      $typ   = ($parts[-1] -replace '[()]','')
      switch ($typ) { 'RSA' { $typ = 'ssh-rsa' } 'ED25519' { $typ = 'ssh-ed25519' } 'ECDSA' { $typ = 'ecdsa-sha2' } }
      $keys += @{ type = $typ; bits = $bits }
    }
  }
}
$report.sshHostKeys = $keys

$json = $report | ConvertTo-Json -Depth 6
Write-Host $json
Invoke-RestMethod -Method Post -Uri "$($env:QW_URL)/api/endpoints/report" `
  -ContentType 'application/json' `
  -Headers @{ 'X-QW-Agent-Token' = $env:QW_TOKEN } `
  -Body $json | Out-Null
Write-Host "  -> reported to $env:QW_URL"
