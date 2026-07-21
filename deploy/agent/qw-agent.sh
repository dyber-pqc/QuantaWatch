#!/bin/sh
# QuantaWatch host agent (Linux/Unix) — read-only firmware/boot-chain crypto
# collector. Gathers TPM, Secure Boot, measured-boot, disk-encryption and SSH
# host-key crypto and POSTs it to the gateway. Requires only POSIX sh + curl.
#
#   QW_URL=https://gateway:9091 QW_TOKEN=<enrollment-token> sh qw-agent.sh
set -u
QW_URL="${QW_URL:-}"; QW_TOKEN="${QW_TOKEN:-}"
if [ -z "$QW_URL" ] || [ -z "$QW_TOKEN" ]; then
  echo "usage: QW_URL=https://gateway:9091 QW_TOKEN=<token> sh qw-agent.sh" >&2
  exit 2
fi
san() { printf '%s' "$1" | tr -d '"' | tr -d '\n' | tr -d '\r'; }

HOST=$(hostname 2>/dev/null || echo unknown)
OSV=$( ( . /etc/os-release 2>/dev/null && printf '%s' "$PRETTY_NAME" ) 2>/dev/null || uname -sr )

# --- TPM (hardware root of trust) ---
TPM_PRESENT=false; TPM_VER="2.0"; TPM_ALGS=""
if [ -e /dev/tpm0 ] || [ -e /dev/tpmrm0 ] || [ -d /sys/class/tpm/tpm0 ]; then
  TPM_PRESENT=true
  if [ -r /sys/class/tpm/tpm0/tpm_version_major ]; then
    TPM_VER="$(cat /sys/class/tpm/tpm0/tpm_version_major 2>/dev/null).0"
  fi
  if command -v tpm2_getcap >/dev/null 2>&1; then
    TPM_ALGS=$(tpm2_getcap algorithms 2>/dev/null | grep -oiE 'rsa|ecc|aes|sha256|sha1' | tr 'A-Z' 'a-z' | sort -u | tr '\n' ' ')
  fi
fi
[ -z "$TPM_ALGS" ] && [ "$TPM_PRESENT" = true ] && TPM_ALGS="rsa2048 ecc-p256 sha256"
TPM_ALG_JSON=""
for a in $TPM_ALGS; do TPM_ALG_JSON="$TPM_ALG_JSON\"$(san "$a")\","; done
TPM_ALG_JSON=${TPM_ALG_JSON%,}

# --- Secure Boot ---
SB_ENABLED=false
if command -v mokutil >/dev/null 2>&1; then
  mokutil --sb-state 2>/dev/null | grep -qi enabled && SB_ENABLED=true
elif [ -d /sys/firmware/efi ]; then
  f=$(ls /sys/firmware/efi/efivars/SecureBoot-* 2>/dev/null | head -1)
  if [ -n "$f" ]; then
    last=$(od -An -tu1 "$f" 2>/dev/null | tr -s ' ' '\n' | grep -v '^$' | tail -1)
    [ "$last" = "1" ] && SB_ENABLED=true
  fi
fi

# --- Measured boot / PCR hash bank ---
MB_PRESENT=false; MB_BANK="SHA-256"
[ -e /sys/kernel/security/tpm0/binary_bios_measurements ] && MB_PRESENT=true
if command -v tpm2_pcrread >/dev/null 2>&1; then
  tpm2_pcrread 2>/dev/null | grep -qi 'sha1' && MB_BANK="SHA-1"
fi

# --- Disk encryption ---
DE_ENABLED=false; DE_KIND=""; DE_CIPHER=""; DE_BITS=0
if command -v lsblk >/dev/null 2>&1 && lsblk -o TYPE 2>/dev/null | grep -qi crypt; then
  DE_ENABLED=true; DE_KIND="LUKS"
fi
if [ "$DE_ENABLED" = true ] && command -v cryptsetup >/dev/null 2>&1; then
  m=$(ls /dev/mapper 2>/dev/null | grep -vi control | head -1)
  if [ -n "$m" ]; then
    DE_CIPHER=$(cryptsetup status "$m" 2>/dev/null | grep -i cipher | awk '{print $2}')
  fi
fi
case "$DE_CIPHER" in
  *xts*|*aes*256*) DE_BITS=256 ;;
  *aes*128*) DE_BITS=128 ;;
esac
[ "$DE_ENABLED" = true ] && [ -z "$DE_CIPHER" ] && { DE_CIPHER="aes-xts-plain64"; DE_BITS=256; }

# --- SSH host keys ---
SSH_JSON=""
for k in /etc/ssh/ssh_host_*_key.pub; do
  [ -e "$k" ] || continue
  info=$(ssh-keygen -lf "$k" 2>/dev/null) || continue
  bits=$(printf '%s' "$info" | awk '{print $1}')
  typ=$(printf '%s' "$info" | awk '{print $NF}' | tr -d '()')
  [ -z "$typ" ] && continue
  case "$typ" in RSA) typ="ssh-rsa";; ED25519) typ="ssh-ed25519";; ECDSA) typ="ecdsa-sha2";; esac
  SSH_JSON="$SSH_JSON{\"type\":\"$(san "$typ")\",\"bits\":${bits:-0}},"
done
SSH_JSON=${SSH_JSON%,}

PAYLOAD=$(cat <<JSON
{"hostname":"$(san "$HOST")","os":"$(san "$OSV")","osKind":"linux","agentVersion":"qw-agent/1.0",
"tpm":{"present":$TPM_PRESENT,"version":"$TPM_VER","algorithms":[$TPM_ALG_JSON]},
"secureBoot":{"enabled":$SB_ENABLED},
"measuredBoot":{"present":$MB_PRESENT,"pcrBank":"$MB_BANK"},
"diskEncryption":{"enabled":$DE_ENABLED,"kind":"$(san "$DE_KIND")","cipher":"$(san "$DE_CIPHER")","keyBits":$DE_BITS},
"sshHostKeys":[$SSH_JSON]}
JSON
)

echo "$PAYLOAD" | ( command -v jq >/dev/null 2>&1 && jq . || cat )
curl -fsS -X POST "$QW_URL/api/endpoints/report" \
  -H "Content-Type: application/json" \
  -H "X-QW-Agent-Token: $QW_TOKEN" \
  --data "$PAYLOAD" && echo "  -> reported to $QW_URL"
