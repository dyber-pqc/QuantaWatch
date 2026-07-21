# QuantaWatch host agent

A tiny, read-only collector that reports a host's **firmware / boot-chain
crypto** — the TPM, Secure Boot, measured-boot PCR bank, disk encryption, and
SSH host keys — which no network or SSH scan can see. It POSTs the inventory to
the gateway, which classifies its post-quantum posture.

## Enroll

In the dashboard: **Endpoints → Enroll agent** to get the enrollment token, or:

    curl -H "Authorization: Bearer <admin-token>" https://<gateway>:9091/api/endpoints/enroll

## Run

Linux/Unix (POSIX sh + curl):

    QW_URL=https://<gateway>:9091 QW_TOKEN=<token> sh qw-agent.sh

Windows (elevated PowerShell):

    $env:QW_URL='https://<gateway>:9091'; $env:QW_TOKEN='<token>'; .\qw-agent.ps1

Schedule it (cron / Task Scheduler) to keep posture current. The token grants
report-only access — it cannot read or change anything else.
