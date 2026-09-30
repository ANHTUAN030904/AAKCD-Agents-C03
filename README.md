# AAKCD — Agentic AI-Based Cyber Kill Chain Defence

A multi-agent detection framework where five AI agents, one per Cyber Kill
Chain phase, detect attacks on a monitored host and report them into a Wazuh
SIEM, mapped to MITRE ATT&CK. A Coordinator agent correlates the individual
findings into a single, connected attack narrative.

This repository is my individual lab setup and implementation for the UTS
Cybersecurity Capstone project (Team C03, Antaeus AI), building on the prior
SNSHD prototype.

## The five agents

| Agent | Kill-chain phase | MITRE technique | Telemetry |
|-------|-----------------|-----------------|-----------|
| Recon | Reconnaissance | T1046 | Live nmap scan |
| Delivery | Delivery | T1566.002 | Email sample |
| Exploitation | Exploitation | T1027 | Command sample |
| Installation | Installation | T1053.003 | Live crontab (SSH) |
| C2 | Command & Control | T1071.001 | Live connections (SSH) |

Detection is LLM-assisted: each agent collects telemetry, reasons over it, and
emits a structured JSON alert (technique, tactic, severity, evidence,
recommended action).

## Components

- `agents/` — the five detection agents plus the Coordinator and shared base
- `agents/remote.py` — remote telemetry collection over SSH
- `scheduler.py` — runs all five agents in parallel on a fixed interval
- `mark_attack.py` / `report_mttd.py` — attack marking and MTTD measurement
- `format_report.py` — human-readable kill-chain report from the JSON logs
- `wazuh/` — Wazuh rules and log-monitoring config
- `schema/` — the alert schema

## Lab environment

Four VMs on an isolated network: a Wazuh manager (SIEM), an agent host
(runs the agents), a victim, and a Kali attacker. Attacks are generated with
Atomic Red Team.

## Results (single test session)

- 5 of 5 kill-chain phases detected
- Mean time-to-detect (MTTD): ~15 seconds at a 30-second polling interval
- Coordinator successfully correlated the five detections into one attack story

See `mttd_results.txt` and `full_attack_report.txt` for the detailed output.

## Setup

```bash
python3.12 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
# set GROQ_API_KEY in a .env file (not committed)
export AAKCD_VICTIM_HOST=<victim-ip> AAKCD_VICTIM_USER=<victim-user>
python scheduler.py --target <victim-ip> --interval 30 --stagger 4
```

## Notes

- Requires Python 3.10–3.13 (CrewAI does not yet support 3.14).
- The API key is read from `.env` and is never committed.
- Live audit-log collection over SSH proved unreliable on Ubuntu 26.04, so the
  Exploitation agent uses representative samples; this is documented as a
  limitation.

## Status

The independent-agent baseline (agents running in parallel with post-hoc
correlation) is complete and measured. The feed-forward escalation-cue
mechanism — where early-phase detections pre-arm later agents to reduce
detection time — is planned as the next phase.
