"""Human-readable AAKCD report from the JSON alert logs (presentation only)."""
from __future__ import annotations
import argparse, json
from pathlib import Path

AGENT_LOGS = [
    ("Reconnaissance", "recon_alerts.jsonl"),
    ("Delivery",       "delivery_alerts.jsonl"),
    ("Exploitation",   "exploitation_alerts.jsonl"),
    ("Installation",   "installation_alerts.jsonl"),
    ("Command & Control", "c2_alerts.jsonl"),
]
COORD_LOG = "coordinator_alerts.jsonl"
WIDTH = 74

def latest_alert(path, host=None):
    p = Path(path)
    if not p.exists(): return None
    last = None
    with p.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try: rec = json.loads(line)
            except json.JSONDecodeError: continue
            if host and rec.get("target_host") != host: continue
            last = rec
    return last

def priority_label(sev):
    if sev >= 12: return "HIGH"
    if sev >= 7:  return "MEDIUM"
    if sev >= 1:  return "LOW"
    return "NONE"

def first_sentence(text):
    for sep in (". ", ".\n"):
        if sep in text: return text.split(sep)[0].strip() + "."
    return text.strip()

def wrap(text, width):
    words = text.split(); out, line = [], ""
    for w in words:
        if len(line) + len(w) + 1 > width:
            out.append(line); line = w
        else:
            line = (line + " " + w).strip()
    if line: out.append(line)
    return out or [""]

def render_alert(phase, rec):
    sev = rec.get("severity", 0); m = rec.get("mitre", {}); ag = rec.get("agent", {})
    L = []
    L.append("=" * WIDTH)
    L.append(f"[{priority_label(sev)}] {phase.upper()} ALERT  (severity {sev})")
    L.append("=" * WIDTH)
    L.append(f"Timestamp : {rec.get('@timestamp','-')}")
    L.append(f"Source    : {ag.get('ip','-')}  ->  target {rec.get('target_host','-')}")
    L.append(f"Agent     : {ag.get('name','-')}")
    L.append(f"Summary   : {first_sentence(rec.get('description',''))}")
    L.append("")
    L.append("MITRE ATT&CK")
    L.append(f"  Technique : {m.get('technique','-')}")
    L.append(f"  Tactic    : {m.get('tactic','-')}")
    L.append("")
    L.append("Details")
    for chunk in wrap(rec.get("description",""), WIDTH-2): L.append("  " + chunk)
    L.append("")
    L.append("Final Answer:")
    L.append(f"  - Category          : {rec.get('category','-')}")
    L.append(f"  - Confidence        : {rec.get('confidence','-')}")
    L.append(f"  - Severity          : {sev}")
    L.append(f"  - Recommended action: {rec.get('recommended_action','-')}")
    L.append("")
    return "\n".join(L)

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default=None)
    args = p.parse_args()
    out = []
    out.append("#" * WIDTH)
    out.append("#" + " AAKCD KILL-CHAIN DETECTION REPORT ".center(WIDTH-2) + "#")
    out.append("#" + " Antaeus AI (Team C03) ".center(WIDTH-2) + "#")
    out.append("#" * WIDTH); out.append("")
    detected = 0
    for phase, log in AGENT_LOGS:
        rec = latest_alert(log, args.host)
        if rec is None:
            out.append("=" * WIDTH)
            out.append(f"[NO DATA] {phase.upper()} ALERT")
            out.append("=" * WIDTH)
            out.append("  No alert found for this agent."); out.append("")
            continue
        if rec.get("severity",0) >= 1: detected += 1
        out.append(render_alert(phase, rec))
    coord = latest_alert(COORD_LOG, args.host)
    if coord:
        out.append("#" * WIDTH)
        out.append("#" + " CORRELATED KILL-CHAIN SUMMARY (Coordinator) ".center(WIDTH-2) + "#")
        out.append("#" * WIDTH)
        out.append(render_alert("Kill-Chain Correlation", coord))
    out.append("=" * WIDTH)
    out.append(f"Phases reporting a detection (severity >= 1): {detected} of 5")
    out.append("=" * WIDTH)
    print("\n".join(out))

if __name__ == "__main__":
    main()
