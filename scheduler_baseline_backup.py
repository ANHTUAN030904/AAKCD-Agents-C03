"""AAKCD baseline scheduler (Stage 3E). Runs all five detection agents
against the victim on a fixed interval, in parallel, then correlates.
Records per-cycle timing and severities to scheduler_cycles.jsonl, and
writes an explicit error-alert to agent_errors.jsonl when an agent crashes
(so a failure is distinguishable from a genuine no-detection). This is the
cue-DISABLED baseline."""

from __future__ import annotations
import argparse, json, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from agents.recon_agent import ReconAgent
from agents.delivery_agent import DeliveryAgent
from agents.exploitation_agent import ExploitationAgent
from agents.installation_agent import InstallationAgent
from agents.c2_agent import C2Agent
from schema.alert_schema import Alert, MitreMapping, write_alert

AGENTS = [
    ("recon",        ReconAgent,        "network_recon",             "010", "T1046",     "Discovery"),
    ("delivery",     DeliveryAgent,     "email_phishing",            "020", "T1566.002", "Initial Access"),
    ("exploitation", ExploitationAgent, "obfuscated_execution",      "030", "T1027",     "Defense Evasion"),
    ("installation", InstallationAgent, "scheduled_task_persistence","040", "T1053.003", "Persistence"),
    ("c2",           C2Agent,           "c2_beaconing",              "050", "T1071.001", "Command and Control"),
]
CYCLE_LOG = "scheduler_cycles.jsonl"
ERROR_LOG = "agent_errors.jsonl"

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def _write_error_alert(name, category, technique, tactic, agent_id, target, agent_ip, err):
    alert = Alert(
        agent_id=agent_id, agent_ip=agent_ip, agent_name=f"{name}_Agent",
        target_host=target, category=f"{category}_ERROR", confidence="low",
        description=f"Agent '{name}' failed this cycle: {type(err).__name__}: {err}",
        mitre=MitreMapping(technique=technique, tactic=tactic),
        severity=0, recommended_action="Investigate agent failure (see scheduler log).")
    write_alert(alert, ERROR_LOG)

def _run_one(spec, target, agent_ip):
    name, cls, category, agent_id, technique, tactic = spec
    rec = {"agent": name}
    t0 = time.monotonic()
    try:
        agent = cls(agent_ip=agent_ip)
        alert = agent.run_once(target=target, category=category)
        rec["ok"] = True
        rec["severity"] = alert.severity
    except Exception as e:
        rec["ok"] = False
        rec["error"] = f"{type(e).__name__}: {e}"
        _write_error_alert(name, category, technique, tactic, agent_id, target, agent_ip, e)
    rec["seconds"] = round(time.monotonic() - t0, 2)
    return rec

def run_cycle(cycle_id, target, agent_ip, mode, stagger):
    cycle = {"cycle": cycle_id, "cycle_start": now_iso(), "mode": mode, "agents": []}
    if mode == "serial":
        for spec in AGENTS:
            cycle["agents"].append(_run_one(spec, target, agent_ip))
    else:
        with ThreadPoolExecutor(max_workers=len(AGENTS)) as ex:
            futures = {}
            for spec in AGENTS:
                futures[ex.submit(_run_one, spec, target, agent_ip)] = spec[0]
                if stagger:
                    time.sleep(stagger)
            for fut in as_completed(futures):
                cycle["agents"].append(fut.result())
    try:
        from agents import coordinator_agent as coord
        all_alerts = coord.collect_all_alerts()
        grouped = coord.group_by_target(all_alerts)
        correlated = 0
        for host, host_alerts in grouped.items():
            if len(host_alerts) >= 2:
                alert = coord.correlate_host(host, host_alerts)
                coord.write_alert(alert, "coordinator_alerts.jsonl")
                correlated += 1
        cycle["correlated_hosts"] = correlated
    except Exception as e:
        cycle["coordinator_error"] = f"{type(e).__name__}: {e}"
    cycle["cycle_end"] = now_iso()
    with open(CYCLE_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(cycle) + "\n")
    return cycle

def main():
    p = argparse.ArgumentParser(description="AAKCD baseline scheduler")
    p.add_argument("--target", required=True)
    p.add_argument("--agent-ip", default="127.0.0.1")
    p.add_argument("--interval", type=int, default=30)
    p.add_argument("--cycles", type=int, default=0)
    p.add_argument("--mode", choices=["parallel", "serial"], default="parallel")
    p.add_argument("--stagger", type=float, default=0.0)
    args = p.parse_args()
    import litellm  # warm-up: finish one-time init single-threaded
    _ = litellm
    print(f"[scheduler] target={args.target} interval={args.interval}s mode={args.mode} "
          f"cycles={'inf' if args.cycles == 0 else args.cycles}")
    print(f"[scheduler] cycle log -> {CYCLE_LOG}, error log -> {ERROR_LOG}\n[scheduler] Ctrl+C to stop.\n")
    cycle_id = 0
    try:
        while True:
            cycle_id += 1
            start = time.monotonic()
            cyc = run_cycle(cycle_id, args.target, args.agent_ip, args.mode, args.stagger)
            sev = {a["agent"]: a.get("severity", "ERR") for a in cyc["agents"]}
            print(f"[cycle {cycle_id}] {cyc['cycle_start']}  severities={sev}  "
                  f"correlated={cyc.get('correlated_hosts', 0)}")
            if args.cycles and cycle_id >= args.cycles:
                break
            time.sleep(max(0.0, args.interval - (time.monotonic() - start)))
    except KeyboardInterrupt:
        print("\n[scheduler] stopped by user.")

if __name__ == "__main__":
    main()
