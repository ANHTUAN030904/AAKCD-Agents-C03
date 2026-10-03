"""AAKCD scheduler (Stage 3F). Runs all five detection agents against the
victim on a fixed interval, in parallel, then correlates. Records per-cycle
timing and severities to scheduler_cycles.jsonl, and writes an explicit
error-alert to agent_errors.jsonl when an agent crashes (so a failure is
distinguishable from a genuine no-detection).

Supports two modes for the cue comparison:
  baseline (default): all agents polled on a fixed interval, independent.
  --warning: feed-forward cue. When an EARLY-phase agent (recon, delivery,
             or exploitation) detects an attack, the scheduler drops to a
             shorter interval for the next HIGH_ALERT_CYCLES cycles, so the
             later phases (installation, c2) are re-polled sooner. This is
             the cue-ENABLED mode."""

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

# --- warning-mode config ---
# Early kill-chain phases whose detection warns the later phases.
EARLY_AGENTS = {"recon", "delivery", "exploitation"}
WARN_SEVERITY = 7          # severity that counts as a real detection
HIGH_ALERT_CYCLES = 10       # number of cycles to stay on the fast interval after a warning

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
    p = argparse.ArgumentParser(description="AAKCD scheduler (baseline / warning)")
    p.add_argument("--target", required=True)
    p.add_argument("--agent-ip", default="127.0.0.1")
    p.add_argument("--interval", type=int, default=30)
    p.add_argument("--cycles", type=int, default=0)
    p.add_argument("--mode", choices=["parallel", "serial"], default="parallel")
    p.add_argument("--stagger", type=float, default=0.0)
    p.add_argument("--warning", action="store_true",
                   help="enable feed-forward cue: early-phase detection speeds up later cycles")
    p.add_argument("--alert-interval", type=int, default=5,
                   help="cycle interval (s) while on high alert (warning mode only)")
    args = p.parse_args()

    import litellm  # warm-up: finish one-time init single-threaded
    _ = litellm

    print(f"[scheduler] target={args.target} interval={args.interval}s mode={args.mode} "
          f"warning={'ON' if args.warning else 'OFF'}"
          f"{' alert-interval='+str(args.alert_interval)+'s' if args.warning else ''} "
          f"cycles={'inf' if args.cycles == 0 else args.cycles}")
    print(f"[scheduler] cycle log -> {CYCLE_LOG}, error log -> {ERROR_LOG}\n[scheduler] Ctrl+C to stop.\n")

    cycle_id = 0
    high_alert_remaining = 0        # warning-mode state: cycles left on the fast interval
    try:
        while True:
            cycle_id += 1
            start = time.monotonic()
            cyc = run_cycle(cycle_id, args.target, args.agent_ip, args.mode, args.stagger)
            sev = {a["agent"]: a.get("severity", "ERR") for a in cyc["agents"]}

            # --- warning logic: did an EARLY-phase agent fire this cycle? ---
            if args.warning:
                triggered = any(
                    a["agent"] in EARLY_AGENTS
                    and isinstance(a.get("severity"), int)
                    and a["severity"] >= WARN_SEVERITY
                    for a in cyc["agents"]
                )
                if triggered:
                    high_alert_remaining = HIGH_ALERT_CYCLES   # (re)arm the fast window

            # choose this cycle's sleep interval
            if args.warning and high_alert_remaining > 0:
                interval = args.alert_interval
                high_alert_remaining -= 1
                alert_flag = f"  [HIGH-ALERT {interval}s]"
            else:
                interval = args.interval
                alert_flag = ""

            print(f"[cycle {cycle_id}] {cyc['cycle_start']}  severities={sev}  "
                  f"correlated={cyc.get('correlated_hosts', 0)}{alert_flag}")

            if args.cycles and cycle_id >= args.cycles:
                break
            time.sleep(max(0.0, interval - (time.monotonic() - start)))
    except KeyboardInterrupt:
        print("\n[scheduler] stopped by user.")

if __name__ == "__main__":
    main()
