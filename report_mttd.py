"""Compute MTTD from the attack log and the agents' alert logs (Stage 3E)."""
from __future__ import annotations
import argparse, json, statistics
from datetime import datetime
from pathlib import Path

ATTACK_LOG = "attack_log.jsonl"
ALERT_LOGS = ["recon_alerts.jsonl","delivery_alerts.jsonl","exploitation_alerts.jsonl",
              "installation_alerts.jsonl","c2_alerts.jsonl"]
CORRELATION_LOG = "coordinator_alerts.jsonl"

def _read_jsonl(path):
    p = Path(path)
    if not p.exists(): return []
    out = []
    with p.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try: out.append(json.loads(line))
                except json.JSONDecodeError: pass
    return out

def _parse(ts): return datetime.fromisoformat(ts)

def match_attack(attack, alerts, window):
    a_time = _parse(attack["attack_time"])
    detector = attack["expected_detector"]; target = attack["target_host"]
    candidates = []
    for al in alerts:
        try:
            if al["agent"]["name"] != detector: continue
            if al.get("target_host") != target: continue
            if al.get("severity", 0) < 1: continue
            delta = (_parse(al["@timestamp"]) - a_time).total_seconds()
            if 0 <= delta <= window: candidates.append((delta, al))
        except (KeyError, ValueError): continue
    if not candidates: return None
    candidates.sort(key=lambda x: x[0])
    return candidates[0]

def match_correlation(attack, corr_alerts, window):
    a_time = _parse(attack["attack_time"]); target = attack["target_host"]; best = None
    for al in corr_alerts:
        try:
            if al.get("target_host") != target: continue
            delta = (_parse(al["@timestamp"]) - a_time).total_seconds()
            if 0 <= delta <= window and (best is None or delta < best): best = delta
        except (KeyError, ValueError): continue
    return best

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--window", type=int, default=600)
    p.add_argument("--run", default=None)
    args = p.parse_args()
    attacks = _read_jsonl(ATTACK_LOG)
    if args.run: attacks = [a for a in attacks if a.get("run") == args.run]
    if not attacks:
        print(f"No attacks found in {ATTACK_LOG}"); return
    alerts = [a for path in ALERT_LOGS for a in _read_jsonl(path)]
    corr = _read_jsonl(CORRELATION_LOG)
    print(f"\n{'='*78}")
    print(f"AAKCD detection latency report   ({len(attacks)} attacks, window {args.window}s"
          + (f", run '{args.run}'" if args.run else "") + ")")
    print(f"{'='*78}\n")
    header = f"{'#':<3} {'TECHNIQUE':<12} {'DETECTOR':<20} {'MTTD(s)':<10} {'CORR(s)':<10} RESULT"
    print(header); print("-" * len(header))
    per_technique = {}; detected = 0
    for i, atk in enumerate(attacks, 1):
        hit = match_attack(atk, alerts, args.window)
        c = match_correlation(atk, corr, args.window)
        tech = atk["technique"]; det = atk["expected_detector"]
        if hit:
            delta, _ = hit; detected += 1
            per_technique.setdefault(tech, []).append(delta)
            mttd = f"{delta:.1f}"; result = "DETECTED"
        else:
            mttd = "-"; result = "MISSED"
        corr_s = f"{c:.1f}" if c is not None else "-"
        print(f"{i:<3} {tech:<12} {det:<20} {mttd:<10} {corr_s:<10} {result}")
    print("\n" + "-" * len(header))
    print(f"Detected {detected}/{len(attacks)} ({100*detected/len(attacks):.0f}% coverage)\n")
    if per_technique:
        print(f"{'TECHNIQUE':<12} {'N':<4} {'MEAN(s)':<10} {'MIN(s)':<10} {'MAX(s)':<10}")
        print("-" * 50)
        for tech in sorted(per_technique):
            v = per_technique[tech]
            print(f"{tech:<12} {len(v):<4} {statistics.mean(v):<10.1f} {min(v):<10.1f} {max(v):<10.1f}")
        allv = [v for vs in per_technique.values() for v in vs]
        print("-" * 50)
        print(f"{'OVERALL':<12} {len(allv):<4} {statistics.mean(allv):<10.1f} {min(allv):<10.1f} {max(allv):<10.1f}")
    print("\nNote: MTTD includes scheduler polling delay. Report the poll interval alongside these figures.\n")

if __name__ == "__main__":
    main()
