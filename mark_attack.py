"""Record the moment an attack is fired, for MTTD measurement (Stage 3E)."""
from __future__ import annotations
import argparse, json
from datetime import datetime, timezone

ATTACK_LOG = "attack_log.jsonl"
EXPECTED_DETECTOR = {
    "T1046":     "Recon_Agent",
    "T1566.002": "Delivery_Agent",
    "T1027":     "Exploitation_Agent",
    "T1053.003": "Installation_Agent",
    "T1071.001": "C2_Agent",
}

def main():
    p = argparse.ArgumentParser(description="Mark an attack for MTTD measurement")
    p.add_argument("--technique", required=True)
    p.add_argument("--target", required=True)
    p.add_argument("--note", default="")
    p.add_argument("--run", default="baseline")
    args = p.parse_args()
    ts = datetime.now(timezone.utc).isoformat()
    record = {"attack_time": ts, "technique": args.technique,
              "target_host": args.target,
              "expected_detector": EXPECTED_DETECTOR.get(args.technique, "unknown"),
              "run": args.run, "note": args.note}
    with open(ATTACK_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")
    print(f"[attack marked] {ts}  {args.technique} -> {args.target}")
    print(f"[attack marked] expected detector: {record['expected_detector']}")

if __name__ == "__main__":
    main()
