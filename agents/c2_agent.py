"""
C2 (Command & Control) agent -- fifth and final kill-chain detection agent
(see the build guide). Scope was deliberately kept to the single simplest
detection to offset the Integration Lead's workload -- see the project
plan's team-structure notes.

Detection behaviour (kept to exactly ONE per the Week 6-7 scope cap):
    Inspect a network connection log entry for signs of C2 beaconing over
    a web protocol (MITRE T1071.001, Application Layer Protocol: Web
    Protocols).

Run it directly for a quick local test (writes to c2_alerts.jsonl, does
not touch Wazuh yet). `target` is a label identifying the connection log
sample -- if a matching file exists at connections/<target>.txt it is
read as the telemetry, otherwise a canned suspicious-beacon sample is
used so the pipeline is testable before real socket/connection auditing
is wired up:

    python -m agents.c2_agent sample-conn-01
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from agents.base_agent import BaseDetectionAgent
from agents.remote import collect_remote, demo_mode, no_telemetry_marker

# Cheap, high-signal indicators for a first MVP detection. Expand this
# list only after the Week 10 validation gate passes.
WATCHED_INDICATORS = [
    "uncommon port",
    "raw IP destination",
    "periodic interval",
    "user-agent mismatch",
    "high connection frequency",
    ".onion",
]


class C2Agent(BaseDetectionAgent):
    def __init__(self, agent_ip: str, log_path: str = "c2_alerts.jsonl") -> None:
        super().__init__(
            agent_id="050",
            agent_name="C2_Agent",
            agent_ip=agent_ip,
            mitre_technique="T1071.001",
            mitre_tactic="Command and Control",
            log_path=log_path,
        )

    def collect_telemetry(self, target: str) -> str:
        """Read a sample connection log entry. Prefers a saved sample file
        (see module docstring); falls back to the host's own active
        connections (`ss -tn`) if no sample exists; finally falls back to
        a canned suspicious-beacon sample so the pipeline is testable
        before real connection auditing is wired up.
        """
        sample_path = Path("connections") / f"{target}.txt"
        if sample_path.exists():
            return sample_path.read_text(encoding="utf-8")

        # Live remote collection over SSH (Stage 3).
        remote = collect_remote(["ss", "-tn"])
        if remote:
            return remote

        try:
            result = subprocess.run(
                ["ss", "-tn"], capture_output=True, text=True, timeout=10, check=False,
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Live eval: an empty/unreachable source is benign, not an
        # attack. Only fall through to the canned sample in demo mode.
        if not demo_mode():
            return no_telemetry_marker("network connections")

        # Fallback sample so the pipeline is testable before connection
        # auditing is set up.
        return (
            "log: host 192.168.88.129 -> 45.33.12.9:8443 (HTTPS) "
            "every 60s +/-2s, 40 bytes out / 40 bytes in each time, "
            "no browser process attached, User-Agent: 'curl/7.68.0'\n"
            "(sample data -- no real connection auditing configured yet)\n"
        )

    def build_task_description(self, telemetry: str, target: str) -> str:
        watched = ", ".join(f'"{w}"' for w in WATCHED_INDICATORS)
        return (
            f"Here is a network connection log entry for host {target}:\n\n"
            f"{telemetry}\n\n"
            f"Watched C2-beaconing indicators for this agent: {watched}.\n"
            "Determine whether this connection shows signs of C2 "
            "beaconing disguised as normal web traffic (fixed periodic "
            "interval, tiny consistent payload size, no legitimate "
            "browser/application attached to the connection, a "
            "suspicious or scripting-tool User-Agent string). If it "
            "does, treat it as suspicious command-and-control traffic "
            "(MITRE T1071.001, Application Layer Protocol: Web "
            "Protocols)."
        )


def main() -> None:
    if len(sys.argv) != 2:
        print("Usage: python -m agents.c2_agent <connection-label>")
        raise SystemExit(1)
    target = sys.argv[1]

    agent = C2Agent(agent_ip="127.0.0.1")  # replace with this VM's real Tailscale IP
    alert = agent.run_once(target=target, category="c2_beaconing")
    print(f"Wrote alert to {agent.log_path}:")
    print(alert.to_json())


if __name__ == "__main__":
    main()
