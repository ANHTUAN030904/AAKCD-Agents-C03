"""
Reconnaissance agent -- the first agent to build (see the build guide).

Detection behaviour (kept to exactly ONE per the Week 6-7 scope cap):
    Scan a target IP and flag any open port running a service commonly
    abused for network reconnaissance / unauthenticated access (matches
    the reference report's own Recon agent test case: T1046).

Run it directly for a quick local test (writes to recon_alerts.jsonl,
does not touch Wazuh yet):

    python -m agents.recon_agent 192.168.88.129
"""

from __future__ import annotations

import subprocess
import sys

from agents.base_agent import BaseDetectionAgent
from agents.remote import demo_mode, no_telemetry_marker

# Ports that are cheap, high-signal indicators for a first MVP detection.
# Expand this list only after the Week 10 validation gate passes.
WATCHED_PORTS = {21: "ftp", 23: "telnet", 3389: "rdp", 5900: "vnc"}


class ReconAgent(BaseDetectionAgent):
    def __init__(self, agent_ip: str, log_path: str = "recon_alerts.jsonl") -> None:
        super().__init__(
            agent_id="010",
            agent_name="Recon_Agent",
            agent_ip=agent_ip,
            mitre_technique="T1046",
            mitre_tactic="Discovery",
            log_path=log_path,
        )

    def collect_telemetry(self, target: str) -> str:
        """Run an nmap scan against the target and return the raw text
        output. Requires nmap installed on the agent VM.

        If nmap isn't available yet (e.g. you're testing this file before
        finishing environment setup), this falls back to a canned sample
        scan so you can exercise the rest of the pipeline end-to-end.
        """
        try:
            result = subprocess.run(
                ["nmap", "-Pn", "--top-ports", "50", target],
                capture_output=True, text=True, timeout=60, check=False,
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Live eval: an empty/unreachable source is benign, not an
        # attack. Only fall through to the canned sample in demo mode.
        if not demo_mode():
            return no_telemetry_marker("open ports")

        # Fallback sample so the pipeline is testable before nmap is set up.
        return (
            f"Nmap scan report for {target}\n"
            "PORT     STATE SERVICE\n"
            "21/tcp   open  ftp\n"
            "80/tcp   open  http\n"
            "(sample data -- nmap not available or scan failed)\n"
        )

    def build_task_description(self, telemetry: str, target: str) -> str:
        watched = ", ".join(f"{port} ({name})" for port, name in WATCHED_PORTS.items())
        return (
            f"Here is an nmap scan result for host {target}:\n\n{telemetry}\n\n"
            f"Watched high-risk ports for this agent: {watched}.\n"
            "Determine whether any watched port is open on this host. "
            "If one is, treat it as suspicious network reconnaissance "
            "exposure (MITRE T1046, Network Service Discovery)."
        )


def main() -> None:
    if len(sys.argv) != 2:
        print("Usage: python -m agents.recon_agent <target-ip>")
        raise SystemExit(1)
    target = sys.argv[1]

    agent = ReconAgent(agent_ip="127.0.0.1")  # replace with this VM's real Tailscale IP
    alert = agent.run_once(target=target, category="network_recon")
    print(f"Wrote alert to {agent.log_path}:")
    print(alert.to_json())


if __name__ == "__main__":
    main()
