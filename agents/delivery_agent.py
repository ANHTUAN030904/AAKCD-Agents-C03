"""
Delivery agent -- second agent in the kill chain (see the build guide).

Detection behaviour (kept to exactly ONE per the Week 6-7 scope cap):
    Inspect an email's subject/body/sender/links for phishing indicators
    and flag suspicious delivery attempts (MITRE T1566.002, Phishing:
    Spearphishing Link).

Run it directly for a quick local test (writes to delivery_alerts.jsonl,
does not touch Wazuh yet). `target` is a label identifying the email --
if a matching sample file exists at emails/<target>.txt it is read as the
"inbox" telemetry, otherwise a canned suspicious sample is used so the
pipeline is testable before real mailbox access (e.g. Gmail API) is wired
up:

    python -m agents.delivery_agent sample-phish-01
"""

from __future__ import annotations

import sys
from pathlib import Path

from agents.base_agent import BaseDetectionAgent
from agents.remote import demo_mode, no_telemetry_marker

# Cheap, high-signal indicators for a first MVP detection. Expand this
# list only after the Week 10 validation gate passes.
WATCHED_INDICATORS = [
    "urgent action required",
    "verify your account",
    "click here",
    "suspended",
    "password expires",
    "bit.ly",
    "tinyurl",
]


class DeliveryAgent(BaseDetectionAgent):
    def __init__(self, agent_ip: str, log_path: str = "delivery_alerts.jsonl") -> None:
        super().__init__(
            agent_id="020",
            agent_name="Delivery_Agent",
            agent_ip=agent_ip,
            mitre_technique="T1566.002",
            mitre_tactic="Initial Access",
            log_path=log_path,
        )

    def collect_telemetry(self, target: str) -> str:
        """Read a sample email's raw text. Requires real mailbox access
        (e.g. the Gmail API) on the agent VM for production use.

        If no sample file exists yet (e.g. you're testing this file before
        finishing mailbox integration), this falls back to a canned
        phishing-style sample so you can exercise the rest of the
        pipeline end-to-end.
        """
        sample_path = Path("emails") / f"{target}.txt"
        if sample_path.exists():
            return sample_path.read_text(encoding="utf-8")

        # Live eval: no email sample means nothing to analyse -> benign.
        # Only use the canned phishing sample in demo mode.
        if not demo_mode():
            return no_telemetry_marker("emails")

        # Fallback sample so the pipeline is testable before mailbox
        # access is set up.
        return (
            "From: it-support@paypa1-secure.com\n"
            "Subject: URGENT: Verify your account or it will be suspended\n\n"
            "Dear user, your account access is suspended. Click here to "
            "verify your identity within 24 hours: "
            "http://bit.ly/3xAmpleLink\n"
            "(sample data -- no real mailbox access configured yet)\n"
        )

    def build_task_description(self, telemetry: str, target: str) -> str:
        watched = ", ".join(f'"{w}"' for w in WATCHED_INDICATORS)
        return (
            f"Here is a raw email (headers + body) received by host {target}:\n\n"
            f"{telemetry}\n\n"
            f"Watched phishing indicators for this agent: {watched}.\n"
            "Determine whether this email shows signs of a phishing "
            "delivery attempt (spoofed/lookalike sender domain, urgency "
            "language, shortened/suspicious links, credential-harvesting "
            "intent). If it does, treat it as suspicious email delivery "
            "(MITRE T1566.002, Phishing: Spearphishing Link)."
        )


def main() -> None:
    if len(sys.argv) != 2:
        print("Usage: python -m agents.delivery_agent <email-label>")
        raise SystemExit(1)
    target = sys.argv[1]

    agent = DeliveryAgent(agent_ip="127.0.0.1")  # replace with this VM's real Tailscale IP
    alert = agent.run_once(target=target, category="email_phishing")
    print(f"Wrote alert to {agent.log_path}:")
    print(alert.to_json())


if __name__ == "__main__":
    main()
