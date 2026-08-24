"""
Coordinator agent -- correlates alerts already written by the five
kill-chain detection agents (Recon, Delivery, Exploitation, Installation,
C2) by target_host, and uses the LLM to synthesize a single narrative
alert describing the full attack chain observed on that host.

Unlike the other five agents, the Coordinator has no MITRE technique of
its own and does not collect its own telemetry -- it reads the alert
logs the other agents have already written (see project plan Section 6,
Phase 3). In production this reads from Wazuh/OpenSearch instead of
local JSON files; for MVP/local testing it reads the same local log
files the other agents write to, which is why it must be run from the
same working directory (or same VM) those logs were written in.

Run it directly for a quick local test, after having run at least TWO of
the other agents against the SAME target_host, so there is something to
correlate (e.g. `python -m agents.recon_agent 192.168.88.129` followed
by `python -m agents.delivery_agent 192.168.88.129` -- note the C2/
Delivery/Exploitation/Installation agents accept any label as `target`,
so reusing an IP as the label works fine for testing correlation):

    python -m agents.coordinator_agent
"""

from __future__ import annotations

import os
from dotenv import load_dotenv
load_dotenv()
from collections import defaultdict

from schema.alert_schema import Alert, MitreMapping, write_alert, read_alerts

# The local alert logs written by each of the five detection agents.
# In production these become Wazuh/OpenSearch queries instead -- see the
# Integration Lead's Week 5 decoder/rule work in the project plan.
SOURCE_LOGS = [
    "recon_alerts.jsonl",
    "delivery_alerts.jsonl",
    "exploitation_alerts.jsonl",
    "installation_alerts.jsonl",
    "c2_alerts.jsonl",
]

MIN_SEVERITY = 1  # ignore severity-0 (clean) alerts when correlating


def _get_llm():
    from crewai import LLM  # deferred import, see recon/base agent for why

    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        raise RuntimeError(
            "GROQ_API_KEY is not set. Copy .env.example to .env, "
            "fill in your key, and load it before running an agent."
        )
    return LLM(model=os.environ.get("AAKCD_MODEL", "groq/openai/gpt-oss-120b"), api_key=api_key)


def collect_all_alerts() -> list[dict]:
    """Read every source agent's local alert log (missing files are
    treated as empty -- an agent that hasn't run yet just contributes
    nothing to the correlation)."""
    all_alerts: list[dict] = []
    for log_path in SOURCE_LOGS:
        all_alerts.extend(read_alerts(log_path))
    return all_alerts


def group_by_target(alerts: list[dict]) -> dict[str, list[dict]]:
    """Group alerts by target_host, keeping only alerts with severity
    at or above MIN_SEVERITY (skip clean/benign scan results).

    NOTE: alert fields live at the top level of each alert dict (see
    schema/alert_schema.py's Aug 2026 flattening fix) -- not under a
    nested "data" key anymore.
    """
    grouped: dict[str, list[dict]] = defaultdict(list)
    for alert in alerts:
        if alert.get("severity", 0) < MIN_SEVERITY:
            continue
        grouped[alert.get("target_host", "unknown")].append(alert)
    return grouped


def build_narrative_prompt(target_host: str, host_alerts: list[dict]) -> str:
    lines = []
    for a in sorted(host_alerts, key=lambda x: x.get("@timestamp", "")):
        agent = a["agent"]["name"]
        lines.append(
            f"- [{a['@timestamp']}] {agent} ({a['mitre']['tactic']} / "
            f"{a['mitre']['technique']}): {a['description']} "
            f"(severity {a['severity']})"
        )
    alert_list = "\n".join(lines)
    return (
        f"The following alerts were raised by different detection agents, "
        f"all about the same host ({target_host}), across different "
        f"stages of the cyber kill chain:\n\n{alert_list}\n\n"
        "Write a short SOC-analyst-readable narrative connecting these "
        "alerts into a single attack story, in chronological order. "
        "State whether this looks like a coordinated multi-stage attack "
        "against this host, and give ONE overall recommended action."
    )


def correlate_host(target_host: str, host_alerts: list[dict]) -> Alert:
    from crewai import Agent, Task, Crew  # deferred import

    # Same known-CrewAI-bug workaround as the other agents (issue #5886).
    import crewai.llms.cache as _crewai_cache
    _crewai_cache.mark_cache_breakpoint = lambda msg: msg

    analyst = Agent(
        role="SOC correlation analyst",
        goal="Connect alerts from multiple detection agents about the "
             "same host into one coherent attack narrative.",
        backstory="You are an experienced SOC analyst who specialises "
                  "in connecting isolated alerts into a bigger picture "
                  "across the cyber kill chain.",
        llm=_get_llm(),
        verbose=False,
    )

    prompt = build_narrative_prompt(target_host, host_alerts)
    prompt += (
        "\n\nRespond in EXACTLY this format (no extra text):\n"
        "SUMMARY: <the narrative, one or two paragraphs>\n"
        "RECOMMENDED_ACTION: <one concrete next step>\n"
    )
    task = Task(description=prompt, agent=analyst,
                expected_output="The two labelled fields described above.")
    crew = Crew(agents=[analyst], tasks=[task], verbose=False)
    raw = str(crew.kickoff())

    summary = raw.strip()
    recommended_action = "Review manually."
    for line in raw.splitlines():
        if line.strip().upper().startswith("SUMMARY:"):
            summary = line.split(":", 1)[1].strip()
        elif line.strip().upper().startswith("RECOMMENDED_ACTION:"):
            recommended_action = line.split(":", 1)[1].strip()

    techniques = sorted({a["mitre"]["technique"] for a in host_alerts})
    tactics = sorted({a["mitre"]["tactic"] for a in host_alerts})
    max_severity = max(a["severity"] for a in host_alerts)

    return Alert(
        agent_id="060",
        agent_ip="127.0.0.1",  # replace with this VM's real Tailscale IP
        agent_name="Coordinator_Agent",
        target_host=target_host,
        category="kill_chain_correlation",
        confidence="high" if len(host_alerts) >= 3 else "medium",
        description=summary,
        mitre=MitreMapping(technique=",".join(techniques), tactic=" -> ".join(tactics)),
        severity=max_severity,
        recommended_action=recommended_action,
    )


def main() -> None:
    all_alerts = collect_all_alerts()
    if not all_alerts:
        print("No alerts found yet -- run at least one of the five "
              "detection agents first (from this same directory).")
        raise SystemExit(1)

    grouped = group_by_target(all_alerts)
    if not grouped:
        print("No suspicious (severity > 0) alerts to correlate yet.")
        raise SystemExit(0)

    correlated_any = False
    for target_host, host_alerts in grouped.items():
        if len(host_alerts) < 2:
            # Only one agent has flagged this host so far -- nothing to
            # correlate yet.
            continue
        correlated_any = True
        alert = correlate_host(target_host, host_alerts)
        write_alert(alert, "coordinator_alerts.jsonl")
        print(f"Wrote correlated alert for {target_host}:")
        print(alert.to_json())

    if not correlated_any:
        hosts = ", ".join(grouped.keys())
        print(
            f"Found alerts for: {hosts} -- but no single host has alerts "
            "from 2+ agents yet, so there's nothing to correlate. Run "
            "two different agents against the SAME target_host to test "
            "this (e.g. reuse an IP or label as the argument to both)."
        )


if __name__ == "__main__":
    main()
