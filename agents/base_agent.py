"""
Base class every kill-chain agent (Recon, Delivery, Exploitation,
Installation, C2) extends.

The pattern is always the same three steps:
    1. collect_telemetry()  -- gather raw data
    2. reason_with_llm()    -- hand telemetry to the LLM via CrewAI
    3. to_alert()           -- turn the judgement into an Alert and log it
"""

from __future__ import annotations

import os
from dotenv import load_dotenv
load_dotenv()
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from schema.alert_schema import Alert, MitreMapping, write_alert


@dataclass
class DetectionResult:
    """Parsed LLM judgement the base class turns into an Alert."""
    suspicious: bool
    severity: int              # 0 (benign) .. 12 (critical), graded by the LLM
    confidence: str            # "low" | "medium" | "high"
    summary: str
    target_host: str
    recommended_action: str


class BaseDetectionAgent(ABC):
    agent_id: str
    agent_name: str
    mitre_technique: str
    mitre_tactic: str
    log_path: str

    def __init__(self, agent_id: str, agent_name: str, agent_ip: str,
                 mitre_technique: str, mitre_tactic: str,
                 log_path: str = "alerts.jsonl") -> None:
        self.agent_id = agent_id
        self.agent_name = agent_name
        self.agent_ip = agent_ip
        self.mitre_technique = mitre_technique
        self.mitre_tactic = mitre_tactic
        self.log_path = log_path

    @abstractmethod
    def collect_telemetry(self, target: str) -> Any:
        """Gather the raw data this agent inspects for its ONE behaviour."""
        raise NotImplementedError

    @abstractmethod
    def build_task_description(self, telemetry: Any, target: str) -> str:
        """Return the prompt CrewAI hands to the LLM given the telemetry."""
        raise NotImplementedError

    def _get_llm(self):
        """Lazily construct the Groq-backed CrewAI LLM. Requires GROQ_API_KEY."""
        from crewai import LLM  # deferred import

        api_key = os.environ.get("GROQ_API_KEY")
        if not api_key:
            raise RuntimeError(
                "GROQ_API_KEY is not set. Copy .env.example to .env, "
                "fill in your key, and load it before running an agent."
            )
        return LLM(model=os.environ.get("AAKCD_MODEL", "groq/openai/gpt-oss-120b"), api_key=api_key)

    def reason_with_llm(self, telemetry: Any, target: str) -> DetectionResult:
        """Run one CrewAI agent+task against the telemetry and parse the result."""
        from crewai import Agent, Task, Crew  # deferred import

        # Workaround for CrewAI bug #5886 (Anthropic-only cache field breaks Groq).
        import crewai.llms.cache as _crewai_cache
        _crewai_cache.mark_cache_breakpoint = lambda msg: msg

        analyst = Agent(
            role=f"{self.agent_name} threat analyst",
            goal="Decide whether the given telemetry indicates the one "
                 "target attack behaviour this agent watches for, and "
                 "explain the reasoning in plain language for a SOC analyst.",
            backstory="You are a focused detection specialist. You only "
                      "judge ONE narrow behaviour -- do not speculate "
                      "about unrelated threats.",
            llm=self._get_llm(),
            verbose=False,
        )

        task_description = self.build_task_description(telemetry, target)
        task_description += (
            "\n\nRespond in EXACTLY this format (no extra text):\n"
            "SUSPICIOUS: <true|false>\n"
            "SEVERITY: <integer 0-12; 0 = benign, 1-4 = low, 5-8 = medium, "
            "9-11 = high, 12 = critical. Rate how strongly the telemetry "
            "indicates this agent's specific attack behaviour.>\n"
            "CONFIDENCE: <low|medium|high>\n"
            "SUMMARY: <one paragraph a SOC analyst can read directly>\n"
            "RECOMMENDED_ACTION: <one concrete next step>\n"
        )

        task = Task(description=task_description, agent=analyst,
                    expected_output="The five labelled fields described above.")
        crew = Crew(agents=[analyst], tasks=[task], verbose=False)
        raw_result = str(crew.kickoff())

        return self._parse_result(raw_result, target)

    @staticmethod
    def _parse_result(raw: str, target: str) -> DetectionResult:
        fields = {"SUSPICIOUS": "false", "SEVERITY": "", "CONFIDENCE": "low",
                  "SUMMARY": raw.strip(), "RECOMMENDED_ACTION": "Review manually."}
        for line in raw.splitlines():
            for key in fields:
                prefix = f"{key}:"
                if line.strip().upper().startswith(prefix):
                    fields[key] = line.split(":", 1)[1].strip()

        suspicious = fields["SUSPICIOUS"].strip().lower().startswith("t")

        # parse the LLM's severity number; clamp to 0-12
        sev_txt = "".join(ch for ch in fields["SEVERITY"] if ch.isdigit())
        if sev_txt:
            severity = max(0, min(12, int(sev_txt)))
        else:
            # LLM gave no number -> fall back to old binary behaviour
            severity = 12 if suspicious else 0

        # keep the two consistent
        if severity == 0:
            suspicious = False
        elif not suspicious:
            suspicious = True

        return DetectionResult(
            suspicious=suspicious,
            severity=severity,
            confidence=fields["CONFIDENCE"].strip().lower(),
            summary=fields["SUMMARY"],
            target_host=target,
            recommended_action=fields["RECOMMENDED_ACTION"],
        )

    def to_alert(self, result: DetectionResult, category: str) -> Alert:
        return Alert(
            agent_id=self.agent_id,
            agent_ip=self.agent_ip,
            agent_name=self.agent_name,
            target_host=result.target_host,
            category=category,
            confidence=result.confidence if result.confidence in ("low", "medium", "high") else "low",
            description=result.summary,
            mitre=MitreMapping(technique=self.mitre_technique, tactic=self.mitre_tactic),
            severity=result.severity,
            recommended_action=result.recommended_action,
        )

    def run_once(self, target: str, category: str) -> Alert | None:
        """Run one full detection cycle against `target`."""
        telemetry = self.collect_telemetry(target)
        result = self.reason_with_llm(telemetry, target)
        alert = self.to_alert(result, category)
        write_alert(alert, self.log_path)
        return alert
