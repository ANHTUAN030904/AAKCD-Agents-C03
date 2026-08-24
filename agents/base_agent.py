"""
Base class every kill-chain agent (Recon, Delivery, Exploitation,
Installation, C2) extends.

The pattern is always the same three steps:
    1. collect_telemetry()  -- gather raw data (nmap output, an email, a
                                process list, a bash log line, ...)
    2. reason_with_llm()    -- hand that telemetry to Gemini via CrewAI and
                                get back a structured judgement
    3. to_alert()           -- turn that judgement into a schema-conformant
                                Alert and write it to the local log

Each subclass only needs to implement collect_telemetry() and
build_task_description() -- everything else is shared.
"""

from __future__ import annotations

import os
from dotenv import load_dotenv
load_dotenv()
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from schema.alert_schema import Alert, MitreMapping, write_alert

# CrewAI / Gemini imports are deferred into _get_llm() so this module can be
# imported (and its structure inspected/tested) even before `pip install
# crewai google-generativeai` has been run on a given machine.


@dataclass
class DetectionResult:
    """What build_task_description()'s LLM call should hand back, parsed
    into plain fields the base class can turn into an Alert."""
    suspicious: bool
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

    # ------------------------------------------------------------------
    # Each agent implements these two methods only.
    # ------------------------------------------------------------------

    @abstractmethod
    def collect_telemetry(self, target: str) -> Any:
        """Gather the raw data this agent inspects for its ONE detection
        behaviour (per the Week 6-7 scope cap: exactly one signal per
        agent). `target` is normally an IP/hostname."""
        raise NotImplementedError

    @abstractmethod
    def build_task_description(self, telemetry: Any, target: str) -> str:
        """Return the natural-language prompt/task description CrewAI
        will hand to Gemini, given the telemetry just collected."""
        raise NotImplementedError

    # ------------------------------------------------------------------
    # Shared machinery -- do not override in subclasses.
    # ------------------------------------------------------------------

    def _get_llm(self):
        """Lazily construct the Groq-backed CrewAI LLM. Requires
        GROQ_API_KEY to be set (see .env.example).

        NOTE: this project originally targeted Gemini, but as of August 2026
        Google's newly-issued "AQ." auth-format API keys are broken against
        both the legacy and the new Interactions API endpoints (confirmed
        via direct REST testing and matching multiple live reports on
        Google's own AI developer forum). Groq was swapped in as a working,
        free-tier replacement -- same CrewAI LLM interface, no other code
        changes needed. Revisit Gemini once Google resolves the bug."""
        from crewai import LLM  # deferred import, see module docstring

        api_key = os.environ.get("GROQ_API_KEY")
        if not api_key:
            raise RuntimeError(
                "GROQ_API_KEY is not set. Copy .env.example to .env, "
                "fill in your key, and load it (e.g. `python-dotenv`) "
                "before running an agent."
            )
        return LLM(model=os.environ.get("AAKCD_MODEL", "groq/openai/gpt-oss-120b"), api_key=api_key)

    def reason_with_llm(self, telemetry: Any, target: str) -> DetectionResult:
        """Run one CrewAI agent+task against the collected telemetry and
        parse the result into a DetectionResult.

        NOTE: this method defines the *contract* your Gemini prompt must
        satisfy (see the required output fields in build_task_description
        docstring below) -- adjust the parsing here if you change the
        prompt's expected output format.
        """
        from crewai import Agent, Task, Crew  # deferred import

        # Workaround for a known CrewAI bug (crewAIInc/crewAI #5886): it
        # injects an Anthropic-only prompt-caching field into every
        # request's messages, which non-Anthropic providers like Groq
        # reject outright ("property 'cache_breakpoint' is unsupported").
        # No-op the function that adds it until CrewAI ships a real fix.
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
            "CONFIDENCE: <low|medium|high>\n"
            "SUMMARY: <one paragraph a SOC analyst can read directly>\n"
            "RECOMMENDED_ACTION: <one concrete next step>\n"
        )

        task = Task(description=task_description, agent=analyst,
                    expected_output="The four labelled fields described above.")
        crew = Crew(agents=[analyst], tasks=[task], verbose=False)
        raw_result = str(crew.kickoff())

        return self._parse_result(raw_result, target)

    @staticmethod
    def _parse_result(raw: str, target: str) -> DetectionResult:
        fields = {"SUSPICIOUS": "false", "CONFIDENCE": "low",
                  "SUMMARY": raw.strip(), "RECOMMENDED_ACTION": "Review manually."}
        for line in raw.splitlines():
            for key in fields:
                prefix = f"{key}:"
                if line.strip().upper().startswith(prefix):
                    fields[key] = line.split(":", 1)[1].strip()
        return DetectionResult(
            suspicious=fields["SUSPICIOUS"].strip().lower().startswith("t"),
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
            severity=12 if result.suspicious else 0,
            recommended_action=result.recommended_action,
        )

    def run_once(self, target: str, category: str) -> Alert | None:
        """Run one full detection cycle against `target`. Returns the
        Alert if written, or None if nothing suspicious was found (the
        reference team still logged clean scans at severity 0 -- adjust
        this if your agent should stay silent on clean results instead)."""
        telemetry = self.collect_telemetry(target)
        result = self.reason_with_llm(telemetry, target)
        alert = self.to_alert(result, category)
        write_alert(alert, self.log_path)
        return alert
