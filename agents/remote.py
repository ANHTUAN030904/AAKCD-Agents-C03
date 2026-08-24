"""Remote telemetry collection for AAKCD live-attack evaluation (Stage 3).

Reproduces the SNSHD reference model: agents reach the victim by IP and
collect telemetry remotely. When AAKCD_VICTIM_HOST and AAKCD_VICTIM_USER
are set, collect_remote() runs a command on the victim over SSH; when
they are not, it returns None and the agent falls back to its existing
local/sample behaviour, so Stage 1 and Stage 2 keep working."""

from __future__ import annotations
import os
import subprocess


def remote_target() -> tuple[str, str] | None:
    host = os.environ.get("AAKCD_VICTIM_HOST")
    user = os.environ.get("AAKCD_VICTIM_USER")
    if host and user:
        return user, host
    return None


def collect_remote(command: list[str], timeout: int = 15) -> str | None:
    """Run `command` on the victim over SSH, return stdout, or None on
    any failure so the caller falls back. Never raises."""
    target = remote_target()
    if target is None:
        return None
    user, host = target
    ssh_cmd = [
        "ssh", "-n", "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", f"ConnectTimeout={timeout}",
        f"{user}@{host}", *command,
    ]
    try:
        result = subprocess.run(
            ssh_cmd, capture_output=True, text=True,
            timeout=timeout + 5, check=False,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return None


def demo_mode() -> bool:
    """True only when AAKCD_DEMO is explicitly set. In demo mode agents may
    fall back to canned attack samples (offline Stage 1/2 testing). In live
    evaluation they must NOT -- an empty real source reads benign."""
    return os.environ.get("AAKCD_DEMO", "").lower() in ("1", "true", "yes")


def no_telemetry_marker(source_desc: str) -> str:
    """Returned when a live source was reached but yielded nothing. Phrased
    so the LLM classifies it benign, not as a fabricated attack."""
    return (
        f"No {source_desc} were collected from the target host. "
        "The source was reachable but returned no entries, so there is "
        "no evidence of any suspicious or malicious activity to report."
    )
