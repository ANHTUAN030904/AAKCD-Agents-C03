import sys
EDITS = [
    ("agents/recon_agent.py",
     "        # Fallback sample so the pipeline is testable before nmap is set up.\n",
     "open ports"),
    ("agents/c2_agent.py",
     "        # Fallback sample so the pipeline is testable before connection\n",
     "network connections"),
    ("agents/installation_agent.py",
     "        # Fallback sample so the pipeline is testable before cron/schtasks\n",
     "cron entries"),
    ("agents/exploitation_agent.py",
     "        # Fallback sample so the pipeline is testable before log tailing\n",
     "command executions"),
]
IMP = "from agents.base_agent import BaseDetectionAgent"
for path, anchor, desc in EDITS:
    src = open(path).read()
    if "from agents.remote import demo_mode" in src:
        print(f"SKIP {path}: already patched"); continue
    if anchor not in src:
        print(f"FAIL {path}: anchor not found"); sys.exit(1)
    if "from agents.remote import collect_remote" in src:
        src = src.replace(
            "from agents.remote import collect_remote",
            "from agents.remote import collect_remote, demo_mode, no_telemetry_marker", 1)
    else:
        src = src.replace(IMP, IMP + "\nfrom agents.remote import demo_mode, no_telemetry_marker", 1)
    guard = (
        "        # Live eval: an empty/unreachable source is benign, not an\n"
        "        # attack. Only fall through to the canned sample in demo mode.\n"
        f'        if not demo_mode():\n'
        f'            return no_telemetry_marker("{desc}")\n\n'
    )
    src = src.replace(anchor, guard + anchor, 1)
    open(path, "w").write(src)
    print(f"OK   {path}")
