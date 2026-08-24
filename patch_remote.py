import sys
EDITS = {
    "agents/c2_agent.py": (
        'sample_path = Path("connections") / f"{target}.txt"\n        if sample_path.exists():\n            return sample_path.read_text(encoding="utf-8")\n',
        '\n        # Live remote collection over SSH (Stage 3).\n        remote = collect_remote(["ss", "-tn"])\n        if remote:\n            return remote\n',
    ),
    "agents/installation_agent.py": (
        'sample_path = Path("tasks") / f"{target}.txt"\n        if sample_path.exists():\n            return sample_path.read_text(encoding="utf-8")\n',
        '\n        # Live remote collection over SSH (Stage 3).\n        remote = collect_remote(["crontab", "-l"])\n        if remote:\n            return remote\n',
    ),
    "agents/exploitation_agent.py": (
        'sample_path = Path("commands") / f"{target}.txt"\n        if sample_path.exists():\n            return sample_path.read_text(encoding="utf-8")\n',
        '\n        # Live remote collection over SSH (Stage 3).\n        remote = collect_remote(["sudo", "ausearch", "-k", "aakcd_exec", "-ts", "recent", "-i"])\n        if remote:\n            return remote\n',
    ),
}
IMP = "from agents.base_agent import BaseDetectionAgent"
for path, (anchor, block) in EDITS.items():
    src = open(path).read()
    if "from agents.remote import collect_remote" in src:
        print(f"SKIP {path}: already patched"); continue
    if anchor not in src:
        print(f"FAIL {path}: anchor not found"); sys.exit(1)
    src = src.replace(IMP, IMP + "\nfrom agents.remote import collect_remote", 1)
    src = src.replace(anchor, anchor + block, 1)
    open(path, "w").write(src)
    print(f"OK   {path}")
