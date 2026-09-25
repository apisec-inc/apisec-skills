#!/usr/bin/env python3
"""Derive always-on rule files for every supported coding agent from rules/*.mdc.

The five Cursor rules in rules/ are the single source of truth. Run this script
after editing any of them and commit the regenerated files under agents/.

  python3 scripts/build-agent-rules.py

Outputs
  agents/claude-code/rules/<rule>.md      Claude Code project rules (.claude/rules/)
  agents/windsurf/rules/<rule>.md         Windsurf workspace rules (.windsurf/rules/)
  agents/copilot/copilot-instructions.md  GitHub Copilot repository instructions
  agents/codex/AGENTS.md                  OpenAI Codex repository instructions
  agents/gemini/GEMINI.md                 Gemini CLI context file
"""
from __future__ import annotations

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
RULES = ROOT / "rules"
OUT = ROOT / "agents"

ORDER = [
    "auth-required",
    "ownership-check",
    "input-validation",
    "error-sanitization",
    "admin-rbac",
]

HEADER = (
    "<!-- Generated from rules/*.mdc by scripts/build-agent-rules.py. "
    "Edit the .mdc sources, not this file. -->\n"
)

INTRO = (
    "# APIsec API security rules\n\n"
    "These rules apply to every API route, handler, controller, and data access\n"
    "path you generate or modify. They implement the OWASP API Security Top 10\n"
    "2023 baseline. Follow them without being asked.\n\n"
)


def parse_mdc(path: pathlib.Path) -> tuple[str, str]:
    text = path.read_text()
    m = re.match(r"^---\n(.*?)\n---\n(.*)$", text, re.S)
    if not m:
        raise SystemExit(f"{path}: missing frontmatter")
    front, body = m.group(1), m.group(2).strip() + "\n"
    desc = re.search(r'^description:\s*"?(.*?)"?\s*$', front, re.M)
    return (desc.group(1) if desc else ""), body


def write(path: pathlib.Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    print(f"wrote {path.relative_to(ROOT)}")


def main() -> None:
    rules = []
    for name in ORDER:
        desc, body = parse_mdc(RULES / f"{name}.mdc")
        rules.append((name, desc, body))

    # Claude Code: one file per rule, no `paths` so they load at launch.
    for name, desc, body in rules:
        write(OUT / "claude-code" / "rules" / f"{name}.md", HEADER + body)

    # Windsurf: one file per rule, always_on trigger.
    for name, desc, body in rules:
        front = f"---\ntrigger: always_on\ndescription: {desc}\n---\n"
        write(OUT / "windsurf" / "rules" / f"{name}.md", front + HEADER + body)

    # Single-file agents: Copilot, Codex, Gemini share one combined document.
    combined = HEADER + INTRO + "\n".join(body for _, _, body in rules)
    write(OUT / "copilot" / "copilot-instructions.md", combined)
    write(OUT / "codex" / "AGENTS.md", combined)
    write(OUT / "gemini" / "GEMINI.md", combined)


if __name__ == "__main__":
    main()
