# Changelog

## 1.1.0 (2026-09-25)

- Always-on rules for every supported agent, generated from the five Cursor rules: Claude Code (`.claude/rules/`), Windsurf (`.windsurf/rules/`), GitHub Copilot (`copilot-instructions.md`), OpenAI Codex (`AGENTS.md`), Gemini CLI (`GEMINI.md`). Before this release the rules only worked in Cursor.
- Claude Code plugin: `/plugin marketplace add apisec-inc/apisec-skills` then `/plugin install apisec@apisec-skills`.
- `scripts/build-agent-rules.py` keeps the per-agent rule files in sync with `rules/*.mdc`.
- README: install commands pointed at this repository (they cloned a repository name that no longer exists), per-agent install steps, repository layout.
- Wording cleanup in the rule sources; behaviour unchanged.

## 1.0.0 (2026-03-12)

- Initial release: five Cursor rules and six Agent Skills covering the OWASP API Security Top 10 2023.
