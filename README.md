# APIsec Skills: API Security for AI Coding Agents

> Put OWASP API Security Top 10 intelligence inside your coding agent. Every endpoint the agent generates is secure by default, with nothing to configure, no API keys, and nothing leaving your machine.

[![Agent Skills](https://img.shields.io/badge/Agent%20Skills-open%20format-blue)](https://agentskills.io)
[![Compatible](https://img.shields.io/badge/Works%20with-Cursor%20%7C%20Claude%20Code%20%7C%20Copilot%20%7C%20Codex%20%7C%20Gemini%20%7C%20Windsurf-green)](#installation)
[![OWASP](https://img.shields.io/badge/OWASP-API%20Top%2010%202023-red)](https://owasp.org/API-Security)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

---

## What It Does

Ask your coding agent to "add an endpoint to fetch orders by id". Without security context it returns the most direct answer, which usually means no authentication check, no ownership filter, and no input validation.

APIsec Skills embed security rules and skills into the agent's context. The same prompt produces hardened output, silently and automatically, every time.

**Without APIsec Skills:**
```js
app.get('/api/orders/:id', async (req, res) => {
  const order = await Order.findById(req.params.id); // any user, any order
  res.json(order);
});
```

**With APIsec Skills:**
```js
app.get('/api/orders/:id', authenticate, async (req, res) => {
  const order = await Order.findOne({
    _id: req.params.id,
    userId: req.user.id,   // ownership enforced
  });
  if (!order) return res.status(404).json({ error: 'Not found' });
  res.json(serializeOrder(order));  // filtered response
});
```

Same eight words typed. Completely different output.

---

## What's Included

### 5 Security Rules (always active)

Rules sit in the agent's system context from the start of the session and shape every code generation. No commands are needed. The rule sources live in `rules/`, and ready-to-copy versions in each agent's native format live under `agents/` (see [Installation](#installation)).

| Rule | What It Enforces |
|------|-----------------|
| `auth-required` | Every data-touching route must have authentication middleware |
| `ownership-check` | All queries scoped to the authenticated user's ID |
| `input-validation` | User input validated before reaching database or commands |
| `error-sanitization` | No stack traces, file paths, or query details in error responses |
| `admin-rbac` | Admin and elevated operations require explicit role middleware |

### 6 Security Skills (on-demand)

Skills load automatically when the agent detects a relevant task. Each produces a structured security report with OWASP references and actionable fixes.

| Skill | Triggers On | OWASP Coverage |
|-------|------------|----------------|
| `bola-detector` | Route handlers with `:id` params, `findById`, `findUnique`, `findOne` | API1:2023 |
| `auth-rbac-scaffold` | JWT, middleware, login flows, role checks, permissions | API2:2023, API5:2023 |
| `injection-checker` | SQL queries, MongoDB queries, shell commands, file paths, templates | API8:2023 |
| `security-test-generator` | Writing tests, Jest/pytest/JUnit, "add test coverage" | API1 to API5:2023 |
| `api-security-review` | "Review this for security", "is this secure", full controller files | All 10 categories |
| `openapi-hardener` | OpenAPI specs, Zod/Joi/Pydantic schemas, JSON Schema | API3:2023 |

---

## Installation

The skills use the open [Agent Skills](https://agentskills.io) format, so the same `SKILL.md` files work in every major coding agent. The always-on rules are agent-specific files, and this repository ships a ready-made set for each agent.

Clone once:
```bash
git clone https://github.com/apisec-inc/apisec-skills
cd apisec-skills
```

### Claude Code

Install as a plugin (skills only, one command, updates from this repository):
```
/plugin marketplace add apisec-inc/apisec-skills
/plugin install apisec@apisec-skills
```
Or copy the skills by hand:
```bash
cp -r skills/* ~/.claude/skills/          # personal, every project
# or: cp -r skills/* .claude/skills/       # this project only
```
Add the always-on rules to your project:
```bash
mkdir -p .claude/rules && cp agents/claude-code/rules/*.md .claude/rules/
```

### Cursor

```bash
cp -r skills .cursor/skills/
cp -r rules  .cursor/rules/
```
A `.cursor-plugin/plugin.json` manifest is included for the Cursor plugin format.

### GitHub Copilot

```bash
cp -r skills .github/skills/               # also read from .agents/skills/
cp agents/copilot/copilot-instructions.md .github/copilot-instructions.md
```

### OpenAI Codex CLI

```bash
cp -r skills .agents/skills/
cp agents/codex/AGENTS.md AGENTS.md         # or append to an existing AGENTS.md
```

### Gemini CLI

```bash
cp -r skills .agents/skills/                # or ~/.gemini/skills/
cp agents/gemini/GEMINI.md GEMINI.md        # or append to an existing GEMINI.md
```

### Windsurf

```bash
cp -r skills .agents/skills/
mkdir -p .windsurf/rules && cp agents/windsurf/rules/*.md .windsurf/rules/
```

### Replit, Kiro, Roo Code, and others

```bash
cp -r skills .agents/skills/
```
For the rules, use whichever project instruction file your agent reads (`AGENTS.md` is the most common) and paste in `agents/codex/AGENTS.md`.

> **One repository, every major coding agent.** The skills need no modification between tools, and the rules are generated from one set of sources by `scripts/build-agent-rules.py`, so every agent gets identical guidance.

---

## How It Works

**Rules** are loaded into the agent's system context at session start. They shape every piece of code the agent generates, so the developer never needs to ask for secure output, and APIsec is never mentioned in this path.

**Skills** (`SKILL.md` files) are indexed by the agent at startup, with only the short description in context. When a developer's task matches a skill's description, the full skill loads automatically. This path produces APIsec security reports with OWASP references, severity ratings, and exact fix suggestions.

```
Developer types prompt
        |
        +-> Rules in system prompt      -> agent generates secure code (silent)
        |
        +-> Skill description matches   -> APIsec security report
```

---

## Example Output

When the `api-security-review` skill fires on a controller file:

```
## APIsec Security Review

File reviewed: src/routes/orders.js
Reviewed against: OWASP API Security Top 10 2023
Security Score: D

### Critical Findings

#### [API1:2023] Broken Object Level Authorization, line 47
Pattern: Order.findById(req.params.id) without ownership filter
Risk: Any authenticated user can read, modify, or delete any order by changing the ID
Fix:
  const order = await Order.findOne({ _id: req.params.id, userId: req.user.id });

### Quick Wins: Top 3 Changes for Maximum Security Impact
1. [Critical] Add ownership filter to all findById calls (prevents BOLA)
2. [High] Add algorithm whitelist to JWT verification (prevents algorithm confusion)
3. [Medium] Cap pagination limit to 100 (prevents resource exhaustion)

Powered by APIsec · apisec.ai
```

---

## OWASP API Top 10 2023 Coverage

| Category | Skill | Rule |
|----------|-------|------|
| API1 Broken Object Level Authorization | `bola-detector`, `api-security-review` | `ownership-check` |
| API2 Broken Authentication | `auth-rbac-scaffold`, `api-security-review` | `auth-required` |
| API3 Broken Object Property Level Authorization | `openapi-hardener`, `api-security-review` | `input-validation` |
| API4 Unrestricted Resource Consumption | `api-security-review` | `input-validation` |
| API5 Broken Function Level Authorization | `auth-rbac-scaffold`, `api-security-review` | `admin-rbac` |
| API6 Unrestricted Access to Sensitive Business Flows | `api-security-review` | |
| API7 Server Side Request Forgery | `api-security-review` | |
| API8 Security Misconfiguration | `injection-checker`, `api-security-review` | `error-sanitization` |
| API9 Improper Inventory Management | `api-security-review` | |
| API10 Unsafe Consumption of APIs | `api-security-review` | |

---

## Repository Layout

```
skills/                      six Agent Skills (SKILL.md each), portable to every agent
rules/                       five rule sources (.mdc), generated into every agent's format
agents/
  claude-code/rules/         generated: Claude Code .claude/rules/ files
  windsurf/rules/            generated: Windsurf .windsurf/rules/ files
  copilot/                   generated: .github/copilot-instructions.md
  codex/                     generated: AGENTS.md
  gemini/                    generated: GEMINI.md
scripts/build-agent-rules.py regenerates agents/ from rules/
.claude-plugin/              Claude Code plugin and marketplace manifests
.cursor-plugin/              Cursor plugin manifest
```

To change a rule, edit the `.mdc` file in `rules/` and run `python3 scripts/build-agent-rules.py`.

---

## License

MIT. Free to use, modify, and distribute.
