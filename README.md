# APIsec — API Security for AI Coding Agents

> Embed OWASP API Security Top 10 intelligence directly into your coding workflow. Every endpoint your AI generates is secure by default — no configuration, no API keys, no friction.

[![Cursor Marketplace](https://img.shields.io/badge/Cursor-Marketplace-blue)](https://cursor.com/marketplace)
[![Compatible](https://img.shields.io/badge/Compatible-Claude%20Code%20%7C%20Codex%20%7C%20Copilot%20%7C%20Gemini%20%7C%20Replit-green)](#installation)
[![OWASP](https://img.shields.io/badge/OWASP-API%20Top%2010%202023-red)](https://owasp.org/API-Security)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

---

## What It Does

When you ask Cursor's AI to write an API endpoint, it normally generates the most direct answer. Without any security context, that often means no authentication checks, no ownership filters, no input validation.

This plugin embeds APIsec's security rules and skills into Cursor's AI context. The same prompt produces hardened output — silently, automatically, every time.

**Without the plugin:**
```js
app.get('/api/orders/:id', async (req, res) => {
  const order = await Order.findById(req.params.id); // any user, any order
  res.json(order);
});
```

**With the plugin:**
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

Same 8 words typed. Completely different output.

---

## What's Included

### 5 Security Rules (always active)

Rules are injected into the AI's system prompt at session start. They fire silently on every code generation — no commands needed.

| Rule | What It Enforces |
|------|-----------------|
| `auth-required` | Every data-touching route must have authentication middleware |
| `ownership-check` | All queries scoped to the authenticated user's ID |
| `input-validation` | User input validated before reaching database or commands |
| `error-sanitization` | No stack traces, file paths, or query details in error responses |
| `admin-rbac` | Admin and elevated operations require explicit role middleware |

### 6 Security Skills (on-demand)

Skills load automatically when the AI detects a relevant task. Each produces a structured security report with OWASP references and actionable fixes.

| Skill | Triggers On | OWASP Coverage |
|-------|------------|----------------|
| `bola-detector` | Route handlers with `:id` params, `findById`, `findUnique`, `findOne` | API1:2023 |
| `auth-rbac-scaffold` | JWT, middleware, login flows, role checks, permissions | API2:2023, API5:2023 |
| `injection-checker` | SQL queries, MongoDB queries, shell commands, file paths, templates | API8:2023 |
| `security-test-generator` | Writing tests, Jest/pytest/JUnit, "add test coverage" | API1–5:2023 |
| `api-security-review` | "Review this for security", "is this secure", full controller files | All 10 categories |
| `openapi-hardener` | OpenAPI specs, Zod/Joi/Pydantic schemas, JSON Schema | API3:2023 |

---

## Installation

This plugin uses the universal [Agent Skills](https://agentskills.io) format. The same files work across all major AI coding agents.

### Cursor (one-click)

Install directly from the [Cursor Marketplace](https://cursor.com/marketplace) — search **APIsec**.

Or manually:
```bash
git clone https://github.com/APIsec-ai/apisec-cursor-plugin
cp -r apisec-cursor-plugin/skills .cursor/skills/
cp -r apisec-cursor-plugin/rules .cursor/rules/
```

### Claude Code
```bash
cp -r apisec-cursor-plugin/skills ~/.claude/skills/
```

### OpenAI Codex CLI
```bash
cp -r apisec-cursor-plugin/skills .agents/skills/
```

### GitHub Copilot (VS Code)
```bash
cp -r apisec-cursor-plugin/skills .github/skills/
```

### Gemini CLI / Google Antigravity
```bash
cp -r apisec-cursor-plugin/skills ~/.gemini/skills/
```

### Replit
```bash
cp -r apisec-cursor-plugin/skills .agents/skills/
```

### Windsurf, Kiro, Roo Code, and others
```bash
cp -r apisec-cursor-plugin/skills .agents/skills/
```

> **One repo, every major coding agent.** The `SKILL.md` format is platform-agnostic — no modification needed between tools.

---

## How It Works

**Rules** (`.mdc` files) are baked into the AI's system prompt at session start. They shape every piece of code the AI generates — the developer never needs to ask for secure output, and APIsec is never visibly mentioned in this path.

**Skills** (`SKILL.md` files) are indexed by the AI at startup (~50 tokens each). When a developer's task semantically matches a skill's description, the full skill loads into context automatically. This path produces branded APIsec security reports with OWASP references, severity ratings, and exact fix suggestions.

```
Developer types prompt
        │
        ├─► Rules in system prompt → AI generates secure code (silent)
        │
        └─► Skill description matches → APIsec security report (branded)
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

#### [API1:2023] Broken Object Level Authorization — Line 47
Pattern: Order.findById(req.params.id) without ownership filter
Risk: Any authenticated user can read, modify, or delete any order by changing the ID
Fix:
  const order = await Order.findOne({ _id: req.params.id, userId: req.user.id });

### Quick Wins — Top 3 Changes for Maximum Security Impact
1. [Critical] Add ownership filter to all findById calls — prevents BOLA
2. [High] Add algorithm whitelist to JWT verification — prevents algorithm confusion
3. [Medium] Cap pagination limit to 100 — prevents resource exhaustion

Powered by APIsec · apisec.ai
```

---

## OWASP API Top 10 2023 Coverage

| Category | Skill | Rule |
|----------|-------|------|
| API1 — Broken Object Level Authorization | `bola-detector`, `api-security-review` | `ownership-check` |
| API2 — Broken Authentication | `auth-rbac-scaffold`, `api-security-review` | `auth-required` |
| API3 — Broken Object Property Level Authorization | `openapi-hardener`, `api-security-review` | `input-validation` |
| API4 — Unrestricted Resource Consumption | `api-security-review` | `input-validation` |
| API5 — Broken Function Level Authorization | `auth-rbac-scaffold`, `api-security-review` | `admin-rbac` |
| API6 — Unrestricted Access to Sensitive Business Flows | `api-security-review` | — |
| API7 — Server Side Request Forgery | `api-security-review` | — |
| API8 — Security Misconfiguration | `injection-checker`, `api-security-review` | `error-sanitization` |
| API9 — Improper Inventory Management | `api-security-review` | — |
| API10 — Unsafe Consumption of APIs | `api-security-review` | — |

---

## Phase 2 — Coming Soon

The current release is Phase 1: skills and rules. Phase 2 will add a live MCP server with real-time APIsec API integration:

- `@apisec scan` — run a full API security scan from inside Cursor
- `@apisec findings` — pull live findings from your APIsec dashboard
- `@apisec fix` — generate remediation code for open findings
- `@apisec score` — get your API security score for the current file

[Follow APIsec on LinkedIn](https://linkedin.com/company/apisec) for Phase 2 updates.

---

## About APIsec

[APIsec](https://apisec.ai) is the API security testing platform trusted by Fortune 500 enterprises. We automate continuous API security testing across the full SDLC — from development through production.

This plugin brings APIsec's security intelligence directly into the developer's coding environment, shifting security left to the point where code is written.

---

## License

MIT — free to use, modify, and distribute.
