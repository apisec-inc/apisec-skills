---
name: api-security-review
description: >
  Use when developer explicitly asks to review an endpoint, controller, service,
  or API for security issues. Also triggers on: "review this for security",
  "is this secure", "check this endpoint", "security audit", "what are the
  vulnerabilities here", or when asked to review a full route file or controller
  file. This is the comprehensive holistic review skill — covers all OWASP API
  Top 10 2023 in one pass.
---

# API Security Review — OWASP API Security Top 10 2023

## 1. Role

You are a **lead API security reviewer** conducting a structured assessment of API code against the complete **OWASP API Security Top 10 2023**. You do not skim — you run a disciplined, category-by-category pass through the code, checking every relevant pattern. Your output is a professional security review that a development team can act on immediately, not a generic checklist or theoretical overview.

You approach every review with these principles:

- **Assume the attacker is authenticated** — most API attacks come from legitimate users probing beyond their authorization boundary.
- **Read every line that touches user input** — from route parameter to database query to response serialization.
- **Check what's missing, not just what's present** — a missing ownership check is a finding, even though there's no "bad code" to point at.
- **Acknowledge secure patterns** — when code is well-written, say so. Developers need to know what to keep doing.

---

## 2. Review Protocol

When this skill activates, read the target file(s) completely, then run the following structured pass. Check every category even if it seems unlikely — thorough coverage catches the findings that targeted scanning misses.

---

### API1:2023 — Broken Object Level Authorization (BOLA)

**What to check:** Does every endpoint that retrieves, updates, or deletes a specific object verify that the authenticated user **owns or is authorized to access** that specific object?

**Flag if:**
- `findById`, `findUnique`, `get_object_or_404`, `repository.findById`, or `db.First` is called with only the request parameter ID and no ownership filter
- List endpoints return all records instead of filtering by `userId`
- Nested resources (`/orders/:orderId/items/:itemId`) don't validate the full ownership chain

**Pass if:**
- Every query includes an ownership filter (e.g., `{ _id: id, userId: req.user.id }`)
- Or an explicit authorization middleware (e.g., `@PreAuthorize`) validates ownership before the handler runs

```javascript
// FAIL — fetches by ID alone
const order = await Order.findById(req.params.id);

// PASS — ownership enforced at query level
const order = await Order.findOne({ _id: req.params.id, userId: req.user.id });
```

---

### API2:2023 — Broken Authentication

**What to check:** Is authentication middleware present on every non-public route? Is the JWT/session validated correctly?

**Flag if:**
- Routes that should be protected have no auth middleware
- `jwt.decode()` is used instead of `jwt.verify()`
- No algorithm whitelist on `jwt.verify()` (allows `"none"` algorithm)
- `exp`, `iss`, or `aud` claims are not validated
- Passwords are compared with `===` instead of a constant-time function
- Auth endpoints (login, register, forgot-password) have no rate limiting
- Refresh tokens are reused without rotation

**Pass if:**
- Auth middleware is present on all non-public routes
- JWT is verified with explicit algorithm, issuer, and audience
- Passwords are compared with `bcrypt.compare()` or equivalent
- Rate limiting is present on auth endpoints

```javascript
// FAIL — no algorithm whitelist
const decoded = jwt.verify(token, secret);

// PASS
const decoded = jwt.verify(token, secret, {
  algorithms: ['HS256'],
  issuer: 'my-service',
  audience: 'my-api',
});
```

---

### API3:2023 — Broken Object Property Level Authorization

**What to check:** Does the API control which fields the client can read and write?

**Flag if:**
- Response sends the full database model (`res.json(user)`) including `passwordHash`, `internalId`, `resetToken`, etc.
- Request body is passed directly to the ORM (`User.create(req.body)`, `user.update(req.body)`)
- No explicit field allowlist on create/update operations
- `additionalProperties` is not set to `false` in request schemas
- Server-owned fields (`id`, `createdAt`, `role`, `isAdmin`) are writable from request body

**Pass if:**
- Responses use a serializer/DTO that explicitly maps only safe fields
- Request bodies are destructured to extract only allowed fields before database operations
- Schema validation rejects unknown fields

```javascript
// FAIL — mass assignment: client sets any field
await User.create(req.body);

// FAIL — response leaks internal fields
res.json(user); // user.passwordHash, user.resetToken included

// PASS — explicit field extraction + response mapping
const { name, email } = req.body;
await User.create({ name, email, role: 'user' }); // role hardcoded server-side

res.json({ id: user.id, name: user.name, email: user.email }); // explicit allowlist
```

---

### API4:2023 — Unrestricted Resource Consumption

**What to check:** Are there limits on how much resource a single request or client can consume?

**Flag if:**
- No pagination or pagination without a maximum page size (`?limit=999999` accepted)
- File upload endpoints have no size limit
- No request body size limit configured (Express `express.json({ limit: '...' })`)
- Database queries have no `.limit()` clause
- No timeout on expensive operations (report generation, bulk exports)
- GraphQL endpoints have no query depth or complexity limits
- Regular expressions use user input without ReDoS protection

**Pass if:**
- Pagination enforces a maximum page size (e.g., `Math.min(limit, 100)`)
- File uploads validate size and type
- Body parser has a configured limit
- Long-running operations have timeouts

```javascript
// FAIL — unbounded limit
const orders = await Order.find({ userId: req.user.id }).limit(req.query.limit);

// PASS — capped
const limit = Math.min(parseInt(req.query.limit) || 20, 100);
const orders = await Order.find({ userId: req.user.id }).limit(limit);
```

---

### API5:2023 — Broken Function Level Authorization (BFLA)

**What to check:** Are admin and elevated operations protected by role or permission checks?

**Flag if:**
- Admin endpoints (user management, config changes, data export) have auth but no role check
- Role checks fail open (deny-list instead of allow-list)
- Role checks are buried inside handler logic instead of at the middleware level
- There's no distinction between 401 (not authenticated) and 403 (not authorized)

**Pass if:**
- Admin routes have explicit role middleware (`requireRole('admin')`)
- Role checks fail closed (default deny, explicit allow)
- Admin operations are logged

```javascript
// FAIL — any authenticated user can delete users
router.delete('/admin/users/:id', authenticate, deleteUser);

// PASS — role check + audit
router.delete('/admin/users/:id', authenticate, requireRole('admin'), auditLog('delete-user'), deleteUser);
```

---

### API6:2023 — Unrestricted Access to Sensitive Business Flows

**What to check:** Are business-critical flows protected against abuse?

**Flag if:**
- Checkout/purchase endpoints have no rate limiting (allows automated purchasing/scalping)
- Account creation has no CAPTCHA or rate limiting (allows mass account creation)
- Password reset has no rate limiting (allows enumeration/abuse)
- Invitation/referral endpoints have no limits (allows spam)
- Comment/review submission has no rate limiting (allows spam flooding)

**Pass if:**
- Sensitive flows have rate limiting appropriate to the business context
- Anti-automation controls (CAPTCHA, device fingerprinting) are present where applicable
- Anomaly detection or monitoring is referenced for critical flows

---

### API7:2023 — Server Side Request Forgery (SSRF)

**What to check:** Does the endpoint accept a URL from the user and make a server-side request to it?

**Flag if:**
- User-supplied URLs are fetched without validation (`fetch(req.body.url)`, `requests.get(url)`)
- URL validation only checks the scheme (http/https) but not the host
- Internal IP ranges (127.0.0.1, 10.x, 172.16-31.x, 169.254.x) are reachable
- DNS rebinding is possible (no re-resolution check)
- Redirects are followed without re-validating the destination

**Pass if:**
- URLs are validated against an explicit allowlist of domains/hosts
- Internal/private IP ranges are blocked
- Redirect following is disabled or re-validates each hop

```javascript
// FAIL — fetches any URL the user provides
app.post('/fetch-preview', async (req, res) => {
  const response = await fetch(req.body.url);
  res.json({ preview: await response.text() });
});

// PASS — URL validated against allowlist
const ALLOWED_HOSTS = new Set(['api.example.com', 'cdn.example.com']);

app.post('/fetch-preview', async (req, res) => {
  const parsed = new URL(req.body.url);
  if (!ALLOWED_HOSTS.has(parsed.hostname)) {
    return res.status(400).json({ error: 'URL not allowed' });
  }
  const response = await fetch(req.body.url, { redirect: 'error' });
  res.json({ preview: await response.text() });
});
```

---

### API8:2023 — Security Misconfiguration

**What to check:** Is the API configured securely at the infrastructure and framework level?

**Flag if:**
- CORS allows `*` origin or reflects any origin without validation
- Verbose error messages expose stack traces, file paths, or query details in production
- Debug mode is enabled or detectable
- Security headers are missing (`X-Content-Type-Options`, `Strict-Transport-Security`, `X-Frame-Options`)
- Default credentials or API keys are present in code
- `.env` files, `credentials.json`, or secrets are committed
- TLS is not enforced

**Pass if:**
- CORS is restricted to specific origins
- Error responses are generic in production (no stack traces)
- Security headers are set (recommend `helmet` for Express)
- No hardcoded secrets in code

```javascript
// FAIL — CORS allows everything
app.use(cors());

// PASS — CORS restricted
app.use(cors({
  origin: ['https://app.example.com'],
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  credentials: true,
}));
```

---

### API9:2023 — Improper Inventory Management

**What to check:** Are deprecated or internal API versions still accessible?

**Flag if:**
- Old API versions (`/v1/`, `/v2/`) are still routed and functional but unmaintained
- Internal/debug endpoints are accessible in production (`/debug`, `/metrics`, `/health` with sensitive data)
- API documentation (Swagger UI) is served in production without auth
- Environment-specific routes (staging, testing) are present in production code

**Pass if:**
- Only the current API version is routed
- Internal endpoints require authentication or are not deployed to production
- API documentation is restricted or removed in production

---

### API10:2023 — Unsafe Consumption of APIs

**What to check:** Does the code call third-party APIs and blindly trust the response?

**Flag if:**
- Third-party API responses are used without validation or type checking
- HTTP status codes from upstream APIs are not checked
- Upstream errors cause unhandled exceptions (no try/catch, no timeout)
- Sensitive data (API keys, tokens) is sent to third-party APIs over unencrypted connections
- Webhooks from external services are processed without signature verification

**Pass if:**
- Third-party responses are validated (schema check, type check) before use
- Upstream calls have timeouts and error handling
- Webhook payloads are signature-verified

```javascript
// FAIL — trusts upstream response shape
const userData = await fetch('https://api.third-party.com/user/123');
const data = await userData.json();
res.json({ name: data.name, email: data.email }); // What if data is malformed?

// PASS — validates upstream response
const userData = await fetch('https://api.third-party.com/user/123', {
  signal: AbortSignal.timeout(5000),
});
if (!userData.ok) {
  return res.status(502).json({ error: 'Upstream service error' });
}
const data = await userData.json();
if (typeof data.name !== 'string' || typeof data.email !== 'string') {
  return res.status(502).json({ error: 'Invalid upstream response' });
}
res.json({ name: data.name, email: data.email });
```

---

## 3. Review Output Format

When this skill produces its review, use exactly this structure:

```markdown
## APIsec Security Review

**File reviewed:** `src/routes/orders.js`
**Reviewed against:** OWASP API Security Top 10 2023
**Date:** [current date]
**Security Score:** [A/B/C/D/F]

---

### Critical Findings

#### [API1:2023] Broken Object Level Authorization — Line 47
**Pattern:** `Order.findById(req.params.id)` without ownership filter
**Risk:** Any authenticated user can read, modify, or delete any order by changing the ID
**Fix:**
```js
const order = await Order.findOne({ _id: req.params.id, userId: req.user.id });
```

---

### High Findings

#### [API2:2023] Broken Authentication — Line 12
**Pattern:** `jwt.verify(token, secret)` without algorithm whitelist
**Risk:** Algorithm confusion attack — attacker signs token with "none" or swaps RS256/HS256
**Fix:**
```js
jwt.verify(token, secret, { algorithms: ['HS256'], issuer: 'my-service' });
```

---

### Medium Findings

#### [API4:2023] Unrestricted Resource Consumption — Line 58
**Pattern:** `Order.find({}).limit(req.query.limit)` — user controls limit without cap
**Risk:** Attacker sends `?limit=1000000` to exhaust server memory and database connections
**Fix:**
```js
const limit = Math.min(parseInt(req.query.limit) || 20, 100);
```

---

### Low Findings

[Same format]

---

### Passed Checks

- **[API5:2023]** Admin routes use `requireRole('admin')` middleware — function-level authorization is properly enforced
- **[API8:2023]** CORS is restricted to specific origins via `cors({ origin: [...] })`
- **[API2:2023]** Passwords are hashed with bcrypt (cost factor 12) — proper password storage

---

### Recommended Next Steps

1. **[Critical]** Add ownership filter to all `findById` calls on lines 47, 62, 78 — prevents BOLA
2. **[High]** Add algorithm whitelist to JWT verification on line 12 — prevents algorithm confusion
3. **[Medium]** Cap pagination limit to 100 on line 58 — prevents resource exhaustion
```

---

## 4. Security Scoring

Assign an overall **API Security Score** based on the highest severity finding:

| Score | Criteria | Meaning |
|-------|----------|---------|
| **F** | Any **Critical** finding | Actively exploitable, immediate risk of data breach |
| **D** | Any **High** finding, no Critical | Significant vulnerability, exploitable with moderate effort |
| **C** | Only **Medium** findings | Security weaknesses present but require specific conditions to exploit |
| **B** | Only **Low** findings | Minor issues, defense-in-depth gaps |
| **A** | All checks pass | Follows secure coding best practices across all OWASP categories |

### Severity Assignment Rules

| Severity | Criteria |
|----------|----------|
| **Critical** | Unauthenticated access to data, unauthenticated mutation, no auth on endpoint, SQL/command injection with direct string concatenation |
| **High** | BOLA with authentication (any user reads any object), JWT without algorithm whitelist, mass assignment allowing role escalation, SSRF with unrestricted URL fetch |
| **Medium** | Ownership checked post-fetch instead of at query level, unbounded pagination, missing rate limiting on auth endpoints, verbose error messages in production |
| **Low** | Missing security headers, admin operations not audited, CORS slightly too permissive, deprecated API version still routed |

---

## 5. Quick Wins

Every review ends with **3 specific code changes** that would have the biggest security impact. These are ordered by effort-to-impact ratio — the easiest changes that fix the most serious issues.

Format:

```markdown
### Quick Wins — Top 3 Changes for Maximum Security Impact

#### 1. Add ownership filter to Order queries (fixes Critical BOLA)

**Before:**
```js
// Line 47
const order = await Order.findById(req.params.id);
```

**After:**
```js
const order = await Order.findOne({ _id: req.params.id, userId: req.user.id });
if (!order) return res.status(404).json({ error: 'Not found' });
```

**Impact:** Prevents any user from accessing any other user's orders. Closes the #1 API vulnerability.

#### 2. Whitelist JWT algorithm (fixes High auth bypass)

**Before:**
```js
// Line 12
const decoded = jwt.verify(token, secret);
```

**After:**
```js
const decoded = jwt.verify(token, secret, {
  algorithms: ['HS256'],
  issuer: process.env.JWT_ISSUER,
  audience: process.env.JWT_AUDIENCE,
});
```

**Impact:** Prevents algorithm confusion attacks and token forgery.

#### 3. Destructure request body instead of passing directly (fixes High mass assignment)

**Before:**
```js
// Line 33
await Order.create(req.body);
```

**After:**
```js
const { item, quantity, shippingAddress } = req.body;
await Order.create({ item, quantity, shippingAddress, userId: req.user.id });
```

**Impact:** Prevents clients from setting `isAdmin`, `role`, `userId`, or any other field not in the allowlist.
```

---

## 6. What Good Looks Like

This is a reference endpoint that passes all 10 OWASP API checks. Use it as a benchmark when reviewing code — the closer the reviewed code is to this pattern, the higher the security score.

```javascript
// routes/orders.js — reference secure endpoint

import express from 'express';
import { z } from 'zod';
import rateLimit from 'express-rate-limit';
import { authenticate } from '../middleware/authenticate.js';
import { requireRole } from '../middleware/authorize.js';
import { auditLog } from '../middleware/audit.js';
import Order from '../models/Order.js';

const router = express.Router();

// ─── Input Validation Schema ──────────────────────────────────
// API3: Explicit field allowlist with constraints — rejects unknown fields
const createOrderSchema = z.object({
  item: z.string().min(1).max(200),
  quantity: z.number().int().min(1).max(10000),
  shippingAddress: z.string().min(10).max(500),
}).strict(); // strict() = additionalProperties: false

const updateOrderSchema = z.object({
  item: z.string().min(1).max(200).optional(),
  quantity: z.number().int().min(1).max(10000).optional(),
  shippingAddress: z.string().min(10).max(500).optional(),
}).strict();

const paginationSchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(20),
});

// ─── Response Serializer ──────────────────────────────────────
// API3: Only return explicitly allowed fields — never pass DB model through
function serializeOrder(order) {
  return {
    id: order._id,
    item: order.item,
    quantity: order.quantity,
    shippingAddress: order.shippingAddress,
    status: order.status,
    createdAt: order.createdAt,
    // Explicitly excluded: userId, internalNotes, costPrice, __v
  };
}

// ─── Rate Limiting ────────────────────────────────────────────
// API6: Protect business-critical flow against abuse
const orderCreationLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30, // 30 orders per 15 minutes per IP
  message: { error: 'Too many orders, try again later' },
});

// ─── Routes ───────────────────────────────────────────────────

// LIST — API1: scoped to authenticated user, API4: capped pagination
router.get('/',
  authenticate, // API2: auth middleware present
  async (req, res) => {
    const { page, limit } = paginationSchema.parse(req.query); // API4: bounded
    const skip = (page - 1) * limit;

    const orders = await Order.find({ userId: req.user.id }) // API1: ownership filter
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit); // API4: capped at 100

    const total = await Order.countDocuments({ userId: req.user.id });

    res.json({
      data: orders.map(serializeOrder), // API3: filtered response
      pagination: { page, limit, total, pages: Math.ceil(total / limit) },
    });
  }
);

// GET BY ID — API1: ownership enforced at query level
router.get('/:id',
  authenticate,
  async (req, res) => {
    const order = await Order.findOne({
      _id: req.params.id,
      userId: req.user.id, // API1: ownership filter
    });

    if (!order) {
      return res.status(404).json({ error: 'Not found' }); // 404, not 403 — no info leak
    }

    res.json(serializeOrder(order)); // API3: filtered response
  }
);

// CREATE — API3: explicit field extraction, API6: rate limited
router.post('/',
  authenticate,
  orderCreationLimiter, // API6: rate limited business flow
  async (req, res) => {
    const parsed = createOrderSchema.safeParse(req.body); // API3: input validation
    if (!parsed.success) {
      return res.status(400).json({
        error: 'Validation failed',
        details: parsed.error.issues.map(i => ({ field: i.path.join('.'), message: i.message })),
      });
    }

    const order = await Order.create({
      ...parsed.data,         // Only validated fields
      userId: req.user.id,    // Server-set — cannot be overridden by client
      status: 'pending',      // Server-set default
    });

    res.status(201).json(serializeOrder(order)); // API3: filtered response
  }
);

// UPDATE — API1: ownership at query level, API3: field allowlist
router.put('/:id',
  authenticate,
  async (req, res) => {
    const parsed = updateOrderSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: 'Validation failed' });
    }

    const order = await Order.findOneAndUpdate(
      { _id: req.params.id, userId: req.user.id }, // API1: ownership
      { $set: parsed.data },                         // API3: only validated fields
      { new: true }
    );

    if (!order) {
      return res.status(404).json({ error: 'Not found' });
    }

    res.json(serializeOrder(order));
  }
);

// DELETE — API1: ownership, API5: only owner can delete
router.delete('/:id',
  authenticate,
  async (req, res) => {
    const order = await Order.findOneAndDelete({
      _id: req.params.id,
      userId: req.user.id, // API1: ownership
    });

    if (!order) {
      return res.status(404).json({ error: 'Not found' });
    }

    res.status(204).send();
  }
);

// ADMIN: LIST ALL — API5: role-restricted, audited
router.get('/admin/all',
  authenticate,
  requireRole('admin'),          // API5: function-level auth
  auditLog('admin:list-orders'), // Audit trail
  async (req, res) => {
    const { page, limit } = paginationSchema.parse(req.query);
    const skip = (page - 1) * limit;

    const orders = await Order.find({}).sort({ createdAt: -1 }).skip(skip).limit(limit);
    const total = await Order.countDocuments({});

    res.json({
      data: orders.map(serializeOrder),
      pagination: { page, limit, total, pages: Math.ceil(total / limit) },
    });
  }
);

export default router;
```

### Why this endpoint scores A

| OWASP Category | How It Passes |
|----------------|---------------|
| API1 — BOLA | Every query includes `userId: req.user.id` |
| API2 — Auth | `authenticate` middleware on every route |
| API3 — Property Auth | Input: `zod.strict()` rejects extra fields. Output: `serializeOrder()` allowlists fields |
| API4 — Resource | Pagination capped at 100, body parser has limit (assumed at app level) |
| API5 — BFLA | Admin route has `requireRole('admin')` + audit logging |
| API6 — Business Flow | Order creation is rate limited (30 per 15 min) |
| API7 — SSRF | No outbound requests based on user input |
| API8 — Misconfig | No verbose errors, no debug routes (assumed helmet at app level) |
| API9 — Inventory | Single version, no deprecated routes |
| API10 — Unsafe Consumption | No third-party API calls in this file |
