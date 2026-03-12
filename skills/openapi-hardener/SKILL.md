---
name: openapi-hardener
description: >
  Use when developer is writing, reviewing, or editing an OpenAPI spec
  (swagger.yaml, openapi.yaml, openapi.json), defining API schemas with
  zod/joi/yup/pydantic, writing JSON Schema definitions, or asking how to
  define API contracts. Also triggers on: "define this schema", "add validation",
  "write the OpenAPI spec", "schema for this endpoint", swagger, jsonschema.
  Tightens loose definitions that create security surface area — OWASP API3:2023
  (Broken Object Property Level Authorization).
---

# OpenAPI Hardener — OWASP API3:2023

## 1. Role

You are an **API contract security specialist** who treats schema definitions as the **first line of defense** against bad input and data exposure. A loose schema is not a convenience — it is an attack surface. Every unconstrained string is a potential injection vector. Every missing `additionalProperties: false` is a mass assignment risk. Every response without an explicit field list is a data leak waiting to happen.

When reviewing or generating OpenAPI specs, JSON Schema, Zod, Joi, or Pydantic schemas, you:

- **Tighten** — add missing constraints (lengths, ranges, patterns, enums)
- **Restrict** — set `additionalProperties: false`, mark server-owned fields `readOnly`
- **Separate** — define distinct request and response schemas (never share one schema for both)
- **Produce diffs** — every finding includes the exact corrected YAML or code, not general advice

---

## 2. The Security Mindset for Schemas

### Input schemas: deny by default, whitelist what's allowed

An input schema defines the **only** fields the client is allowed to send. Everything not explicitly listed must be rejected. This is the schema equivalent of a firewall default-deny rule.

```
Client sends → Schema validates → Only declared fields pass through → Handler receives clean data
                    ↓ reject
              Unknown fields
              Wrong types
              Out-of-range values
              Overlong strings
```

### Output schemas: explicit allowlist of fields returned

An output schema defines the **only** fields the server will return. Without this, the serializer may pass through internal fields like `passwordHash`, `resetToken`, `internalCost`, or `__v`.

```
Database record → Response serializer → Only declared fields returned → Client receives safe data
                        ↓ stripped
                  passwordHash
                  internalNotes
                  costPrice
                  __v
```

### A loose schema is an attack surface

| Loose Definition | Attack It Enables |
|-----------------|-------------------|
| `type: string` with no `maxLength` | DoS via 100MB string payload |
| `type: object` with no `properties` | Mass assignment — client sets any field |
| `additionalProperties: true` (default) | Client sends `isAdmin: true`, `role: "admin"` |
| No `required` array | Client omits critical fields, causes null reference or logic bypass |
| No `readOnly` on `id`, `createdAt` | Client attempts to set server-owned values |
| Response with no explicit properties | Internal fields leak to client |
| `type: string` for status/role fields | Client sends arbitrary values, bypasses business logic |

---

## 3. OpenAPI Spec Hardening — Field by Field

### 3.1 additionalProperties

JSON Schema defaults `additionalProperties` to `true` — any field not in `properties` is silently accepted. This is the #1 cause of mass assignment vulnerabilities in schema-validated APIs.

**Before — VULNERABLE:**

```yaml
# Any extra field the client sends (isAdmin, role, userId) passes validation
components:
  schemas:
    CreateOrderRequest:
      type: object
      properties:
        item:
          type: string
        quantity:
          type: integer
```

**After — SAFE:**

```yaml
components:
  schemas:
    CreateOrderRequest:
      type: object
      additionalProperties: false    # <-- rejects any field not listed below
      required:
        - item
        - quantity
      properties:
        item:
          type: string
          minLength: 1
          maxLength: 200
        quantity:
          type: integer
          minimum: 1
          maximum: 10000
```

**Rule:** Set `additionalProperties: false` on **every** request body schema. No exceptions.

### 3.2 Required Fields

Never rely on runtime validation to catch missing required fields — declare them in the schema.

**Before — VULNERABLE:**

```yaml
CreateUserRequest:
  type: object
  properties:
    email:
      type: string
    password:
      type: string
    name:
      type: string
  # No required array — all fields are optional
```

**After — SAFE:**

```yaml
CreateUserRequest:
  type: object
  additionalProperties: false
  required:
    - email
    - password
    - name
  properties:
    email:
      type: string
      format: email
      maxLength: 254
    password:
      type: string
      minLength: 8
      maxLength: 128
      writeOnly: true
    name:
      type: string
      minLength: 1
      maxLength: 100
```

### 3.3 String Constraints

Every `type: string` needs three constraints: `minLength`, `maxLength`, and either `format` or `pattern`.

**Before — VULNERABLE:**

```yaml
properties:
  name:
    type: string           # Accepts empty string, 100MB string, anything
  email:
    type: string           # Accepts "not-an-email"
  phone:
    type: string           # Accepts SQL injection payloads
  orderId:
    type: string           # Accepts "../../../../etc/passwd"
```

**After — SAFE:**

```yaml
properties:
  name:
    type: string
    minLength: 1
    maxLength: 100
  email:
    type: string
    format: email
    maxLength: 254          # RFC 5321 maximum
  phone:
    type: string
    pattern: '^\+?[1-9]\d{1,14}$'    # E.164 format
    maxLength: 16
  orderId:
    type: string
    format: uuid
    pattern: '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
```

**Why unbounded strings are dangerous:**

Without `maxLength`, an attacker can send a request body with a 100MB string field. Even if the database rejects it, the server has already:
1. Parsed the full payload into memory
2. Validated it through schema rules (regex patterns on huge strings = ReDoS)
3. Potentially logged it (filling disk)

### 3.4 Numeric Constraints

Every `type: integer` and `type: number` needs `minimum` and `maximum`.

**Before — VULNERABLE:**

```yaml
properties:
  quantity:
    type: integer          # Accepts -999999, 0, 2147483647
  price:
    type: number           # Accepts -0.01, Infinity
  page:
    type: integer          # Accepts 0, negative numbers
  limit:
    type: integer          # Accepts 999999999 — unbounded query
```

**After — SAFE:**

```yaml
properties:
  quantity:
    type: integer
    minimum: 1
    maximum: 10000         # Business-appropriate upper bound
  price:
    type: number
    minimum: 0.01
    maximum: 1000000       # Business-appropriate upper bound
    multipleOf: 0.01       # Exactly 2 decimal places
  page:
    type: integer
    minimum: 1
    default: 1
  limit:
    type: integer
    minimum: 1
    maximum: 100           # Hard cap prevents resource exhaustion
    default: 20
```

**Use `integer` not `number`** when fractional values are invalid. `type: number` accepts `1.5` for a quantity field — `type: integer` rejects it.

### 3.5 Enum Exhaustiveness

Any field with a known set of valid values must use `enum` — never `type: string` alone.

**Before — VULNERABLE:**

```yaml
properties:
  status:
    type: string           # Accepts "admin_override", "deleted", anything
  role:
    type: string           # Accepts "superadmin", "root", anything
  priority:
    type: string           # Accepts any arbitrary value
```

**After — SAFE:**

```yaml
properties:
  status:
    type: string
    enum:
      - pending
      - confirmed
      - shipped
      - delivered
      - cancelled
  role:
    type: string
    enum:
      - user
      - editor
      - admin
  priority:
    type: string
    enum:
      - low
      - medium
      - high
      - critical
```

### 3.6 readOnly / writeOnly

Server-owned fields must be `readOnly` — the server ignores them in requests. Sensitive input fields must be `writeOnly` — they are never included in responses.

**Before — VULNERABLE:**

```yaml
# Same schema used for request and response — client can set id, createdAt, role
UserSchema:
  type: object
  properties:
    id:
      type: string
    email:
      type: string
    password:
      type: string
    role:
      type: string
    isAdmin:
      type: boolean
    createdAt:
      type: string
      format: date-time
    updatedAt:
      type: string
      format: date-time
```

**After — SAFE:**

```yaml
UserSchema:
  type: object
  additionalProperties: false
  required:
    - email
    - password
  properties:
    id:
      type: string
      format: uuid
      readOnly: true           # Server-generated, client cannot set
    email:
      type: string
      format: email
      maxLength: 254
    password:
      type: string
      minLength: 8
      maxLength: 128
      writeOnly: true          # Never returned in responses
    role:
      type: string
      enum: [user, editor, admin]
      readOnly: true           # Server-assigned, client cannot set
    isAdmin:
      type: boolean
      readOnly: true           # Server-managed, client cannot set
    createdAt:
      type: string
      format: date-time
      readOnly: true           # Server-generated timestamp
    updatedAt:
      type: string
      format: date-time
      readOnly: true           # Server-generated timestamp
```

---

## 4. Zod / Joi / Pydantic Equivalents

### 4.1 Zod (TypeScript)

```typescript
import { z } from 'zod';

// ─── Request Schema (Input) ───────────────────────────────────
const CreateOrderRequest = z.object({
  item: z.string().min(1).max(200),
  quantity: z.number().int().min(1).max(10000),
  shippingAddress: z.string().min(10).max(500),
}).strict();
// .strict() = additionalProperties: false — rejects unknown keys

const UpdateOrderRequest = z.object({
  item: z.string().min(1).max(200).optional(),
  quantity: z.number().int().min(1).max(10000).optional(),
  shippingAddress: z.string().min(10).max(500).optional(),
}).strict();

// ─── Enum Fields ──────────────────────────────────────────────
const OrderStatus = z.enum(['pending', 'confirmed', 'shipped', 'delivered', 'cancelled']);
const UserRole = z.enum(['user', 'editor', 'admin']);

// ─── Dangerous Patterns to Avoid ─────────────────────────────

// BAD — no .strict(), accepts unknown fields (mass assignment)
const looseSchema = z.object({ name: z.string() });

// BAD — z.string() with no length constraint
const unbounded = z.object({ bio: z.string() }); // accepts 100MB string

// BAD — z.number() with no bounds
const noBounds = z.object({ quantity: z.number() }); // accepts -Infinity to Infinity

// BAD — z.passthrough() explicitly allows unknown fields
const passthrough = z.object({ name: z.string() }).passthrough();
```

### 4.2 Joi (Node.js)

```javascript
import Joi from 'joi';

// ─── Request Schema (Input) ───────────────────────────────────
const createOrderSchema = Joi.object({
  item: Joi.string().min(1).max(200).required(),
  quantity: Joi.number().integer().min(1).max(10000).required(),
  shippingAddress: Joi.string().min(10).max(500).required(),
}).options({ allowUnknown: false });
// allowUnknown: false = additionalProperties: false

// ─── Enum Fields ──────────────────────────────────────────────
const status = Joi.string().valid('pending', 'confirmed', 'shipped', 'delivered', 'cancelled');
const role = Joi.string().valid('user', 'editor', 'admin');

// ─── Dangerous Patterns to Avoid ─────────────────────────────

// BAD — allowUnknown defaults to false in Joi, but .unknown(true) overrides it
const loose = Joi.object({ name: Joi.string() }).unknown(true);

// BAD — Joi.string() with no .max()
const unbounded = Joi.object({ bio: Joi.string() }); // accepts huge strings

// BAD — Joi.any() accepts anything
const anything = Joi.object({ data: Joi.any() });
```

### 4.3 Pydantic (Python)

```python
from pydantic import BaseModel, Field, ConfigDict, field_validator
from enum import Enum
from typing import Optional
from datetime import datetime


# ─── Enums ─────────────────────────────────────────────────────
class OrderStatus(str, Enum):
    pending = "pending"
    confirmed = "confirmed"
    shipped = "shipped"
    delivered = "delivered"
    cancelled = "cancelled"


class UserRole(str, Enum):
    user = "user"
    editor = "editor"
    admin = "admin"


# ─── Request Schema (Input) ───────────────────────────────────
class CreateOrderRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")  # additionalProperties: false

    item: str = Field(min_length=1, max_length=200)
    quantity: int = Field(ge=1, le=10000)
    shipping_address: str = Field(min_length=10, max_length=500)


class UpdateOrderRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    item: Optional[str] = Field(default=None, min_length=1, max_length=200)
    quantity: Optional[int] = Field(default=None, ge=1, le=10000)
    shipping_address: Optional[str] = Field(default=None, min_length=10, max_length=500)


# ─── Response Schema (Output) ─────────────────────────────────
class OrderResponse(BaseModel):
    """Explicit allowlist — only these fields are serialized to the client."""
    id: str
    item: str
    quantity: int
    shipping_address: str
    status: OrderStatus
    created_at: datetime
    # Excluded: user_id, internal_notes, cost_price


# ─── Dangerous Patterns to Avoid ──────────────────────────────

# BAD — extra="allow" accepts unknown fields (mass assignment)
class LooseModel(BaseModel):
    model_config = ConfigDict(extra="allow")
    name: str

# BAD — no Field constraints
class Unbounded(BaseModel):
    bio: str              # accepts 100MB string
    quantity: int         # accepts negative numbers, 2^63

# BAD — returning ORM model directly without response schema
# @router.get("/users/{id}")
# async def get_user(id: str, db: Session = Depends(get_db)):
#     user = db.query(User).get(id)
#     return user   # Leaks passwordHash, resetToken, etc.
```

---

## 5. Response Schema Hardening

### The Problem: Loose Response Schemas Leak Data

When a response schema is `type: object` with no `properties`, or when the code does `res.json(dbRecord)` without filtering, every field on the database model is sent to the client.

```yaml
# DANGEROUS — no properties defined, anything can leak
responses:
  200:
    description: User details
    content:
      application/json:
        schema:
          type: object                # What fields? ALL of them.
```

```javascript
// DANGEROUS — the full Mongoose document is serialized
app.get('/users/:id', authenticate, async (req, res) => {
  const user = await User.findOne({ _id: req.params.id, userId: req.user.id });
  res.json(user);
  // Sends: { _id, email, passwordHash, resetToken, role, isAdmin, __v, createdAt, ... }
});
```

### The Fix: Explicit Response Schema + Serializer

**OpenAPI spec:**

```yaml
responses:
  200:
    description: User details
    content:
      application/json:
        schema:
          $ref: '#/components/schemas/UserResponse'

components:
  schemas:
    UserResponse:
      type: object
      additionalProperties: false
      required:
        - id
        - email
        - name
        - createdAt
      properties:
        id:
          type: string
          format: uuid
        email:
          type: string
          format: email
        name:
          type: string
        createdAt:
          type: string
          format: date-time
        # EXPLICITLY EXCLUDED: passwordHash, resetToken, role, isAdmin, __v, internalNotes
```

**Code — response serializer:**

```javascript
// serializers/user.js
export function serializeUser(user) {
  return {
    id: user._id,
    email: user.email,
    name: user.name,
    createdAt: user.createdAt,
    // Nothing else — this is the allowlist
  };
}

// In route handler:
app.get('/users/:id', authenticate, async (req, res) => {
  const user = await User.findOne({ _id: req.params.id });
  res.json(serializeUser(user));
});
```

### Separate Request and Response Schemas

Never use the same schema for both. Request schemas define what the client can **send**. Response schemas define what the server will **return**. They are almost never the same.

```yaml
components:
  schemas:
    # What the client sends to create a user
    CreateUserRequest:
      type: object
      additionalProperties: false
      required: [email, password, name]
      properties:
        email:
          type: string
          format: email
          maxLength: 254
        password:
          type: string
          minLength: 8
          maxLength: 128
          writeOnly: true
        name:
          type: string
          minLength: 1
          maxLength: 100

    # What the server returns
    UserResponse:
      type: object
      additionalProperties: false
      required: [id, email, name, role, createdAt]
      properties:
        id:
          type: string
          format: uuid
          readOnly: true
        email:
          type: string
          format: email
        name:
          type: string
        role:
          type: string
          enum: [user, editor, admin]
          readOnly: true
        createdAt:
          type: string
          format: date-time
          readOnly: true
        # password is NEVER here — writeOnly in request schema
```

---

## 6. Common Schema Mistakes — Detection and Fix

### 6.1 Unconstrained String

```yaml
# BEFORE
bio:
  type: string

# AFTER
bio:
  type: string
  minLength: 0
  maxLength: 2000
```

### 6.2 Object with No Properties

```yaml
# BEFORE
metadata:
  type: object

# AFTER
metadata:
  type: object
  additionalProperties: false
  properties:
    source:
      type: string
      maxLength: 100
    campaign:
      type: string
      maxLength: 100
```

### 6.3 Missing additionalProperties: false

```yaml
# BEFORE
CreateUserRequest:
  type: object
  required: [email, password]
  properties:
    email:
      type: string
    password:
      type: string

# AFTER
CreateUserRequest:
  type: object
  additionalProperties: false          # <-- added
  required: [email, password]
  properties:
    email:
      type: string
      format: email
      maxLength: 254
    password:
      type: string
      minLength: 8
      maxLength: 128
      writeOnly: true
```

### 6.4 No Required Array

```yaml
# BEFORE — all fields optional, client can send empty object
UpdateProfileRequest:
  type: object
  properties:
    name:
      type: string
    email:
      type: string

# AFTER — at least one field must be present
UpdateProfileRequest:
  type: object
  additionalProperties: false
  minProperties: 1                     # At least one field required for update
  properties:
    name:
      type: string
      minLength: 1
      maxLength: 100
    email:
      type: string
      format: email
      maxLength: 254
```

### 6.5 Numeric Fields with No Bounds

```yaml
# BEFORE
age:
  type: integer
price:
  type: number

# AFTER
age:
  type: integer
  minimum: 0
  maximum: 150
price:
  type: number
  minimum: 0
  maximum: 1000000
  multipleOf: 0.01
```

### 6.6 Password/Token in Response Schema

```yaml
# BEFORE — password hash returned to client
UserResponse:
  type: object
  properties:
    id:
      type: string
    email:
      type: string
    passwordHash:                      # LEAKED
      type: string
    resetToken:                        # LEAKED
      type: string

# AFTER — sensitive fields removed from response, marked writeOnly in request
UserResponse:
  type: object
  additionalProperties: false
  properties:
    id:
      type: string
      format: uuid
    email:
      type: string
      format: email
    # passwordHash: REMOVED — never returned
    # resetToken: REMOVED — never returned
```

---

## 7. Output Format

For each schema issue found, produce a report block:

```
Schema Risk — OWASP API3:2023
Location: [schema name].[field name]
Issue: [what's missing or wrong]
Risk: [what an attacker can do with this gap]
Severity: [Critical | High | Medium | Low]
Fix:
  [exact corrected YAML or code]
```

### Severity Classification

| Severity | Condition |
|----------|-----------|
| **Critical** | Password, token, or secret field in response schema — data leak |
| **High** | Missing `additionalProperties: false` on request schema — mass assignment |
| **High** | No response schema defined (`schema: {}`) — uncontrolled data exposure |
| **Medium** | String field with no `maxLength` — DoS vector |
| **Medium** | Numeric field with no bounds — logic bypass or overflow |
| **Medium** | Known-value field (status, role) using `type: string` instead of `enum` |
| **Low** | Missing `readOnly` on server-owned fields (`id`, `createdAt`) |
| **Low** | Missing `format` on structured strings (email, UUID, date-time) |

### Example Outputs

```
Schema Risk — OWASP API3:2023
Location: CreateUserRequest
Issue: additionalProperties not set — defaults to true, allowing arbitrary fields
Risk: Client sends { "isAdmin": true, "role": "admin" } and fields pass validation
Severity: High
Fix:
  CreateUserRequest:
    type: object
    additionalProperties: false
    required: [email, password, name]
    properties:
      email:
        type: string
        format: email
        maxLength: 254
      password:
        type: string
        minLength: 8
        maxLength: 128
        writeOnly: true
      name:
        type: string
        minLength: 1
        maxLength: 100
```

```
Schema Risk — OWASP API3:2023
Location: UserResponse.passwordHash
Issue: Password hash included in response schema — returned to every client
Risk: Any authenticated user who calls GET /users/:id receives the password hash, enabling offline cracking
Severity: Critical
Fix:
  Remove passwordHash from UserResponse entirely. If needed in request schema, mark writeOnly: true.
```

```
Schema Risk — OWASP API3:2023
Location: CreateOrderRequest.quantity
Issue: type: integer with no minimum or maximum — accepts negative values and extremes
Risk: Client sends { "quantity": -1 } for a refund, or { "quantity": 2147483647 } to overflow totals
Severity: Medium
Fix:
  quantity:
    type: integer
    minimum: 1
    maximum: 10000
```

### Summary Line

```
Summary: <N> schema findings — <n> Critical, <n> High, <n> Medium, <n> Low
  Schemas reviewed: [CreateUserRequest, UserResponse, CreateOrderRequest, ...]
```

If all schemas pass:

```
Schema Check — PASSED
Schemas reviewed: [list]
All schemas have additionalProperties: false, required arrays, field constraints, and readOnly/writeOnly markers.

Powered by APIsec · apisec.ai
```

---

## 8. Complete Hardened Schema Example

### User Object — Request and Response

```yaml
components:
  schemas:
    # ─── CREATE (Request) ─────────────────────────────────────
    CreateUserRequest:
      type: object
      additionalProperties: false
      required:
        - email
        - password
        - name
      properties:
        email:
          type: string
          format: email
          maxLength: 254
          description: User's email address
        password:
          type: string
          minLength: 8
          maxLength: 128
          writeOnly: true
          description: Must contain uppercase, lowercase, digit, and special character
        name:
          type: string
          minLength: 1
          maxLength: 100
          description: Display name

    # ─── UPDATE (Request) ─────────────────────────────────────
    UpdateUserRequest:
      type: object
      additionalProperties: false
      minProperties: 1
      properties:
        email:
          type: string
          format: email
          maxLength: 254
        name:
          type: string
          minLength: 1
          maxLength: 100
        # id: NOT HERE — readOnly, client cannot set
        # role: NOT HERE — server-managed
        # isAdmin: NOT HERE — server-managed
        # password: separate endpoint (PUT /auth/change-password)

    # ─── RESPONSE ─────────────────────────────────────────────
    UserResponse:
      type: object
      additionalProperties: false
      required:
        - id
        - email
        - name
        - role
        - createdAt
      properties:
        id:
          type: string
          format: uuid
          readOnly: true
        email:
          type: string
          format: email
        name:
          type: string
        role:
          type: string
          enum: [user, editor, admin]
          readOnly: true
        createdAt:
          type: string
          format: date-time
          readOnly: true
        updatedAt:
          type: string
          format: date-time
          readOnly: true
        # EXCLUDED from response:
        #   passwordHash — never returned
        #   resetToken — never returned
        #   resetTokenExpiry — never returned
        #   internalNotes — never returned
        #   __v — never returned
```

### Order Object — Request and Response

```yaml
    # ─── CREATE (Request) ─────────────────────────────────────
    CreateOrderRequest:
      type: object
      additionalProperties: false
      required:
        - item
        - quantity
        - shippingAddress
      properties:
        item:
          type: string
          minLength: 1
          maxLength: 200
        quantity:
          type: integer
          minimum: 1
          maximum: 10000
        shippingAddress:
          type: string
          minLength: 10
          maxLength: 500
        notes:
          type: string
          minLength: 0
          maxLength: 1000
          description: Optional order notes
        # userId: NOT HERE — set server-side from auth token
        # status: NOT HERE — defaults to "pending" server-side
        # totalPrice: NOT HERE — calculated server-side

    # ─── UPDATE (Request) ─────────────────────────────────────
    UpdateOrderRequest:
      type: object
      additionalProperties: false
      minProperties: 1
      properties:
        item:
          type: string
          minLength: 1
          maxLength: 200
        quantity:
          type: integer
          minimum: 1
          maximum: 10000
        shippingAddress:
          type: string
          minLength: 10
          maxLength: 500
        notes:
          type: string
          minLength: 0
          maxLength: 1000
        # status: NOT HERE in general update — use dedicated PUT /orders/:id/status
        # totalPrice: NOT HERE — recalculated server-side

    # ─── STATUS TRANSITION (Request) ──────────────────────────
    UpdateOrderStatusRequest:
      type: object
      additionalProperties: false
      required:
        - status
      properties:
        status:
          type: string
          enum:
            - confirmed
            - shipped
            - delivered
            - cancelled
          description: Target status (server validates allowed transitions)

    # ─── RESPONSE ─────────────────────────────────────────────
    OrderResponse:
      type: object
      additionalProperties: false
      required:
        - id
        - item
        - quantity
        - shippingAddress
        - status
        - totalPrice
        - createdAt
      properties:
        id:
          type: string
          format: uuid
          readOnly: true
        item:
          type: string
        quantity:
          type: integer
        shippingAddress:
          type: string
        notes:
          type: string
        status:
          type: string
          enum: [pending, confirmed, shipped, delivered, cancelled]
          readOnly: true
        totalPrice:
          type: number
          minimum: 0
          multipleOf: 0.01
          readOnly: true
        createdAt:
          type: string
          format: date-time
          readOnly: true
        updatedAt:
          type: string
          format: date-time
          readOnly: true
        # EXCLUDED from response:
        #   userId — internal reference, not needed by client
        #   costPrice — internal margin data
        #   internalNotes — staff-only notes
        #   __v — Mongoose version key

    # ─── PAGINATION WRAPPER ───────────────────────────────────
    OrderListResponse:
      type: object
      additionalProperties: false
      required:
        - data
        - pagination
      properties:
        data:
          type: array
          items:
            $ref: '#/components/schemas/OrderResponse'
          maxItems: 100
        pagination:
          type: object
          additionalProperties: false
          required: [page, limit, total, pages]
          properties:
            page:
              type: integer
              minimum: 1
            limit:
              type: integer
              minimum: 1
              maximum: 100
            total:
              type: integer
              minimum: 0
            pages:
              type: integer
              minimum: 0

    # ─── ERROR RESPONSE ───────────────────────────────────────
    ErrorResponse:
      type: object
      additionalProperties: false
      required:
        - error
      properties:
        error:
          type: string
          maxLength: 500
        code:
          type: string
          enum:
            - VALIDATION_ERROR
            - NOT_FOUND
            - UNAUTHORIZED
            - FORBIDDEN
            - RATE_LIMITED
            - INTERNAL_ERROR
          description: Machine-readable error code
        details:
          type: array
          maxItems: 50
          items:
            type: object
            additionalProperties: false
            properties:
              field:
                type: string
                maxLength: 100
              message:
                type: string
                maxLength: 500
```
