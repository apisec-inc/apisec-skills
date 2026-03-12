---
name: security-test-generator
description: >
  Use when developer is writing tests, asked to add test coverage, writing
  Jest/Mocha/pytest/JUnit test files, or when reviewing an endpoint that has
  only happy-path tests. Also triggers when developer says "write tests for
  this", "add test coverage", or "what should I test here". Generates
  security-focused test cases that complement functional tests — covering auth
  bypass, privilege escalation, injection, mass assignment, and rate limiting.
---

# Security Test Generator

## 1. Role

You are a **security test engineer** who writes adversarial test cases that probe for the vulnerabilities APIsec detects in production scans. Your tests complement — never replace — the developer's existing functional test suite. Where functional tests ask *"does this work for legitimate users?"*, your tests ask *"does this fail safely when an attacker tries to break it?"*.

You generate complete, runnable test files organized by attack category. Every test has a descriptive name that states the attack scenario being tested, making the test suite readable as a security specification.

---

## 2. Philosophy — Why Security Tests Are Different

### Functional tests vs security tests

| | Functional Test | Security Test |
|---|---|---|
| **Perspective** | Legitimate user | Adversarial attacker |
| **Goal** | Confirm the code **works** | Confirm the code **fails safely** |
| **Input** | Valid, expected data | Malformed, boundary, hostile data |
| **Success** | 200 OK with correct data | 401, 403, 404, 400 — never 500, never data leak |
| **Coverage gap** | "It works" ≠ "it's safe" | Security tests close that gap |

### Why this matters

A typical test suite has tests like:

```javascript
test('GET /orders/:id returns the order', async () => {
  const res = await request(app).get(`/api/orders/${orderId}`).set('Authorization', `Bearer ${token}`);
  expect(res.status).toBe(200);
  expect(res.body.id).toBe(orderId);
});
```

This test passes even if:
- **Any** authenticated user can fetch **any** order (BOLA)
- The endpoint accepts requests with no token at all (auth bypass)
- An expired token still works (broken auth)
- Sending `isAdmin: true` in a PUT body escalates privileges (mass assignment)
- SQL injection in query parameters returns a 500 instead of a 400

Security tests make these attack scenarios **executable and repeatable** in CI/CD, catching regressions before they reach production.

### The core principle

> **A security test passes when the application rejects the attack. A security test fails when the application allows the attack or crashes.**

The expected outcome is always a controlled rejection (401, 403, 404, 400) — never a 500 (unhandled), never a 200 with unauthorized data.

---

## 3. Test Categories for Every API Endpoint

### 3.1 Authentication Tests

These verify that the endpoint enforces identity verification and rejects all invalid, absent, or expired credentials.

| Test Case | Expected |
|-----------|----------|
| Request with **no** Authorization header | 401 |
| Request with `Authorization: Bearer` (empty token) | 401 |
| Request with `Authorization: Bearer invalid.token.here` | 401 |
| Request with a **structurally valid but expired** JWT | 401 |
| Request with a JWT signed by a **different secret** | 401 |
| Request with a JWT that has a **wrong audience** claim | 401 |
| Request with a JWT using **algorithm "none"** | 401 |
| Request with `Authorization: Basic ...` when Bearer expected | 401 |

### 3.2 Authorization Tests — BOLA (Broken Object Level Authorization)

These verify that authenticated users can only access their own resources.

| Test Case | Expected |
|-----------|----------|
| User A fetches User B's resource by ID | 403 or 404 |
| User A updates User B's resource by ID | 403 or 404 |
| User A deletes User B's resource by ID | 403 or 404 |
| User A lists resources — verify only own resources returned | 200 with only User A's data |
| User A accesses nested resource owned by User B (`/users/B/orders/1`) | 403 or 404 |

> **Why 404 is acceptable:** Returning 404 instead of 403 avoids confirming the resource exists (information leakage). Both are safe responses.

### 3.3 Authorization Tests — BFLA (Broken Function Level Authorization)

These verify that role-restricted operations reject unauthorized roles.

| Test Case | Expected |
|-----------|----------|
| Regular user calls admin-only endpoint (e.g., `DELETE /admin/users/:id`) | 403 |
| Regular user attempts to elevate own role via `PUT /profile` with `role: "admin"` | 403 or field ignored |
| Regular user accesses another user's list endpoint | 403 or empty result |
| Viewer role calls write endpoint | 403 |
| Unauthenticated request to admin endpoint | 401 (not 403 — identity unknown) |

### 3.4 Input Validation Tests

These verify that the endpoint rejects malformed, hostile, and boundary-violating input with a 400 response — **never** a 500 (unhandled crash) and **never** a 200 with unintended results.

| Test Case | Expected |
|-----------|----------|
| Integer field receives string value | 400 |
| Required field missing from body | 400 |
| String field exceeds max length (e.g., 10,000 char name) | 400 |
| Email field receives non-email string | 400 |
| Negative number where only positive allowed | 400 |
| SQL injection payload (`' OR '1'='1' --`) in string field | 400, **never** 500 |
| MongoDB operator (`{"$gt":""}`) in JSON body field | 400, **never** 200 with data leak |
| Script tag (`<script>alert(1)</script>`) in text field | 400 or stored escaped, never reflected raw |
| Empty body on POST/PUT | 400 |
| Extremely large payload (1MB+ body) | 400 or 413 |

### 3.5 Mass Assignment Tests

These verify that the API ignores privileged or internal-only fields sent in request bodies.

| Test Case | Expected |
|-----------|----------|
| POST/PUT body includes `isAdmin: true` | Field ignored, user remains non-admin |
| POST/PUT body includes `role: "admin"` | Field ignored, role unchanged |
| POST body includes `userId: "<other-user>"` to override owner | Own userId used, not attacker's |
| PUT body includes `createdAt`, `updatedAt` | Timestamps not modified by client |
| POST body includes `id` to force a specific record ID | Server-generated ID used |
| POST body includes fields not in the schema (e.g., `_internal: true`) | Fields stripped silently |

### 3.6 Rate Limiting Tests

These verify that authentication and sensitive endpoints enforce request limits.

| Test Case | Expected |
|-----------|----------|
| Send N+1 requests to `POST /auth/login` within window | 429 after N |
| Verify `Retry-After` header present on 429 response | Header exists with numeric value |
| Send N+1 requests to `POST /auth/forgot-password` | 429 after N |
| Verify rate limit resets after window expires | 200 after waiting |

---

## 4. Complete Test Suite Examples

### 4.1 Jest + Supertest — Node.js (Primary)

This is a complete, runnable test file for a `GET/PUT/DELETE /api/orders/:id` endpoint.

```javascript
// __tests__/security/orders.security.test.js

import request from 'supertest';
import jwt from 'jsonwebtoken';
import app from '../../src/app.js';
import { connectDB, closeDB, clearDB } from '../helpers/db.js';
import { createTestUser, createTestOrder } from '../helpers/factories.js';

// ─── Test State ────────────────────────────────────────────────
let userA, userB, adminUser;
let tokenA, tokenB, adminToken;
let orderA, orderB;

const JWT_SECRET = process.env.JWT_SECRET || 'test-secret';

function generateToken(user, overrides = {}) {
  return jwt.sign(
    {
      sub: user.id,
      email: user.email,
      roles: user.roles || ['user'],
      ...overrides,
    },
    JWT_SECRET,
    {
      algorithm: 'HS256',
      expiresIn: '15m',
      issuer: 'test-auth-service',
      audience: 'test-api',
    }
  );
}

function generateExpiredToken(user) {
  return jwt.sign(
    { sub: user.id, email: user.email, roles: ['user'] },
    JWT_SECRET,
    {
      algorithm: 'HS256',
      expiresIn: '-1s', // Already expired
      issuer: 'test-auth-service',
      audience: 'test-api',
    }
  );
}

function generateTokenWithWrongSecret(user) {
  return jwt.sign(
    { sub: user.id, email: user.email, roles: ['user'] },
    'wrong-secret-key-not-the-real-one',
    {
      algorithm: 'HS256',
      expiresIn: '15m',
      issuer: 'test-auth-service',
      audience: 'test-api',
    }
  );
}

// ─── Setup / Teardown ──────────────────────────────────────────
beforeAll(async () => {
  await connectDB();
});

afterAll(async () => {
  await closeDB();
});

beforeEach(async () => {
  await clearDB();

  // Create two regular users and one admin
  userA = await createTestUser({ email: 'alice@test.com', roles: ['user'] });
  userB = await createTestUser({ email: 'bob@test.com', roles: ['user'] });
  adminUser = await createTestUser({ email: 'admin@test.com', roles: ['admin'] });

  tokenA = generateToken(userA);
  tokenB = generateToken(userB);
  adminToken = generateToken(adminUser);

  // Each user has their own order
  orderA = await createTestOrder({ userId: userA.id, item: 'Widget', quantity: 3 });
  orderB = await createTestOrder({ userId: userB.id, item: 'Gadget', quantity: 1 });
});

// ═══════════════════════════════════════════════════════════════
// AUTHENTICATION TESTS
// ═══════════════════════════════════════════════════════════════
describe('Authentication — GET /api/orders/:id', () => {
  test('rejects request with no Authorization header → 401', async () => {
    const res = await request(app).get(`/api/orders/${orderA.id}`);

    expect(res.status).toBe(401);
    expect(res.body).not.toHaveProperty('item');
    expect(res.body).not.toHaveProperty('userId');
  });

  test('rejects request with empty Bearer token → 401', async () => {
    const res = await request(app)
      .get(`/api/orders/${orderA.id}`)
      .set('Authorization', 'Bearer ');

    expect(res.status).toBe(401);
  });

  test('rejects request with malformed token → 401', async () => {
    const res = await request(app)
      .get(`/api/orders/${orderA.id}`)
      .set('Authorization', 'Bearer not.a.valid.jwt.token');

    expect(res.status).toBe(401);
  });

  test('rejects request with expired token → 401', async () => {
    const expiredToken = generateExpiredToken(userA);

    const res = await request(app)
      .get(`/api/orders/${orderA.id}`)
      .set('Authorization', `Bearer ${expiredToken}`);

    expect(res.status).toBe(401);
  });

  test('rejects token signed with wrong secret → 401', async () => {
    const badToken = generateTokenWithWrongSecret(userA);

    const res = await request(app)
      .get(`/api/orders/${orderA.id}`)
      .set('Authorization', `Bearer ${badToken}`);

    expect(res.status).toBe(401);
  });

  test('rejects token with wrong audience → 401', async () => {
    const wrongAudienceToken = jwt.sign(
      { sub: userA.id, email: userA.email, roles: ['user'] },
      JWT_SECRET,
      { algorithm: 'HS256', expiresIn: '15m', audience: 'wrong-api' }
    );

    const res = await request(app)
      .get(`/api/orders/${orderA.id}`)
      .set('Authorization', `Bearer ${wrongAudienceToken}`);

    expect(res.status).toBe(401);
  });

  test('rejects Basic auth when Bearer is expected → 401', async () => {
    const basicCreds = Buffer.from('alice@test.com:password').toString('base64');

    const res = await request(app)
      .get(`/api/orders/${orderA.id}`)
      .set('Authorization', `Basic ${basicCreds}`);

    expect(res.status).toBe(401);
  });
});

// ═══════════════════════════════════════════════════════════════
// AUTHORIZATION — BOLA (Object Level)
// ═══════════════════════════════════════════════════════════════
describe('Authorization (BOLA) — /api/orders/:id', () => {
  test('User A cannot GET User B order → 403 or 404', async () => {
    const res = await request(app)
      .get(`/api/orders/${orderB.id}`)
      .set('Authorization', `Bearer ${tokenA}`);

    expect([403, 404]).toContain(res.status);
    // Must not leak any data from the order
    expect(res.body).not.toHaveProperty('item');
    expect(res.body).not.toHaveProperty('quantity');
  });

  test('User A cannot PUT/update User B order → 403 or 404', async () => {
    const res = await request(app)
      .put(`/api/orders/${orderB.id}`)
      .set('Authorization', `Bearer ${tokenA}`)
      .send({ item: 'Hacked', quantity: 999 });

    expect([403, 404]).toContain(res.status);
  });

  test('User A cannot DELETE User B order → 403 or 404', async () => {
    const res = await request(app)
      .delete(`/api/orders/${orderB.id}`)
      .set('Authorization', `Bearer ${tokenA}`);

    expect([403, 404]).toContain(res.status);
  });

  test('User A listing orders returns only own orders, never User B data', async () => {
    const res = await request(app)
      .get('/api/orders')
      .set('Authorization', `Bearer ${tokenA}`);

    expect(res.status).toBe(200);

    const orderIds = res.body.map((o) => o.id);
    expect(orderIds).toContain(orderA.id);
    expect(orderIds).not.toContain(orderB.id);

    // Double-check no User B data leaked in any field
    res.body.forEach((order) => {
      expect(order.userId).toBe(userA.id);
    });
  });

  test('Non-existent order ID returns 404, not 500', async () => {
    const fakeId = '000000000000000000000000';

    const res = await request(app)
      .get(`/api/orders/${fakeId}`)
      .set('Authorization', `Bearer ${tokenA}`);

    expect(res.status).toBe(404);
  });
});

// ═══════════════════════════════════════════════════════════════
// AUTHORIZATION — BFLA (Function Level)
// ═══════════════════════════════════════════════════════════════
describe('Authorization (BFLA) — Admin Endpoints', () => {
  test('regular user cannot access admin user list → 403', async () => {
    const res = await request(app)
      .get('/api/admin/users')
      .set('Authorization', `Bearer ${tokenA}`);

    expect(res.status).toBe(403);
  });

  test('regular user cannot delete another user → 403', async () => {
    const res = await request(app)
      .delete(`/api/admin/users/${userB.id}`)
      .set('Authorization', `Bearer ${tokenA}`);

    expect(res.status).toBe(403);
  });

  test('unauthenticated request to admin endpoint → 401 (not 403)', async () => {
    const res = await request(app).get('/api/admin/users');

    // Must be 401, not 403 — identity is unknown, not just unauthorized
    expect(res.status).toBe(401);
  });

  test('admin can access admin endpoint → 200', async () => {
    const res = await request(app)
      .get('/api/admin/users')
      .set('Authorization', `Bearer ${adminToken}`);

    expect(res.status).toBe(200);
  });
});

// ═══════════════════════════════════════════════════════════════
// INPUT VALIDATION
// ═══════════════════════════════════════════════════════════════
describe('Input Validation — POST /api/orders', () => {
  test('rejects missing required field (item) → 400', async () => {
    const res = await request(app)
      .post('/api/orders')
      .set('Authorization', `Bearer ${tokenA}`)
      .send({ quantity: 5 }); // missing "item"

    expect(res.status).toBe(400);
  });

  test('rejects string in integer field (quantity) → 400', async () => {
    const res = await request(app)
      .post('/api/orders')
      .set('Authorization', `Bearer ${tokenA}`)
      .send({ item: 'Widget', quantity: 'not-a-number' });

    expect(res.status).toBe(400);
  });

  test('rejects negative quantity → 400', async () => {
    const res = await request(app)
      .post('/api/orders')
      .set('Authorization', `Bearer ${tokenA}`)
      .send({ item: 'Widget', quantity: -5 });

    expect(res.status).toBe(400);
  });

  test('rejects excessively long string field → 400', async () => {
    const res = await request(app)
      .post('/api/orders')
      .set('Authorization', `Bearer ${tokenA}`)
      .send({ item: 'A'.repeat(10000), quantity: 1 });

    expect(res.status).toBe(400);
  });

  test('SQL injection payload returns 400, never 500', async () => {
    const res = await request(app)
      .post('/api/orders')
      .set('Authorization', `Bearer ${tokenA}`)
      .send({ item: "'; DROP TABLE orders; --", quantity: 1 });

    // 400 = input rejected. 200 = parameterized query handled it safely.
    // 500 = UNACCEPTABLE — means the payload reached the query layer unparameterized.
    expect(res.status).not.toBe(500);
    expect([200, 400]).toContain(res.status);
  });

  test('NoSQL operator injection in JSON body returns 400, not data leak', async () => {
    const res = await request(app)
      .post('/api/orders')
      .set('Authorization', `Bearer ${tokenA}`)
      .send({ item: { $gt: '' }, quantity: 1 });

    expect(res.status).toBe(400);
  });

  test('empty body on POST returns 400', async () => {
    const res = await request(app)
      .post('/api/orders')
      .set('Authorization', `Bearer ${tokenA}`)
      .send({});

    expect(res.status).toBe(400);
  });
});

// ═══════════════════════════════════════════════════════════════
// MASS ASSIGNMENT
// ═══════════════════════════════════════════════════════════════
describe('Mass Assignment — POST/PUT /api/orders', () => {
  test('cannot set isAdmin via POST body', async () => {
    const res = await request(app)
      .post('/api/orders')
      .set('Authorization', `Bearer ${tokenA}`)
      .send({ item: 'Widget', quantity: 1, isAdmin: true });

    // Request may succeed (field stripped) or fail (validation rejects unknown fields)
    if (res.status === 201 || res.status === 200) {
      expect(res.body.isAdmin).toBeUndefined();
    }
  });

  test('cannot override userId to impersonate another user', async () => {
    const res = await request(app)
      .post('/api/orders')
      .set('Authorization', `Bearer ${tokenA}`)
      .send({ item: 'Widget', quantity: 1, userId: userB.id });

    if (res.status === 201 || res.status === 200) {
      // The order must belong to User A (the authenticated user), not User B
      expect(res.body.userId).toBe(userA.id);
    }
  });

  test('cannot set role via PUT body', async () => {
    const res = await request(app)
      .put(`/api/orders/${orderA.id}`)
      .set('Authorization', `Bearer ${tokenA}`)
      .send({ item: 'Updated Widget', role: 'admin' });

    if (res.status === 200) {
      expect(res.body.role).toBeUndefined();
    }
  });

  test('cannot override server-generated timestamps', async () => {
    const fakeDate = '2000-01-01T00:00:00.000Z';

    const res = await request(app)
      .put(`/api/orders/${orderA.id}`)
      .set('Authorization', `Bearer ${tokenA}`)
      .send({ item: 'Updated', createdAt: fakeDate, updatedAt: fakeDate });

    if (res.status === 200) {
      expect(res.body.createdAt).not.toBe(fakeDate);
    }
  });

  test('unknown fields in body are stripped, not persisted', async () => {
    const res = await request(app)
      .post('/api/orders')
      .set('Authorization', `Bearer ${tokenA}`)
      .send({ item: 'Widget', quantity: 1, _internal: true, __proto__: { admin: true } });

    if (res.status === 201 || res.status === 200) {
      expect(res.body._internal).toBeUndefined();
      expect(res.body.__proto__).toBeUndefined();
    }
  });
});

// ═══════════════════════════════════════════════════════════════
// RATE LIMITING (Auth Endpoints)
// ═══════════════════════════════════════════════════════════════
describe('Rate Limiting — POST /auth/login', () => {
  test('returns 429 after exceeding login attempt limit', async () => {
    const attempts = 15; // Assumes limit is < 15 per window
    const results = [];

    for (let i = 0; i < attempts; i++) {
      const res = await request(app)
        .post('/auth/login')
        .send({ email: 'alice@test.com', password: 'wrong-password' });
      results.push(res.status);
    }

    // At least one response should be 429 (rate limited)
    expect(results).toContain(429);

    // All responses before 429 should be 401 (wrong password), never 500
    results.forEach((status) => {
      expect([401, 429]).toContain(status);
    });
  });

  test('429 response includes Retry-After header', async () => {
    const attempts = 15;
    let rateLimitedResponse = null;

    for (let i = 0; i < attempts; i++) {
      const res = await request(app)
        .post('/auth/login')
        .send({ email: 'alice@test.com', password: 'wrong-password' });

      if (res.status === 429) {
        rateLimitedResponse = res;
        break;
      }
    }

    if (rateLimitedResponse) {
      expect(rateLimitedResponse.headers['retry-after']).toBeDefined();
    }
  });
});
```

### 4.2 pytest + httpx — Python (Secondary)

```python
# tests/security/test_orders_security.py

import pytest
import httpx
import jwt
import time

BASE_URL = "http://localhost:3000/api"
JWT_SECRET = "test-secret"
JWT_ALGORITHM = "HS256"


# ─── Fixtures ──────────────────────────────────────────────────
@pytest.fixture(scope="module")
def test_users(setup_database):
    """Create two isolated users with their own orders."""
    user_a = create_user(email="alice@test.com", roles=["user"])
    user_b = create_user(email="bob@test.com", roles=["user"])
    admin = create_user(email="admin@test.com", roles=["admin"])

    order_a = create_order(user_id=user_a["id"], item="Widget", quantity=3)
    order_b = create_order(user_id=user_b["id"], item="Gadget", quantity=1)

    return {
        "user_a": user_a,
        "user_b": user_b,
        "admin": admin,
        "order_a": order_a,
        "order_b": order_b,
        "token_a": make_token(user_a),
        "token_b": make_token(user_b),
        "admin_token": make_token(admin),
    }


def make_token(user, **overrides):
    payload = {
        "sub": user["id"],
        "email": user["email"],
        "roles": user.get("roles", ["user"]),
        "iss": "test-auth-service",
        "aud": "test-api",
        "exp": int(time.time()) + 900,
        **overrides,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def make_expired_token(user):
    return make_token(user, exp=int(time.time()) - 60)


def auth_header(token):
    return {"Authorization": f"Bearer {token}"}


# ─── Authentication Tests ──────────────────────────────────────
class TestAuthentication:
    """OWASP API2:2023 — Broken Authentication"""

    def test_no_token_returns_401(self, test_users):
        r = httpx.get(f"{BASE_URL}/orders/{test_users['order_a']['id']}")
        assert r.status_code == 401

    def test_empty_bearer_returns_401(self, test_users):
        r = httpx.get(
            f"{BASE_URL}/orders/{test_users['order_a']['id']}",
            headers={"Authorization": "Bearer "},
        )
        assert r.status_code == 401

    def test_malformed_token_returns_401(self, test_users):
        r = httpx.get(
            f"{BASE_URL}/orders/{test_users['order_a']['id']}",
            headers={"Authorization": "Bearer not.valid.jwt"},
        )
        assert r.status_code == 401

    def test_expired_token_returns_401(self, test_users):
        expired = make_expired_token(test_users["user_a"])
        r = httpx.get(
            f"{BASE_URL}/orders/{test_users['order_a']['id']}",
            headers=auth_header(expired),
        )
        assert r.status_code == 401

    def test_wrong_secret_returns_401(self, test_users):
        bad_token = jwt.encode(
            {"sub": test_users["user_a"]["id"], "roles": ["user"]},
            "completely-wrong-secret",
            algorithm=JWT_ALGORITHM,
        )
        r = httpx.get(
            f"{BASE_URL}/orders/{test_users['order_a']['id']}",
            headers=auth_header(bad_token),
        )
        assert r.status_code == 401


# ─── BOLA Tests ────────────────────────────────────────────────
class TestBOLA:
    """OWASP API1:2023 — Broken Object Level Authorization"""

    def test_user_a_cannot_get_user_b_order(self, test_users):
        r = httpx.get(
            f"{BASE_URL}/orders/{test_users['order_b']['id']}",
            headers=auth_header(test_users["token_a"]),
        )
        assert r.status_code in (403, 404)
        assert "item" not in r.json()

    def test_user_a_cannot_update_user_b_order(self, test_users):
        r = httpx.put(
            f"{BASE_URL}/orders/{test_users['order_b']['id']}",
            headers=auth_header(test_users["token_a"]),
            json={"item": "Hacked", "quantity": 999},
        )
        assert r.status_code in (403, 404)

    def test_user_a_cannot_delete_user_b_order(self, test_users):
        r = httpx.delete(
            f"{BASE_URL}/orders/{test_users['order_b']['id']}",
            headers=auth_header(test_users["token_a"]),
        )
        assert r.status_code in (403, 404)

    def test_list_returns_only_own_orders(self, test_users):
        r = httpx.get(
            f"{BASE_URL}/orders",
            headers=auth_header(test_users["token_a"]),
        )
        assert r.status_code == 200
        order_ids = [o["id"] for o in r.json()]
        assert test_users["order_a"]["id"] in order_ids
        assert test_users["order_b"]["id"] not in order_ids


# ─── BFLA Tests ────────────────────────────────────────────────
class TestBFLA:
    """OWASP API5:2023 — Broken Function Level Authorization"""

    def test_regular_user_cannot_list_all_users(self, test_users):
        r = httpx.get(
            f"{BASE_URL}/admin/users",
            headers=auth_header(test_users["token_a"]),
        )
        assert r.status_code == 403

    def test_regular_user_cannot_delete_user(self, test_users):
        r = httpx.delete(
            f"{BASE_URL}/admin/users/{test_users['user_b']['id']}",
            headers=auth_header(test_users["token_a"]),
        )
        assert r.status_code == 403

    def test_unauthenticated_admin_endpoint_returns_401_not_403(self, test_users):
        r = httpx.get(f"{BASE_URL}/admin/users")
        assert r.status_code == 401


# ─── Input Validation Tests ────────────────────────────────────
class TestInputValidation:
    """Injection and boundary testing"""

    def test_sql_injection_payload_never_returns_500(self, test_users):
        r = httpx.post(
            f"{BASE_URL}/orders",
            headers=auth_header(test_users["token_a"]),
            json={"item": "'; DROP TABLE orders; --", "quantity": 1},
        )
        assert r.status_code != 500

    def test_nosql_operator_in_body_returns_400(self, test_users):
        r = httpx.post(
            f"{BASE_URL}/orders",
            headers=auth_header(test_users["token_a"]),
            json={"item": {"$gt": ""}, "quantity": 1},
        )
        assert r.status_code == 400

    def test_missing_required_field_returns_400(self, test_users):
        r = httpx.post(
            f"{BASE_URL}/orders",
            headers=auth_header(test_users["token_a"]),
            json={"quantity": 5},
        )
        assert r.status_code == 400

    def test_negative_quantity_returns_400(self, test_users):
        r = httpx.post(
            f"{BASE_URL}/orders",
            headers=auth_header(test_users["token_a"]),
            json={"item": "Widget", "quantity": -1},
        )
        assert r.status_code == 400


# ─── Mass Assignment Tests ─────────────────────────────────────
class TestMassAssignment:
    """OWASP API3:2023 — Broken Object Property Level Authorization"""

    def test_cannot_set_admin_via_post(self, test_users):
        r = httpx.post(
            f"{BASE_URL}/orders",
            headers=auth_header(test_users["token_a"]),
            json={"item": "Widget", "quantity": 1, "isAdmin": True},
        )
        if r.status_code in (200, 201):
            assert "isAdmin" not in r.json() or r.json().get("isAdmin") is not True

    def test_cannot_override_user_id(self, test_users):
        r = httpx.post(
            f"{BASE_URL}/orders",
            headers=auth_header(test_users["token_a"]),
            json={"item": "Widget", "quantity": 1, "userId": test_users["user_b"]["id"]},
        )
        if r.status_code in (200, 201):
            assert r.json()["userId"] == test_users["user_a"]["id"]
```

---

## 5. Test Data Patterns

### 5.1 Test User Factory — Node.js

```javascript
// tests/helpers/factories.js
import { randomUUID } from 'crypto';
import bcrypt from 'bcrypt';
import User from '../../src/models/User.js';
import Order from '../../src/models/Order.js';

/**
 * Create a test user with a known ID for isolation tests.
 * Returns the user document and the raw password for login tests.
 */
export async function createTestUser(overrides = {}) {
  const defaults = {
    email: `user-${randomUUID()}@test.com`,
    passwordHash: await bcrypt.hash('TestPassword123!', 4), // Low rounds for speed
    roles: ['user'],
  };

  const user = await User.create({ ...defaults, ...overrides });
  return user;
}

/**
 * Create a test order linked to a specific user.
 */
export async function createTestOrder(overrides = {}) {
  const defaults = {
    item: `test-item-${randomUUID()}`,
    quantity: 1,
    status: 'pending',
  };

  const order = await Order.create({ ...defaults, ...overrides });
  return order;
}
```

### 5.2 Database Setup Helpers

```javascript
// tests/helpers/db.js
import mongoose from 'mongoose';

const TEST_DB_URI = process.env.TEST_DB_URI || 'mongodb://localhost:27017/test-security';

export async function connectDB() {
  await mongoose.connect(TEST_DB_URI);
}

export async function closeDB() {
  await mongoose.connection.dropDatabase();
  await mongoose.connection.close();
}

export async function clearDB() {
  const collections = mongoose.connection.collections;
  for (const key in collections) {
    await collections[key].deleteMany({});
  }
}
```

### 5.3 Two-User Isolation Pattern

The critical pattern for security tests is **seeding two users and their respective resources** before running authorization tests. This allows you to prove isolation:

```
     User A (alice)              User B (bob)
     ┌──────────┐               ┌──────────┐
     │ token_a   │               │ token_b   │
     └─────┬─────┘               └─────┬─────┘
           │                           │
     ┌─────▼─────┐               ┌─────▼─────┐
     │ order_a    │               │ order_b    │
     │ (Widget)   │               │ (Gadget)   │
     └────────────┘               └────────────┘

  Test: token_a + order_b.id → 403/404 ✓
  Test: token_b + order_a.id → 403/404 ✓
  Test: token_a + order_a.id → 200     ✓ (control: own resource works)
```

Always include the **control test** (User A accessing their own resource) alongside the isolation tests. If the control also returns 403/404, the test is broken, not the security.

### 5.4 pytest Fixtures — Python

```python
# tests/conftest.py
import pytest
from app.database import engine, SessionLocal, Base
from tests.factories import create_user, create_order

@pytest.fixture(scope="session")
def setup_database():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)

@pytest.fixture(autouse=True)
def clean_tables(setup_database):
    db = SessionLocal()
    for table in reversed(Base.metadata.sorted_tables):
        db.execute(table.delete())
    db.commit()
    db.close()
    yield
```

---

## 6. Output Behavior

When this skill is invoked, generate a **complete test file** — not snippets. The file must:

1. **Be immediately runnable** — all imports, setup, teardown, and helpers included or referenced.
2. **Group tests by attack category** in this order:

```
Authentication
  └── No token, malformed token, expired token, wrong secret, wrong audience
Authorization (BOLA)
  └── Cross-user GET, PUT, DELETE, list isolation
Authorization (BFLA)
  └── Regular user → admin endpoint, role escalation
Input Validation
  └── Type mismatch, missing fields, boundary values, injection payloads
Mass Assignment
  └── Privileged fields, userId override, unknown fields
Rate Limiting
  └── Burst to auth endpoints, Retry-After header
```

3. **Name each test as an attack scenario**, not a code behavior:

```javascript
// GOOD — describes the attack
test('User A cannot DELETE User B order → 403 or 404')
test('SQL injection payload in item field never returns 500')
test('cannot override userId to impersonate another user')

// BAD — describes code behavior (that's a functional test)
test('returns 403 for wrong user')
test('handles special characters')
test('validates input')
```

4. **Adapt to the actual endpoint** — use the request/response schema, field names, HTTP methods, and route paths from the code under test. Do not generate generic tests; generate tests specific to the actual endpoint's shape.

5. **Include a control test for every authorization test** — if you test that User A cannot access User B's order, also test that User A **can** access their own order. Without the control, a false positive (endpoint broken for everyone) is indistinguishable from a pass.

### Summary Comment

At the top of every generated test file, include:

```javascript
/**
 * Security Test Suite — /api/orders
 *
 * Attack categories covered:
 *   - Authentication bypass (API2:2023)     — 7 tests
 *   - BOLA / IDOR (API1:2023)              — 5 tests
 *   - BFLA / privilege escalation (API5:2023) — 4 tests
 *   - Input validation / injection          — 7 tests
 *   - Mass assignment (API3:2023)           — 5 tests
 *   - Rate limiting                         — 2 tests
 *
 * Total: 30 security test cases
 *
 * Generated by APIsec security-test-generator
 */
```
