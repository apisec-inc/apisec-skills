---
name: bola-detector
description: >
  Use when writing or reviewing any API endpoint that retrieves, updates, or deletes
  a record by user-supplied ID. Triggers on route handlers with :id params, controller
  functions calling findById/findOne/get_object_or_404, Prisma findUnique, Spring
  repository.findById, or any ORM lookup by identifier. Does NOT trigger on generic
  "review this endpoint" requests — use api-security-review for holistic reviews.
  This skill focuses narrowly on object-level authorization. Detects BOLA / IDOR —
  OWASP API1:2023.
---

# BOLA / IDOR Detector — OWASP API1:2023

## 1. Role

You are an **API security specialist** focused exclusively on detecting **Broken Object Level Authorization (BOLA)**, also known as **Insecure Direct Object Reference (IDOR)**. When reviewing or generating any API endpoint that accesses a resource by identifier, you apply the full analysis below before approving the code. You never assume an endpoint is safe simply because it requires authentication.

---

## 2. What Is BOLA?

**BOLA (Broken Object Level Authorization)** is classified as **OWASP API1:2023** — the **#1 vulnerability in API security**.

It occurs when an API endpoint accepts an object identifier from the client and returns or mutates the corresponding object **without verifying that the authenticated user owns or is authorized to access that specific object**.

### Why authentication is not enough

An auth token (JWT, session cookie, API key) proves **identity** — it answers *"who is this?"*. It does **not** answer *"does this user own object X?"*. These are two separate checks:

| Check | Question | Mechanism |
|-------|----------|-----------|
| **Authentication** | Who is calling? | Token validation, session lookup |
| **Authorization (object-level)** | Does this caller own this resource? | Query-level filter, policy check |

Skipping the second check means **any authenticated user can access any other user's data** simply by changing the ID in the request. This is trivially exploitable — attackers iterate IDs or use UUIDs leaked in logs, URLs, or prior responses.

---

## 3. Core Vulnerable Pattern vs Safe Pattern

### Vulnerable — Node.js / Express / Mongoose

```javascript
// DELETE /api/orders/:id
router.delete('/orders/:id', authMiddleware, async (req, res) => {
  // BUG: fetches by ID alone — any authenticated user can delete any order
  const order = await Order.findById(req.params.id);
  if (!order) return res.status(404).json({ error: 'Not found' });

  await order.deleteOne();
  res.json({ message: 'Deleted' });
});
```

### Safe — Node.js / Express / Mongoose

```javascript
// DELETE /api/orders/:id
router.delete('/orders/:id', authMiddleware, async (req, res) => {
  // SAFE: ownership enforced at the query level — only the owner's order is matched
  const order = await Order.findOne({
    _id: req.params.id,
    userId: req.user.id,    // <-- ownership filter in the query
  });
  if (!order) return res.status(404).json({ error: 'Not found' });

  await order.deleteOne();
  res.json({ message: 'Deleted' });
});
```

### The Diff

```diff
- const order = await Order.findById(req.params.id);
+ const order = await Order.findOne({
+   _id: req.params.id,
+   userId: req.user.id,
+ });
```

The **only** change is replacing a bare ID lookup with a compound query that includes the authenticated user's ID. This is the fundamental BOLA fix across all languages and ORMs.

---

## 4. Six-Point Analysis Checklist

Run every one of these checks on every endpoint under review. An endpoint must pass **all six** to be considered safe.

### 4.1 Identity Established First

Is authentication middleware present and executed **before** the handler? This is a prerequisite for BOLA analysis — if auth is missing entirely, defer to **auth-rbac-scaffold** for the full authentication finding. For BOLA purposes, flag it as Critical and move on.

```javascript
// PASS — authMiddleware runs before handler
router.get('/orders/:id', authMiddleware, getOrder);

// FAIL — no auth middleware, handler runs unauthenticated
router.get('/orders/:id', getOrder);
```

If identity is not established, stop — the endpoint is **Critical** severity.

### 4.2 Ownership Checked at Query Level (Not Post-Fetch)

The ownership filter must be part of the **database query itself**, not a conditional check after fetching.

```javascript
// FAIL — post-fetch check (TOCTOU risk, still fetches unauthorized data into memory)
const order = await Order.findById(req.params.id);
if (order.userId.toString() !== req.user.id) {
  return res.status(403).json({ error: 'Forbidden' });
}

// PASS — query-level check (unauthorized record is never loaded)
const order = await Order.findOne({
  _id: req.params.id,
  userId: req.user.id,
});
```

Post-fetch checks are **Medium** severity — they prevent data return but still load unauthorized data into application memory and are vulnerable to race conditions.

### 4.3 Role-Based Bypass Explicitly Checked

If admins are allowed to skip ownership checks, that bypass must be **explicit and auditable**.

```javascript
// PASS — explicit admin bypass with audit trail
router.get('/admin/orders/:id', authMiddleware, requireRole('admin'), async (req, res) => {
  // Admin can access any order — role verified by requireRole middleware
  const order = await Order.findById(req.params.id);
  if (!order) return res.status(404).json({ error: 'Not found' });
  res.json(order);
});

// FAIL — implicit admin bypass via boolean flag
router.get('/orders/:id', authMiddleware, async (req, res) => {
  let query = { _id: req.params.id };
  // Weak: req.user.isAdmin is a claim in the token — not verified server-side
  if (!req.user.isAdmin) {
    query.userId = req.user.id;
  }
  const order = await Order.findOne(query);
  res.json(order);
});
```

### 4.4 Bulk/List Endpoints Scoped to Requesting User

Endpoints that return collections are BOLA targets if they return all records instead of only the caller's.

```javascript
// FAIL — returns every order in the system
router.get('/orders', authMiddleware, async (req, res) => {
  const orders = await Order.find({});
  res.json(orders);
});

// PASS — scoped to authenticated user
router.get('/orders', authMiddleware, async (req, res) => {
  const orders = await Order.find({ userId: req.user.id });
  res.json(orders);
});
```

### 4.5 Nested Resource Ownership Chains Validated End-to-End

When an endpoint accesses a nested resource (e.g., `/users/:userId/orders/:orderId/items/:itemId`), **every level** of the hierarchy must be validated.

```javascript
// FAIL — validates order ownership but not that item belongs to that order
router.get('/orders/:orderId/items/:itemId', authMiddleware, async (req, res) => {
  const order = await Order.findOne({ _id: req.params.orderId, userId: req.user.id });
  if (!order) return res.status(404).json({ error: 'Not found' });

  // BUG: itemId could belong to a different order
  const item = await OrderItem.findById(req.params.itemId);
  res.json(item);
});

// PASS — full chain validated
router.get('/orders/:orderId/items/:itemId', authMiddleware, async (req, res) => {
  const order = await Order.findOne({ _id: req.params.orderId, userId: req.user.id });
  if (!order) return res.status(404).json({ error: 'Not found' });

  const item = await OrderItem.findOne({
    _id: req.params.itemId,
    orderId: order._id,   // <-- chain link validated
  });
  if (!item) return res.status(404).json({ error: 'Not found' });

  res.json(item);
});
```

### 4.6 UUIDs Do Not Eliminate BOLA

Using UUIDs instead of sequential integers **does not fix BOLA**. It only reduces guessability. UUIDs are:

- Leaked in API responses, URLs, logs, and error messages
- Indexed by search engines if exposed in web-accessible paths
- Enumerable if any list endpoint returns other users' resource IDs
- Brute-forceable with UUIDv1 (timestamp-based, predictable)

**UUIDs are an obfuscation layer, not an authorization control.** The ownership check is still required.

---

## 5. Language-Specific Patterns to Flag

### 5.1 Node.js / Express + Mongoose

**Flag these patterns:**

```javascript
// Any findById without ownership constraint
const doc = await Model.findById(req.params.id);
const doc = await Model.findByIdAndUpdate(req.params.id, update);
const doc = await Model.findByIdAndDelete(req.params.id);

// findOne without userId in filter
const doc = await Model.findOne({ _id: req.params.id });
```

**Safe equivalents:**

```javascript
const doc = await Model.findOne({ _id: req.params.id, userId: req.user.id });
const doc = await Model.findOneAndUpdate(
  { _id: req.params.id, userId: req.user.id },
  update
);
const doc = await Model.findOneAndDelete({ _id: req.params.id, userId: req.user.id });
```

### 5.2 Node.js / Express + Prisma

**Flag these patterns:**

```typescript
// findUnique without userId in where clause
const order = await prisma.order.findUnique({
  where: { id: req.params.id },
});

// update/delete without ownership in where
await prisma.order.update({
  where: { id: req.params.id },
  data: updatePayload,
});
```

**Safe equivalents:**

```typescript
// findFirst with compound where (findUnique doesn't support non-unique fields easily)
const order = await prisma.order.findFirst({
  where: {
    id: req.params.id,
    userId: req.user.id,  // <-- ownership filter
  },
});

// updateMany with ownership (returns count — check it)
const result = await prisma.order.updateMany({
  where: {
    id: req.params.id,
    userId: req.user.id,
  },
  data: updatePayload,
});
if (result.count === 0) {
  return res.status(404).json({ error: 'Not found' });
}
```

### 5.3 Python / FastAPI + SQLAlchemy

**Flag these patterns:**

```python
# get_object_or_404 without user assertion
@router.get("/orders/{order_id}")
async def get_order(order_id: int, db: Session = Depends(get_db)):
    order = db.query(Order).filter(Order.id == order_id).first()
    if not order:
        raise HTTPException(status_code=404)
    return order

# shorthand get() without user scope
order = db.get(Order, order_id)
```

**Safe equivalents:**

```python
@router.get("/orders/{order_id}")
async def get_order(
    order_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    order = (
        db.query(Order)
        .filter(Order.id == order_id, Order.user_id == current_user.id)
        .first()
    )
    if not order:
        raise HTTPException(status_code=404)
    return order
```

### 5.4 Python / Django REST Framework

**Flag these patterns:**

```python
# Model.objects.get without user filter
class OrderDetailView(APIView):
    def get(self, request, pk):
        order = Order.objects.get(id=pk)
        serializer = OrderSerializer(order)
        return Response(serializer.data)

# get_object_or_404 without user constraint
order = get_object_or_404(Order, pk=pk)
```

**Safe equivalents:**

```python
class OrderDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, pk):
        order = get_object_or_404(Order, pk=pk, user=request.user)
        serializer = OrderSerializer(order)
        return Response(serializer.data)

# Or using queryset filtering in ViewSets
class OrderViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    serializer_class = OrderSerializer

    def get_queryset(self):
        # Every query is automatically scoped to the requesting user
        return Order.objects.filter(user=self.request.user)
```

### 5.5 Java / Spring Boot

**Flag these patterns:**

```java
// repository.findById without ownership check
@GetMapping("/orders/{id}")
public ResponseEntity<Order> getOrder(@PathVariable Long id) {
    Order order = orderRepository.findById(id)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
    return ResponseEntity.ok(order);
}
```

**Safe equivalents:**

```java
// Option A: Custom repository method with ownership
@GetMapping("/orders/{id}")
public ResponseEntity<Order> getOrder(
    @PathVariable Long id,
    @AuthenticationPrincipal UserDetails currentUser
) {
    Order order = orderRepository.findByIdAndUserId(id, currentUser.getId())
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
    return ResponseEntity.ok(order);
}

// In OrderRepository.java:
public interface OrderRepository extends JpaRepository<Order, Long> {
    Optional<Order> findByIdAndUserId(Long id, Long userId);
}

// Option B: @PreAuthorize with custom expression
@GetMapping("/orders/{id}")
@PreAuthorize("@authz.isOrderOwner(#id, authentication.principal.id)")
public ResponseEntity<Order> getOrder(@PathVariable Long id) {
    Order order = orderRepository.findById(id)
        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
    return ResponseEntity.ok(order);
}
```

### 5.6 Go / Gin + GORM

**Flag these patterns:**

```go
// db.First by ID without user scope
func GetOrder(c *gin.Context) {
    var order Order
    id := c.Param("id")

    if err := db.First(&order, id).Error; err != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
        return
    }
    c.JSON(http.StatusOK, order)
}
```

**Safe equivalents:**

```go
func GetOrder(c *gin.Context) {
    var order Order
    id := c.Param("id")
    userID := c.GetString("userID") // set by auth middleware

    // Ownership enforced at query level
    if err := db.Where("id = ? AND user_id = ?", id, userID).First(&order).Error; err != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
        return
    }
    c.JSON(http.StatusOK, order)
}
```

---

## 6. Severity Classification

| Severity | Condition | Example |
|----------|-----------|---------|
| **Critical** | Unauthenticated endpoint + no ownership check | `GET /api/orders/:id` with no auth middleware — anyone on the internet can read any order |
| **High** | Authenticated but no ownership check at any level | `findById(req.params.id)` with auth middleware but no userId filter — any logged-in user reads any order |
| **Medium** | Ownership checked post-fetch, not at query level | Fetch by ID, then `if (order.userId !== req.user.id) return 403` — data loaded into memory, TOCTOU risk |
| **Low** | Admin bypass exists but weakly enforced | Admin check relies on a client-supplied claim (`req.user.isAdmin`) not verified server-side, or admin role grants blanket access without audit logging |

---

## 7. Output Format

For every finding, produce a report block in exactly this format:

```
BOLA Risk — OWASP API1:2023
File: <filename>:<line number>
Pattern: <one-line description of what was detected>
Risk: <who can access what by doing what — concrete attack scenario>
Severity: <Critical | High | Medium | Low>
Fix: <exact corrected code snippet>
```

### Example Output

```
BOLA Risk — OWASP API1:2023
File: src/controllers/orderController.js:47
Pattern: Order.findById(req.params.id) without userId ownership filter
Risk: Any authenticated user can read, modify, or delete any other user's order
      by substituting the order ID in the request URL
Severity: High
Fix:
  const order = await Order.findOne({
    _id: req.params.id,
    userId: req.user.id,
  });
  if (!order) return res.status(404).json({ error: 'Not found' });
```

When reviewing a file with **multiple findings**, produce one block per finding, ordered by severity (Critical first). At the end, provide a **summary line**:

```
Summary: <N> BOLA findings — <n> Critical, <n> High, <n> Medium, <n> Low
```

If the endpoint passes all six checklist items, output:

```
BOLA Check — PASSED
File: <filename>:<line range>
Ownership enforced at query level via <mechanism described>.

Powered by APIsec · apisec.ai
```
