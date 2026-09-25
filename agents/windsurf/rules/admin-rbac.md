---
trigger: always_on
description: Requires explicit role assertion before executing admin-scoped operations. Prevents privilege escalation and BFLA vulnerabilities.
---
<!-- Generated from rules/*.mdc by scripts/build-agent-rules.py. Edit the .mdc sources, not this file. -->
## Admin RBAC rule

Any endpoint or function that performs an admin-scoped operation, such as accessing all users, modifying system config, deleting records belonging to other users, or reading privileged data, must include an explicit role check before executing.

Authentication alone is not sufficient. Being logged in does not imply admin access.

Never generate admin operations that rely on implicit permission inheritance from authenticated state.

Required pattern:
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden' });
  }

This check must appear BEFORE any privileged operation. Generate it at the top of the handler, not nested inside logic.
