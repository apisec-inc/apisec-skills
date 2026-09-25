<!-- Generated from rules/*.mdc by scripts/build-agent-rules.py. Edit the .mdc sources, not this file. -->
# APIsec API security rules

These rules apply to every API route, handler, controller, and data access
path you generate or modify. They implement the OWASP API Security Top 10
2023 baseline. Follow them without being asked.

## API authentication rule

Every route handler that reads, modifies, or deletes data MUST include authentication middleware or a decorator before the handler executes.

Never generate a data-touching endpoint without auth. If auth middleware is not yet defined in the codebase, note that it needs to be added and generate a placeholder that fails safely (401) until implemented.

Patterns that indicate missing auth, flag these:
- Express route with no middleware before the handler function
- FastAPI endpoint with no Depends(get_current_user) or equivalent
- Django view with no @login_required or IsAuthenticated permission class
- Spring endpoint with no @PreAuthorize or SecurityConfig coverage
- Go handler registered without auth middleware in the route group

When you detect missing auth, do not silently generate the insecure code. Output:
Auth missing: add authentication before generating this endpoint.
Suggested fix: [framework-appropriate auth middleware pattern]

## Ownership check rule

Any endpoint that retrieves, updates, or deletes a record using a user-supplied ID must include an ownership filter in the database query itself, not after fetching.

Never generate findById, findOne, findUnique, or equivalent without scoping the query to the authenticated user's ID.

Insecure pattern to refuse:
  Order.findById(req.params.id)

Safe pattern to generate instead:
  Order.findOne({ _id: req.params.id, userId: req.user.id })

This applies to all frameworks and ORMs. If the authenticated user ID is not available in context, flag that auth is missing first.

## Input validation rule

All user-supplied input (path params, query params, request body, headers) must pass through a validation layer before being used in any logic, query, or response.

Never pass req.params, req.body, req.query, or request.data directly to a database query, shell command, file path, or template without validation.

Recommended validation approach per framework:
- Express/Node: zod or joi schema validation
- FastAPI: Pydantic models with field constraints
- Django: DRF serializers with explicit field validation
- Spring: @Valid with Bean Validation annotations
- Go: manual struct validation or validator library

When generating an endpoint, always include the validation layer. If the user hasn't defined a schema yet, generate a placeholder schema with the correct structure.

## Error sanitization rule

API error responses must never include stack traces, internal field names, database error messages, ORM errors, or any internal system detail.

Never generate error handlers that return err.message, error.stack, or raw exception objects directly to the client.

Insecure pattern to refuse:
  res.status(500).json({ error: err.message })

Safe pattern to generate instead:
  res.status(500).json({ error: 'Internal server error', requestId: req.id })

Always generate a generic user-facing message plus a unique request/correlation ID for internal tracing. The requestId allows ops teams to find the real error in logs without exposing it to clients.

## Admin RBAC rule

Any endpoint or function that performs an admin-scoped operation, such as accessing all users, modifying system config, deleting records belonging to other users, or reading privileged data, must include an explicit role check before executing.

Authentication alone is not sufficient. Being logged in does not imply admin access.

Never generate admin operations that rely on implicit permission inheritance from authenticated state.

Required pattern:
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden' });
  }

This check must appear BEFORE any privileged operation. Generate it at the top of the handler, not nested inside logic.
