<!-- Generated from rules/*.mdc by scripts/build-agent-rules.py. Edit the .mdc sources, not this file. -->
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
