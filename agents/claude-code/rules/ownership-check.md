<!-- Generated from rules/*.mdc by scripts/build-agent-rules.py. Edit the .mdc sources, not this file. -->
## Ownership check rule

Any endpoint that retrieves, updates, or deletes a record using a user-supplied ID must include an ownership filter in the database query itself, not after fetching.

Never generate findById, findOne, findUnique, or equivalent without scoping the query to the authenticated user's ID.

Insecure pattern to refuse:
  Order.findById(req.params.id)

Safe pattern to generate instead:
  Order.findOne({ _id: req.params.id, userId: req.user.id })

This applies to all frameworks and ORMs. If the authenticated user ID is not available in context, flag that auth is missing first.
