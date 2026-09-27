# Password Strength Report Reaches the Caller

`create_keyring` and `init_keyring` accept an `on_password_report` callback and invoke it with the Password Strength Report before the Keyring is derived. ADR 0012 and the v1 specification both require that report to reach the user before Keyring creation, but the SDK previously computed it and discarded the value, so the only consumer of that requirement was a test that called `check_password_strength` directly. Applications that want to refuse a weak Master Password now can; v1 still does not block one on its own.

## Alternatives considered

Keeping the report internal and leaving strength display entirely to the CLI was rejected because it makes the specification requirement unenforceable for every non-CLI embedder, which is the majority of SDK consumers. Making a weak report raise an error was rejected because it would contradict ADR 0012 and break existing Keyrings' holders mid-upgrade. Returning the report as a second value was rejected because it changes the return type of two public functions in three languages for a value most callers ignore.

## Consequences

Callers that pass no callback keep the previous behaviour exactly. The CLI prints the level, warnings, and suggestions, so the `hxdl init` path no longer creates a weak Keyring silently.
