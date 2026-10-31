# Password Strength Report Reaches the Caller

`create_keyring` and `init_keyring` accept an `on_password_report` callback and invoke it with the Password Strength Report before the Keyring is derived. ADR 0012 and the v1 specification both require that report to reach the user before Keyring creation. The callback still runs first. ADR 0025 then refuses a weak report unless the caller passes `allow_weak_password`. Opening an existing Keyring does not consult the report.

## Alternatives considered

Keeping the report internal and leaving strength display entirely to the CLI was rejected because it makes the specification requirement unenforceable for every non-CLI embedder, which is the majority of SDK consumers. Returning the report as a second value was rejected because it changes the return type of two public functions in three languages for a value most callers ignore. Refusing a weak report is now the default under ADR 0025; the earlier rejection of that refusal applied only while creation was warning-only. Existing Keyrings still open, because the refusal is create-time only.

## Consequences

Callers that pass no callback still receive the refusal when the report is weak. The CLI prints the level, warnings, and suggestions, then refuses a weak Master Password unless `--allow-weak-password` is set.
