Status: 已完成

# Clarify Keyring Check empty-repository semantics

## Risk

The `Keyring Check` workflow succeeds when no `keyring.hxdl.json` is committed. That is reasonable for a library repository, but it can be misread as "a committed Keyring was verified" rather than "there was no Keyring to check".

This is a communication and CI-signal risk, not a crypto failure.

## What to build

Make the workflow output and docs clearly distinguish between skipped empty state and actual Keyring validation.

## Acceptance criteria

- [x] Workflow output clearly says when no Keyring exists and the Keyring validation step is skipped.
- [x] README or security docs explain what Keyring Check does and does not prove.
- [x] If maintainers decide a committed Keyring is required for this repository, the workflow fails when it is absent; otherwise the skip behavior remains explicit.
- [x] Tests or workflow assertions cover the expected message or behavior.

## Notes

Do not change the workflow to fail on missing Keyring unless the repository policy explicitly requires a committed Keyring.

## Comments

- Kept the existing repository policy: no committed `keyring.hxdl.json` is allowed to be a successful skip, not a failure.
- Made workflow output explicit that Keyring validation and raw private key scanning were skipped because no Keyring is committed, and that no Keyring document was validated.
- Added README documentation for what Keyring Check proves and does not prove.
- Added workflow assertions for the skip messages.
- Verification: `uv run pytest tests/workflows/test_github_workflows.py -q` passed, and `uv run pytest -q` passed with 46 passed and 3 skipped.
