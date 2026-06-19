Status: 已完成

# Make CLI verify commands enforce stable JSON expectations

## What was found

Issue 05 requires verification commands to validate stable JSON expectations. Python CLI `verify-keyring` and `verify-public` currently accept compact JSON that does not match the v1 writer format.

## Acceptance criteria

- [x] `hxdl verify-keyring` rejects Keyrings that are structurally valid but not in stable v1 JSON form.
- [x] `hxdl verify-public` rejects Public Key Documents that are structurally valid but not in stable v1 JSON form.
- [x] Rejections use consistently parseable CLI failure output.
- [x] Tests cover the behavior through the CLI.

## Evidence

- A generated Keyring and Public Key Document rewritten with compact JSON were both accepted by Python CLI verify commands.

## Comments

- Fixed through TDD with CLI-level coverage in `tests/py/test_cli_v1.py`. Verification now uses stable JSON checks for Keyrings and Public Key Documents. Verified with `uv run pytest -q`.
