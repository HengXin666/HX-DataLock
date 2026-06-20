Status: 已完成

# Close v1 TypeScript and Android Kotlin implementation gaps

## What was found

Validation of `.scratch/v1-spec/issues/*` found that issues 06, 08, and 09 are marked complete, but the repository does not contain a TypeScript project or an Android Kotlin project. The current cross-language implementation is Python plus a Node `.mjs` module.

## Acceptance criteria

- [x] Decide whether the v1 JavaScript implementation should be documented as Node JavaScript or replaced with a real TypeScript SDK and CLI.
- [x] If TypeScript remains required, add a TypeScript project with source, type checking, tests, and the v1 SDK/CLI surface from issue 06.
- [x] Add an Android Kotlin SDK project for the local User DataLock scope from issue 08, or change the v1 scope documents and issues to remove that claim.
- [x] Replace fixture-only Android compatibility claims with runnable matrix coverage, or document Android as not implemented.
- [x] Update issue statuses and README wording so completion state matches the repository.

## Evidence

- No `package.json`, `tsconfig.json`, `.ts`, `.kt`, `.kts`, or Gradle files were present during validation.
- `uv run pytest -q` passed, but covered Python and Node `.mjs`, not TypeScript or Kotlin.
- Current repository now contains `sdk/node/package.json`, `sdk/node/tsconfig.json`, TypeScript sources under `sdk/node/src`, and Kotlin/Gradle sources under `sdk/knolin`.
- Kotlin User DataLock coverage is runnable through `sdk/knolin` Gradle tests plus `tests/knolin/test_knolin_sdk.py` cross-SDK compatibility tests.
- `.github/workflows/sdk-tests.yml` now includes Knolin unit and cross-SDK jobs.
