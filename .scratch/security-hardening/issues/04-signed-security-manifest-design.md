Status: 已完成

# Design signed security and compatibility manifests

## Risk

Current compatibility manifests and documentation can describe what the SDK supports, but they do not prove that a manifest or Public Key Document was produced by the project or a trusted owner.

For public distribution and automation, unsigned metadata leaves a gap between structural validation and authenticity.

## What to build

Create an ADR and initial design for signed manifests that can authenticate published v1 metadata without changing the existing Data Envelope format.

## Acceptance criteria

- [x] ADR defines the signed object shape, signature algorithm, key management model, and verification flow.
- [x] ADR explains how signed manifests relate to Public Key Document pinning and future key rotation.
- [x] A prototype command or script can sign and verify a manifest.
- [x] CI or release documentation explains where verification should happen.
- [x] The design explicitly states what is out of scope for v1, including automatic trust discovery if deferred.

## Notes

This is primarily a design issue. Avoid adding a permanent public API until the ADR settles the trust model.

## Comments

- Added ADR 0022 for signed security and compatibility manifests.
- Added prototype script `scripts/hxdl-manifest-sign.py` for signing and verifying manifest wrappers with HMAC-SHA256 using a secret from the environment.
- Added tests proving the prototype verifies valid signed manifests and rejects tampered payloads.
- Added root README release/CI documentation pointer.
- The design explicitly keeps automatic trust discovery, embedded envelope signatures, stable SDK API, and automatic key rotation out of v1.
