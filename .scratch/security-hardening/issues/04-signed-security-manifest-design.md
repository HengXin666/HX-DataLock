Status: 交给代理

# Design signed security and compatibility manifests

## Risk

Current compatibility manifests and documentation can describe what the SDK supports, but they do not prove that a manifest or Public Key Document was produced by the project or a trusted owner.

For public distribution and automation, unsigned metadata leaves a gap between structural validation and authenticity.

## What to build

Create an ADR and initial design for signed manifests that can authenticate published v1 metadata without changing the existing Data Envelope format.

## Acceptance criteria

- [ ] ADR defines the signed object shape, signature algorithm, key management model, and verification flow.
- [ ] ADR explains how signed manifests relate to Public Key Document pinning and future key rotation.
- [ ] A prototype command or script can sign and verify a manifest.
- [ ] CI or release documentation explains where verification should happen.
- [ ] The design explicitly states what is out of scope for v1, including automatic trust discovery if deferred.

## Notes

This is primarily a design issue. Avoid adding a permanent public API until the ADR settles the trust model.
