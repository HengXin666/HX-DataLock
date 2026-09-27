# Offline Guessing Resistance Is Measured, Not Assumed

The security budget of a leaked Keyring is defined by how long a real dictionary attack takes against it, so this repository measures that directly in CI instead of asserting it in prose. `.github/workflows/crack-audit.yml` generates Keyrings for real user-chosen passwords across weak, medium, and strong tiers, then attempts recovery from leaked-password dictionaries sharded across parallel runners. Random strings are included only as an explicit upper bound and are never used to characterise real users.

## Alternatives considered

Running the audit on a workstation was rejected: scrypt is memory-hard, so a full sweep saturates the developer machine for hours and interferes with unrelated work. Stating expected crack times analytically from the scrypt cost parameters was rejected because the analytic figure omits dictionary rank, mangling rules, and the parallel hardware an attacker actually rents. Adding a bundled password denylist to the SDK was rejected for now because it would ship a leaking corpus inside the library and hard-code a policy that ADR 0012 leaves to the application.

## Consequences

The measured per-guess cost fixes the conversion between a dictionary rank and wall-clock time at the default scrypt parameters, so a reported rank is directly actionable. Generated targets embed known plaintext passwords and are excluded from the repository. The audit reports rank rather than only success, so it also exposes how deep into a dictionary a password survives.
