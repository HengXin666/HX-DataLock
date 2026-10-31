# Kotlin stream format and Android AAR

Status: 交给代理

Python, Node, and the browser module implement `hxdl.stream.v1` and `hxdl.manifest.v1`. The Kotlin JVM module does not. Android apps can depend on the JVM jar, but this repo does not build an AAR and does not run instrumented tests.

## Acceptance

- `lockStream` / `openStream` on `InputStream` match the Python and TypeScript containers, including truncation and reorder failures.
- An Android library module publishes an AAR for API 26+, with a written choice about BouncyCastle versus the platform provider.
- Default scrypt cost is documented against a real device memory budget.
