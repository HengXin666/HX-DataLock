# Kotlin stream format and Android AAR

Status: 交给人工

`lockStream` / `openStream` and `:android:assembleRelease` landed. What is still open:

- A public Kotlin wrapper for building and opening `hxdl.manifest.v1` the way Python's `seal_chunked` does. Chunk diffing exists as `Stream.changedChunkIndexes`.
- An instrumented test on a device or emulator. The AAR was assembled with compile SDK 34; it was not installed on hardware.
- A written app-level choice when `bcprov-jdk18on` clashes with Android's conscrypt. The platform note records the dependency; it does not pick a winner for every app.
