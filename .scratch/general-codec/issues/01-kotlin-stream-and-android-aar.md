# Kotlin stream format and Android AAR

Status: 部分落地

Sender `sealChunked` and User `openChunked` match Python `seal_chunked` / `open_chunked`, including reuse of an unchanged chunk at the same index. The release AAR excludes BouncyCastle signature files. `docs/platforms.md` tells apps to keep `bcprov-jdk18on` and drop `bcprov-jdk15on` / SpongyCastle.

`CodecInstrumentedTest` and `.github/workflows/android-instrumented.yml` are in the tree. This environment started an API 34 emulator, then adb stayed offline and the guest did not finish booting, so the instrumented test was not executed here. The GitHub workflow is the run that still has to go green.
