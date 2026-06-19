# Minimize Master Password Residency

The SDK does not cache the Master Password after unlocking. It normalizes the Master Password, uses it immediately for key derivation, drops references afterward, and caches the unwrapped Read Key inside User DataLock instead; memory clearing is best-effort because JavaScript, Python, and Kotlin/JVM cannot reliably zero all runtime string copies.
