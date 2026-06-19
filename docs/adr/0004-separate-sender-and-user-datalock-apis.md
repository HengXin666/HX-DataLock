# Separate Sender and User DataLock APIs

The SDK exposes separate Sender DataLock and User DataLock entry points instead of one generic client parameterized by mode. The split makes the write-only boundary visible in every supported language: automation can lock data with the Write Key, while only a local user environment can unwrap and use the Read Key.
