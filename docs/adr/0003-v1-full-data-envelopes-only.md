# V1 Full Data Envelopes Only

The first supported SDK surface encrypts and decrypts Full Data Envelopes only, including single files up to 25 MB read fully into memory; larger files are rejected. Chunked File Envelopes are deferred because stream/chunk design affects long-term compatibility, parallel decryption, partial failure handling, and storage layout; documenting the concept now is safer than shipping an unstable chunk format.
