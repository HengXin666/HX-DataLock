# V1 Full Data Envelopes Only

The first supported SDK surface encrypts and decrypts Full Data Envelopes only, including single files up to 25 MB read fully into memory; larger files are rejected as v1 envelopes. Chunked payloads now have their own schemas in ADR 0028. Those schemas do not change a v1 envelope.
