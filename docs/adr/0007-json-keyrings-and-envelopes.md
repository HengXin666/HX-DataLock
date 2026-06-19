# JSON Keyrings and Envelopes

Keyrings and v1 Data Envelopes use JSON with base64-encoded binary fields. This favors cross-language implementation, public storage compatibility, and debuggability over compactness; the base64 size overhead is acceptable because v1 only supports Full Data Envelopes and rejects files larger than 25 MB.
