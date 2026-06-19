# Stable JSON Output, Parsed JSON Input

V1 Keyrings, Public Key Documents, and Data Envelopes use stable JSON output for readability and cross-language tests: UTF-8, two-space indentation, documented field order, and a trailing newline. Input parsing is field-based and does not require the same field order; cryptographic AAD binds explicit schema and key identifiers rather than the raw JSON serialization.
