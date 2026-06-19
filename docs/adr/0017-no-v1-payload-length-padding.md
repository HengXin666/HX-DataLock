# No V1 Payload Length Padding

V1 does not pad Payload Bytes to hide Data Envelope size. Public Storage observers may learn approximate payload size, Creation Time, and Recipient Key ID, but they do not learn Master Password length because the Master Password is never stored in or sent with Keyrings, Public Key Documents, or Data Envelopes.
