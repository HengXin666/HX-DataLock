# No V1 Key Rotation

V1 does not support changing the Master Password or rotating the Write Key and Read Key in place. A true rotation requires opening existing Data Envelopes and locking the Payload Bytes under a new Keyring, which depends on application storage and migration semantics; users should choose the Master Password carefully at setup time and treat later migration as a business-owned Data Migration.
