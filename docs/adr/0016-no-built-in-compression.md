# No Built-in Compression

V1 does not compress Payload Bytes before locking and does not record compression metadata in Data Envelopes. Compression changes compatibility and can expose length side channels in some workflows, so applications that need compression must apply it before `lockBytes` and reverse it after `openBytes`.
