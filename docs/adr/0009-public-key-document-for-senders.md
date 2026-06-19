# Public Key Document for Senders

V1 supports a Public Key Document containing only the Write Key as the only input for Write-only Senders. Users create a full Keyring locally, export the Public Key Document, and give only that public document to GitHub Actions or other automation; automation must not receive Master Password-related material, including the encrypted Read Key.

User DataLock uses the full Keyring directly. Because the full Keyring already contains the Write Key and the encrypted Read Key, a local user environment can both lock new data and open existing Data Envelopes without loading a separate Public Key Document.
