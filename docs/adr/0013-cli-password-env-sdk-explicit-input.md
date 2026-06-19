# CLI Password Env, SDK Explicit Input

The CLI may read the Master Password from an explicit environment variable option for automation, but SDKs do not read environment variables themselves. Applications must pass the Master Password explicitly, and Write-only Sender environments should not define any Master Password variable because they only use the Public Key Document.
