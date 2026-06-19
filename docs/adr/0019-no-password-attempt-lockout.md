# No Password Attempt Lockout

V1 does not implement password attempt limits or lockout as a security control. A leaked Keyring can be copied and attacked offline, so lockout would only constrain honest clients; offline attack resistance comes from Master Password strength and the configured scrypt cost.
