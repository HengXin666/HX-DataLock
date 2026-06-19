# CLI Confirms Master Password

Interactive `hxdl init` asks for the Master Password twice before creating a Keyring, because a mistyped Master Password can make future Data Envelopes unusable. SDK keyring creation accepts one Master Password value and leaves confirmation to the calling application; non-interactive environment-variable input also skips confirmation.
