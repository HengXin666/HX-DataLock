# Raise the scrypt floor for new Keyrings

Status: 不予处理

Done. New Keyrings with `N < 2^17` fail with `INSECURE_SCRYPT_PARAMETERS` unless the caller passes `allow_low_scrypt_n` / `allowLowScryptN` / `--allow-low-scrypt-n`. Readers still open Keyrings down to `2^14`. Parameters outside the reader window still use `INVALID_SCRYPT_PARAMS`.
