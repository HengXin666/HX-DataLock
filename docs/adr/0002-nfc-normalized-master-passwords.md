# NFC-normalized Master Passwords

Master Passwords are normalized with Unicode NFC before UTF-8 encoding and key derivation. This keeps Chinese, Japanese, and other non-English input usable while reducing accidental lockout from visually identical but differently encoded text; NFKC was rejected because it can collapse characters that users may reasonably expect to remain distinct.
