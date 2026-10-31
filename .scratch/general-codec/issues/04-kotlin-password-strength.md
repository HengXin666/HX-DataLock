# Kotlin password strength

Status: 不予处理

Done in the codec branch. `HxDataLock.checkPasswordStrength` uses `com.nulab-inc:zxcvbn` and the same score / 46-bit / 80-bit rules as Python and TypeScript. `createKeyring` refuses a weak password unless `allowWeakPassword` is set.
