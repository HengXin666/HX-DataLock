package com.hxdatalock

// Same weak/not-weak policy as the Python and TypeScript Password Strength
// Reports. Kotlin does not expose the report object; createKeyring uses this
// only to refuse a weak Master Password unless the caller opts in.
internal object PasswordStrength {
    private val COMMON_PASSWORDS = setOf(
        "password", "123456", "12345678", "123456789", "1234567890", "qwerty",
        "abc123", "letmein", "monkey", "dragon", "iloveyou", "admin", "admin123",
        "welcome", "login", "princess", "sunshine", "master", "football",
        "baseball", "starwars", "whatever", "trustno1", "000000", "111111",
        "121212", "654321", "qwerty123", "1q2w3e4r", "zaq12wsx", "superman",
        "passw0rd", "p@ssw0rd", "password1", "password123", "pass123", "a123456",
        "1qaz2wsx", "qazwsx", "woaini", "woaini1314", "woaini520", "5201314",
        "5201314520", "aa123456", "123456a", "123456789a", "asdfgh", "zxcvbnm",
        "asdf1234", "qwerty123456", "admin888", "root123", "test123",
    )

    private val LEET = mapOf(
        '@' to 'a', '4' to 'a', '0' to 'o', '3' to 'e', '1' to 'l', '5' to 's', '7' to 't',
        '$' to 's', '!' to 'i', '8' to 'b', '9' to 'g', '2' to 'z',
    )

    private val TRAILING = listOf(
        "123456", "12345", "1234", "123", "12", "1", "2026", "2025",
        "2024", "2023", "2022", "2021", "1314", "520", "666", "888",
    )

    fun isWeak(masterPassword: String): Boolean {
        val uniqueChars = masterPassword.toSet().size
        val compromised = dictionaryForms(masterPassword).any { it in COMMON_PASSWORDS }
        val repeated = isRepetition(masterPassword)
        if (compromised || masterPassword.length < 12 || repeated) return true
        if (uniqueChars <= 4 && masterPassword.length >= 8) return true
        return false
    }

    private fun collapseLeet(text: String): String = text.map { LEET[it] ?: it }.joinToString("")

    private fun dictionaryForms(password: String): Set<String> {
        val lowered = password.lowercase()
        val forms = mutableSetOf(lowered, collapseLeet(lowered))
        val stripped = forms.flatMap { form ->
            listOf("_", "-", ".", " ").map { separator -> form.replace(separator, "") }
        }
        forms.addAll(stripped)
        val expanded = forms.toMutableSet()
        for (form in forms.toList()) {
            for (suffix in TRAILING) {
                if (form.length > suffix.length && form.endsWith(suffix)) {
                    val withoutSuffix = form.dropLast(suffix.length)
                    expanded.add(withoutSuffix)
                    for (extra in TRAILING) {
                        if (withoutSuffix.length > extra.length && withoutSuffix.endsWith(extra)) {
                            expanded.add(withoutSuffix.dropLast(extra.length))
                        }
                    }
                }
            }
        }
        return expanded
    }

    private fun isRepetition(password: String): Boolean {
        if (password.length < 4) return false
        for (period in 1..password.length / 2) {
            if (password.length % period == 0) {
                val unit = password.substring(0, period)
                if (unit.repeat(password.length / period) == password) return true
            }
        }
        return false
    }
}
