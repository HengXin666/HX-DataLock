from __future__ import annotations

from typing import Literal, TypedDict


class PasswordStrengthReport(TypedDict, total=False):
    level: Literal["weak", "fair", "good", "strong"]
    allowed: bool
    warnings: list[str]
    suggestions: list[str]
    estimatedEntropyBits: float
    compromised: bool


# A small anchor set of the passwords that dominate leak corpora. It is not a
# substitute for a full denylist: it exists so the estimator stops reporting a
# several-hundred-million-fold overestimate for the worst offenders. ADR 0012
# keeps the estimator out of the document format, so this list can grow with no
# compatibility consequence.
COMMON_PASSWORDS = frozenset({
    "password", "123456", "12345678", "123456789", "1234567890", "qwerty",
    "abc123", "letmein", "monkey", "dragon", "iloveyou", "admin", "admin123",
    "welcome", "login", "princess", "sunshine", "master", "football",
    "baseball", "starwars", "whatever", "trustno1", "000000", "111111",
    "121212", "654321", "qwerty123", "1q2w3e4r", "zaq12wsx", "superman",
    "passw0rd", "p@ssw0rd", "password1", "password123", "pass123", "a123456",
    "1qaz2wsx", "qazwsx", "woaini", "woaini1314", "woaini520", "5201314",
    "5201314520", "aa123456", "123456a", "123456789a", "asdfgh", "zxcvbnm",
    "asdf1234", "qwerty123456", "admin888", "root123", "test123",
})

# Leet substitutions collapse back to the base word, so P@ssw0rd is checked as
# password rather than as an unrelated 8-character string.
_LEET_MAP = {
    "@": "a", "4": "a", "0": "o", "3": "e", "1": "l", "5": "s", "7": "t",
    "$": "s", "!": "i", "8": "b", "9": "g", "2": "z",
}

# Suffixes users append to a dictionary word. Stripping them before the lookup
# is what catches Summer2024 and iloveyou123.
_TRAILING = ("123456", "12345", "1234", "123", "12", "1", "2026", "2025",
             "2024", "2023", "2022", "2021", "1314", "520", "666", "888")


def _collapse_leet(text: str) -> str:
    return "".join(_LEET_MAP.get(ch, ch) for ch in text)


def _dictionary_forms(password: str) -> set[str]:
    """Every form of the password that a mangling rule would generate."""
    lowered = password.lower()
    forms = {lowered, _collapse_leet(lowered)}
    forms |= {form.replace(sep, "") for form in list(forms) for sep in ("_", "-", ".", " ")}
    expanded = set(forms)
    for form in forms:
        for suffix in _TRAILING:
            if len(form) > len(suffix) and form.endswith(suffix):
                stripped = form[: -len(suffix)]
                expanded.add(stripped)
                for extra in _TRAILING:
                    if len(stripped) > len(extra) and stripped.endswith(extra):
                        expanded.add(stripped[: -len(extra)])
    return expanded


def _is_repetition(password: str) -> bool:
    """True for aaaaaa and for abcabcabc, both of which collapse to a period."""
    if len(password) < 4:
        return False
    for period in range(1, len(password) // 2 + 1):
        if len(password) % period == 0:
            if password == password[:period] * (len(password) // period):
                return True
    return False


def check_password_strength(master_password: str) -> PasswordStrengthReport:
    """Estimate Master Password strength.

    The previous estimator was length-and-alphabet arithmetic
    (len * 3 + unique_chars * 1.5), which reported 39 bits for Password1 while
    that password sits at rank 2006 of a leaked-password dictionary and falls
    to a rented cluster in a fraction of a second. ADR 0012 asks for mature
    estimation, so dictionary membership and repetition now cap the estimate
    before any length term is credited.
    """
    unique_chars = len(set(master_password))
    compromised = bool(_dictionary_forms(master_password) & COMMON_PASSWORDS)
    repeated = _is_repetition(master_password)

    warnings: list[str] = []
    suggestions: list[str] = []

    if compromised:
        warnings.append("Master Password appears in common-password lists.")
        suggestions.append("Choose a phrase that is not in any leaked-password list.")
    if len(master_password) < 12:
        warnings.append("Master Password is short.")
        suggestions.append("Use a longer passphrase.")
    if unique_chars <= 4 and len(master_password) >= 8:
        warnings.append("Master Password uses too little character variety.")
        suggestions.append("Use several unrelated words or more varied characters.")
    if repeated:
        warnings.append("Master Password is a repetition or a simple sequence.")
        suggestions.append("Avoid repeated or sequential characters.")

    # A dictionary word cannot be credited for its length: an offline attacker
    # never enumerates its characters.
    if compromised or repeated:
        estimated_entropy = min(20.0, float(max(1, len(master_password))))
    else:
        estimated_entropy = min(128.0, round(len(master_password) * 3.0 + unique_chars * 1.5, 1))

    if warnings:
        level: Literal["weak", "fair", "good", "strong"] = "weak"
    elif len(master_password) >= 32 and unique_chars >= 12:
        level = "strong"
    elif len(master_password) >= 20 and unique_chars >= 10:
        level = "good"
    else:
        level = "fair"

    return {
        "level": level,
        "allowed": True,
        "warnings": warnings,
        "suggestions": suggestions,
        "estimatedEntropyBits": estimated_entropy,
        "compromised": compromised,
    }
