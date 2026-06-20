from __future__ import annotations

from typing import Literal, TypedDict


class PasswordStrengthReport(TypedDict, total=False):
    level: Literal["weak", "fair", "good", "strong"]
    allowed: bool
    warnings: list[str]
    suggestions: list[str]
    estimatedEntropyBits: float


def check_password_strength(master_password: str) -> PasswordStrengthReport:
    unique_chars = len(set(master_password))
    estimated_entropy = min(128.0, round(len(master_password) * 3.0 + unique_chars * 1.5, 1))
    warnings: list[str] = []
    suggestions: list[str] = []

    common_passwords = {"password", "123456", "qwerty", "admin", "letmein"}
    lower_password = master_password.lower()
    if len(master_password) < 12:
        warnings.append("Master Password is short.")
        suggestions.append("Use a longer passphrase.")
    if lower_password in common_passwords:
        warnings.append("Master Password is a commonly used password.")
        suggestions.append("Avoid common passwords.")
    if unique_chars <= 4 and len(master_password) >= 8:
        warnings.append("Master Password uses too little character variety.")
        suggestions.append("Use several unrelated words or more varied characters.")

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
    }
