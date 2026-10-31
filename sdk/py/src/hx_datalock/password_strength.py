from __future__ import annotations

import math
from typing import Literal, TypedDict

from zxcvbn import zxcvbn

from .constants import PRIVATE_MIN_GUESSES_LOG10, PUBLIC_MIN_GUESSES_LOG10


class PasswordStrengthReport(TypedDict, total=False):
    level: Literal["weak", "fair", "good", "strong"]
    allowed: bool
    warnings: list[str]
    suggestions: list[str]
    estimatedEntropyBits: float
    compromised: bool
    score: int
    guessesLog10: float
    allowedForPublicKeyring: bool


_LEVEL_BY_SCORE: dict[int, Literal["weak", "fair", "good", "strong"]] = {
    0: "weak",
    1: "weak",
    2: "fair",
    3: "good",
    4: "strong",
}


def check_password_strength(master_password: str) -> PasswordStrengthReport:
    """Estimate Master Password strength with zxcvbn.

    `allowed` is true only when zxcvbn's score is at least 3 (safely
    unguessable) and the guess-count estimate is at least about 46 bits.
    Score alone is not enough: zxcvbn can mark some name-and-date strings as
    score 4 while still putting them well under that floor. Public Keyring
    creation uses `allowedForPublicKeyring`, which requires about 80 bits.
    """
    if not isinstance(master_password, str):
        raise TypeError("master_password must be a string")

    measured = zxcvbn(master_password)
    score = int(measured["score"])
    guesses_log10 = float(measured["guesses_log10"])
    entropy_bits = round(guesses_log10 * math.log2(10), 1)
    feedback = measured.get("feedback") or {}
    warning = feedback.get("warning") or ""
    suggestions = [item for item in (feedback.get("suggestions") or []) if item]

    warnings: list[str] = []
    if warning:
        warnings.append(warning)
    level = _LEVEL_BY_SCORE.get(score, "weak")
    if guesses_log10 < PRIVATE_MIN_GUESSES_LOG10 and level in {"good", "strong"}:
        level = "fair"
        warnings.append(
            "Estimated entropy is below 46 bits. That is not enough if a Keyring copy leaks."
        )
        suggestions.append("Use a longer passphrase or a randomly generated Master Password.")

    compromised = score <= 1 or "common" in warning.lower()
    allowed = score >= 3 and guesses_log10 >= PRIVATE_MIN_GUESSES_LOG10
    allowed_for_public = guesses_log10 >= PUBLIC_MIN_GUESSES_LOG10

    return {
        "level": level,
        "allowed": allowed,
        "warnings": warnings,
        "suggestions": suggestions,
        "estimatedEntropyBits": entropy_bits,
        "compromised": compromised,
        "score": score,
        "guessesLog10": round(guesses_log10, 4),
        "allowedForPublicKeyring": allowed_for_public,
    }
