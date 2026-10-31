package com.hxdatalock

import com.nulabinc.zxcvbn.Zxcvbn
import kotlin.math.log2
import kotlin.math.round

data class PasswordStrengthReport(
    val level: String,
    val allowed: Boolean,
    val warnings: List<String>,
    val suggestions: List<String>,
    val estimatedEntropyBits: Double,
    val compromised: Boolean,
    val score: Int,
    val guessesLog10: Double,
    val allowedForPublicKeyring: Boolean,
)

/**
 * Same zxcvbn thresholds as the Python and TypeScript SDKs.
 * `allowed` requires score >= 3 and about 46 bits. Public Keyring creation
 * requires about 80 bits and cannot be waived with allowWeakPassword.
 */
internal object PasswordStrength {
    private val estimator = Zxcvbn()
    private const val PRIVATE_MIN_GUESSES_LOG10 = 14.0
    private const val PUBLIC_MIN_GUESSES_LOG10 = 24.082399653118497
    private val levels = listOf("weak", "weak", "fair", "good", "strong")

    fun check(masterPassword: String): PasswordStrengthReport {
        val measured = estimator.measure(masterPassword)
        val score = measured.score
        val guessesLog10 = measured.guessesLog10
        val entropyBits = round(guessesLog10 * log2(10.0) * 10.0) / 10.0
        val warning = measured.feedback?.warning.orEmpty()
        val suggestions = measured.feedback?.suggestions?.toMutableList() ?: mutableListOf()
        val warnings = mutableListOf<String>()
        if (warning.isNotEmpty()) warnings.add(warning)
        var level = levels.getOrElse(score) { "weak" }
        if (guessesLog10 < PRIVATE_MIN_GUESSES_LOG10 && (level == "good" || level == "strong")) {
            level = "fair"
            warnings.add("Estimated entropy is below 46 bits. That is not enough if a Keyring copy leaks.")
            suggestions.add("Use a longer passphrase or a randomly generated Master Password.")
        }
        val compromised = score <= 1 || warning.contains("common", ignoreCase = true)
        return PasswordStrengthReport(
            level = level,
            allowed = score >= 3 && guessesLog10 >= PRIVATE_MIN_GUESSES_LOG10,
            warnings = warnings,
            suggestions = suggestions,
            estimatedEntropyBits = entropyBits,
            compromised = compromised,
            score = score,
            guessesLog10 = round(guessesLog10 * 10000.0) / 10000.0,
            allowedForPublicKeyring = guessesLog10 >= PUBLIC_MIN_GUESSES_LOG10,
        )
    }
}
