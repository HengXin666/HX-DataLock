import Foundation
import zxcvbn

enum PasswordStrength {
    static let privateMinLog10 = 14.0
    static let publicMinLog10 = 24.082399653118497

    static func check(_ password: String) -> PasswordStrengthReport {
        let measured = zxcvbn(password)
        let score = measured.score ?? 0
        let guessesLog10 = measured.guessesLog10
        let entropy = (guessesLog10 * log2(10) * 10).rounded() / 10
        var warnings: [String] = []
        var suggestions: [String] = []
        if let feedback = measured.feedback {
            if let warning = feedback["warning"]?.first, !warning.isEmpty {
                warnings.append(warning)
            }
            suggestions.append(contentsOf: feedback["suggestions"] ?? [])
        }
        let levels = ["weak", "weak", "fair", "good", "strong"]
        var level = score >= 0 && score < levels.count ? levels[score] : "weak"
        if guessesLog10 < privateMinLog10 && (level == "good" || level == "strong") {
            level = "fair"
            warnings.append("Estimated entropy is below 46 bits. That is not enough if a Keyring copy leaks.")
            suggestions.append("Use a longer passphrase or a randomly generated Master Password.")
        }
        let warningText = warnings.first ?? ""
        return PasswordStrengthReport(
            level: level,
            allowed: score >= 3 && guessesLog10 >= privateMinLog10,
            warnings: warnings,
            suggestions: suggestions,
            estimatedEntropyBits: entropy,
            compromised: score <= 1 || warningText.lowercased().contains("common"),
            score: score,
            guessesLog10: (guessesLog10 * 10000).rounded() / 10000,
            allowedForPublicKeyring: guessesLog10 >= publicMinLog10
        )
    }
}
