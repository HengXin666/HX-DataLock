export function checkPasswordStrength(masterPassword) {
  const uniqueChars = new Set(masterPassword).size;
  const warnings = [];
  const suggestions = [];
  const common = new Set(['password', '123456', 'qwerty', 'admin', 'letmein']);
  if (masterPassword.length < 12) {
    warnings.push('Master Password is short.');
    suggestions.push('Use a longer passphrase.');
  }
  if (common.has(masterPassword.toLowerCase())) {
    warnings.push('Master Password is a commonly used password.');
    suggestions.push('Avoid common passwords.');
  }
  if (uniqueChars <= 4 && masterPassword.length >= 8) {
    warnings.push('Master Password uses too little character variety.');
    suggestions.push('Use several unrelated words or more varied characters.');
  }
  let level = 'fair';
  if (warnings.length) {
    level = 'weak';
  } else if (masterPassword.length >= 32 && uniqueChars >= 12) {
    level = 'strong';
  } else if (masterPassword.length >= 20 && uniqueChars >= 10) {
    level = 'good';
  }
  return {
    level,
    allowed: true,
    warnings,
    suggestions,
    estimatedEntropyBits: Math.min(128, Math.round((masterPassword.length * 3 + uniqueChars * 1.5) * 10) / 10),
  };
}
