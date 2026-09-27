// Master Password strength estimation.
//
// The previous estimator was length-and-alphabet arithmetic
// (length * 3 + uniqueChars * 1.5), which reported 39 bits for Password1 while
// that password sits at rank 2006 of a leaked-password dictionary and falls to
// a rented cluster in a fraction of a second. ADR 0012 asks for mature
// estimation, so dictionary membership and repetition now cap the estimate
// before any length term is credited.

// A small anchor set of the passwords that dominate leak corpora. It is not a
// substitute for a full denylist: it exists so the estimator stops reporting a
// several-hundred-million-fold overestimate for the worst offenders.
const COMMON_PASSWORDS = new Set([
  'password', '123456', '12345678', '123456789', '1234567890', 'qwerty',
  'abc123', 'letmein', 'monkey', 'dragon', 'iloveyou', 'admin', 'admin123',
  'welcome', 'login', 'princess', 'sunshine', 'master', 'football',
  'baseball', 'starwars', 'whatever', 'trustno1', '000000', '111111',
  '121212', '654321', 'qwerty123', '1q2w3e4r', 'zaq12wsx', 'superman',
  'passw0rd', 'p@ssw0rd', 'password1', 'password123', 'pass123', 'a123456',
  '1qaz2wsx', 'qazwsx', 'woaini', 'woaini1314', 'woaini520', '5201314',
  '5201314520', 'aa123456', '123456a', '123456789a', 'asdfgh', 'zxcvbnm',
  'asdf1234', 'qwerty123456', 'admin888', 'root123', 'test123',
]);

const LEET_MAP = {
  '@': 'a', '4': 'a', '0': 'o', '3': 'e', '1': 'l', '5': 's', '7': 't',
  '$': 's', '!': 'i', '8': 'b', '9': 'g', '2': 'z',
};

const TRAILING = ['123456', '12345', '1234', '123', '12', '1', '2026', '2025',
  '2024', '2023', '2022', '2021', '1314', '520', '666', '888'];

function collapseLeet(text) {
  return [...text].map((ch) => LEET_MAP[ch] ?? ch).join('');
}

function dictionaryForms(password) {
  const lowered = password.toLowerCase();
  const forms = new Set([lowered, collapseLeet(lowered)]);
  for (const sep of ['_', '-', '.', ' ']) {
    for (const form of [...forms]) forms.add(form.split(sep).join(''));
  }
  const expanded = new Set(forms);
  for (const form of forms) {
    for (const suffix of TRAILING) {
      if (form.length > suffix.length && form.endsWith(suffix)) {
        const stripped = form.slice(0, -suffix.length);
        expanded.add(stripped);
        for (const extra of TRAILING) {
          if (stripped.length > extra.length && stripped.endsWith(extra)) {
            expanded.add(stripped.slice(0, -extra.length));
          }
        }
      }
    }
  }
  return expanded;
}

function isRepetition(password) {
  if (password.length < 4) return false;
  for (let period = 1; period <= password.length / 2; period += 1) {
    if (password.length % period === 0) {
      if (password === password.slice(0, period).repeat(password.length / period)) return true;
    }
  }
  return false;
}

export function checkPasswordStrength(masterPassword) {
  const uniqueChars = new Set(masterPassword).size;
  const warnings = [];
  const suggestions = [];

  const compromised = [...dictionaryForms(masterPassword)].some((form) => COMMON_PASSWORDS.has(form));
  const repeated = isRepetition(masterPassword);

  if (compromised) {
    warnings.push('Master Password appears in common-password lists.');
    suggestions.push('Choose a phrase that is not in any leaked-password list.');
  }
  if (masterPassword.length < 12) {
    warnings.push('Master Password is short.');
    suggestions.push('Use a longer passphrase.');
  }
  if (uniqueChars <= 4 && masterPassword.length >= 8) {
    warnings.push('Master Password uses too little character variety.');
    suggestions.push('Use several unrelated words or more varied characters.');
  }
  if (repeated) {
    warnings.push('Master Password is a repetition or a simple sequence.');
    suggestions.push('Avoid repeated or sequential characters.');
  }

  // A dictionary word cannot be credited for its length: an offline attacker
  // never enumerates its characters.
  const estimatedEntropyBits = (compromised || repeated)
    ? Math.min(20, Math.max(1, masterPassword.length))
    : Math.min(128, Math.round((masterPassword.length * 3 + uniqueChars * 1.5) * 10) / 10);

  let level = 'fair';
  if (warnings.length) {
    level = 'weak';
  } else if (masterPassword.length >= 32 && uniqueChars >= 12) {
    level = 'strong';
  } else if (masterPassword.length >= 20 && uniqueChars >= 10) {
    level = 'good';
  }
  return { level, allowed: true, warnings, suggestions, estimatedEntropyBits, compromised };
}
