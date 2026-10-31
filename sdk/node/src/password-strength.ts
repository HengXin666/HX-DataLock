import { ZxcvbnFactory } from '@zxcvbn-ts/core';
import * as zxcvbnCommonPackage from '@zxcvbn-ts/language-common';
import * as zxcvbnEnPackage from '@zxcvbn-ts/language-en';
import { PRIVATE_MIN_GUESSES_LOG10, PUBLIC_MIN_GUESSES_LOG10 } from './constants.js';

const zxcvbn = new ZxcvbnFactory({
  translations: zxcvbnEnPackage.translations,
  graphs: zxcvbnCommonPackage.adjacencyGraphs,
  dictionary: {
    ...zxcvbnCommonPackage.dictionary,
    ...zxcvbnEnPackage.dictionary,
  },
});

export type PasswordLevel = 'weak' | 'fair' | 'good' | 'strong';

export interface PasswordStrengthReport {
  level: PasswordLevel;
  allowed: boolean;
  warnings: string[];
  suggestions: string[];
  estimatedEntropyBits: number;
  compromised: boolean;
  score: number;
  guessesLog10: number;
  allowedForPublicKeyring: boolean;
}

const LEVEL_BY_SCORE: PasswordLevel[] = ['weak', 'weak', 'fair', 'good', 'strong'];

export function checkPasswordStrength(masterPassword: string): PasswordStrengthReport {
  if (typeof masterPassword !== 'string') {
    throw new TypeError('masterPassword must be a string');
  }
  const measured = zxcvbn.check(masterPassword);
  const score = measured.score;
  const guessesLog10 = measured.guessesLog10;
  const entropyBits = Math.round(guessesLog10 * Math.LOG2E * Math.LN10 * 10) / 10;
  const warning = measured.feedback?.warning || '';
  const suggestions = [...(measured.feedback?.suggestions || [])];
  const warnings: string[] = [];
  if (warning) warnings.push(warning);
  let level = LEVEL_BY_SCORE[score] ?? 'weak';
  if (guessesLog10 < PRIVATE_MIN_GUESSES_LOG10 && (level === 'good' || level === 'strong')) {
    level = 'fair';
    warnings.push('Estimated entropy is below 46 bits. That is not enough if a Keyring copy leaks.');
    suggestions.push('Use a longer passphrase or a randomly generated Master Password.');
  }
  const compromised = score <= 1 || warning.toLowerCase().includes('common');
  return {
    level,
    allowed: score >= 3 && guessesLog10 >= PRIVATE_MIN_GUESSES_LOG10,
    warnings,
    suggestions,
    estimatedEntropyBits: entropyBits,
    compromised,
    score,
    guessesLog10: Math.round(guessesLog10 * 10000) / 10000,
    allowedForPublicKeyring: guessesLog10 >= PUBLIC_MIN_GUESSES_LOG10,
  };
}
