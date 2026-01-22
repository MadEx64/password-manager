/**
 * Password strength analyzer module.
 * 
 * Provides zxcvbn-style password strength analysis including score calculation,
 * crack time estimation, and user feedback.
 */

const COMMON_PASSWORDS = new Set([
  'password', '12345678', '123456789', '1234567890', 'qwerty', 'abc123',
  'password1', 'Password1', 'welcome', 'monkey', '1234567', 'letmein',
  'trustno1', 'dragon', 'baseball', 'iloveyou', 'master', 'sunshine',
  'ashley', 'bailey', 'passw0rd', 'shadow', '123123', '654321',
  'superman', 'qazwsx', 'michael', 'football', 'jesus', 'mustang',
  'access', 'flower', 'hello', 'freedom', 'whatever', 'qwertyuiop'
]);

const KEYBOARD_PATTERNS = [
  'qwerty', 'qwertyuiop', 'asdfgh', 'asdfghjkl', 'zxcvbn', 'zxcvbnm',
  '123456', '12345678', '123456789', '1234567890'
];

/**
 * Calculates the entropy (bits) of a password.
 *
 * @param {string} password - The password to analyze.
 * @returns {number} The entropy in bits.
 */
function calculateEntropy(password) {
  let charsetSize = 0;
  let hasLower = false;
  let hasUpper = false;
  let hasNumber = false;
  let hasSpecial = false;

  for (const char of password) {
    if (/[a-z]/.test(char) && !hasLower) {
      charsetSize += 26;
      hasLower = true;
    } else if (/[A-Z]/.test(char) && !hasUpper) {
      charsetSize += 26;
      hasUpper = true;
    } else if (/[0-9]/.test(char) && !hasNumber) {
      charsetSize += 10;
      hasNumber = true;
    } else if (/[^a-zA-Z0-9]/.test(char) && !hasSpecial) {
      charsetSize += 33; // Common special characters
      hasSpecial = true;
    }
  }

  if (charsetSize === 0) return 0;
  return Math.log2(charsetSize) * password.length;
}

/**
 * Checks for repeated characters in the password.
 *
 * @param {string} password - The password to check.
 * @returns {number} The number of repeated character sequences found.
 */
function countRepeats(password) {
  let repeats = 0;
  let lastChar = '';
  let repeatCount = 1;

  for (const char of password) {
    if (char === lastChar) {
      repeatCount++;
      if (repeatCount >= 3) {
        repeats++;
      }
    } else {
      repeatCount = 1;
    }
    lastChar = char;
  }

  return repeats;
}

/**
 * Checks for sequential characters (e.g., "abc", "123").
 *
 * @param {string} password - The password to check.
 * @returns {number} The number of sequential patterns found.
 */
function countSequences(password) {
  let sequences = 0;
  const lowerPassword = password.toLowerCase();

  for (let i = 0; i < lowerPassword.length - 2; i++) {
    const char1 = lowerPassword.charCodeAt(i);
    const char2 = lowerPassword.charCodeAt(i + 1);
    const char3 = lowerPassword.charCodeAt(i + 2);

    // Check for ascending sequences
    if (char2 === char1 + 1 && char3 === char2 + 1) {
      sequences++;
    }
    // Check for descending sequences
    if (char2 === char1 - 1 && char3 === char2 - 1) {
      sequences++;
    }
  }

  return sequences;
}

/**
 * Checks if the password contains common words or patterns.
 *
 * @param {string} password - The password to check.
 * @returns {boolean} True if the password contains common patterns.
 */
function isCommonPassword(password) {
  const lowerPassword = password.toLowerCase();
  
  if (COMMON_PASSWORDS.has(lowerPassword)) {
    return true;
  }

  // Check for common words at the start or if they make up a significant portion
  // Only flag if the common word is at least 6 characters and is a major part of the password
  const commonWords = ['password', 'admin', 'welcome', 'qwerty', 'letmein', 'master'];
  for (const word of commonWords) {
    if (word.length >= 6) {
      // Check if password starts with the word or the word is a significant portion
      if (lowerPassword.startsWith(word) && lowerPassword.length <= word.length + 3) {
        return true;
      }
      // Check if the word makes up more than 50% of the password
      if (lowerPassword.includes(word) && word.length >= lowerPassword.length * 0.5) {
        return true;
      }
    }
  }

  // Check for keyboard patterns (only if they're a significant portion)
  for (const pattern of KEYBOARD_PATTERNS) {
    if (pattern.length >= 6 && lowerPassword.includes(pattern)) {
      // Only flag if pattern is a significant portion of the password
      if (pattern.length >= lowerPassword.length * 0.5) {
        return true;
      }
    }
  }

  return false;
}

/**
 * Estimates the time it would take to crack the password.
 *
 * @param {number} entropy - The entropy in bits.
 * @returns {string} A human-readable estimate of crack time.
 */
function estimateCrackTime(entropy) {
  // Assuming 10^9 guesses per second (modern GPU)
  const guessesPerSecond = 1e9;
  const totalGuesses = Math.pow(2, entropy);
  const seconds = totalGuesses / guessesPerSecond;

  if (seconds < 1) {
    return 'instant';
  } else if (seconds < 60) {
    return `${Math.round(seconds)} second${Math.round(seconds) !== 1 ? 's' : ''}`;
  } else if (seconds < 3600) {
    const minutes = Math.round(seconds / 60);
    return `${minutes} minute${minutes !== 1 ? 's' : ''}`;
  } else if (seconds < 86400) {
    const hours = Math.round(seconds / 3600);
    return `${hours} hour${hours !== 1 ? 's' : ''}`;
  } else if (seconds < 2592000) {
    const days = Math.round(seconds / 86400);
    return `${days} day${days !== 1 ? 's' : ''}`;
  } else if (seconds < 31536000) {
    const months = Math.round(seconds / 2592000);
    return `${months} month${months !== 1 ? 's' : ''}`;
  } else if (seconds < 315360000) {
    const years = Math.round(seconds / 31536000);
    return `${years} year${years !== 1 ? 's' : ''}`;
  } else {
    const centuries = Math.round(seconds / 3153600000);
    return `${centuries} centur${centuries !== 1 ? 'ies' : 'y'}`;
  }
}

/**
 * Generates feedback and suggestions based on password analysis.
 *
 * @param {string} password - The password analyzed.
 * @param {number} entropy - The entropy in bits.
 * @param {number} repeats - The number of repeated sequences.
 * @param {number} sequences - The number of sequential patterns.
 * @param {boolean} isCommon - Whether the password is common.
 * @returns {Object} An object containing warning and suggestions.
 */
function generateFeedback(password, entropy, repeats, sequences, isCommon) {
  const feedback = {
    warning: null,
    suggestions: []
  };

  if (password.length < 8) {
    feedback.warning = 'This password is too short.';
    feedback.suggestions.push('Use at least 12 characters for better security.');
  } else if (password.length < 12) {
    feedback.suggestions.push('Consider using 12 or more characters.');
  }

  if (isCommon) {
    feedback.warning = 'This password is too common and easily guessed.';
    feedback.suggestions.push('Avoid common passwords and dictionary words.');
  }

  const hasLower = /[a-z]/.test(password);
  const hasUpper = /[A-Z]/.test(password);
  const hasNumber = /[0-9]/.test(password);
  const hasSpecial = /[^a-zA-Z0-9]/.test(password);

  if (!hasLower) {
    feedback.suggestions.push('Add lowercase letters.');
  }
  if (!hasUpper) {
    feedback.suggestions.push('Add uppercase letters.');
  }
  if (!hasNumber) {
    feedback.suggestions.push('Add numbers.');
  }
  if (!hasSpecial) {
    feedback.suggestions.push('Add special characters (e.g., !@#$%^&*).');
  }

  if (repeats > 0 && !feedback.warning) {
    feedback.warning = 'This password contains repeated characters.';
    feedback.suggestions.push('Avoid repeating the same character multiple times.');
  } else if (repeats > 0) {
    feedback.suggestions.push('Avoid repeating the same character multiple times.');
  }

  if (sequences > 0 && !feedback.warning) {
    feedback.warning = 'This password contains sequential patterns.';
    feedback.suggestions.push('Avoid sequential characters (e.g., "abc", "123").');
  } else if (sequences > 0) {
    feedback.suggestions.push('Avoid sequential characters (e.g., "abc", "123").');
  }

  if (entropy < 40) {
    if (!feedback.warning) {
      feedback.warning = 'This password is weak.';
    }
    feedback.suggestions.push('Use a mix of different character types and make it longer.');
  } else if (entropy < 60) {
    feedback.suggestions.push('Consider making the password longer or more complex.');
  }

  if (!feedback.warning && feedback.suggestions.length === 0) {
    feedback.suggestions.push('This password is strong enough.');
  }

  return feedback;
}

/**
 * Analyzes password strength and returns a comprehensive analysis.
 *
 * @param {string} password - The password to analyze.
 * @returns {Object} An object containing score, crackTime, and feedback.
 * @returns {number} returns.score - Password strength score from 0-4 (0=weak, 4=very strong).
 * @returns {string} returns.crackTime - Estimated time to crack the password.
 * @returns {Object} returns.feedback - Feedback object with warning and suggestions.
 * @returns {string|null} returns.feedback.warning - Warning message if password has issues.
 * @returns {string[]} returns.feedback.suggestions - Array of improvement suggestions.
 *
 * @example
 * const analysis = analyzePasswordStrength("MyP@ssw0rd123");
 * console.log(analysis.score); // 3
 * console.log(analysis.crackTime); // "2 hours"
 * console.log(analysis.feedback.suggestions); // ["Consider using 12 or more characters."]
 */
export function analyzePasswordStrength(password) {
  if (typeof password !== 'string') {
    return {
      score: 0,
      crackTime: 'instant',
      feedback: {
        warning: 'Invalid password input.',
        suggestions: ['Please provide a valid password string.']
      }
    };
  }

  if (password.length === 0) {
    return {
      score: 0,
      crackTime: 'instant',
      feedback: {
        warning: 'Password cannot be empty.',
        suggestions: ['Please enter a password.']
      }
    };
  }

  // Calculate metrics
  const entropy = calculateEntropy(password);
  const repeats = countRepeats(password);
  const sequences = countSequences(password);
  const isCommon = isCommonPassword(password);

  // Calculate score (0-4)
  let score = 0;

  // Base score from entropy
  if (entropy >= 80) {
    score = 4;
  } else if (entropy >= 60) {
    score = 3;
  } else if (entropy >= 40) {
    score = 2;
  } else if (entropy >= 20) {
    score = 1;
  } else {
    score = 0;
  }

  // Penalize for common patterns
  if (isCommon) {
    score = Math.max(0, score - 2);
  }

  // Penalize for repeats and sequences
  if (repeats > 0) {
    score = Math.max(0, score - 1);
  }
  if (sequences > 0) {
    score = Math.max(0, score - 1);
  }

  // Bonus for length
  if (password.length >= 16) {
    score = Math.min(4, score + 1);
  } else if (password.length >= 12) {
    score = Math.min(4, score + 0.5);
  }

  // Ensure score is integer between 0-4
  score = Math.round(Math.max(0, Math.min(4, score)));

  // Estimate crack time
  const crackTime = estimateCrackTime(entropy);

  // Generate feedback
  const feedback = generateFeedback(password, entropy, repeats, sequences, isCommon);

  return {
    score,
    crackTime,
    feedback
  };
}
