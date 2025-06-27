import { 
  getSecureRandomInt, 
  getSecureRandomChar, 
  secureShuffleArray 
} from "./encryption/index.js";
import { PasswordManagerError } from "./errorHandler.js";
import { ERROR_CODES } from "./constants.js";
import { red, bold } from "./logger.js";

/**
 * Generates a cryptographically secure random password with specified or random length (8-32 characters),
 * guaranteed to contain at least one lowercase letter, one uppercase letter, one number, and one special character.
 *
 * @param {number} [userLength=0] - Optional. The desired password length (8-32). If 0 or invalid, uses random length between 12-16.
 * @returns {string} The generated password.
 * @throws {PasswordManagerError} If the password length is invalid.
 *
 * @example
 * const password = generateRandomPassword();
 * console.log(password); // "aB3!kL9@mP1$" (random length 12-16)
 *
 * const password = generateRandomPassword(20);
 * console.log(password); // "aB3!kL9@mP1$nR5%qT8&" (exactly 20 characters)
 */
export function generateRandomPassword(userLength = 0) {
  const charSets = {
    lowercase: "abcdefghijklmnopqrstuvwxyz",
    uppercase: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    numbers: "0123456789",
    special: "-.!@#$%^&*_+=/?",
  };

  const minLength = 8;
  const maxLength = 32;
  const defaultMinLength = 12;
  const defaultMaxLength = 16;

  let length;
  if (userLength >= minLength && userLength <= maxLength) {
    length = Math.floor(userLength);
  } else {
    length = getSecureRandomInt(defaultMinLength, defaultMaxLength);
  }

  if (length < 4) {
    throw new PasswordManagerError(
      red("Password length must be at least 4 characters to include all required character types"),
      bold(red(ERROR_CODES.INVALID_INPUT))
    );
  }

  const allChars = Object.values(charSets).join("");

  const requiredChars = [
    getSecureRandomChar(charSets.lowercase),
    getSecureRandomChar(charSets.uppercase),
    getSecureRandomChar(charSets.numbers),
    getSecureRandomChar(charSets.special),
  ];

  const remainingLength = length - requiredChars.length;
  const randomChars = [];

  for (let i = 0; i < remainingLength; i++) {
    randomChars.push(getSecureRandomChar(allChars));
  }

  const allPasswordChars = [...requiredChars, ...randomChars];
  secureShuffleArray(allPasswordChars);

  return allPasswordChars.join("");
}


