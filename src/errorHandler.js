import chalk from 'chalk';
import { ERROR_CODES } from './constants.js';
const red = chalk.red;

/**
 * Custom error class for the password manager
 * @extends {Error}
 * @description This class is used to create custom errors for the password manager.
 */
export class PasswordManagerError extends Error {
  /**
   * Creates a new PasswordManagerError
   * @param {string} message - The error message
   * @param {string} code - The error code
   */
  constructor(message, code) {
    super(message);
    this.name = 'Error';
    this.code = code;
  }
}

/**
 * Handles an error and logs it to the console
 * @param {Error} error - The error to handle
 * @returns {void} If the error is a PasswordManagerError, it logs the error to the console and exits the program
 */
export const handleError = (error) => {
  if (error instanceof PasswordManagerError) {
    console.log(red(`\n ✗ Error (${error.code}): ${error.message}\n`));
  } else if (error.code === ERROR_CODES.FILE_NOT_FOUND) {
    console.log(red(`\n ✗ Error (${error.code}): ${error.message}\n`));
  } else if (error.code === ERROR_CODES.PERMISSION_DENIED) {
    console.log(red(`\n ✗ Error (${error.code}): ${error.message}\n`));
  } else {
    console.log(red(`\n ✗ Error (${error.code}): ${error.message}\n`));
  }

  // Exit the program
  console.log(red('Exiting...'));
  process.exit(1);
};

/**
 * Validates an input (e.g. empty input)
 * @param {string} input - The input to validate
 * @param {string} fieldName - The name of the field to validate
 * @returns {boolean | string} True if the input is valid, error message otherwise
 * @description This function validates the input and returns an error message if the input is invalid (e.g. empty input)
 */
export const validateInput = (input, fieldName) => {
  if (!input || input.trim() === '') {
    throw new PasswordManagerError(
      `Please enter a valid ${fieldName}.`,
      ERROR_CODES.INVALID_INPUT
    );
  }
  return true;
};

/**
 * Validates a password (e.g. password length, password characters)
 * @param {string} password
 * @returns {boolean | string} True if the password is valid, error message otherwise
 * @description This function validates the password and returns an error message if the password is invalid.
 */
export const validatePassword = (password) => {
  if (password.length < 8) {
    return "✗ Password must be at least 8 characters long. Please try again.";
  }
  if (!/[A-Z]/.test(password)) {
    return "✗ Password must contain at least one uppercase letter. Please try again.";
  }
  if (!/[0-9]/.test(password)) {
    return "✗ Password must contain at least one number. Please try again.";
  }
  if (!/[-.!@#$%^&*_+=/?]/.test(password)) {
    return "✗ Password must contain at least one special character. Please try again.";
  }

  // If all checks pass, return true
  return true;
};

/**
 * Checks if the password and the password to check match
 * @param {string} password - The password to check
 * @param {string} passwordToCheck - The password to check against
 * @returns {boolean} True if the passwords match, otherwise an error message
 */
export const checkPasswordMatch = (password, passwordToCheck) => {
  if (password !== passwordToCheck) {
    return "✗ Passwords do not match. Please try again.";
  }
  return true;
};