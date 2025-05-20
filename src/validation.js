import { red, log } from "./logger.js";
import { PASSWORD_STRENGTH } from "./constants.js";

/**
 * Handles prompt input field validation.
 * @param {string} input - The input to validate.
 * @param {string} fieldName - The name of the field to validate.
 * @param {Object[]} entries - The password entries to validate against.
 * @returns {boolean|string} True if the input is valid, otherwise an error message.
 * @description This function validates the input and returns an error message if the input is invalid (e.g. empty input).
 * If the input is an identifier, it will also validate that it is not already used in the password entries.
 * @example
 * validateInput("example", "Service Name") // true
 * validateInput("", "Service Name") // false
 * validateInput("example", "Service Name", [{ identifier: "example" }]) // false
 */
function validateInput(input, fieldName = null) {
  if (!input || input.trim() === '') {
    if (fieldName) {
      return red(`Please enter a valid non-empty ${fieldName}.`);
    }
    return red("Please enter a valid non-empty input.");
  }

  return true;
}

/**
 * Handles empty input validation for non password fields.
 * @param {string} value - The input value to validate.
 * @returns {boolean|string} True if the input is valid, otherwise an error message.
 * 
 * @example
 * validateNonEmptyInput("example") // true
 * validateNonEmptyInput("") // false
 */
function validateNonEmptyInput(value) {
  if (value.trim() === "") {
    return red("Input cannot be empty. Please try again.");
  }
  return true;
}

/**
 * Validates that an identifier is not already used in the password entries.
 * @param {string} identifier - The identifier to validate.
 * @param {Object[]} entries - The password entries to validate against.
 * @returns {boolean|string} True if the identifier is valid, otherwise an error message.
 * 
 * @example
 * validateNonDuplicateIdentifier("example", [{ identifier: "example" }]) // false
 * validateNonDuplicateIdentifier("example", [{ identifier: "example1" }]) // true
 */
function validateNonDuplicateIdentifier(identifier, entries) {
  if (entries.some(entry => entry.identifier === identifier.trim())) {
    return red("Identifier already exists for this service. Please try again with a different identifier.");
  }
  return true;
}

/**
 * Validates password complexity.
 * @param {string} password - The password to validate.
 * @returns {boolean|string} True if the password is valid, otherwise an error message.
 * @description This function checks all the password complexity requirements and returns an error message if the password is invalid.
 * 
 * @example
 * validatePassword("Password123!") // true
 * validatePassword("pass") // false
 * validatePassword("Password") // false
 * validatePassword("Password123") // false
 * validatePassword("Password123^$") // true
 */
function validatePassword(password, oldPassword = null) {
  if (password.length < PASSWORD_STRENGTH.MIN_LENGTH) {
    return red("Password must be at least 8 characters long. Please try again.");
  }
  if (password.length > PASSWORD_STRENGTH.MAX_LENGTH) {
    return red("Password must be less than 16 characters long. Please try again.");
  }
  if (!PASSWORD_STRENGTH.REQUIRED_CHARS.UPPERCASE.test(password)) {
    return red("Password must contain at least one uppercase letter. Please try again.");
  }
  if (!PASSWORD_STRENGTH.REQUIRED_CHARS.LOWERCASE.test(password)) {
    return red("Password must contain at least one lowercase letter. Please try again.");
  }
  if (!PASSWORD_STRENGTH.REQUIRED_CHARS.NUMBER.test(password)) {
    return red("Password must contain at least one number. Please try again.");
  }
  if (!PASSWORD_STRENGTH.REQUIRED_CHARS.SPECIAL.test(password)) {
    return red("Password must contain at least one special character(e.g. -.!@#$%^&*_+=/?). Please try again.");
  }
  if (oldPassword && password === oldPassword) {
    return red("New password cannot be the same as the old password. Please try again.");
  }
  return true;
}

/**
 * Validates a password entry structure.
 * 
 * @param {Object} entry - The password entry to validate.
 * @returns {boolean} True if the entry is valid, false otherwise.
 */
function validatePasswordEntry(entry) {
  if (!entry || typeof entry !== 'object') {
    log(red('Invalid entry:'), entry);
    return false;
  }

  if (!entry.service || typeof entry.service !== 'string') {
    log(red('Invalid service:'), entry.service);
    return false;
  }
  
  if (!entry.identifier || typeof entry.identifier !== 'string') {
    log(red('Invalid identifier:'), entry.identifier);
    return false;
  }

  if (!entry.password || typeof entry.password !== 'string') {
    log(red('Invalid password:'), entry.password);
    return false;
  }

  if (entry.createdAt && typeof entry.createdAt !== 'string') {
    log(red('Invalid createdAt:'), entry.createdAt);
    return false;
  }

  if (entry.updatedAt && typeof entry.updatedAt !== 'string') {
    log(red('Invalid updatedAt:'), entry.updatedAt);
    return false;
  }

  return true;
}

/**
 * Checks if the password and the password to check match.
 * @param {string} password - The password to check.
 * @param {string} passwordToCheck - The password to check against.
 * @returns {boolean|string} True if the passwords match, otherwise an error message.
 * 
 * @example
 * checkPasswordMatch("Password123!", "Password123!") // true
 * checkPasswordMatch("Password123!", "Password123") // false
 */
function checkPasswordMatch(password, passwordToCheck) {
  if (password !== passwordToCheck) {
    return red("Passwords do not match. Please try again.");
  }
  return true;
}

const validationTools = {
  validateInput,
  validateNonEmptyInput,
  validateNonDuplicateIdentifier,
  validatePassword,
  validatePasswordEntry,
  checkPasswordMatch
}

export default validationTools;