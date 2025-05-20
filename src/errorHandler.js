import { error as errorLogger, log, yellow } from './logger.js';
import { ERROR_CODES, isTestMode } from './constants.js';

/**
 * Custom error class for the password manager.
 * 
 * Handles error messages and codes.
 * @extends {Error}
 * @description This class is used to create custom errors for the password manager.
 * @property {string} code - The error code.
 * @property {string} message - The error message.
 */
class PasswordManagerError extends Error {
  /**
   * Creates a new PasswordManagerError.
   * @param {string} message - The error message.
   * @param {string} code - The error code.
   */
  constructor(message, code) {
    super(message);
    this.code = code;
    this.name = 'PasswordManagerError';
  }
}

/**
 * Prints a helpful suggestion based on the error code.
 * @param {string} code - The error code.
 */
function printSuggestion(code) {
  switch (code) {
    case ERROR_CODES.AUTHENTICATION_FAILED:
      log(yellow('Check your master password or try the recovery tool.'));
      break;
    case ERROR_CODES.FILE_NOT_FOUND:
      log(yellow('Ensure the required file exists or restore from backup.'));
      break;
    case ERROR_CODES.PERMISSION_DENIED:
      log(yellow('Check your file permissions or try running as administrator.'));
      break;
    case ERROR_CODES.DUPLICATE_IDENTIFIER:
      log(yellow('This identifier already exists. Update existing entry instead.'));
      break;
    case ERROR_CODES.DECRYPTION_FAILED:
      log(yellow('The file could not be decrypted. Check your master password or recovery key.'));
      break;
    case ERROR_CODES.ENCRYPTION_FAILED:
      log(yellow('The file could not be encrypted. Check your master password or recovery key.'));
      break;
    case ERROR_CODES.MIGRATION_FAILED:
      log(yellow('Migration failed. Try restoring from a backup or import from a different source.'));
      break;
    case ERROR_CODES.FILE_CORRUPTED:
      log(yellow('The file appears corrupted. Try restoring from a backup or import from a different source.'));
      break;
    default:
      break;
  }
}

/**
 * Handles an error, logs it, prints suggestions, and exits if not in test mode.
 * @param {Error} error - The error to handle.
 */
function handleError(error) {
  if (error instanceof PasswordManagerError) {
    errorLogger(`[${error.code}] ${error.message}`);
    printSuggestion(error.code);
  } else {
    errorLogger(error.message);
  }
  if (!isTestMode) process.exit(1);
}

export {
  handleError,
  PasswordManagerError
}