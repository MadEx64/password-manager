import { join } from 'path';

export const BASE_DIR = process.cwd();
export const BACKUP_DIR = join(BASE_DIR, '.backups');
export const TEST_DIR = join(BASE_DIR, 'test_data');
export const isTestMode = process.env.NODE_ENV === 'test';
export const ROOT_DIR = isTestMode ? TEST_DIR : BASE_DIR;

export const FILE_LOCK_TIMEOUT = 10000;
export const FILE_ENCRYPTION_ENABLED = true;
export const NEWLINE = '\n';
export const CHARSET = 'utf-8';

/**
 * Paths to files in the root directory.
 * @type {Object}
 * @property {string} PASSWORDS - Path to the passwords file.
 * @property {string} PASSWORDS_BACKUP - Path to the passwords backup file.
 */
export const PATHS = {
  PASSWORDS: join(ROOT_DIR, '.passwords'),
  PASSWORDS_BACKUP: join(ROOT_DIR, '.passwords.bak'),
};

/**
 * Password strength requirements.
 * @type {Object}
 * @property {number} MIN_LENGTH - Minimum length of the password.
 * @property {number} MAX_LENGTH - Maximum length of the password.
 * @property {Object} REQUIRED_CHARS - Required characters in the password.
 * @property {Object} REQUIRED_CHARS.UPPERCASE - Uppercase letter.
 * @property {Object} REQUIRED_CHARS.LOWERCASE - Lowercase letter.
 * @property {Object} REQUIRED_CHARS.NUMBER - Number.
 * @property {Object} REQUIRED_CHARS.SPECIAL - Special character (e.g. -.!@#$%^&*_+=/?).
 */
export const PASSWORD_STRENGTH = {
  MIN_LENGTH: 8,
  MAX_LENGTH: 16,
  REQUIRED_CHARS: {
    UPPERCASE: {
      regex: /[A-Z]/,
      description: "uppercase letter"
    },
    LOWERCASE: {
      regex: /[a-z]/,
      description: "lowercase letter"
    },
    NUMBER: {
      regex: /[0-9]/,
      description: "number"
    },
    SPECIAL: {
      regex: /[-.!@#$%^&*_+=/?]/,
      description: "special character"
    }
  }
};

/**
 * Error codes.
 * @type {Object} 
 * @property {string} INTERNAL_ERROR - Internal error. Default error code.
 * @property {string} AUTHENTICATION_FAILED - Authentication failed.
 * @property {string} INVALID_INPUT - Invalid user input (e.g. empty input).
 * @property {string} INVALID_PASSWORD_ENTRY - Invalid password entry (e.g. password entry structure is invalid).
 * @property {string} FILE_NOT_FOUND - File not found.
 * @property {string} PERMISSION_DENIED - Permission denied.
 * @property {string} DUPLICATE_IDENTIFIER - Duplicate identifier.
 * @property {string} DECRYPTION_FAILED - Decryption failed.
 * @property {string} ENCRYPTION_FAILED - Encryption failed.
 * @property {string} RECOVERY_KEY_GENERATION_FAILED - Recovery key generation failed.
 * @property {string} MASTER_PASSWORD_KEY_GENERATION_FAILED - Master password key generation failed.
 * @property {string} APP_SECRET_KEY_GENERATION_FAILED - Application secret key generation failed.
 * @property {string} AUTH_KEY_DERIVATION_FAILED - Authentication key derivation failed.
 * @property {string} MIGRATION_FAILED - Migration failed.
 * @property {string} FILE_CORRUPTED - File is corrupted.
 * @property {string} INVALID_ENCRYPTION_FORMAT - Invalid encryption format.
 */
export const ERROR_CODES = {
  INTERNAL_ERROR: 'INTERNAL_ERROR',
  AUTHENTICATION_FAILED: 'AUTHENTICATION_FAILED',
  INVALID_INPUT: 'INVALID_INPUT',
  INVALID_INPUT_LENGTH: 'INVALID_INPUT_LENGTH',
  INVALID_PASSWORD_ENTRY: 'INVALID_PASSWORD_ENTRY',
  FILE_NOT_FOUND: 'FILE_NOT_FOUND',
  PERMISSION_DENIED: 'PERMISSION_DENIED',
  DUPLICATE_IDENTIFIER: 'DUPLICATE_IDENTIFIER',
  DECRYPTION_FAILED: 'DECRYPTION_FAILED',
  ENCRYPTION_FAILED: 'ENCRYPTION_FAILED',
  RECOVERY_KEY_GENERATION_FAILED: 'RECOVERY_KEY_GENERATION_FAILED',
  MASTER_PASSWORD_KEY_GENERATION_FAILED: 'MASTER_PASSWORD_KEY_GENERATION_FAILED',
  APP_SECRET_KEY_GENERATION_FAILED: 'APP_SECRET_KEY_GENERATION_FAILED',
  AUTH_KEY_DERIVATION_FAILED: 'AUTH_KEY_DERIVATION_FAILED',
  MIGRATION_FAILED: 'MIGRATION_FAILED',
  FILE_CORRUPTED: 'FILE_CORRUPTED',
  INVALID_ENCRYPTION_FORMAT: 'INVALID_ENCRYPTION_FORMAT'
};

/**
 * File locking configuration.
 * @type {Object}
 * @property {string} LOCK_FILE - Path to the lock file.
 * @property {number} LOCK_TIMEOUT - Timeout for the lock file.
 * @property {number} MAX_RETRIES - Maximum number of retries for the lock file.
 */
export const FILE_LOCK = {
  LOCK_FILE: join(ROOT_DIR, '.lock'),
  LOCK_TIMEOUT: FILE_LOCK_TIMEOUT,
  MAX_RETRIES: 3
};