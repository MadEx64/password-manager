import { join } from 'path';

const BASE_DIR = process.cwd();
const TEST_DIR = join(BASE_DIR, 'test_data');

const isTestMode = process.env.NODE_ENV === 'test';
const ROOT_DIR = isTestMode ? TEST_DIR : BASE_DIR;

/**
 * Paths to the files
 * @type {Object}
 * @property {string} PASSWORDS - Path to the passwords file
 * @property {string} PASSWORDS_BACKUP - Path to the passwords backup file
 * @property {string} MASTER_PASSWORD - Path to the master password file
 * @property {string} MASTER_PASSWORD_BACKUP - Path to the master password backup file
 */
export const PATHS = {
  PASSWORDS: join(ROOT_DIR, 'passwords'),
  PASSWORDS_BACKUP: join(ROOT_DIR, 'passwords.bak'),
  MASTER_PASSWORD: join(ROOT_DIR, '.masterPassword'),
  MASTER_PASSWORD_BACKUP: join(ROOT_DIR, '.masterPassword.bak'),
};

/**
 * Password strength requirements
 * @type {Object}
 * @property {number} MIN_LENGTH - Minimum length of the password
 * @property {number} MAX_LENGTH - Maximum length of the password
 * @property {Object} REQUIRED_CHARS - Required characters in the password
 */
export const PASSWORD_STRENGTH = {
  MIN_LENGTH: 8,
  MAX_LENGTH: 16,
  REQUIRED_CHARS: {
    UPPERCASE: /[A-Z]/,
    NUMBER: /[0-9]/,
    SPECIAL: /[-.!@#$%^&*_+=/?]/
  }
};

/**
 * Error codes
 * @type {Object}
 * @property {string} INVALID_INPUT - Invalid input (e.g. empty input)
 * @property {string} INVALID_INPUT_LENGTH - Invalid input length (e.g. password length is not between 8 and 16 characters)
 * @property {string} INVALID_PASSWORD - Invalid password (e.g. password does not have at least one number, one capital letter or one special character)
 * @property {string} FILE_NOT_FOUND - File not found
 * @property {string} PERMISSION_DENIED - Permission denied
 * @property {string} AUTHENTICATION_FAILED - Authentication failed
 * @property {string} DUPLICATE_SERVICE - Duplicate service
 */
export const ERROR_CODES = {
  INVALID_INPUT: 'INVALID_INPUT',
  INVALID_INPUT_LENGTH: 'INVALID_INPUT_LENGTH',
  INVALID_PASSWORD: 'INVALID_PASSWORD',
  FILE_NOT_FOUND: 'FILE_NOT_FOUND',
  PERMISSION_DENIED: 'PERMISSION_DENIED',
  AUTHENTICATION_FAILED: 'AUTHENTICATION_FAILED',
  DUPLICATE_SERVICE: 'DUPLICATE_SERVICE',
  DECRYPTION_FAILED: 'DECRYPTION_FAILED',
  ENCRYPTION_FAILED: 'ENCRYPTION_FAILED'
};

/**
 * 256-bit key
 * @type {number[]}
 */
export const KEY = [
  1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
  23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
];

/**
 * File locking configuration
 * @type {Object}
 */
export const FILE_LOCK = {
  LOCK_FILE: join(ROOT_DIR, '.lock'),
  LOCK_TIMEOUT: 5000, // 5 seconds
  MAX_RETRIES: 3
};