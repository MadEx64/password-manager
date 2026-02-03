import { join } from 'path';

export const BASE_DIR = process.cwd();
export const BACKUP_DIR = join(BASE_DIR, '.backups');
export const TEST_DIR = join(BASE_DIR, 'test_data');
export const isTestMode = process.env.NODE_ENV === 'test';
export const ROOT_DIR = isTestMode ? TEST_DIR : BASE_DIR;
export const DB_DIR = join(ROOT_DIR, 'src', 'database');

export const FILE_LOCK_TIMEOUT = 10000;
export const FILE_ENCRYPTION_ENABLED = true;
export const NEWLINE = '\n';
export const CHARSET = 'utf-8';

/**
 * Paths to files in the root directory.
 * @type {Object}
 * @property {string} PASSWORDS - Path to the passwords file.
 * @property {string} PASSWORDS_BACKUP - Path to the passwords backup file.
 * @property {string} DATABASE - Path to the SQLite database file.
 * @property {string} DATABASE_BACKUP - Path to the database backup file.
 * @property {string} PASSWORDS_MIGRATED - Path to the archived passwords file after migration.
 */
export const PATHS = {
  PASSWORDS: join(ROOT_DIR, '.passwords'),
  PASSWORDS_BACKUP: join(ROOT_DIR, '.passwords.bak'),
  DATABASE: join(DB_DIR, 'password_vault.db'),
  DATABASE_BACKUP: join(DB_DIR, 'password_vault.db.bak'),
  PASSWORDS_MIGRATED: join(ROOT_DIR, '.passwords.migrated'),
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
  APP_SECRET_KEY_GENERATION_FAILED: 'APP_SECRET_KEY_GENERATION_FAILED',
  AUTH_KEY_DERIVATION_FAILED: 'AUTH_KEY_DERIVATION_FAILED',
  MIGRATION_FAILED: 'MIGRATION_FAILED',
  FILE_CORRUPTED: 'FILE_CORRUPTED',
  INVALID_ENCRYPTION_FORMAT: 'INVALID_ENCRYPTION_FORMAT',
  DATABASE_ERROR: 'DATABASE_ERROR',
  DATABASE_CONNECTION_FAILED: 'DATABASE_CONNECTION_FAILED',
  DATABASE_INTEGRITY_FAILED: 'DATABASE_INTEGRITY_FAILED',
  ROLLBACK_FAILED: 'ROLLBACK_FAILED'
};

export const DATABASE_CONFIG = {
  SCHEMA_VERSION: 1,
  CIPHER_ALGORITHM: 'aes-256-cbc'
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