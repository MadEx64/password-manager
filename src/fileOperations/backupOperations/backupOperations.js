import fs from "fs";
import { join } from "path";
import { PATHS, BACKUP_DIR, ERROR_CODES, CHARSET } from "../../constants.js";
import { PasswordManagerError } from "../../errorHandler.js";
import { writeFileAsync, readFileAsync, renameAsync, readdirAsync } from "../index.js";
import { acquireLock, releaseLock } from "../../fileLock.js";
import { isFileEncrypted, encryptData, decryptData } from "../../encryption/index.js";
import { red, bold } from "../../logger.js";
import { getEncryptionKey, getCachedMasterPassword } from "../../auth/masterPasswordCache.js";
import {
  databaseExists,
  isDatabaseInitialized,
  closeDatabase,
  openDatabase,
} from "../../database/index.js";
import * as PasswordRepository from "../../repositories/PasswordRepository.js";

/**
 * Checks if the application is using database storage.
 * @returns {boolean} True if using database.
 */
function isUsingDatabase() {
  return databaseExists() && isDatabaseInitialized();
}

/**
 * Creates a backup of the password vault (file or database).
 * Always creates an encrypted backup, regardless of the original file's state.
 * @param {boolean} skipLock - Whether to skip the lock acquisition.
 * @returns {Promise<string>} The path to the backup file if successful.
 * @throws {PasswordManagerError} If the backup fails.
 */
export async function createBackup(skipLock = false) {
  // Route to appropriate backup method based on storage mode
  if (isUsingDatabase()) {
    return await createDatabaseBackup(skipLock);
  }

  return await createFileBackup(skipLock);
}

/**
 * Creates a backup of the database by exporting entries to an encrypted file.
 * @param {boolean} skipLock - Whether to skip the lock acquisition.
 * @returns {Promise<string>} The path to the backup file if successful.
 * @throws {PasswordManagerError} If the backup fails.
 */
async function createDatabaseBackup(skipLock = false) {
  let lockAcquired = false;

  try {
    if (!fs.existsSync(BACKUP_DIR)) {
      fs.mkdirSync(BACKUP_DIR, { recursive: true, mode: 0o755 });
    }

    // Delete oldest backup if we have more than 10 backups
    const backups = await listBackups();
    if (backups.length >= 10) {
      await deleteBackup(backups[backups.length - 1]);
    }

    const timestamp = new Date()
      .toISOString()
      .replace(/:/g, "-")
      .replace(/\./g, "-");
    const backupFilename = `passwords_backup_${timestamp}.bak`;
    const backupPath = join(BACKUP_DIR, backupFilename);

    // Acquire lock for backup operation
    if (!skipLock) {
      if (!(await acquireLock(10))) {
        throw new PasswordManagerError(
          red("Could not acquire file lock for backup"),
          bold(red(ERROR_CODES.PERMISSION_DENIED))
        );
      }
      lockAcquired = true;
    }

    // Get encryption key from secure authentication system
    const cachedMasterPassword = getCachedMasterPassword();
    const encryptionKey = await getEncryptionKey(cachedMasterPassword);

    if (!encryptionKey) {
      if (lockAcquired) await releaseLock();
      throw new PasswordManagerError(
        red("Authentication required for backup encryption"),
        bold(red(ERROR_CODES.AUTHENTICATION_FAILED))
      );
    }

    // Export database entries to JSON
    const entries = await PasswordRepository.findAll();
    const jsonContent = JSON.stringify(
      entries.map((entry) => ({
        service: entry.service,
        identifier: entry.identifier,
        password: entry.password,
        createdAt: entry.createdAt,
        updatedAt: entry.updatedAt,
      })),
      null,
      2
    );

    // Encrypt the backup
    const backupData = encryptData(jsonContent, encryptionKey);
    await writeFileAsync(backupPath, backupData);

    if (lockAcquired) await releaseLock();

    return backupPath;
  } catch (error) {
    if (lockAcquired) await releaseLock();
    throw new PasswordManagerError(
      red("Failed to create database backup: " + error.message),
      bold(red(ERROR_CODES.INTERNAL_ERROR))
    );
  }
}

/**
 * Creates a backup of the password vault file.
 * Always creates an encrypted backup, regardless of the original file's state.
 * @param {boolean} skipLock - Whether to skip the lock acquisition.
 * @returns {Promise<string>} The path to the backup file if successful.
 * @throws {PasswordManagerError} If the backup fails.
 */
async function createFileBackup(skipLock = false) {
  let lockAcquired = false;
  try {
    if (!fs.existsSync(BACKUP_DIR)) {
      fs.mkdirSync(BACKUP_DIR, { recursive: true, mode: 0o755 });
    }

    if (!fs.existsSync(PATHS.PASSWORDS)) {
      return false;
    }

    const backups = await listBackups();
    if (backups.length >= 10) {
      await deleteBackup(backups[backups.length - 1]);
    }

    const timestamp = new Date()
      .toISOString()
      .replace(/:/g, "-")
      .replace(/\./g, "-");
    const backupFilename = `passwords_backup_${timestamp}.bak`;
    const backupPath = join(BACKUP_DIR, backupFilename);

    if (!skipLock) {
      if (!(await acquireLock(10))) {
        throw new PasswordManagerError(
          red("Could not acquire file lock for backup"),
          bold(red(ERROR_CODES.PERMISSION_DENIED))
        );
      }
      lockAcquired = true;
    }

    const fileBuffer = await readFileAsync(PATHS.PASSWORDS);
    let backupData;

    const cachedMasterPassword = getCachedMasterPassword();
    const encryptionKey = await getEncryptionKey(cachedMasterPassword);

    if (!encryptionKey) {
      if (lockAcquired) await releaseLock();
      throw new PasswordManagerError(
        red("Authentication required for backup encryption"),
        bold(red(ERROR_CODES.AUTHENTICATION_FAILED))
      );
    }

    if (isFileEncrypted(fileBuffer)) {
      backupData = fileBuffer;
    } else {
      backupData = encryptData(fileBuffer.toString(CHARSET), encryptionKey);
    }

    await writeFileAsync(backupPath, backupData);

    if (lockAcquired) await releaseLock();

    return backupPath;
  } catch (error) {
    if (lockAcquired) await releaseLock();
    throw new PasswordManagerError(
      red("Failed to create backup: " + error.message),
      bold(red(ERROR_CODES.INTERNAL_ERROR))
    );
  }
}

/**
 * Restores a backup of the password vault (to file or database).
 * Always restores as an encrypted file, regardless of the backup's state.
 * @param {string} backupPath - The path to the backup file.
 * @param {boolean} skipLock - Whether to skip the lock acquisition.
 * @returns {Promise<boolean>} True if the restore was successful.
 * @throws {PasswordManagerError} If the restore fails.
 */
export async function restoreBackup(backupPath, skipLock = false) {
  if (isUsingDatabase()) {
    return await restoreDatabaseBackup(backupPath, skipLock);
  }

  return await restoreFileBackup(backupPath, skipLock);
}

/**
 * Restores a backup to the database from a backup file containing password entries in JSON format.
 * @param {string} backupPath - The path to the backup file.
 * @param {boolean} skipLock - Whether to skip the lock acquisition.
 * @returns {Promise<boolean>} True if the restore was successful.
 * @throws {PasswordManagerError} If the restore fails.
 */
async function restoreDatabaseBackup(backupPath, skipLock = false) {
  let lockAcquired = false;

  try {
    if (!fs.existsSync(backupPath)) {
      throw new PasswordManagerError(
        "Backup file not found",
        ERROR_CODES.FILE_NOT_FOUND
      );
    }

    const backupBuffer = await readFileAsync(backupPath);

    const cachedMasterPassword = getCachedMasterPassword();
    const encryptionKey = await getEncryptionKey(cachedMasterPassword);

    if (!encryptionKey) {
      throw new PasswordManagerError(
        red("Authentication required for backup decryption"),
        bold(red(ERROR_CODES.AUTHENTICATION_FAILED))
      );
    }

    if (!skipLock) {
      if (!(await acquireLock(10))) {
        throw new PasswordManagerError(
          red("Could not acquire file lock for restore"),
          bold(red(ERROR_CODES.PERMISSION_DENIED))
        );
      }
      lockAcquired = true;
    }

    let decryptedData;
    if (isFileEncrypted(backupBuffer)) {
      decryptedData = decryptData(backupBuffer, encryptionKey);
    } else {
      decryptedData = backupBuffer.toString(CHARSET);
    }

    const entries = JSON.parse(decryptedData);

    if (!Array.isArray(entries)) {
      throw new PasswordManagerError(
        red("Invalid backup format"),
        bold(red(ERROR_CODES.FILE_CORRUPTED))
      );
    }

    const existingEntries = await PasswordRepository.findAll();

    for (const entry of existingEntries) {
      await PasswordRepository.deleteById(entry.id);
    }

    if (entries.length > 0) {
      await PasswordRepository.bulkCreate(entries);
    }

    if (lockAcquired) await releaseLock();

    return true;
  } catch (error) {
    if (lockAcquired) await releaseLock();
    throw new PasswordManagerError(
      red("Failed to restore backup to database: " + error.message),
      bold(red(ERROR_CODES.INTERNAL_ERROR))
    );
  }
}

/**
 * Restores a backup of the password vault file.
 * Always restores as an encrypted file, regardless of the backup's state.
 * @param {string} backupPath - The path to the backup file.
 * @param {boolean} skipLock - Whether to skip the lock acquisition.
 * @returns {Promise<boolean>} True if the restore was successful.
 * @throws {PasswordManagerError} If the restore fails.
 */
async function restoreFileBackup(backupPath, skipLock = false) {
  let lockAcquired = false;
  try {
    if (!fs.existsSync(backupPath)) {
      throw new PasswordManagerError(
        "Backup file not found",
        ERROR_CODES.FILE_NOT_FOUND
      );
    }

    const backupBuffer = await readFileAsync(backupPath);

    const cachedMasterPassword = getCachedMasterPassword();
    const encryptionKey = await getEncryptionKey(cachedMasterPassword);

    if (!encryptionKey) {
      throw new PasswordManagerError(
        red("Authentication required for backup decryption"),
        bold(red(ERROR_CODES.AUTHENTICATION_FAILED))
      );
    }

    let decryptedData;
    if (isFileEncrypted(backupBuffer)) {
      decryptedData = decryptData(backupBuffer, encryptionKey);
    } else {
      decryptedData = backupBuffer.toString(CHARSET);
    }

    const encryptedData = encryptData(decryptedData, encryptionKey);

    if (!skipLock) {
      if (!(await acquireLock(10))) {
        throw new PasswordManagerError(
          red("Could not acquire file lock for restore"),
          bold(red(ERROR_CODES.PERMISSION_DENIED))
        );
      }
      lockAcquired = true;
    }

    if (fs.existsSync(PATHS.PASSWORDS)) {
      await renameAsync(PATHS.PASSWORDS, PATHS.PASSWORDS_BACKUP);
    }
    await writeFileAsync(PATHS.PASSWORDS, encryptedData);
    if (lockAcquired) await releaseLock();

    return true;
  } catch (error) {
    if (lockAcquired) await releaseLock();
    throw new PasswordManagerError(
      red("Failed to restore backup: " + error.message),
      bold(red(ERROR_CODES.INTERNAL_ERROR))
    );
  }
}

/**
 * Deletes a backup of the password vault file.
 * @param {string} backupPath - The path to the backup file to delete.
 * @returns {Promise<boolean>} True if the backup was deleted successfully.
 * @throws {PasswordManagerError} If the backup deletion fails.
 * @description This function deletes a backup file from the backups directory.
 */
export async function deleteBackup(backupPath) {
  try {
    if (!fs.existsSync(backupPath)) {
      throw new PasswordManagerError(
        "Backup file not found",
        ERROR_CODES.FILE_NOT_FOUND
      );
    }

    const absoluteBackupPath = fs.realpathSync(backupPath);
    const absoluteBackupDir = fs.realpathSync(BACKUP_DIR);

    if (!absoluteBackupPath.startsWith(absoluteBackupDir)) {
      throw new PasswordManagerError(
        "Invalid backup path - not in backups directory",
        ERROR_CODES.FILE_NOT_FOUND
      );
    }

    fs.unlinkSync(backupPath);
    return true;
  } catch (error) {
    throw new PasswordManagerError(
      red("Failed to delete backup: " + error.message),
      bold(red(ERROR_CODES.INTERNAL_ERROR))
    );
  }
}

/**
 * Lists all available backups of the password vault file.
 * @returns {Promise<string[]>} Array of backup file paths.
 * @description This function lists all available backups in the backup directory.
 */
export async function listBackups() {
  try {
    if (!fs.existsSync(BACKUP_DIR)) {
      fs.mkdirSync(BACKUP_DIR, { recursive: true });
      return [];
    }

    const files = await readdirAsync(BACKUP_DIR);

    return files
      .filter((file) => file.endsWith(".bak"))
      .map((file) => join(BACKUP_DIR, file))
      .sort((a, b) => {
        // Sort by modification time (most recent first)
        const statA = fs.statSync(a);
        const statB = fs.statSync(b);
        return statB.mtime.getTime() - statA.mtime.getTime();
      });
  } catch (error) {
    throw new PasswordManagerError(
      red("Failed to list backups: " + error.message),
      bold(red(ERROR_CODES.INTERNAL_ERROR))
    );
  }
}

/**
 * Creates a direct copy of the database file for backup.
 * This is useful for full database file backups.
 * @returns {Promise<string>} The path to the backup file.
 * @throws {PasswordManagerError} If the backup fails.
 */
export async function createDatabaseFileBackup() {
  try {
    if (!databaseExists()) {
      throw new PasswordManagerError(
        "Database not found",
        ERROR_CODES.FILE_NOT_FOUND
      );
    }

    if (!fs.existsSync(BACKUP_DIR)) {
      fs.mkdirSync(BACKUP_DIR, { recursive: true, mode: 0o755 });
    }

    const timestamp = new Date()
      .toISOString()
      .replace(/:/g, "-")
      .replace(/\./g, "-");
    const backupFilename = `database_backup_${timestamp}.db.bak`;
    const backupPath = join(BACKUP_DIR, backupFilename);

    await closeDatabase();

    await fs.promises.copyFile(PATHS.DATABASE, backupPath);

    const cachedMasterPassword = getCachedMasterPassword();
    const encryptionKey = await getEncryptionKey(cachedMasterPassword);
    if (encryptionKey) {
      await openDatabase(encryptionKey);
    }

    return backupPath;
  } catch (error) {
    throw new PasswordManagerError(
      red("Failed to create database file backup: " + error.message),
      bold(red(ERROR_CODES.INTERNAL_ERROR))
    );
  }
}
