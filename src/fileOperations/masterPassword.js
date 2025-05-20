import fs from "fs";
import { PATHS, FILE_ENCRYPTION_ENABLED, ERROR_CODES, NEWLINE, CHARSET } from "../constants.js";
import { PasswordManagerError } from "../errorHandler.js";
import { readFileAsync, writeFileAsync } from "./index.js";
import { isFileEncrypted, decryptFile, encryptFile } from "../utils.js";
import { encryptPassword } from "../utils.js";
import { acquireLock, releaseLock } from "../fileLock.js";
import { generateRecoveryKey } from "../recovery.js";
import { createChecksum, verifyChecksum } from "./checksum.js";
import { log, yellow, red, bold } from "../logger.js";

/**
 * Reads the master password from the master password file. If it can't decrypt the master password file, it will try to restore from the backup.
 * @param {boolean} skipLock - Whether to skip the lock acquisition.
 * @returns {Promise<string>} The master password.
 * @throws {PasswordManagerError} If the master password file is not found or is corrupted.
 */
export async function readMasterPassword(skipLock = false) {
  try {
    let lockAcquired = false;
    if (!skipLock) {
      if (!(await acquireLock())) {
        throw new PasswordManagerError(
          "Could not acquire file lock",
        ERROR_CODES.PERMISSION_DENIED
        );
      }
      lockAcquired = true;
    }

    if (!fs.existsSync(PATHS.MASTER_PASSWORD)) {
      if (lockAcquired) await releaseLock();
      return "";
    }

    // Read the master password file as buffer to check if it's encrypted
    const fileBuffer = await fs.promises.readFile(PATHS.MASTER_PASSWORD);
    let fileData;
    
    if (FILE_ENCRYPTION_ENABLED && isFileEncrypted(fileBuffer)) {
      fileData = await readAndDecryptWithBackup(fileBuffer, PATHS.MASTER_PASSWORD_BACKUP);
    } else {
      // Traditional plaintext file format
      fileData = fileBuffer.toString(CHARSET);
    }
    
    if (fileData.includes(NEWLINE)) {
      const { password, checksum } = parsePasswordFileContent(fileData);

      if (!verifyChecksum(password, checksum)) {
        // Try to restore from backup
        await restorePasswordFromBackup(fileData);

        throw new PasswordManagerError(
          red("Master password file is corrupted"),
          bold(red(ERROR_CODES.FILE_CORRUPTED))
        );
      }

      if (lockAcquired) await releaseLock();
      return password;
    } else {
      // Old format - just the password without checksum
      // Upgrade to new format
      const password = fileData.trim();
      await writeMasterPassword(password);
      if (lockAcquired) await releaseLock();
      return password;
    }
  } catch (error) {
    if (lockAcquired) await releaseLock();
    throw new PasswordManagerError(
      error.message,
      ERROR_CODES.AUTHENTICATION_FAILED
    );
  }
}

/**
 * Encrypts the master password and writes it to the master password file.
 * It also creates a backup of the existing master password file.
 * @param {string} password - The master password.
 */
export async function writeMasterPassword(password) {
  try {
    if (!(await acquireLock())) {
      throw new PasswordManagerError(
        "Could not acquire file lock",
        ERROR_CODES.PERMISSION_DENIED
      );
    }

    password = encryptPassword(password);
    const checksum = createChecksum(password);
    const content = `${password}${NEWLINE}${checksum}`;
    
    const recoveryKey = await generateRecoveryKey();
    const encryptedData = encryptFile(content, recoveryKey);
    await writeFileAsync(PATHS.MASTER_PASSWORD, encryptedData);

    if (fs.existsSync(PATHS.MASTER_PASSWORD)) {
      const backupData = await readFileAsync(PATHS.MASTER_PASSWORD, CHARSET);
      await writeFileAsync(PATHS.MASTER_PASSWORD_BACKUP, backupData);
    }

    await releaseLock();
  } catch (error) {
    await releaseLock();
    throw new PasswordManagerError(
      red("Failed to write master password"),
      bold(red(ERROR_CODES.INTERNAL_ERROR))
    );
  }
}

// Helper functions

/**
 * Reads and decrypts the master password file. If it can't decrypt the master password file, it will try to decrypt the backup file.
 * @param {Buffer} fileBuffer - The buffer of the master password file.
 * @param {string} backupPath - The path to the backup file.
 * @returns {Promise<string>} The decrypted master password data or the backup password data.
 */
async function readAndDecryptWithBackup(fileBuffer, backupPath) {
  const recoveryKey = await generateRecoveryKey();
  try {
    return decryptFile(fileBuffer, recoveryKey);
  } catch (error) {
    if (fs.existsSync(backupPath)) {
      log(yellow("Primary master password file corrupted, attempting to restore from backup..."));
      const backupBuffer = await fs.promises.readFile(backupPath);
      return decryptFile(backupBuffer, recoveryKey);
    } else {
      throw new PasswordManagerError(
        red("Failed to decrypt master password file and backup"),
        bold(red(ERROR_CODES.DECRYPTION_FAILED))
      );
    }
  }
}

/**
 * Parses the password file content.
 * @param {string} fileData - The content of the master password file.
 * @returns {Object} The password and checksum.
 */
function parsePasswordFileContent(fileData) {
  const [password, checksum] = fileData.split(NEWLINE);
  return { password, checksum };
}

/**
 * Restores the password from the backup file.
 * @returns {Promise<string>} The restored password.
 */
async function restorePasswordFromBackup(backupData) {
  if (fs.existsSync(PATHS.MASTER_PASSWORD_BACKUP)) {
    const { password: backupPassword, checksum: backupChecksum } = parsePasswordFileContent(backupData);

    if (verifyChecksum(backupPassword, backupChecksum)) {
      // transfer backup data to master password by replacing the existing file
      await writeFileAsync(PATHS.MASTER_PASSWORD, backupData);
      return backupPassword;
    }
  }
}