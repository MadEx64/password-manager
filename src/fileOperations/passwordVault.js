import fs from "fs";
import { log, yellow, green, red, bold } from "../logger.js";
import { PATHS, CHARSET, ERROR_CODES, NEWLINE, FILE_ENCRYPTION_ENABLED } from "../constants.js";
import { handleError, PasswordManagerError } from "../errorHandler.js";
import { isFileEncrypted, decryptFile, encryptFile } from "../utils.js";
import { sortEntries, parseLines, convertToJsonFormat } from "./utils.js";
import { renameAsync, writeFileAsync, readFileAsync } from "./index.js";
import { createBackup } from "./backupOperations/backupOperations.js";
import { readMasterPassword } from "./masterPassword.js";
import { createChecksum, verifyChecksum } from "./checksum.js";

/**
 * Gets the metadata of the password vault file.
 * @param {Buffer} fileBuffer - The buffer of the password vault file.
 * @returns {Object} The metadata of the password vault file.
 */
function getFileMetadata(fileBuffer) {
  const checksum = createChecksum(fileBuffer);
  const metadata = {
    isEncrypted: isFileEncrypted(fileBuffer),
    checksum: checksum,
    isCorrupted: !verifyChecksum(fileBuffer, checksum),
  };
  return metadata;
}

/**
 * Checks the integrity of the password vault file.
 */
export async function checkPasswordVaultIntegrity() {
  try {
    if (!fs.existsSync(PATHS.PASSWORDS)) {
      log(yellow("Can't find password vault, setting up..."));
      await createPasswordVaultFile();
    }

    log(yellow("Checking password vault integrity..."));
    const fileBuffer = await readFileAsync(PATHS.PASSWORDS);
    const fileLength = fileBuffer.length;
    const metadata = getFileMetadata(fileBuffer);

    if (fileLength === 0) {
      log(red("Password vault is empty. Please add some passwords."));
    }

    if (fileLength > 0) {
      if (metadata.isEncrypted) {
        log(yellow("Password vault is encrypted."));
      } else {
        log(green("Password vault is not encrypted."));
      }
      if (metadata.isCorrupted) {
        log(red("Password vault is corrupted."));
      }
      if (metadata.checksum) {
        log(green("Password vault checksum is valid."));
      } else {
        log(red("Password vault checksum is invalid."));
      }
    }

    log(green("✔ Password vault integrity check complete." + NEWLINE));

  } catch (error) {
    throw new PasswordManagerError(
      red("Failed to check password vault integrity: " + error.message),
      bold(red(ERROR_CODES.INTERNAL_ERROR))
    );
  }
}

/**
 * Creates the password vault if it doesn't exist and logs a message to the console.
 * @throws {PasswordManagerError} If the password vault file is not writable.
 */
export async function createPasswordVaultFile() {
  try {
    await writeFileAsync(PATHS.PASSWORDS, "");
    log(green("✔ Password vault created successfully." + NEWLINE));
  } catch (error) {
    handleError(error);
    throw new PasswordManagerError(
      red("Failed to create password vault file"),
      bold(red(ERROR_CODES.PERMISSION_DENIED))
    );
  }
}

/**
 * Migrates the passwords file from line-based format to JSON format
 * @returns {Promise<boolean>} True if migration was successful
 * @throws {PasswordManagerError} If the migration fails.
 */
export async function migrateToJsonFormat() {
  try {
    if (!fs.existsSync(PATHS.PASSWORDS)) {
      throw new PasswordManagerError(
        "Password vault file not found",
        ERROR_CODES.FILE_NOT_FOUND
      );
    }

    // Read the file as a buffer first to detect if it's encrypted
    const fileBuffer = await fs.promises.readFile(PATHS.PASSWORDS);
    let lines;

    if (FILE_ENCRYPTION_ENABLED && isFileEncrypted(fileBuffer)) {
      // Get master password for decryption
      const encryptedMasterPassword = await readMasterPassword();
      if (!encryptedMasterPassword) {
        throw new PasswordManagerError(
          red("Master password not found for file decryption"),
          bold(red(ERROR_CODES.AUTHENTICATION_FAILED))
        );
      }

      const decryptedData = decryptFile(fileBuffer, encryptedMasterPassword);
      lines = parseLines(decryptedData);
    } else {
      // Traditional plaintext file format
      const data = fileBuffer.toString(CHARSET);
      lines = parseLines(data);
    }

    // Convert to JSON format
    const jsonEntries = convertToJsonFormat(lines);
    const jsonContent = JSON.stringify(jsonEntries, null, 2);

    // Create backup before migration
    if (fs.existsSync(PATHS.PASSWORDS)) {
      await renameAsync(PATHS.PASSWORDS, PATHS.PASSWORDS_BACKUP);
    }

    // Write the new JSON format
    if (FILE_ENCRYPTION_ENABLED) {
      const encryptedMasterPassword = await readMasterPassword();
      if (!encryptedMasterPassword) {
        throw new PasswordManagerError(
          red("Master password not found for file encryption"),
          bold(red(ERROR_CODES.AUTHENTICATION_FAILED))
        );
      }
      const encryptedData = encryptFile(jsonContent, encryptedMasterPassword);
      await writeFileAsync(PATHS.PASSWORDS, encryptedData);
    } else {
      await writeFileAsync(PATHS.PASSWORDS, jsonContent, CHARSET);
    }

    return true;
  } catch (error) {
    handleError(error);
    throw new PasswordManagerError(
      red("Failed to migrate to JSON format"),
      bold(red(ERROR_CODES.MIGRATION_FAILED))
    );
  }
}

/**
 * Reads the password entries from the passwords file.
 * @returns {Promise<Object[]>} Array of password entries in JSON format.
 * @throws {PasswordManagerError} If the passwords file is not found.
 */
export async function readPasswordEntries() {
  try {
    if (!fs.existsSync(PATHS.PASSWORDS)) {
      throw new PasswordManagerError(
        "Password vault file not found",
        ERROR_CODES.FILE_NOT_FOUND
      );
    }

    // Read the file as a buffer first to detect if it's encrypted
    const fileBuffer = await fs.promises.readFile(PATHS.PASSWORDS);
    let data;

    if (FILE_ENCRYPTION_ENABLED && isFileEncrypted(fileBuffer)) {
      const encryptedMasterPassword = await readMasterPassword();
      if (!encryptedMasterPassword) {
        throw new PasswordManagerError(
          red("Master password not found for file decryption"),
          bold(red(ERROR_CODES.AUTHENTICATION_FAILED))
        );
      }

      data = decryptFile(fileBuffer, encryptedMasterPassword);
    } else {
      data = fileBuffer.toString(CHARSET);
    }

    // Check if the data is in JSON format
    try {
      return JSON.parse(data);
    } catch (jsonError) {
      // If not JSON, it's in the old line-based format, so we need to migrate to JSON format
      const lines = parseLines(data);
      const migrated = await migrateToJsonFormat();
      if (!migrated) {
        throw new PasswordManagerError(
          red("Failed to migrate to JSON format"),
          bold(red(ERROR_CODES.MIGRATION_FAILED))
        );
      }
      return convertToJsonFormat(lines);
    }
  } catch (error) {
    handleError(error);
    throw new PasswordManagerError(
      red("Failed to read password entries: " + error.message),
      bold(red(ERROR_CODES.INTERNAL_ERROR))
    );
  }
}

/**
 * Writes password entries to the passwords file.
 * @param {Object[]} entries - Array of password entries to write.
 * @returns {Promise<void>}
 */
export async function writePasswordEntries(entries) {
  try {
    sortEntries(entries);

    // Convert entries to JSON format
    const jsonContent = JSON.stringify(entries, null, 2);
    
    if (FILE_ENCRYPTION_ENABLED) {
      // Get master password for encryption
      const encryptedMasterPassword = await readMasterPassword();
      if (!encryptedMasterPassword) {
        throw new PasswordManagerError(
          red("Master password not found for file encryption"),
          bold(red(ERROR_CODES.AUTHENTICATION_FAILED))
        );
      }

      // Make automated backup to backup directory before writing new entries
      await createBackup(true);
        
      // Encrypt the entire file content
      const encryptedData = encryptFile(jsonContent, encryptedMasterPassword);
      await writeFileAsync(PATHS.PASSWORDS, encryptedData);
    } else {
      // Write the plaintext file
      await writeFileAsync(PATHS.PASSWORDS, jsonContent, CHARSET);
    }
  } catch (error) {
    handleError(error);
    throw new PasswordManagerError(
      red("Failed to write password entries: " + error.message),
      bold(red(ERROR_CODES.INTERNAL_ERROR))
    );
  }
}

/**
 * Updates a password entry in the passwords file.
 * @param {Object} entry - The password entry to update.
 * @returns {Promise<void>}
 */
export async function updatePasswordEntry(entry) {
  try {
    const entries = await readPasswordEntries();
    const updatedEntries = entries.map(e => {
      if (e.service === entry.service && e.identifier === entry.identifier) {
        return {
          ...e,
          ...entry,
          updatedAt: new Date().toISOString(),
        };
      }
      return e;
    });

    await writePasswordEntries(updatedEntries);
  } catch (error) {
    handleError(error);
    throw new PasswordManagerError(
      red("Failed to update password entry: " + error.message),
      bold(red(ERROR_CODES.INTERNAL_ERROR))
    );
  }
}

/**
 * Deletes a password entry from the passwords file.
 * @param {Object} entry - The password entry to delete.
 * @returns {Promise<void>}
 */
export async function deletePasswordEntry(entry) {
  try {
    const entries = await readPasswordEntries();
    const updatedEntries = entries.filter(
      (e) => e.service !== entry.service || e.identifier !== entry.identifier
    );
    await writePasswordEntries(updatedEntries);
  } catch (error) {
    handleError(error);
    throw new PasswordManagerError(
      red("Failed to delete password entry: " + error.message),
      bold(red(ERROR_CODES.INTERNAL_ERROR))
    );
  }
}
