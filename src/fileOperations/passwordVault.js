import fs from "fs";
import { red, bold } from "../logger.js";
import {
  PATHS,
  CHARSET,
  ERROR_CODES,
  FILE_ENCRYPTION_ENABLED,
} from "../constants.js";
import { handleError, PasswordManagerError } from "../errorHandler.js";
import { isFileEncrypted, decryptData, encryptData } from "../encryption/index.js";
import { sortEntries } from "./utils.js";
import { writeFileAsync } from "./index.js";
import { createBackup } from "./backupOperations/backupOperations.js";
import { getEncryptionKey } from "../auth/masterPasswordCache.js";

/**
 * Creates the password vault if it doesn't exist and logs a message to the console.
 * @throws {PasswordManagerError} If the password vault file is not writable.
 */
export async function createPasswordVaultFile() {
  try {
    const content = "[]";
    
    const { isFirstTimeSetup } = await import('../auth/secureAuth.js');
    if (isFirstTimeSetup) {
      await writeFileAsync(PATHS.PASSWORDS, content, CHARSET);
      return;
    }
    
    try {
      const key = await getEncryptionKey();
      if (key && key.length === 32) {
        const encryptedContent = encryptData(content, key);
        await writeFileAsync(PATHS.PASSWORDS, encryptedContent);
      } else {
        await writeFileAsync(PATHS.PASSWORDS, content, CHARSET);
      }
    } catch (keyError) {
      await writeFileAsync(PATHS.PASSWORDS, content, CHARSET);
    }
  } catch (error) {
    handleError(error);
    throw new PasswordManagerError(
      "Failed to create password vault file: " + error.message,
      ERROR_CODES.PERMISSION_DENIED
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

    const fileBuffer = await fs.promises.readFile(PATHS.PASSWORDS);
    let data;

    if (FILE_ENCRYPTION_ENABLED && isFileEncrypted(fileBuffer)) {
      const key = await getEncryptionKey();
      if (!key) {
        throw new PasswordManagerError(
          red("Authentication required to access encrypted vault"),
          bold(red(ERROR_CODES.AUTHENTICATION_FAILED))
        );
      }
      data = decryptData(fileBuffer, key);
    } else {
      data = fileBuffer.toString(CHARSET);
    }

    try {
      return JSON.parse(data);
    } catch (jsonError) {
      if (data === "") {
        return [];
      }
      throw new PasswordManagerError(
        red("Invalid password vault format"),
        bold(red(ERROR_CODES.FILE_CORRUPTED))
      );
    }
  } catch (error) {
    handleError(error);
    throw new PasswordManagerError(
      "Failed to read password entries: " + error.message,
      error.code || ERROR_CODES.INTERNAL_ERROR
    );
  }
}
/**
 * Writes password entries to the passwords file.
 * @param {Object[]} entries - Array of password entries to write.
 * @returns {Promise<void>}
 * @throws {PasswordManagerError} If writing fails or authentication is required.
 */
export async function writePasswordEntries(entries) {
  try {
    sortEntries(entries);
    const jsonContent = JSON.stringify(entries, null, 2);

    if (FILE_ENCRYPTION_ENABLED) {
      const key = await getEncryptionKey();
      if (!key) {
        throw new PasswordManagerError(
          red("Authentication required to write encrypted vault"),
          bold(red(ERROR_CODES.AUTHENTICATION_FAILED))
        );
      }

      await createBackup(true);

      const encryptedData = encryptData(jsonContent, key);
      await writeFileAsync(PATHS.PASSWORDS, encryptedData);
    } else {
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
    const updatedEntries = entries.map((e) => {
      if (
        e.service === entry.service &&
        e.identifier === (entry.oldIdentifier || entry.identifier)
      ) {
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
