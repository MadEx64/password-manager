import fs from "fs";
import { log, yellow, green, red } from "../logger.js";
import {
  PATHS,
  NEWLINE,
  FILE_ENCRYPTION_ENABLED,
} from "../constants.js";
import { isFileEncrypted } from "../encryption/index.js";
import { readFileAsync } from "./index.js";
import { listBackups } from "./backupOperations/backupOperations.js";
import { createChecksum, verifyChecksum } from "./checksum.js";
import { isFirstTimeSetup } from "../auth/secureAuth.js";
import { databaseExists } from "../database/index.js";

/**
 * Checks the integrity of the password vault, authentication system, and backups.
 * @returns {Promise<boolean>} True if no critical issues, false otherwise.
 */
export async function checkIntegrity() {
  let overallHealthy = true;

  const vaultHealthy = await checkPasswordVaultIntegrity(isFirstTimeSetup);
  if (!vaultHealthy) {
    overallHealthy = false;
  }

  if (!isFirstTimeSetup) {
    const authenticationHealthy = await checkAuthenticationIntegrity();
    if (!authenticationHealthy) {
      overallHealthy = false;
    }
  }

  if (!isFirstTimeSetup) {
    const backupsHealthy = await checkBackupsIntegrity();
    if (!backupsHealthy) {
      overallHealthy = false;
    }
  }

  return overallHealthy;
}

/**
 * Checks the integrity of the authentication system files.
 * Reports only critical issues.
 * @returns {Promise<boolean>} True if no critical issues, false otherwise.
 */
export async function checkAuthenticationIntegrity() {
  let isHealthy = true;
  try {
    const { getAuthSystemInfo } = await import('../auth/secureAuth.js');
    const authInfo = await getAuthSystemInfo();
    
    if (!authInfo.hasSecretKey) {
      log(red("Application secret key not found."));
      isHealthy = false;
    }

    if (!authInfo.hasAuthHash) {
      log(red("Authentication hash not found."));
      isHealthy = false;
    }

    if (authInfo.hasSecretKey && authInfo.hasAuthHash) {
      // Only log during first-time setup or if there are issues
      // log(green(`✓ Secure authentication system active (${authInfo.storageType})`));
    } else {
      log(yellow("⚠ Secure authentication system needs setup."));
      isHealthy = false;
    }
  } catch (error) {
    log(red("Error during authentication integrity check: " + error.message));
    isHealthy = false;
  }
  return isHealthy;
}

/**
 * Performs a health check on the password vault (database or file).
 * Logs only essential information and potential errors.
 * @param {boolean} isFirstTimeSetup - Whether the application is being set up for the first time.
 * @returns {Promise<boolean>} True if the password vault is healthy, false otherwise.
 */
export async function checkPasswordVaultIntegrity(isFirstTimeSetup) {
  let vaultHealthy = true;
  let vaultMessages = [];

  try {
    // Check if database exists - this is the preferred storage
    if (databaseExists()) {
      // Database exists, check its basic integrity
      try {
        const dbStats = fs.statSync(PATHS.DATABASE);
        if (dbStats.size === 0) {
          vaultMessages.push(red("Database file is empty or corrupted."));
          vaultHealthy = false;
        }
        // Database integrity will be fully verified after authentication
        // when we can decrypt it
      } catch (dbError) {
        vaultMessages.push(red("Failed to access database: " + dbError.message));
        vaultHealthy = false;
      }
    } else if (fs.existsSync(PATHS.PASSWORDS)) {
      // Legacy file-based storage exists
      const fileBuffer = await readFileAsync(PATHS.PASSWORDS);
      const fileLength = fileBuffer.length;
      const metadata = getFileMetadata(fileBuffer);

      if (fileLength === 0) {
        if (!isFirstTimeSetup) {
          vaultMessages.push(
            yellow("Password vault is empty. Consider adding password entries.")
          );
        }
      } else {
        if (!metadata.isEncrypted && FILE_ENCRYPTION_ENABLED && !isFirstTimeSetup) {
          vaultMessages.push(
            yellow(
              "Password vault is not encrypted. Add a password entry to encrypt it."
            )
          );
        }
        if (metadata.isCorrupted) {
          vaultMessages.push(
            red(
              "Password vault is corrupted. Restore from backup or run recovery tool."
            )
          );
          vaultHealthy = false;
        }
      }
    } else {
      // No database and no file - first time setup or fresh install
      if (isFirstTimeSetup) {
        // For first time setup, we'll create storage after authentication
        // The database will be created when the user authenticates
        log(yellow("Welcome! Setting up your password manager..."));
      } else {
        // This shouldn't happen normally - no storage found but not first time
        log(yellow("No password storage found. A new vault will be created after authentication."));
      }
    }
    
    if (vaultMessages.length > 0 && !isFirstTimeSetup) {
      log(yellow("Password Vault Status:"));
      vaultMessages.forEach((msg) => log("  " + msg));
    }

    return vaultHealthy;
  } catch (error) {
    log(
      red(
        "A critical error occurred during the health check: " +
          error.message +
          NEWLINE
      )
    );
    return false;
  }
}

/**
 * Checks the integrity of password vault backups.
 * Reports only critical issues.
 * @returns {Promise<boolean>} True if no critical issues, false otherwise.
 */
export async function checkBackupsIntegrity() {
  let backupsHealthy = true;
  let issuesFound = false;
  try {
    const backupFiles = await listBackups();
    if (backupFiles.length === 0) {
      return backupsHealthy;
    }

    let backupIssuesMessages = [];

    for (const backupPath of backupFiles) {
      try {
        const backupBuffer = await readFileAsync(backupPath);
        if (backupBuffer.length === 0) {
          backupIssuesMessages.push(
            `Error: Backup file ${backupPath} is empty.`
          );
          issuesFound = true;
          continue;
        }

        const backupChecksum = createChecksum(backupBuffer);
        if (!verifyChecksum(backupBuffer, backupChecksum)) {
          backupIssuesMessages.push(
            `Error: Backup ${backupPath} checksum is invalid (file might be corrupted).`
          );
          issuesFound = true;
        }
      } catch (e) {
        backupIssuesMessages.push(
          `Error: Failed to read or check backup ${backupPath}: ${e.message}`
        );
        issuesFound = true;
      }
    }
    if (issuesFound) {
      log(red("Backup integrity issues detected:"));
      backupIssuesMessages.forEach((msg) => log(red("  " + msg)));
      backupsHealthy = false;
    }
  } catch (error) {
    log(red("Failed to list or check backups: " + error.message + NEWLINE));
    backupsHealthy = false;
  }
  return backupsHealthy;
}

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
