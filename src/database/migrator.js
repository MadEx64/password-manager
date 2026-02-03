// src/database/migrator.js

/**
 * Migrator module for handling database migrations.
 * Provides functionality to migrate passwords from legacy file system to SQLite database.
 * Also includes rollback functionality and integrity verification.
 */

import fs from "fs";
import inquirer from "inquirer";
import ora from "ora";
import {
  PATHS,
  ERROR_CODES,
  CHARSET,
  FILE_ENCRYPTION_ENABLED,
  NEWLINE,
} from "../constants.js";
import { PasswordManagerError, handleError } from "../errorHandler.js";
import { red, bold, log, green, yellow } from "../logger.js";
import {
  createDatabase,
  openDatabase,
  closeDatabase,
  databaseExists,
  legacyFileExists,
  needsMigration,
  deleteDatabase,
  migratedFileExists,
} from "./index.js";
import {
  bulkCreate,
  findAll,
  getCount,
} from "../repositories/PasswordRepository.js";
import { isFileEncrypted, decryptData } from "../encryption/index.js";
import { decryptPassword } from "../encryption/index.js";
import { createBackup, listBackups } from "../fileOperations/backupOperations/backupOperations.js";

/**
 * Reads password entries from the legacy JSON file.
 * @param {Buffer} encryptionKey - The encryption key for decryption.
 * @returns {Promise<Object[]>} Array of password entries.
 * @throws {PasswordManagerError} If reading fails.
 */
async function readLegacyFile(encryptionKey) {
  const fileBuffer = await fs.promises.readFile(PATHS.PASSWORDS);
  let data;

  if (FILE_ENCRYPTION_ENABLED && isFileEncrypted(fileBuffer)) {
    data = decryptData(fileBuffer, encryptionKey);
  } else {
    data = fileBuffer.toString(CHARSET);
  }

  try {
    return JSON.parse(data);
  } catch (error) {
    throw new PasswordManagerError(
      red("Invalid password vault format - cannot parse JSON"),
      bold(red(ERROR_CODES.FILE_CORRUPTED))
    );
  }
}

/**
 * Reads password entries from the migrated file.
 * @param {Buffer} encryptionKey - The encryption key for decryption.
 * @returns {Promise<Object[]>} Array of password entries.
 * @throws {PasswordManagerError} If reading fails.
 */
async function readMigratedFile(encryptionKey) {
  if (!migratedFileExists()) {
    throw new PasswordManagerError(
      red("Migrated password file not found"),
      bold(red(ERROR_CODES.FILE_NOT_FOUND))
    );
  }

  const fileBuffer = await fs.promises.readFile(PATHS.PASSWORDS_MIGRATED);
  let data;

  if (FILE_ENCRYPTION_ENABLED && isFileEncrypted(fileBuffer)) {
    data = decryptData(fileBuffer, encryptionKey);
  } else {
    data = fileBuffer.toString(CHARSET);
  }

  try {
    return JSON.parse(data);
  } catch (error) {
    throw new PasswordManagerError(
      red("Invalid migrated password vault format - cannot parse JSON"),
      bold(red(ERROR_CODES.FILE_CORRUPTED))
    );
  }
}

/**
 * Archives the legacy passwords file after successful migration.
 * @returns {Promise<void>}
 */
async function archiveLegacyFile() {
  await fs.promises.rename(PATHS.PASSWORDS, PATHS.PASSWORDS_MIGRATED);
}

/**
 * Restores the legacy passwords file from archive.
 * @returns {Promise<void>}
 */
async function restoreLegacyFile() {
  if (fs.existsSync(PATHS.PASSWORDS_MIGRATED)) {
    await fs.promises.rename(PATHS.PASSWORDS_MIGRATED, PATHS.PASSWORDS);
  }
}

/**
 * Verifies data integrity after migration.
 * @param {Object[]} originalEntries - The original entries from file.
 * @param {Buffer} encryptionKey - The encryption key for verification.
 * @returns {Promise<{success: boolean, message: string}>} Verification result.
 */
async function verifyMigrationIntegrity(originalEntries, encryptionKey) {
  const dbCount = await getCount();
  if (dbCount !== originalEntries.length) {
    return {
      success: false,
      message: `Count mismatch: file has ${originalEntries.length} entries, database has ${dbCount}`,
    };
  }

  // Sample verification - test decryption on up to 5 random entries
  const dbEntries = await findAll();
  const sampleSize = Math.min(5, dbEntries.length);

  if (sampleSize > 0) {
    const sampleIndices = [];
    while (sampleIndices.length < sampleSize) {
      const idx = Math.floor(Math.random() * dbEntries.length);
      if (!sampleIndices.includes(idx)) {
        sampleIndices.push(idx);
      }
    }

    for (const idx of sampleIndices) {
      const dbEntry = dbEntries[idx];
      const originalEntry = originalEntries.find(
        (e) =>
          e.service === dbEntry.service && e.identifier === dbEntry.identifier
      );

      if (!originalEntry) {
        return {
          success: false,
          message: `Entry not found in original data: ${dbEntry.service} (${dbEntry.identifier})`,
        };
      }

      if (originalEntry.password !== dbEntry.password) {
        return {
          success: false,
          message: `Password mismatch for ${dbEntry.service} (${dbEntry.identifier})`,
        };
      }

      try {
        await decryptPassword(dbEntry.password, encryptionKey);
      } catch (error) {
        return {
          success: false,
          message: `Decryption failed for ${dbEntry.service} (${dbEntry.identifier})`,
        };
      }
    }
  }

  // Service/identifier uniqueness check
  const seen = new Set();
  for (const entry of dbEntries) {
    const key = `${entry.service}:${entry.identifier}`;
    if (seen.has(key)) {
      return {
        success: false,
        message: `Duplicate entry found: ${entry.service} (${entry.identifier})`,
      };
    }
    seen.add(key);
  }

  return {
    success: true,
    message: `Verified ${dbCount} entries successfully`,
  };
}

/**
 * Migrates password data from the legacy JSON file to the SQLite database.
 * Handles cases where database already exists or migration was partially completed.
 * @param {Buffer} encryptionKey - The encryption key for both file and database.
 * @returns {Promise<boolean>} True if migration was successful.
 * @throws {PasswordManagerError} If migration fails.
 */
export async function migrateFromFileToDatabase(encryptionKey) {
  const spinner = ora("Starting migration to SQLite database...").start();

  try {
    // Step 1: Check if database already exists
    if (databaseExists()) {
      spinner.text = "Database already exists. Checking integrity...";
      const integrityCheck = await checkDatabaseIntegrity(encryptionKey);
      
      if (!integrityCheck.corrupted) {
        // Database exists and is healthy - check if migration was already completed
        const { getCount } = await import("../repositories/PasswordRepository.js");
        const dbCount = await getCount();
        
        if (dbCount > 0) {
          spinner.warn("Database already contains password entries.");
          
          // Check if migrated file exists (indicating previous successful migration)
          if (migratedFileExists()) {
            spinner.fail("Migration already completed. Database is up to date.");
            return false;
          }
          
          // Database exists with entries but no migrated file - might be partial migration
          log(yellow("Warning: Database exists but migrated file not found."));
          log(yellow("This might indicate a previous partial migration."));
          
          const { confirmOverwrite } = await inquirer.prompt([
            {
              type: "confirm",
              name: "confirmOverwrite",
              message: "Do you want to re-migrate from the password file? (This will overwrite existing database entries)",
              default: false,
            },
          ]);
          
          if (!confirmOverwrite) {
            spinner.fail("Migration cancelled.");
            return false;
          }
          
          // Close and delete existing database
          await closeDatabase();
          await deleteDatabase();
        } else {
          // Database exists but is empty - safe to proceed
          await closeDatabase();
          await deleteDatabase();
        }
      } else {
        // Database exists but is corrupted
        spinner.warn(`Database integrity check failed: ${integrityCheck.error}`);
        log(yellow("Removing corrupted database and proceeding with migration..."));
        
        await closeDatabase();
        await deleteDatabase();
      }
    }

    // Step 2: Verify source file exists
    if (!legacyFileExists()) {
      // Check if we can recover from migrated file instead
      if (migratedFileExists()) {
        spinner.text = "No legacy file found, but migrated file exists. Recovering from migrated file...";
        const recovered = await recoverDatabase(encryptionKey);
        if (recovered) {
          spinner.succeed(green(""));
          return true;
        }
      }
      
      spinner.fail("No legacy password file found to migrate");
      return false;
    }

    // Step 3: Create backup before migration
    spinner.text = "Creating backup of existing password file...";
    try {
      await createBackup(true);
    } catch (backupError) {
      spinner.warn("Could not create backup, proceeding anyway...");
      log(yellow("Backup creation failed: " + backupError.message));
    }

    // Step 4: Read entries from legacy file
    spinner.text = "Reading password entries from file...";
    let entries;
    try {
      entries = await readLegacyFile(encryptionKey);
    } catch (readError) {
      spinner.fail("Failed to read password file");
      throw new PasswordManagerError(
        red("Cannot read password file: " + readError.message),
        bold(red(ERROR_CODES.FILE_CORRUPTED))
      );
    }

    if (!Array.isArray(entries)) {
      throw new PasswordManagerError(
        red("Invalid password file format - expected array"),
        bold(red(ERROR_CODES.FILE_CORRUPTED))
      );
    }

    if (entries.length === 0) {
      spinner.warn("Password file is empty. Creating empty database...");
      await createDatabase(encryptionKey);
      await archiveLegacyFile();
      spinner.succeed(green("Migration complete! Empty database created."));
      return true;
    }

    spinner.text = `Found ${entries.length} password entries`;

    // Step 5: Create new database
    spinner.text = "Creating encrypted database...";
    try {
      await createDatabase(encryptionKey);
    } catch (dbError) {
      spinner.fail("Failed to create database");
      throw new PasswordManagerError(
        red("Database creation failed: " + dbError.message),
        bold(red(ERROR_CODES.DATABASE_ERROR))
      );
    }

    // Step 6: Insert all entries
    spinner.text = "Migrating password entries...";
    try {
      if (entries.length > 0) {
        await bulkCreate(entries);
      }
    } catch (insertError) {
      spinner.fail("Failed to insert entries into database");
      // Rollback on insert failure
      await closeDatabase();
      await deleteDatabase();
      throw new PasswordManagerError(
        red("Failed to insert entries: " + insertError.message),
        bold(red(ERROR_CODES.DATABASE_ERROR))
      );
    }

    // Step 7: Verify migration integrity
    spinner.text = "Verifying data integrity...";
    const verification = await verifyMigrationIntegrity(entries, encryptionKey);

    if (!verification.success) {
      spinner.fail(`Migration verification failed: ${verification.message}`);
      // Rollback on verification failure
      await closeDatabase();
      await deleteDatabase();
      throw new PasswordManagerError(
        red("Migration verification failed: " + verification.message),
        bold(red(ERROR_CODES.DATABASE_INTEGRITY_FAILED))
      );
    }

    // Step 8: Archive old file
    spinner.text = "Archiving old password file...";
    try {
      await archiveLegacyFile();
    } catch (archiveError) {
      spinner.warn("Failed to archive old file, but migration succeeded");
      log(yellow("Warning: Could not archive password file: " + archiveError.message));
      log(yellow("Database migration completed successfully, but original file remains."));
    }

    spinner.succeed(
      green(
        `Migration complete! ${entries.length} password entries migrated successfully.`
      )
    );
    log(
      yellow(
        `Note: Your old password file has been archived to ${PATHS.PASSWORDS_MIGRATED}${NEWLINE}`
      )
    );

    return true;
  } catch (error) {
    spinner.fail("Migration failed");
    handleError(error);

    // Attempt cleanup
    try {
      await closeDatabase();
      if (databaseExists()) {
        await deleteDatabase();
      }
    } catch (cleanupError) {
      log(yellow("Warning: Failed to clean up after migration failure: " + cleanupError.message));
    }

    // Don't throw if it's already a PasswordManagerError
    if (error instanceof PasswordManagerError) {
      throw error;
    }

    throw new PasswordManagerError(
      red("Migration failed: " + error.message),
      bold(red(ERROR_CODES.MIGRATION_FAILED))
    );
  }
}

/**
 * Rolls back a database migration to restore the legacy file system.
 * @returns {Promise<boolean>} True if rollback was successful.
 * @throws {PasswordManagerError} If rollback fails.
 */
export async function rollbackMigration() {
  const spinner = ora("Rolling back database migration...").start();

  try {
    // Check for archived file
    if (!fs.existsSync(PATHS.PASSWORDS_MIGRATED)) {
      spinner.fail("No archived password file found for rollback");
      throw new PasswordManagerError(
        red("Cannot rollback: no archived password file found"),
        bold(red(ERROR_CODES.ROLLBACK_FAILED))
      );
    }

    // Close and delete database
    spinner.text = "Removing database...";
    await closeDatabase();
    if (databaseExists()) {
      await deleteDatabase();
    }

    // Restore archived file
    spinner.text = "Restoring password file...";
    await restoreLegacyFile();

    spinner.succeed(green("Rollback complete! Password file restored."));
    return true;
  } catch (error) {
    spinner.fail("Rollback failed");
    throw new PasswordManagerError(
      red("Rollback failed: " + error.message),
      bold(red(ERROR_CODES.ROLLBACK_FAILED))
    );
  }
}

/**
 * Checks if migration is needed and prompts user for confirmation.
 * @returns {Promise<boolean>} True if migration should proceed.
 */
export async function checkAndPromptMigration() {
  if (!needsMigration()) {
    return false;
  }

  log(
    yellow(
      "═══════════════════════════════════════════════════════════════════"
    )
  );
  log(yellow("                    DATABASE MIGRATION AVAILABLE"));
  log(
    yellow(
      "═══════════════════════════════════════════════════════════════════"
    )
  );
  log(NEWLINE);
  log("A new SQLite database storage system is available, offering improved");
  log("performance and security. Your current password file can be migrated.");
  log(NEWLINE);
  log("What will happen:");
  log("  • Your passwords will be migrated to an encrypted SQLite database");
  log("  • A backup of your current file will be created");
  log("  • Your original file will be archived (not deleted)");
  log("  • You can rollback to the file system if needed");
  log(NEWLINE);

  const { confirmMigration } = await inquirer.prompt([
    {
      type: "confirm",
      name: "confirmMigration",
      message: "Would you like to migrate to the new database system?",
      default: true,
    },
  ]);

  return confirmMigration;
}

/**
 * Performs the auto-migration check on application startup.
 * @param {Buffer} encryptionKey - The encryption key.
 * @returns {Promise<boolean>} True if migration was performed or not needed.
 */
export async function performAutoMigration(encryptionKey) {
  try {
    const shouldMigrate = await checkAndPromptMigration();

    if (shouldMigrate) {
      return await migrateFromFileToDatabase(encryptionKey);
    }

    if (needsMigration()) {
      log(
        yellow(
          "Migration skipped. You can migrate later when prompted again." + NEWLINE
        )
      );
    }

    return true;
  } catch (error) {
    handleError(error);
    return false;
  }
}

/**
 * Checks if the database is corrupted or unavailable.
 * @param {Buffer} encryptionKey - The encryption key.
 * @returns {Promise<{corrupted: boolean, error?: string}>} Result of corruption check.
 */
export async function checkDatabaseIntegrity(encryptionKey) {
  if (!databaseExists()) {
    return { corrupted: true, error: "Database file does not exist" };
  }

  try {
    // Try to open and query the database
    await openDatabase(encryptionKey);
    
    try {
      // Try a simple query to verify database is accessible
      const { getRow } = await import("./index.js");
      await getRow("SELECT 1");
      
      return { corrupted: false };
    } catch (queryError) {
      // Query failed - database might be corrupted
      await closeDatabase();
      return {
        corrupted: true,
        error: queryError.message || "Database query failed",
      };
    }
  } catch (error) {
    // Database exists but cannot be opened - likely corrupted
    // Make sure connection is closed
    try {
      await closeDatabase();
    } catch (closeError) {
      // Ignore close errors
    }
    return {
      corrupted: true,
      error: error.message || "Database cannot be opened",
    };
  }
}

/**
 * Recovers the database from migrated file or backup.
 * @param {Buffer} encryptionKey - The encryption key.
 * @returns {Promise<boolean>} True if recovery was successful.
 */
export async function recoverDatabase(encryptionKey) {
  const spinner = ora("Attempting to recover database...").start();

  try {
    // First, try to recover from migrated file
    if (migratedFileExists()) {
      spinner.text = "Recovering from migrated password file...";
      try {
        const entries = await readMigratedFile(encryptionKey);

        // Remove corrupted database if it exists
        if (databaseExists()) {
          await closeDatabase();
          await deleteDatabase();
        }

        // Create new database
        await createDatabase(encryptionKey);

        // Insert entries
        if (entries.length > 0) {
          await bulkCreate(entries);
        }

        spinner.succeed(
          green(
            `Database recovered successfully from migrated file. ${entries.length} entries restored.` + NEWLINE
          )
        );
        return true;
      } catch (migratedError) {
        spinner.warn("Failed to recover from migrated file, trying backups...");
        log(yellow("Migrated file recovery failed: " + migratedError.message));
      }
    }

    // Try to recover from backups
    spinner.text = "Checking for backups...";
    const backups = await listBackups();

    if (backups.length === 0) {
      spinner.fail("No backups found for recovery");
      throw new PasswordManagerError(
        red("Cannot recover database: no migrated file or backups available"),
        bold(red(ERROR_CODES.DATABASE_ERROR))
      );
    }

    // Try the most recent backup
    spinner.text = `Attempting to recover from backup: ${backups[0]}...`;
    
    // Remove corrupted database if it exists
    if (databaseExists()) {
      await closeDatabase();
      await deleteDatabase();
    }

    // Create new database
    await createDatabase(encryptionKey);

    // Read and restore entries from backup
    const { readFileAsync } = await import("../fileOperations/index.js");
    const backupBuffer = await readFileAsync(backups[0]);
    
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

    // Insert restored entries
    if (entries.length > 0) {
      await bulkCreate(entries);
    }

    spinner.succeed(
      green(`Database recovered successfully from backup. ${entries.length} entries restored.`)
    );
    return true;
  } catch (error) {
    spinner.fail("Database recovery failed");
    handleError(error);
    throw new PasswordManagerError(
      red("Database recovery failed: " + error.message),
      bold(red(ERROR_CODES.DATABASE_ERROR))
    );
  }
}

/**
 * Initializes the database for the application.
 * Opens existing database or creates a new one.
 * Checks for corruption and attempts recovery if needed.
 * @param {Buffer} encryptionKey - The encryption key.
 * @returns {Promise<boolean>} True if database is ready.
 */
export async function initializeDatabase(encryptionKey) {
  try {
    if (databaseExists()) {
      // Check if database is corrupted
      const integrityCheck = await checkDatabaseIntegrity(encryptionKey);
      
      if (integrityCheck.corrupted) {
        log(
          yellow(
            `Database integrity check failed: ${integrityCheck.error}${NEWLINE}`
          )
        );
        log(yellow("Attempting to recover database..."));
        
        // Attempt recovery
        const recovered = await recoverDatabase(encryptionKey);
        if (recovered) {
          // Re-open the recovered database
          await openDatabase(encryptionKey);
          return true;
        } else {
          return false;
        }
      }

      // Database is healthy
      return true;
    }

    // If no database but migrated file exists, recover from it
    if (migratedFileExists() && !legacyFileExists()) {
      log(
        yellow(
          "Database not found but migrated file exists. Attempting recovery..."
        )
      );
      const recovered = await recoverDatabase(encryptionKey);
      if (recovered) {
        await openDatabase(encryptionKey);
        return true;
      }
      return false;
    }

    // If no database and no legacy file, create new database
    if (!legacyFileExists()) {
      await createDatabase(encryptionKey);
      return true;
    }

    // Legacy file exists but no database - migration scenario
    // This is handled by performAutoMigration
    return false;
  } catch (error) {
    handleError(error);
    return false;
  }
}

/**
 * Gets the current storage mode.
 * @returns {"database" | "file" | "none"} The storage mode.
 */
export function getStorageMode() {
  if (databaseExists()) {
    return "database";
  }
  if (legacyFileExists()) {
    return "file";
  }
  return "none";
}

/**
 * Checks if the application is using database storage.
 * @returns {boolean} True if using database.
 */
export function isUsingDatabase() {
  return databaseExists();
}

// Re-export from database index for convenience
export { needsMigration, databaseExists, legacyFileExists } from "./index.js";
