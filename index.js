import inquirer from "inquirer";
import { log, green, yellow, red } from "./src/logger.js";
import { NEWLINE } from "./src/constants.js";
import { checkIntegrity, handleBackup } from "./src/fileOperations/index.js";
import { authenticateUser, handleMasterPasswordUpdate } from "./src/auth/index.js";
import {
  addPassword,
  viewPassword,
  searchPassword,
} from "./src/passwordManager.js";
import {
  handleExportPasswords,
  handleImportPasswords,
} from "./src/fileOperations/exportImportOperations.js";
import { PasswordManagerError, handleError } from "./src/errorHandler.js";
import { ERROR_CODES } from "./src/constants.js";
import { NavigationAction } from "./src/navigation.js";
import yargs from "yargs";
import { hideBin } from "yargs/helpers";
import {
  performAutoMigration,
  initializeDatabase,
  needsMigration,
  isUsingDatabase,
  rollbackMigration,
  migrateFromFileToDatabase,
  getStorageMode,
} from "./src/database/migrator.js";
import { closeDatabase } from "./src/database/index.js";
import { getEncryptionKey } from "./src/auth/masterPasswordCache.js";

const argv = yargs(hideBin(process.argv))
  .option("session-timeout", {
    alias: "t",
    type: "number",
    description: "Session timeout in minutes",
  })
  .help()
  .parse();

if (argv.sessionTimeout) {
  process.env.PASSWORD_MANAGER_SESSION_TIMEOUT = (
    argv.sessionTimeout *
    60 *
    1000
  ).toString();
  log(
    green(`[Config] Session timeout set to ${argv.sessionTimeout} minute(s).`)
  );
}

/**
 * Main function to manage passwords.
 * @returns {Promise<void>}
 * @description This function is the entry point for the application.
 * It authenticates the user, then displays a list of actions to choose from.
 * It then prompts the user to select an action and executes it.
 * It continues to prompt the user to select an action until they choose to exit.
 */
async function managePasswords() {
  const isHealthy = await checkIntegrity();
  if (!isHealthy) {
    log(red("--------------------------------"));
    log(red("✘ Password manager health check complete with issues. Please review messages above."));
    log(red("--------------------------------" + NEWLINE));
    process.exit(1);
  } else {
    log(green("--------------------------------"));
    log(green("✓ Password manager health check complete. All systems nominal."));
    log(green("--------------------------------" + NEWLINE));
  }

  try {
    await authenticateUser();
    const encryptionKey = await getEncryptionKey();

    if (encryptionKey) {
      if (needsMigration()) {
        const migrated = await performAutoMigration(encryptionKey);
        if (!migrated && !needsMigration()) {
          log(green("Database initialized successfully." + NEWLINE));
        }
      } else {
        const dbInitialized = await initializeDatabase(encryptionKey);
        if (dbInitialized && isUsingDatabase()) {
          log(green("Using secure SQLite database for password storage." + NEWLINE));
        }
      }
    }

    const getMenuChoices = () => {
      const choices = [
        "Add password",
        "View password",
        "Search password",
        "Update master password",
        "Backup & Restore",
        "Export passwords",
        "Import passwords",
        "Security Info"
      ];

      // Add migration option if migration is available but deferred
      if (needsMigration()) {
        choices.push("Migrate to Database");
      }

      // Add rollback option if using database and archived file exists
      if (isUsingDatabase()) {
        choices.push("Database Rollback");
      }

      choices.push("Exit");

      return choices;
    };

    while (true) {
      const { action } = await inquirer.prompt([
        {
          type: "list",
          name: "action",
          message: "What would you like to do?",
          choices: getMenuChoices(),
        },
      ]);

      let result;
      switch (action) {
        case "Add password":
          result = await addPassword();
          break;
        case "View password":
          result = await viewPassword();
          break;
        case "Update master password":
          result = await handleMasterPasswordUpdate();
          break;
        case "Search password":
          result = await searchPassword();
          break;
        case "Backup & Restore":
          result = await handleBackup();
          break;
        case "Export passwords":
          result = await handleExportPasswords();
          break;
        case "Import passwords":
          result = await handleImportPasswords();
          break;
        case "Migrate to Database":
          result = await handleMigration(encryptionKey);
          break;
        case "Database Rollback":
          result = await handleRollback();
          break;
        case "Security Info":
          result = await showSecurityInfo();
          break;
        case "Exit":
          log(yellow("Exiting..."));
          await closeDatabase();
          return;
      }

      // Handle operation results
      if (result === NavigationAction.MAIN_MENU) {
        // Already at main menu, continue to next iteration
        continue;
      } else if (result === false) {
        // Operation failed, continue to next iteration
        continue;
      } else if (result === true) {
        // Operation succeeded, continue to next iteration
        continue;
      }
    }
  } catch (error) {
    await closeDatabase();
    throw new PasswordManagerError(
      red(error.message),
      ERROR_CODES.INTERNAL_ERROR
    );
  }
}

/**
 * Handles manual database migration from the menu.
 * @param {Buffer} encryptionKey - The encryption key.
 * @returns {Promise<boolean>} True if migration was successful.
 */
async function handleMigration(encryptionKey) {
  try {
    log(NEWLINE);
    log(
      yellow(
        "═══════════════════════════════════════════════════════════════════"
      )
    );
    log(yellow("                    DATABASE MIGRATION"));
    log(
      yellow(
        "═══════════════════════════════════════════════════════════════════"
      )
    );
    log(NEWLINE);
    log("This will migrate your passwords to a secure SQLite database.");
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
        message: "Would you like to proceed with the migration?",
        default: true,
      },
    ]);

    if (!confirmMigration) {
      log(yellow("Migration cancelled." + NEWLINE));
      return false;
    }

    const result = await migrateFromFileToDatabase(encryptionKey);

    if (result) {
      log(green("Migration completed successfully!" + NEWLINE));
    }

    return result;
  } catch (error) {
    handleError(error);
    return false;
  }
}

/**
 * Handles database rollback from the menu.
 * @returns {Promise<boolean>} True if rollback was successful.
 */
async function handleRollback() {
  try {
    log(NEWLINE);
    log(yellow("⚠ WARNING: Database Rollback"));
    log(yellow("This will:"));
    log(yellow("  • Remove the SQLite database"));
    log(yellow("  • Restore your password file from the archived version"));
    log(yellow("  • You will return to using file-based storage"));
    log(NEWLINE);

    const { confirmRollback } = await inquirer.prompt([
      {
        type: "confirm",
        name: "confirmRollback",
        message: "Are you sure you want to rollback to file-based storage?",
        default: false,
      },
    ]);

    if (!confirmRollback) {
      log(yellow("Rollback cancelled." + NEWLINE));
      return false;
    }

    const result = await rollbackMigration();

    if (result) {
      log(green("✔ Rollback complete. Please restart the application." + NEWLINE));
      process.exit(0);
    }

    return result;
  } catch (error) {
    handleError(error);
    return false;
  }
}

/**
 * Shows security information about the password manager.
 * @returns {Promise<boolean>} True if info was displayed successfully.
 */
async function showSecurityInfo() {
  try {
    const { getAuthSystemInfo } = await import("./src/auth/secureAuth.js");
    const info = await getAuthSystemInfo();
    const storageMode = getStorageMode();

    log(green("\n=== Security Information ==="));
    log(yellow(`Platform: ${info.platform}`));
    log(yellow(`Storage Type: ${info.storageType}`));
    log(yellow(`Password Storage: ${storageMode === 'database' ? 'SQLite Database (Encrypted)' : storageMode === 'file' ? 'Encrypted File' : 'Not Initialized'}`));
    log(yellow(`Secure Storage Available: ${info.secureStorageAvailable ? 'Yes' : 'No'}`));
    log(yellow(`Authentication System Initialized: ${info.isInitialized ? 'Yes' : 'No'}`));
    log(yellow(`Has Secret Key: ${info.hasSecretKey ? 'Yes' : 'No'}`));
    log(yellow(`Has Auth Hash: ${info.hasAuthHash ? 'Yes' : 'No'}`));

    if (storageMode === 'database') {
      log(green("\n✓ Using SQLite database with SQLCipher encryption for enhanced security."));
    } else if (needsMigration()) {
      log(yellow("\n⚠ A database migration is available. Consider migrating for improved performance."));
    }

    if (!info.secureStorageAvailable) {
      log(red("\n⚠ Warning: System secure storage is not available."));
      log(yellow("Using encrypted file fallback in: " + info.fallbackDir));
      log(yellow("Consider installing required dependencies:"));

      switch (info.platform) {
        case 'linux':
          log(yellow("  - Ubuntu/Debian: sudo apt-get install libsecret-1-dev"));
          log(yellow("  - Red Hat/CentOS: sudo yum install libsecret-devel"));
          log(yellow("  - Arch: sudo pacman -S libsecret"));
          break;
        case 'win32':
          log(yellow("  - Windows Credential Manager should be available by default"));
          break;
        case 'darwin':
          log(yellow("  - macOS Keychain should be available by default"));
          break;
      }
    } else {
      log(green("\n✓ Your credentials are stored securely using the system credential store."));
    }

    log(green("===============================\n"));

    return true;
  } catch (error) {
    log(red("Failed to get security information: " + error.message));
    return false;
  }
}

managePasswords();
