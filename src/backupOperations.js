import fs from "fs";
import inquirer from "inquirer";
import ora from "ora";
import {
  readMasterPassword,
  createBackup,
  restoreBackup,
  listBackups,
  deleteBackup,
} from "./fileOperations.js";
import { decryptPassword } from "./utils.js";
import { handleError } from "./errorHandler.js";
import { validateMasterPassword, clearSession } from "./authentication.js";
import { promptNavigation, NavigationAction } from "./navigation.js";

// Chalk variables
import chalk from "chalk";
const log = console.log;
const yellow = chalk.yellow;
const red = chalk.red;

/**
 * Creates a backup of the passwords file
 * @returns {Promise<boolean|string>} Path to the backup file if successful, false otherwise,
 * or a NavigationAction if navigation was requested
 */
export const createBackupPassword = async () => {
  try {
    if (!(await validateMasterPassword())) {
      return false;
    }

    // Get master password directly to pass to createBackup to avoid lock conflicts
    let masterPassword;
    try {
      const savedMasterPassword = await readMasterPassword();
      masterPassword = decryptPassword(savedMasterPassword);
    } catch (error) {
      log(red("Failed to read master password for backup: " + error.message));
      return false;
    }

    const spinner = ora("Creating backup...").start();

    try {
      // Create the backup with the master password to avoid lock conflicts
      const backupPath = await createBackup(true, masterPassword);

      if (!backupPath) {
        spinner.fail("No passwords to backup.");
        return false;
      }

      spinner.succeed(`Backup created successfully at: ${backupPath}\n`);

      clearSession();
      return backupPath;
    } catch (error) {
      spinner.fail(`Backup failed: ${error.message}`);
      return false;
    }
  } catch (error) {
    handleError(error);
    return false;
  }
};

/**
 * Restores a backup of the passwords file
 * @returns {Promise<boolean|string>} True if the restore was successful, false otherwise,
 * or a NavigationAction if navigation was requested
 */
export const restoreBackupPassword = async () => {
  try {
    if (!(await validateMasterPassword())) {
      return false;
    }

    // Get master password directly to pass to restoreBackup to avoid lock conflicts
    let masterPassword;
    try {
      const savedMasterPassword = await readMasterPassword();
      masterPassword = decryptPassword(savedMasterPassword);
    } catch (error) {
      log(red("Failed to read master password for restore: " + error.message));
      return false;
    }

    const backupFiles = await listBackups();

    if (backupFiles.length === 0) {
      log(yellow("No backup files found."));
      return false;
    }

    // Format backup filenames for display
    const backupChoices = await Promise.all(
      backupFiles.map(async (path) => {
        const filename = path.split("/").pop();
        const stats = await fs.promises.stat(path);
        const date = new Date(stats.mtime).toLocaleString();
        return {
          name: `${filename} (${date})`,
          value: path,
        };
      })
    );

    backupChoices.push({
      name: "Cancel restoration",
      value: "cancel",
    });

    const { selectedBackup } = await inquirer.prompt([
      {
        type: "list",
        name: "selectedBackup",
        message: "Select a backup to restore:",
        choices: backupChoices,
        pageSize: 10,
      },
    ]);

    if (selectedBackup === "cancel") {
      log(yellow("Restoration cancelled."));
      return false;
    }

    // Add navigation prompt here after user has selected a backup
    const navigationAction = await promptNavigation();
    if (navigationAction === NavigationAction.GO_BACK) {
      return await restoreBackupPassword(); // Let the user select a backup again
    } else if (navigationAction === NavigationAction.MAIN_MENU) {
      clearSession();
      return NavigationAction.MAIN_MENU;
    }

    const { confirmRestore } = await inquirer.prompt([
      {
        type: "confirm",
        name: "confirmRestore",
        message:
          "Are you sure you want to restore this backup? This will overwrite your current passwords.",
        default: false,
      },
    ]);

    if (!confirmRestore) {
      log(yellow("Restoration cancelled."));
      return false;
    }

    const spinner = ora("Restoring backup...").start();

    try {
      // Restore the backup with the master password to avoid lock conflicts
      const success = await restoreBackup(selectedBackup, masterPassword);

      if (success) {
        spinner.succeed("Backup restored successfully!\n");
        clearSession();
        return true;
      } else {
        spinner.fail("Failed to restore backup.");
        return false;
      }
    } catch (error) {
      spinner.fail(`Restoration failed: ${error.message}`);
      return false;
    }
  } catch (error) {
    handleError(error);
    return false;
  }
};

/**
 * Deletes a backup file
 * @returns {Promise<boolean|string>} True if the backup was deleted successfully, false otherwise,
 * or a NavigationAction if navigation was requested
 */
export const deleteBackupPassword = async () => {
  try {
    // Validate the master password before proceeding
    if (!(await validateMasterPassword())) {
      return false;
    }

    // Get available backups
    const backupFiles = await listBackups();

    if (backupFiles.length === 0) {
      log(yellow("No backup files found."));
      return false;
    }

    // Format backup filenames for display
    const backupChoices = backupFiles.map((path) => {
      const filename = path.split("/").pop();
      const stats = fs.statSync(path);
      const date = new Date(stats.mtime).toLocaleString();
      return {
        name: `${filename} (${date})`,
        value: path,
      };
    });

    // Add cancel option
    backupChoices.push({
      name: "Cancel deletion",
      value: "cancel",
    });

    // Ask user to select a backup
    const { selectedBackup } = await inquirer.prompt([
      {
        type: "list",
        name: "selectedBackup",
        message: "Select a backup to delete:",
        choices: backupChoices,
        pageSize: 10,
      },
    ]);

    if (selectedBackup === "cancel") {
      log(yellow("Deletion cancelled."));
      return false;
    }

    // Add navigation prompt here after user has selected a backup
    const navigationAction = await promptNavigation();
    if (navigationAction === NavigationAction.GO_BACK) {
      return await deleteBackupPassword(); // Let the user select a backup again
    } else if (navigationAction === NavigationAction.MAIN_MENU) {
      clearSession();
      return NavigationAction.MAIN_MENU;
    }

    // Ask for confirmation
    const { confirmDelete } = await inquirer.prompt([
      {
        type: "confirm",
        name: "confirmDelete",
        message:
          "Are you sure you want to delete this backup? This action cannot be undone.",
        default: false,
      },
    ]);

    if (!confirmDelete) {
      log(yellow("Deletion cancelled."));
      return false;
    }

    const spinner = ora("Deleting backup...").start();

    try {
      // Delete the backup
      const success = await deleteBackup(selectedBackup);

      if (success) {
        spinner.succeed("Backup deleted successfully!\n");
        clearSession();
        return true;
      } else {
        spinner.fail("Failed to delete backup.");
        return false;
      }
    } catch (error) {
      spinner.fail(`Deletion failed: ${error.message}`);
      return false;
    }
  } catch (error) {
    handleError(error);
    return false;
  }
};
