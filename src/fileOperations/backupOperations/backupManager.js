import fs from "fs";
import inquirer from "inquirer";
import ora from "ora";
import {
  createBackup,
  restoreBackup,
  listBackups,
  deleteBackup,
} from "../index.js";
import { handleError } from "../../errorHandler.js";
import { isSessionValid, authenticateUser, sessionState } from "../../auth/index.js";
import { promptNavigation, NavigationAction } from "../../navigation.js";
import { NEWLINE } from "../../constants.js";
import { log, yellow, red } from "../../logger.js";

/**
 * Prompts the user for backup operations.
 * @returns {Promise<boolean>} True if the backup operation was successful, false otherwise
 */
export async function handleBackup() {
  const { backupChoice } = await inquirer.prompt([
    {
      type: "list",
      name: "backupChoice",
      message: "This tool allows you to manually create, restore, and delete existing backups of your password vault. Select a backup operation:",
      choices: [
        {
          name: "Create backup",
          value: "create",
        },
        {
          name: "Restore backup",
          value: "restore",
        },
        {
          name: "Delete backup",
          value: "delete",
        },
        {
          name: "Cancel",
          value: "cancel",
        },
      ],
    },
  ]);

  switch (backupChoice) {
    case "create":
      return await createBackupPasswordVault();
    case "restore":
      return await restoreBackupPasswordVault();
    case "delete":
      return await deleteBackupPasswordVault();
    case "cancel":
      log(yellow("Backup operation cancelled." + NEWLINE));
      return false;
    default:
      log(red("Invalid backup operation selected." + NEWLINE));
      return false;
  }
}

/**
 * Creates a backup of the password vault file.
 * @returns {Promise<boolean|string>} Path to the backup file if successful, false otherwise
 */
export async function createBackupPasswordVault() {
  try {
    // Check session and authenticate if needed
    if (!isSessionValid(sessionState)) {
      if (!(await authenticateUser())) {
        return false;
      }
    }

    const spinner = ora("Creating backup file..." + NEWLINE).start();

    try {
      const backupPath = await createBackup(true);

      if (!backupPath) {
        spinner.fail("No passwords to backup.");
        return false;
      }

      spinner.succeed(`Backup created successfully at: ${backupPath}${NEWLINE}`);

      return backupPath;
    } catch (error) {
      spinner.fail(`Backup failed: ${error.message}`);
      return false;
    }
  } catch (error) {
    handleError(error);
    return false;
  }
}

/**
 * Restores a backup of the password vault file.
 * @returns {Promise<boolean|string>} True if the restore was successful, false otherwise
 */
export async function restoreBackupPasswordVault() {
  try {
    // Check session and authenticate if needed
    if (!isSessionValid(sessionState)) {
      if (!(await authenticateUser())) {
        return false;
      }
    }

    const backupFiles = await listBackups();

    if (backupFiles.length === 0) {
      log(yellow("No backup files found." + NEWLINE));
      return false;
    }

    // Format backup filenames for display
    const backupChoices = await Promise.all(
      backupFiles.map((path) => formatBackupChoice(path))
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
      log(yellow("Restoration cancelled." + NEWLINE));
      return false;
    }

    // Add navigation prompt here after user has selected a backup
    const navigationAction = await promptNavigation();
    if (navigationAction === NavigationAction.GO_BACK) {
      return await restoreBackupPasswordVault(); // Let the user select a backup again
    } else if (navigationAction === NavigationAction.MAIN_MENU) {
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
      log(yellow("Restoration cancelled.\n"));
      return false;
    }

    const spinner = ora("Restoring backup..." + NEWLINE).start();

    try {
      const success = await restoreBackup(selectedBackup, true);

      if (success) {
        spinner.succeed("Backup restored successfully!" + NEWLINE);
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
}

/**
 * Deletes a backup of the password vault.
 * @returns {Promise<boolean|string>} True if the backup was deleted successfully, false otherwise
 */
export async function deleteBackupPasswordVault() {
  try {
    // Check session and authenticate if needed
    if (!isSessionValid(sessionState)) {
      if (!(await authenticateUser())) {
        return false;
      }
    }

    const backupFiles = await listBackups();

    if (backupFiles.length === 0) {
      log(yellow("No backup files found." + NEWLINE));
      return false;
    }

    const backupChoices = await Promise.all(
      backupFiles.map((path) => formatBackupChoice(path))
    );

    backupChoices.push({
      name: "Cancel deletion",
      value: "cancel",
    });

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
      log(yellow("Deletion cancelled.\n"));
      return false;
    }

    const navigationAction = await promptNavigation();
    if (navigationAction === NavigationAction.GO_BACK) {
      return await deleteBackupPasswordVault(); // Let the user select a backup again
    } else if (navigationAction === NavigationAction.MAIN_MENU) {
      return NavigationAction.MAIN_MENU;
    }

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
      log(yellow("Deletion cancelled." + NEWLINE));
      return false;
    }

    const spinner = ora("Deleting backup...").start();

    try {
      const success = await deleteBackup(selectedBackup);

      if (success) {
        spinner.succeed("Backup deleted successfully!" + NEWLINE);
        return true;
      } else {
        spinner.fail("Failed to delete backup." + NEWLINE);
        return false;
      }
    } catch (error) {
      spinner.fail(`Deletion failed: ${error.message}` + NEWLINE);
      return false;
    }
  } catch (error) {
    handleError(error);
    return false;
  }
}

/**
 * Formats the backup choice for display
 * @param {string} path - The path to the backup file
 * @returns {Promise<{ name: string, value: string }>} The formatted backup choice
 */
async function formatBackupChoice(path) {
  const filename = path.split("/").pop();
  const stats = await fs.promises.stat(path);
  const date = new Date(stats.mtime).toLocaleString();
  return {
    name: `${filename} (${date})`,
    value: path,
  };
}