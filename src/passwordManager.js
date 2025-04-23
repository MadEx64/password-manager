import {
  writeLines,
  getAppNames,
  readMasterPassword,
  sortLines,
  createBackup,
  restoreBackup,
  listBackups,
  deleteBackup
} from "./fileOperations.js";
import {
  generateRandomPassword,
  encryptPassword,
  decryptPassword,
} from "./utils.js";
import {
  PasswordManagerError,
  handleError,
  validateInput,
  checkPasswordMatch,
  validatePassword,
} from "./errorHandler.js";
import { validateMasterPassword, clearSession } from "./authentication.js";
import { ERROR_CODES } from "./constants.js";
import inquirer from "inquirer";
import clipboard from "clipboardy";
import ora from "ora";
import fs from "fs";
import { promptNavigation, handleNavigation, NavigationAction } from "./navigation.js";

// Chalk variables
import chalk from "chalk";
const log = console.log;
const bold = chalk.bold;
const underline = chalk.underline;
const green = chalk.green;
const yellow = chalk.yellow;
const red = chalk.red;

/**
 * Adds a password to the password manager
 * @returns {Promise<boolean|string>} True if the password was added successfully, 
 * false otherwise, or a NavigationAction if navigation was requested
 */
export const addPassword = async (lines) => {
  try {
    // Validate the master password before proceeding
    if (!(await validateMasterPassword())) {
      return false;
    }

    // TODO: fix Spinner not allowing prompt to be shown
    // const spinner = ora("Adding password...").start();

    // First prompt for the application name separately
    const { name } = await inquirer.prompt([
      {
        type: "input",
        name: "name",
        message: "Enter the name of the site or application:",
        validate: (value) => validateInput(value, "application name"),
        filter: (value) =>
          value.trim().charAt(0).toUpperCase() + value.slice(1),
      },
    ]);

    // Then prompt for the rest of the information
    const answers = await inquirer.prompt([
      {
        type: "input",
        name: "identifier",
        message: "Enter the identifier (e.g., email address, username):",
        validate: (value) => {
          // Check if identifier is valid (not empty), and is not already in the lines array with the same application name
          if (value.trim() === "") {
            return "Identifier cannot be empty. Please enter a valid identifier.";
          }
          if (lines.some((line) => line.includes(value) && line.startsWith(name))) {
            return "Identifier already exists. Please try again with a different identifier.";
          }
          return true;
        },
        filter: (value) => value.trim(),
      },
      {
        type: "confirm",
        name: "generatePassword",
        message: "Would you like to generate a random password?",
        default: true,
      },
      {
        type: "confirm",
        name: "customLength",
        message: "Would you like to specify the password length?",
        default: false,
        when: (answers) => answers.generatePassword,
      },
      {
        type: "number",
        name: "passwordLength",
        message: "Enter desired password length (minimum 8):",
        default: 12,
        when: (answers) => answers.generatePassword && answers.customLength,
        validate: (value) => {
          if (isNaN(value) || !Number.isInteger(value) || value < 8) {
            return "Please enter a valid integer of at least 8";
          }
          return true;
        },
      },
      {
        type: "password",
        name: "userPassword",
        message: "Enter your password:",
        when: (answers) => !answers.generatePassword,
        validate: (value) => validatePassword(value),
        mask: "*",
      },
      {
        type: "password",
        name: "confirmPassword",
        message: "Confirm your password:",
        mask: "*",
        when: (answers) => !answers.generatePassword,
        validate: (value, answers) =>
          checkPasswordMatch(value, answers.userPassword),
      },
    ]);

    // After user enters all application details, then prompt for navigation
    const navigationAction = await promptNavigation();
    if (navigationAction === NavigationAction.GO_BACK) {
      return await addPassword(lines); // Let the user start over
    } else if (navigationAction === NavigationAction.MAIN_MENU) {
      clearSession();
      return NavigationAction.MAIN_MENU;
    }

    const password = answers.generatePassword
      ? generateRandomPassword(answers.passwordLength || 0)
      : answers.userPassword;

    const encryptedPassword = encryptPassword(password);
    const lastLine = `${name} - ${answers.identifier} - ${encryptedPassword}`;
    lines.push(lastLine);
    const sortedLines = sortLines(lines);
    await writeLines(sortedLines);

    if (answers.generatePassword) {
      log(yellow(`Generated password: ${password}`));
    }

    // spinner.succeed("Password added successfully!");
    log(green("✓ Password added successfully!\n"));

    await new Promise((resolve) => setTimeout(resolve, 1000));
    return true;
  } catch (error) {
    handleError(error);
    return false;
  }
};

/**
 * Views a password from the password manager
 * @returns {Promise<boolean|string>} True if the password was viewed successfully, 
 * false otherwise, or a NavigationAction if navigation was requested
 */
export const viewPassword = async (lines) => {
  try {
    if (lines.length === 0) {
      log(yellow("No passwords stored yet.\n"));
      return false;
    }

    // Validate the master password before proceeding
    if (!(await validateMasterPassword())) {
      return false;
    }

    const appNames = getAppNames(lines);
    const appNamesWithIdentifiers = appNames.map((app) => {
      const appPasswords = lines.filter((line) => line.startsWith(app));
      const identifiers = appPasswords.map((line) => line.split(" - ")[1]);
      return { app, identifiers };
    });

    const { selectedApp } = await inquirer.prompt([
      {
        type: "list",
        name: "selectedApp",
        message: "Select an application:",
        choices: appNames,
      },
    ]);

    // Get the identifiers for the selected app from the appNamesWithIdentifiers array
    const selectedAppIdentifiers = appNamesWithIdentifiers.find(
      (app) => app.app === selectedApp
    ).identifiers;

    // Prompt the user to select an identifier from the selected app
    const { selectedIdentifier } = await inquirer.prompt([
      {
        type: "list",
        name: "selectedIdentifier",
        message: "Select an identifier:",
        choices: selectedAppIdentifiers,
      },
    ]);

    // Only add navigation here after user has selected app and identifier
    const navigationAction = await promptNavigation();
    if (navigationAction === NavigationAction.GO_BACK) {
      return await viewPassword(lines); // Let the user select an app and identifier again
    } else if (navigationAction === NavigationAction.MAIN_MENU) {
      clearSession();
      return NavigationAction.MAIN_MENU;
    }

    // Find the line that starts with the selected app and includes the selected identifier
    const selectedLine = lines.find(
      (line) =>
        line.startsWith(selectedApp) && line.includes(selectedIdentifier)
    );
    if (!selectedLine) {
      throw new PasswordManagerError(
        "Selected application not found",
        ERROR_CODES.FILE_NOT_FOUND
      );
    }

    // Split the line into app, identifier, and encrypted password
    const [app, identifier, encryptedPassword] = selectedLine.split(" - ");
    const decryptedPassword = decryptPassword(encryptedPassword);

    const { action } = await inquirer.prompt([
      {
        type: "list",
        name: "action",
        message: "What would you like to do?",
        choices: ["Show Password", "Copy to Clipboard"],
      },
    ]);

    if (action === "Show Password") {
      log(underline(`\nApplication`), bold.green(app));
      log(underline(`Identifier`), bold.green(identifier));
      log(underline(`Password`), bold.green(decryptedPassword), "\n");
    } else if (action === "Copy to Clipboard") {
      clipboard.writeSync(decryptedPassword);
      log(green("Password copied to clipboard!\n"));
    }

    await new Promise((resolve) => setTimeout(resolve, 1000));
    return true;
  } catch (error) {
    handleError(error);
    return false;
  }
};

/**
 * Deletes a password from the password manager
 * @returns {Promise<boolean|string>} True if the password was deleted successfully, 
 * false otherwise, or a NavigationAction if navigation was requested
 */
export const deletePassword = async (lines) => {
  try {
    if (lines.length === 0) {
      log(yellow("No passwords stored yet.\n"));
      return false;
    }

    // Validate the master password before proceeding
    if (!(await validateMasterPassword())) {
      return false;
    }

    const appNames = getAppNames(lines);

    const { selectedApp } = await inquirer.prompt([
      {
        type: "list",
        name: "selectedApp",
        message: "Select an application to delete a password from:",
        choices: appNames,
      },
    ]);

    const selectedAppLines = lines.filter((line) =>
      line.startsWith(selectedApp)
    );
    const identifiers = selectedAppLines.map((line) => line.split(" - ")[1]);

    const { selectedIdentifier } = await inquirer.prompt([
      {
        type: "list",
        name: "selectedIdentifier",
        message: "Select an identifier to delete a password from:",
        choices: identifiers,
      },
    ]);

    // Add navigation prompt here after user has selected app and identifier but before confirmation
    const navigationAction = await promptNavigation();
    if (navigationAction === NavigationAction.GO_BACK) {
      return await deletePassword(lines); // Let the user select an app and identifier again
    } else if (navigationAction === NavigationAction.MAIN_MENU) {
      clearSession();
      return NavigationAction.MAIN_MENU;
    }

    const { confirmDelete } = await inquirer.prompt([
      {
        type: "confirm",
        name: "confirmDelete",
        message: "Are you sure you want to delete this password?",
        default: false,
      },
    ]);

    if (confirmDelete) {
      const updatedLines = lines.filter((line) => {
        // Keep lines that do not match the selected app and identifier
        const [app, identifier] = line.split(" - ");
        return !(app === selectedApp && identifier === selectedIdentifier);
      });
      // Rewrite the updated lines to the file to avoid empty lines
      await writeLines(updatedLines);

      log(green("Password deleted successfully!\n"));
      clearSession();
      return true;
    } else {
      log(yellow("Deletion cancelled.\n"));
      return false;
    }
  } catch (error) {
    handleError(error);
    return false;
  }
};

/**
 * Updates a password in the password manager
 * @returns {Promise<boolean|string>} True if the password was updated successfully, 
 * false otherwise, or a NavigationAction if navigation was requested
 * @throws {PasswordManagerError} If the application or identifier is not found
 */
export const updatePassword = async (lines) => {
  try {
    if (lines.length === 0) {
      log(yellow("No passwords stored yet.\n"));
      return false;
    }

    // Validate the master password before proceeding
    if (!(await validateMasterPassword())) {
      return false;
    }

    const appNames = getAppNames(lines);
    const { selectedApp } = await inquirer.prompt([
      {
        type: "list",
        name: "selectedApp",
        message: "Select an application to update:",
        choices: appNames,
      },
    ]);

    const selectedAppLines = lines.filter((line) =>
      line.startsWith(selectedApp)
    );
    const identifiers = selectedAppLines.map((line) => line.split(" - ")[1]);

    const { selectedIdentifier } = await inquirer.prompt([
      {
        type: "list",
        name: "selectedIdentifier",
        message: "Select an identifier to update:",
        choices: identifiers,
      },
    ]);

    // Add navigation prompt here after user has selected app and identifier
    const navigationAction = await promptNavigation();
    if (navigationAction === NavigationAction.GO_BACK) {
      return await updatePassword(lines); // Let the user select an app and identifier again
    } else if (navigationAction === NavigationAction.MAIN_MENU) {
      clearSession();
      return NavigationAction.MAIN_MENU;
    }

    const {
      newIdentifier,
      keepCurrentPassword,
      generatePassword,
      customLength,
      passwordLength,
      newPassword,
    } = await inquirer.prompt([
      {
        type: "input",
        name: "newIdentifier",
        message: "Enter new identifier (press Enter to keep current):",
        default: selectedIdentifier,
        validate: (value) => validateInput(value, "identifier"),
      },
      {
        type: "confirm",
        name: "keepCurrentPassword",
        message: "Would you like to keep the current password?",
        default: false,
      },
      {
        type: "confirm",
        name: "generatePassword",
        message: "Would you like to generate a new random password?",
        default: true,
        when: (answers) => !answers.keepCurrentPassword,
      },
      {
        type: "confirm",
        name: "customLength",
        message: "Would you like to specify the password length?",
        default: false,
        when: (answers) => !answers.keepCurrentPassword && answers.generatePassword,
      },
      {
        type: "number",
        name: "passwordLength",
        message: "Enter desired password length (minimum 8):",
        default: 12,
        when: (answers) => !answers.keepCurrentPassword && answers.generatePassword && answers.customLength,
        validate: (value) => {
          if (isNaN(value) || !Number.isInteger(value) || value < 8) {
            return "Please enter a valid integer of at least 8";
          }
          return true;
        },
      },
      {
        type: "password",
        name: "newPassword",
        message: "Enter new password:",
        when: (answers) =>
          !answers.keepCurrentPassword && !answers.generatePassword,
        validate: (value) => validateInput(value, "password"),
        mask: "*",
      },
      {
        type: "password",
        name: "confirmPassword",
        message: "Confirm new password:",
        when: (answers) =>
          !answers.keepCurrentPassword && !answers.generatePassword,
        validate: (value, answers) =>
          checkPasswordMatch(value, answers.newPassword),
        mask: "*",
      },
    ]);

    // Add final navigation prompt after all update information has been collected
    const finalNavigationAction = await promptNavigation();
    if (finalNavigationAction === NavigationAction.GO_BACK) {
      return await updatePassword(lines); // Let the user update details again
    } else if (finalNavigationAction === NavigationAction.MAIN_MENU) {
      clearSession();
      return NavigationAction.MAIN_MENU;
    }

    const selectedLine = lines.find(
      (line) =>
        line.startsWith(selectedApp) && line.includes(selectedIdentifier)
    );
    if (!selectedLine || !selectedLine.includes(selectedIdentifier)) {
      throw new PasswordManagerError(
        "Selected application or identifier not found",
        ERROR_CODES.FILE_NOT_FOUND
      );
    }

    const [app, currentIdentifier, currentPassword] = selectedLine.split(" - ");
    const updatedIdentifier = newIdentifier || currentIdentifier;

    // If the user wants to keep the current password and the identifier is the same, cancel the update
    if (keepCurrentPassword && updatedIdentifier === currentIdentifier) {
      log(yellow("Update cancelled. No changes were made.\n"));
      return false;
    }

    // Determine the updated password based on user preferences
    const updatedPassword = keepCurrentPassword
      ? currentPassword
      : generatePassword
      ? generateRandomPassword(customLength ? passwordLength : 0)
      : newPassword;

    const encryptedPassword = encryptPassword(updatedPassword);
    const updatedLine = `${app} - ${updatedIdentifier} - ${encryptedPassword}`;
    // Replace the old line with the updated line
    const updatedLines = lines.map((line) =>
      line === selectedLine ? updatedLine : line
    );
    await writeLines(updatedLines);

    if (generatePassword) {
      log(yellow(`Generated password: ${updatedPassword}\n`));
    }
    log(green("Password updated successfully!\n"));
    // Prompt after a delay of 1 second
    await new Promise((resolve) => setTimeout(resolve, 1000));
    clearSession();
    return true;
  } catch (error) {
    handleError(error);
    return false;
  }
};

/**
 * Searches for a password in the password manager by prompting the user for a search query (e.g. application name or identifier)
 * @returns {Promise<boolean|string>} True if the password was searched successfully, 
 * false otherwise, or a NavigationAction if navigation was requested
 */
export const searchPassword = async (lines) => {
  try {
    if (lines.length === 0) {
      log(yellow("No passwords stored yet.\n"));
      return false;
    }

    const { searchQuery } = await inquirer.prompt([
      {
        type: "input",
        name: "searchQuery",
        message: "Enter a search query (e.g. application name or identifier):",
        validate: (value) => validateInput(value, "search query"),
        filter: (value) => value.trim().toLowerCase(),
      },
    ]);

    const results = lines.filter((line) =>
      line.toLowerCase().includes(searchQuery.toLowerCase())
    );

    if (results.length === 0) {
      log(yellow("No results found.\n"));
      return false;
    }

    log(green(`Found ${results.length} results.\n`));

    return await viewPassword(results);
  } catch (error) {
    handleError(error);
    return false;
  }
};

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
    const backupChoices = backupFiles.map(path => {
      const filename = path.split('/').pop();
      const stats = fs.statSync(path);
      const date = new Date(stats.mtime).toLocaleString();
      return {
        name: `${filename} (${date})`,
        value: path
      };
    });

    backupChoices.push({
      name: "Cancel restoration",
      value: "cancel"
    });

    const { selectedBackup } = await inquirer.prompt([
      {
        type: "list",
        name: "selectedBackup",
        message: "Select a backup to restore:",
        choices: backupChoices,
        pageSize: 10
      }
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
        message: "Are you sure you want to restore this backup? This will overwrite your current passwords.",
        default: false
      }
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
    const backupChoices = backupFiles.map(path => {
      const filename = path.split('/').pop();
      const stats = fs.statSync(path);
      const date = new Date(stats.mtime).toLocaleString();
      return {
        name: `${filename} (${date})`,
        value: path
      };
    });

    // Add cancel option
    backupChoices.push({
      name: "Cancel deletion",
      value: "cancel"
    });

    // Ask user to select a backup
    const { selectedBackup } = await inquirer.prompt([
      {
        type: "list",
        name: "selectedBackup",
        message: "Select a backup to delete:",
        choices: backupChoices,
        pageSize: 10
      }
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
        message: "Are you sure you want to delete this backup? This action cannot be undone.",
        default: false
      }
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