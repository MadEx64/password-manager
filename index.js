import inquirer from "inquirer";
import chalk from "chalk";
import {
  authenticateUser,
  isUserAuthenticated,
  updateMasterPassword,
} from "./src/authentication.js";
import {
  addPassword,
  viewPassword,
  deletePassword,
  updatePassword,
  searchPassword,
  createBackupPassword,
  restoreBackupPassword,
  deleteBackupPassword
} from "./src/passwordManager.js";
import { handleExportPasswords, handleImportPasswords } from "./src/exportImportOperations.js";
import { createPasswordsFile, readLines } from "./src/fileOperations.js";
import { handleError } from "./src/errorHandler.js";
import { NavigationAction } from "./src/navigation.js";

/**
 * Main function to manage passwords
 * @returns {Promise<void>}
 * @description This function is the entry point for the application.
 * It authenticates the user, then displays a list of actions to choose from.
 * It then prompts the user to select an action and executes it.
 * It continues to prompt the user to select an action until they choose to exit.
 */
const managePasswords = async () => {
  // Run createPasswordsFile to create the passwords file if it doesn't exist
  const passwordsFileCreated = await createPasswordsFile();

  if (passwordsFileCreated) {
    console.log(chalk.green("Passwords file created successfully"));
  }

  const lines = await readLines();

  try {
    // Authenticate the user if they are not already authenticated
    while (!isUserAuthenticated()) {
      await authenticateUser();
    }

    while (isUserAuthenticated()) {
      const { action } = await inquirer.prompt([
        {
          type: "list",
          name: "action",
          message: "What would you like to do?",
          choices: [
            "Add password",
            "View password",
            "Delete password",
            "Update password",
            "Search password",
            "Update master password",
            "Create backup",
            "Restore backup",
            "Delete backup",
            "Export passwords",
            "Import passwords",
            "Exit",
          ],
        },
      ]);

      let result;
      switch (action) {
        case "Add password":
          result = await addPassword(lines);
          if (result === NavigationAction.MAIN_MENU) {
            // Already at main menu, do nothing
            break;
          }
          break;
        case "View password":
          result = await viewPassword(lines);
          if (result === NavigationAction.MAIN_MENU) {
            // Already at main menu, do nothing
            break;
          }
          break;
        case "Delete password":
          result = await deletePassword(lines);
          if (result === NavigationAction.MAIN_MENU) {
            // Already at main menu, do nothing
            break;
          } else if (result === true) {
            const updatedLines = await readLines();
            lines.splice(0, lines.length, ...updatedLines);
          }
          break;
        case "Update password":
          result = await updatePassword(lines);
          if (result === NavigationAction.MAIN_MENU) {
            // Already at main menu, do nothing
            break;
          }
          break;
        case "Update master password":
          result = await updateMasterPassword();
          if (result === NavigationAction.MAIN_MENU) {
            // Already at main menu, do nothing
            break;
          }
          break;
        case "Search password":
          result = await searchPassword(lines);
          if (result === NavigationAction.MAIN_MENU) {
            // Already at main menu, do nothing
            break;
          }
          break;
        case "Create backup":
          result = await createBackupPassword();
          if (result === NavigationAction.MAIN_MENU) {
            // Already at main menu, do nothing
            break;
          }
          break;
        case "Restore backup":
          result = await restoreBackupPassword();
          if (result === NavigationAction.MAIN_MENU) {
            // Already at main menu, do nothing
            break;
          } else if (result === true) {
            // Reload the lines after restoring a backup
            const updatedLines = await readLines();
            lines.splice(0, lines.length, ...updatedLines);
          }
          break;
        case "Delete backup":
          result = await deleteBackupPassword();
          if (result === NavigationAction.MAIN_MENU) {
            // Already at main menu, do nothing
            break;
          }
          break;
        case "Export passwords": {
          const { format } = await inquirer.prompt([
            {
              type: "list",
              name: "format",
              message: "Choose export format:",
              choices: ["JSON", "CSV", "Cancel"],
            },
          ]);
          result = await handleExportPasswords(format, lines);
          break;
        }
        case "Import passwords": {
          const { format } = await inquirer.prompt([
            {
              type: "list",
              name: "format",
              message: "Choose import format:",
              choices: ["JSON", "CSV", "Cancel"],
            },
          ]);
          result = await handleImportPasswords(format, lines);
          if (result === true) {
            const updatedLines = await readLines();
            lines.splice(0, lines.length, ...updatedLines);
          }
          break;
        }
        case "Exit":
          console.log(chalk.yellow("Exiting..."));
          return;
      }
    }
  } catch (error) {
    handleError(error);
  }
};

managePasswords();
