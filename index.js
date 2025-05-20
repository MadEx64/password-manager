import inquirer from "inquirer";
import { log, green, yellow, red, bold } from "./src/logger.js";
import { checkPasswordVaultIntegrity, handleBackup } from "./src/fileOperations/index.js";
import { authenticateUser, handlePasswordUpdate } from "./src/auth/index.js";
import {
  addPassword,
  viewPassword,
  searchPassword,
} from "./src/passwordManager.js";
import {
  handleExportPasswords,
  handleImportPasswords,
} from "./src/exportImportOperations.js";
import { PasswordManagerError } from "./src/errorHandler.js";
import { ERROR_CODES } from "./src/constants.js";
import { NavigationAction } from "./src/navigation.js";
import yargs from "yargs";
import { hideBin } from "yargs/helpers";

// Parse CLI options
const argv = yargs(hideBin(process.argv))
  .option("session-timeout", {
    alias: "t",
    type: "number",
    description: "Session timeout in minutes",
  })
  .help()
  .parse();

if (argv.sessionTimeout) {
  // Set env variable in ms
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
  await checkPasswordVaultIntegrity();

  try {
    // Authenticate the user on first run
    await authenticateUser();

    while (true) {
      const { action } = await inquirer.prompt([
        {
          type: "list",
          name: "action",
          message: "What would you like to do?",
          choices: [
            "Add password",
            "View password",
            "Search password",
            "Update master password",
            "Backup & Restore",
            "Export passwords",
            "Import passwords",
            "Exit",
          ],
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
          result = await handlePasswordUpdate();
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
        case "Exit":
          log(yellow("Exiting..."));
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
    throw new PasswordManagerError(
      red(error.message),
      bold(red(ERROR_CODES.INTERNAL_ERROR))
    );
  }
}

managePasswords();
