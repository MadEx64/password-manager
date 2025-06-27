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
            "Security Info",
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
        case "Security Info":
          result = await showSecurityInfo();
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
      ERROR_CODES.INTERNAL_ERROR
    );
  }
}

async function showSecurityInfo() {
  try {
    const { getAuthSystemInfo } = await import("./src/auth/secureAuth.js");
    const info = await getAuthSystemInfo();
    
    log(green("\n=== Security Information ==="));
    log(yellow(`Platform: ${info.platform}`));
    log(yellow(`Storage Type: ${info.storageType}`));
    log(yellow(`Secure Storage Available: ${info.secureStorageAvailable ? 'Yes' : 'No'}`));
    log(yellow(`Authentication System Initialized: ${info.isInitialized ? 'Yes' : 'No'}`));
    log(yellow(`Has Secret Key: ${info.hasSecretKey ? 'Yes' : 'No'}`));
    log(yellow(`Has Auth Hash: ${info.hasAuthHash ? 'Yes' : 'No'}`));
    
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
