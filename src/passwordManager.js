import inquirer from "inquirer";
import clipboard from "clipboardy";
import ora from "ora";
import { authenticateUser } from "./auth/index.js";
import { promptIdentifier } from "./prompts.js";
import {
  writePasswordEntries,
  readPasswordEntries,
  deletePasswordEntry,
  updatePasswordEntry,
} from "./fileOperations/index.js";
import {
  generateRandomPassword,
  encryptPassword,
  decryptPassword,
} from "./utils.js";
import { handleError, PasswordManagerError } from "./errorHandler.js";
import validationTools from "./validation.js";
import { ERROR_CODES, NEWLINE } from "./constants.js";
import { promptNavigation, NavigationAction } from "./navigation.js";
import { log, bold, underline, green, yellow, red } from "./logger.js";

/**
 * Adds a new password entry to the vault.
 *
 * Prompts the user to enter the name of the service (e.g. Google, Facebook, etc.), the identifier (e.g. email address, username), and the password.
 * The user can also choose to generate a random password or use their own password.
 *
 * @returns {Promise<boolean|string>} True if the password was added successfully,
 * false otherwise, or a NavigationAction if navigation was requested.
 */
export async function addPassword() {
  while (true) {
    try {
      if (!(await authenticateUser())) {
        return false;
      }

      const entries = await readPasswordEntries();

      const { service } = await inquirer.prompt([
        {
          type: "input",
          name: "service",
          message: "Enter the name of the service:",
          validate: (value) =>
            validationTools.validateInput(value, "service name"),
          filter: (value) =>
            value.trim().charAt(0).toUpperCase() + value.slice(1),
        },
      ]);

      const identifier = await promptIdentifier(service, entries);

      const answers = await inquirer.prompt([
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
              return "Please enter a valid number of at least 8";
            }
            return true;
          },
        },
        {
          type: "password",
          name: "userPassword",
          message: "Enter your password:",
          when: (answers) => !answers.generatePassword,
          validate: (value) => validationTools.validatePassword(value),
          mask: "*",
        },
        {
          type: "password",
          name: "confirmPassword",
          message: "Confirm your password:",
          mask: "*",
          when: (answers) => !answers.generatePassword,
          validate: (value, answers) =>
            validationTools.checkPasswordMatch(value, answers.userPassword),
        },
      ]);

      const navigationAction = await promptNavigation();
      if (navigationAction === NavigationAction.GO_BACK) {
        continue;
      } else if (navigationAction === NavigationAction.MAIN_MENU) {
        log(yellow("Aborting. Returning to main menu..." + NEWLINE));
        return NavigationAction.MAIN_MENU;
      }

      const password = answers.generatePassword
        ? generateRandomPassword(answers.passwordLength || 12)
        : answers.userPassword;

      const encryptedPassword = encryptPassword(password);

      if (
        !validationTools.validatePasswordEntry({
          service: service,
          identifier: identifier,
          password: encryptedPassword,
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        })
      ) {
        throw new PasswordManagerError(
          red("Invalid password entry structure"),
          bold(red(ERROR_CODES.INVALID_PASSWORD_ENTRY))
        );
      }

      entries.push({
        service: service,
        identifier: identifier,
        password: encryptedPassword,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      });

      await writePasswordEntries(entries);

      if (answers.generatePassword) {
        await hidePassword(password, "Generated password");
      }

      log(green("✔ Password added successfully!" + NEWLINE));

      const { addAnother } = await inquirer.prompt([
        {
          type: "confirm",
          name: "addAnother",
          message: "Would you like to add another password?",
          default: false,
        },
      ]);
      if (!addAnother) {
        return true;
      }

      continue;
    } catch (error) {
      handleError(error);
    }
  }
}

/**
 * Prompts the user to show a password entry, copy to the clipboard, update it, delete it, or return to the main menu.
 *
 * @param {Object[]} entries - Optional array of password entries to show (used when searching for a password entry).
 * If not provided, the user will be prompted to select a service and identifier.
 *
 * @returns {Promise<boolean|function|NavigationAction>} True if the password entry was shown successfully, a function call, or a NavigationAction if navigation was requested.
 */
export async function viewPassword(entries = null) {
  while (true) {
    try {
      if (!(await authenticateUser())) {
        return false;
      }

      if (!entries) {
        entries = await readPasswordEntries();
      }

      if (entries.length === 0) {
        log(yellow("No passwords stored yet." + NEWLINE));
        return false;
      }

      const serviceNames = [...new Set(entries.map((entry) => entry.service))];
      const serviceNamesWithIdentifiers = serviceNames.map((service) => {
        const serviceEntries = entries.filter(
          (entry) => entry.service === service
        );
        return {
          service,
          identifiers: serviceEntries.map((entry) => entry.identifier),
        };
      });

      const { selectedService } = await inquirer.prompt([
        {
          type: "list",
          name: "selectedService",
          message: "Select a service:",
          choices: serviceNames,
        },
      ]);

      const selectedServiceIdentifiers = serviceNamesWithIdentifiers.find(
        (service) => service.service === selectedService
      ).identifiers;

      const { selectedIdentifier } = await inquirer.prompt([
        {
          type: "list",
          name: "selectedIdentifier",
          message: "Select an identifier:",
          choices: selectedServiceIdentifiers,
        },
      ]);

      const selectedEntry = entries.find(
        (entry) =>
          entry.service === selectedService &&
          entry.identifier === selectedIdentifier
      );

      if (!selectedEntry) {
        throw new PasswordManagerError(
          red("Selected service not found"),
          bold(red(ERROR_CODES.SERVICE_NOT_FOUND))
        );
      }

      const { action } = await inquirer.prompt([
        {
          type: "list",
          name: "action",
          message: "What would you like to do?",
          choices: [
            "Show Password",
            "Copy to Clipboard",
            "Update Password",
            "Delete Password",
            "Main Menu",
          ],
        },
      ]);

      const decryptedPassword = decryptPassword(selectedEntry.password);

      if (action === "Show Password") {
        log(underline(`\nService`), bold.green(selectedEntry.service));
        log(underline(`Identifier`), bold.green(selectedEntry.identifier));
        await hidePassword(decryptedPassword, underline(`Password`));
      } else if (action === "Copy to Clipboard") {
        try {
          clipboard.writeSync(decryptedPassword);
          log(green("✔ Password copied to clipboard!" + NEWLINE));
        } catch (error) {
          log(
            red(
              "Failed to copy password to clipboard. Please try again." +
                NEWLINE
            )
          );
        }
      } else if (action === "Update Password") {
        return await updatePassword(selectedEntry);
      } else if (action === "Delete Password") {
        return await deletePassword(selectedEntry);
      } else if (action === "Main Menu") {
        return NavigationAction.MAIN_MENU;
      }

      const { viewAnother } = await inquirer.prompt([
        {
          type: "confirm",
          name: "viewAnother",
          message: "Would you like to view another password?",
          default: false,
        },
      ]);

      if (!viewAnother) {
        try {
          return true;
        } catch (error) {
          log(yellow("Session cleared." + NEWLINE));
        }
      }

      continue;
    } catch (error) {
      handleError(error);
    }
  }
}

/**
 * Updates a password entry in the vault.
 *
 * @returns {Promise<boolean|string>} True if the password was updated successfully.
 * false otherwise, or a NavigationAction if navigation was requested.
 */
export async function updatePassword(selectedEntry) {
  try {
    if (!(await authenticateUser())) {
      return false;
    }

    const selectedService = selectedEntry.service;
    const selectedIdentifier = selectedEntry.identifier;

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
        validate: (value) => {
          const inputValidation = validationTools.validateInput(
            value,
            "identifier"
          );
          if (inputValidation !== true) return inputValidation;

          return true;
        },
        filter: (value) => value.trim(),
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
        when: (answers) =>
          !answers.keepCurrentPassword && answers.generatePassword,
      },
      {
        type: "number",
        name: "passwordLength",
        message: "Enter desired password length (minimum 8):",
        default: 12,
        when: (answers) =>
          !answers.keepCurrentPassword &&
          answers.generatePassword &&
          answers.customLength,
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
        validate: (value) => {
          const inputValidation = validationTools.validateInput(
            value,
            "password"
          );
          if (inputValidation !== true) return inputValidation;

          const passwordValidation = validationTools.validatePassword(value);
          if (passwordValidation !== true) return passwordValidation;

          return true;
        },
        mask: "*",
      },
      {
        type: "password",
        name: "confirmPassword",
        message: "Confirm new password:",
        when: (answers) =>
          !answers.keepCurrentPassword && !answers.generatePassword,
        validate: (value, answers) =>
          validationTools.checkPasswordMatch(value, answers.newPassword),
        mask: "*",
      },
    ]);

    const navigationAction = await promptNavigation([
      {
        name: "Continue with current operation",
        value: NavigationAction.CONTINUE,
      },
      { name: "Abort, return to main menu", value: NavigationAction.MAIN_MENU },
    ]);

    if (navigationAction === NavigationAction.MAIN_MENU) {
      log(yellow("Aborting update. Returning to main menu." + NEWLINE));
      return NavigationAction.MAIN_MENU;
    }

    if (keepCurrentPassword && newIdentifier === selectedIdentifier) {
      log(
        yellow(
          "Update cancelled. No changes were made. Returning to main menu..." +
            NEWLINE
        )
      );
      return false;
    }

    const updatedPassword = keepCurrentPassword
      ? decryptPassword(selectedEntry.password)
      : generatePassword
      ? generateRandomPassword(customLength ? passwordLength : 0)
      : newPassword;

    const encryptedPassword = encryptPassword(updatedPassword);

    if (
      !validationTools.validatePasswordEntry({
        service: selectedService,
        identifier: newIdentifier,
        password: encryptedPassword,
        updatedAt: new Date().toISOString(),
      })
    ) {
      throw new PasswordManagerError(
        red("Invalid password entry structure"),
        bold(red(ERROR_CODES.INVALID_PASSWORD_ENTRY))
      );
    }

    await updatePasswordEntry({
      service: selectedService,
      identifier: newIdentifier,
      password: encryptedPassword,
      updatedAt: new Date().toISOString(),
    });

    if (generatePassword) {
      await hidePassword(updatedPassword, "Generated password");
    }

    log(green("✔ Password entry updated successfully!" + NEWLINE));

    return true;
  } catch (error) {
    handleError(error);
  }
}

/**
 * Deletes a password entry from the vault.
 *
 * @returns {Promise<boolean|string>} True if the password was deleted successfully.
 * false otherwise, or a NavigationAction if navigation was requested.
 */
export async function deletePassword(entry) {
  try {
    if (!(await authenticateUser())) {
      return false;
    }

    const { confirmDelete } = await inquirer.prompt([
      {
        type: "confirm",
        name: "confirmDelete",
        message: `Are you sure you want to delete the password for ${entry.service} (${entry.identifier})?`,
        default: false,
      },
    ]);

    if (confirmDelete) {
      await deletePasswordEntry(entry);
      log(green("✔ Password deleted successfully!" + NEWLINE));
      return true;
    } else {
      log(yellow("Aborting deletion. Returning to main menu." + NEWLINE));
      return NavigationAction.MAIN_MENU;
    }
  } catch (error) {
    handleError(error);
  }
}

/**
 * Searches for a password entry in the vault by prompting the user for a search query.
 *
 * @returns {Promise<boolean|string>} True if the password was searched successfully,
 * false otherwise, or a NavigationAction if navigation was requested
 */
export async function searchPassword() {
  try {
    const entries = await readPasswordEntries();

    if (entries.length === 0) {
      log(yellow("No passwords stored yet." + NEWLINE));
      return false;
    }

    const { searchQuery } = await inquirer.prompt([
      {
        type: "input",
        name: "searchQuery",
        message: "Enter a search query (e.g. service name or identifier):",
        validate: (value) =>
          validationTools.validateInput(value, "search query"),
        filter: (value) => value.trim().toLowerCase(),
      },
    ]);

    const results = entries.filter(
      (entry) =>
        entry.service.toLowerCase().includes(searchQuery.toLowerCase()) ||
        entry.identifier.toLowerCase().includes(searchQuery.toLowerCase())
    );

    if (results.length === 0) {
      log(yellow("No results found." + NEWLINE));
      return false;
    }

    log(
      green(
        `Found ${results.length} result${
          results.length === 1 ? "" : "s"
        }.${NEWLINE}`
      )
    );

    const { viewResults } = await inquirer.prompt([
      {
        type: "confirm",
        name: "viewResults",
        message: "Would you like to view the results?",
        default: true,
      },
    ]);

    if (viewResults) {
      return await viewPassword(results);
    }

    return true;
  } catch (error) {
    handleError(error);
  }
}

/**
 * Hides the password from the console after it is generated.
 *
 * @param {string} password - The password to hide.
 * @returns {Promise<void>}
 */
async function hidePassword(password, message) {
  const hiddenPassword = "*".repeat(Math.floor(Math.random() * 9) + 8);
  process.stdout.write(`${message}: ${yellow(password)}${NEWLINE}`);

  const spinner = ora(`Hiding password in 5 seconds...`).start();
  spinner.color = "yellow";

  await new Promise((resolve) => setTimeout(resolve, 5000));
  spinner.stop();

  process.stdout.moveCursor(0, -1);
  process.stdout.clearLine(0);
  process.stdout.write(`${message}: ${yellow(hiddenPassword)}${NEWLINE}`);
  process.stdout.moveCursor(0, 1);
}
