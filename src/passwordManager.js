import inquirer from "inquirer";
import clipboard from "clipboardy";
import ora from "ora";
import { withAuthentication } from "./auth/authWrapper.js";
import { promptIdentifier } from "./prompts.js";
import {
  writePasswordEntries,
  readPasswordEntries,
  deletePasswordEntry,
  updatePasswordEntry,
} from "./fileOperations/index.js";
import { encryptPassword, decryptPassword } from "./encryption/index.js";
import { generateRandomPassword } from "./utils.js";
import { handleError, PasswordManagerError } from "./errorHandler.js";
import validationTools from "./validation.js";
import { ERROR_CODES, NEWLINE } from "./constants.js";
import { promptNavigation, NavigationAction } from "./navigation.js";
import { log, bold, underline, green, yellow, red, blue, drawTable, stripAnsi } from "./logger.js";
import { getEncryptionKey } from "./auth/masterPasswordCache.js";
import { analyzePasswordStrength } from "./security/strengthAnalyzer.js";

/**
 * Adds a new password entry to the vault.
 *
 * Prompts the user to enter the name of the service (e.g. Google, Facebook, etc.), the identifier (e.g. email address, username), and the password.
 * The user can also choose to generate a random password or use their own password.
 *
 * @returns {Promise<boolean|string>} True if the password was added successfully,
 * false otherwise, or a NavigationAction if navigation was requested.
 */
export const addPassword = withAuthentication(async () => {
  while (true) {
    try {
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
          message: "Enter desired password length (minimum 8, maximum 32):",
          default: 16,
          when: (answers) => answers.generatePassword && answers.customLength,
          validate: (value) => {
            if (
              isNaN(value) ||
              !Number.isInteger(value) ||
              value < 8 ||
              value > 32
            ) {
              return "Please enter a valid number between 8 and 32";
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
        ? generateRandomPassword(answers.passwordLength)
        : answers.userPassword;

      const key = await getEncryptionKey();
      const encryptedPassword = await encryptPassword(password, key);

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
          red("Invalid password entry structure. Please try again."),
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
});

/**
 * Prompts the user to show a password entry, copy to the clipboard, update it, delete it, or return to the main menu.
 *
 * @param {Object[]} entries - Optional array of password entries to show (used when searching for a password entry).
 * If not provided, the user will be prompted to select a service and identifier.
 *
 * @returns {Promise<boolean|function|NavigationAction>} True if the password entry was shown successfully, a function call, or a NavigationAction if navigation was requested.
 */
export const viewPassword = withAuthentication(async (entries = null) => {
  while (true) {
    try {
      if (!entries) {
        entries = await readPasswordEntries();
        if (entries === "{}") {
          log(yellow("No passwords stored yet." + NEWLINE));
          return false;
        }
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
            "Analyze Password Strength",
            "Copy to Clipboard",
            "Update Password",
            "Delete Password",
            "Main Menu",
          ],
        },
      ]);

      const key = await getEncryptionKey();
      const decryptedPassword = await decryptPassword(
        selectedEntry.password,
        key
      );

      if (action === "Show Password") {
        const labels = ["Service", "Identifier", "Password"];
        const maxLabelLen = Math.max(...labels.map(l => stripAnsi(l).length));
        const data = [
          { label: "Service", value: bold.green(selectedEntry.service) },
          { label: "Identifier", value: bold.green(selectedEntry.identifier) },
        ];

        const stripAnsiSelectedService = stripAnsi(bold.green(selectedEntry.service));
        const stripAnsiSelectedIdentifier = stripAnsi(bold.green(selectedEntry.identifier));
        const stripAnsiDecryptedPassword = stripAnsi(yellow(decryptedPassword));

        const maxValueLen = Math.max(
          stripAnsiSelectedService.length,
          stripAnsiSelectedIdentifier.length,
          stripAnsiDecryptedPassword.length
        );

        const width = Math.max(maxLabelLen + maxValueLen + 5, "Password Entry".length + 4);

        drawTable([
          ...data,
          { type: 'separator' }
        ], "Password Entry", true);

        await hidePassword(decryptedPassword, underline(`Password`), { width, maxLabelLen });
      } else if (action === "Analyze Password Strength") {
        const strength = analyzePasswordStrength(decryptedPassword);
        const strengthEntries = [
          { label: "Strength Score", value: green(`${strength.score} (0-4)`) },
          { label: "Crack Time", value: green(strength.crackTime) },
        ];

        if (strength.feedback.warning) {
          strengthEntries.push({ label: "Warning", value: red(strength.feedback.warning) });
        }

        if (strength.feedback.suggestions.length > 0) {
          strengthEntries.push({ label: "Suggestions", value: yellow(strength.feedback.suggestions.join(', ')) });
        }

        drawTable(strengthEntries, "Security Analysis");
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
});

/**
 * Updates a password entry in the vault.
 *
 * @returns {Promise<boolean|string>} True if the password was updated successfully.
 * false otherwise, or a NavigationAction if navigation was requested.
 */
export const updatePassword = withAuthentication(async (selectedEntry) => {
  try {
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
        validate: async (value) => {
          const inputValidation = validationTools.validateInput(
            value,
            "identifier"
          );
          if (inputValidation !== true) return inputValidation;

          if (value.trim() === selectedIdentifier) return true; // allow keeping the same identifier

          const entries = await readPasswordEntries();

          const identifierValidation =
            validationTools.validateNonDuplicateIdentifier(
              value.trim(),
              selectedService,
              entries
            );
          if (identifierValidation !== true) return identifierValidation;

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
      ? selectedEntry.password
      : generatePassword
      ? generateRandomPassword(customLength ? passwordLength : 0)
      : newPassword;

    const key = await getEncryptionKey();
    const encryptedPassword = await encryptPassword(updatedPassword, key);

    if (
      !validationTools.validatePasswordEntry({
        service: selectedService,
        identifier: newIdentifier,
        password: encryptedPassword,
        updatedAt: new Date().toISOString(),
      })
    ) {
      throw new PasswordManagerError(
        red("Invalid password entry structure. Please try again."),
        bold(red(ERROR_CODES.INVALID_PASSWORD_ENTRY))
      );
    }

    await updatePasswordEntry({
      service: selectedService,
      identifier: newIdentifier,
      oldIdentifier: selectedIdentifier,
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
});

/**
 * Deletes a password entry from the vault.
 *
 * @returns {Promise<boolean|string>} True if the password was deleted successfully.
 * false otherwise, or a NavigationAction if navigation was requested.
 */
export const deletePassword = withAuthentication(async (entry) => {
  try {
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
});

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
        `Found ${results.length} result${results.length === 1 ? "" : "s"
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
 * @param {string} message - The label to show (e.g. "Password").
 * @param {Object} tableMeta - Metadata for table alignment (width, maxLabelLen).
 * @returns {Promise<void>}
 */
async function hidePassword(password, message, tableMeta) {
  const { width, maxLabelLen } = tableMeta;
  const horizontalLine = "─".repeat(width);
  const hiddenPassword = "*".repeat(Math.floor(Math.random() * 9) + 8);

  const formatPasswordRow = (pwd) => {
    const labelStr = stripAnsi(message);
    const labelPadding = " ".repeat(Math.max(0, maxLabelLen - labelStr.length));
    const lineContent = ` ${underline(message)}${labelPadding} : ${yellow(pwd)}`;
    const lineContentLen = 1 + labelStr.length + labelPadding.length + 3 + stripAnsi(yellow(pwd)).length;
    const endPadding = " ".repeat(Math.max(0, width - lineContentLen));
    return blue("│") + lineContent + endPadding + blue("│");
  };

  // Initial show
  process.stdout.write(formatPasswordRow(password) + NEWLINE);
  log(blue(`└${horizontalLine}┘`));
  log("");

  const spinner = ora(`Hiding password in 5 seconds...`).start();
  spinner.color = "yellow";

  await new Promise((resolve) => setTimeout(resolve, 5000));
  spinner.stop();

  // Move up three lines (row + bottom border + spacing)
  process.stdout.moveCursor(0, -3);
  process.stdout.clearLine(0);
  process.stdout.write(formatPasswordRow(hiddenPassword) + NEWLINE);
  process.stdout.clearLine(0);
  log(blue(`└${horizontalLine}┘`));
  log("");
}