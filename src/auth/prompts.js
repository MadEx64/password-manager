import inquirer from "inquirer";
import { PasswordManagerError } from "../errorHandler.js";
import { red, bold } from "../logger.js";
import validationTools from "../validation.js";
import { ERROR_CODES } from "../constants.js";

/**
 * Prompts the user for their master password.
 *
 * @returns {Promise<string>} The user's master password.
 */
export async function promptMasterPassword() {
  try {
    const { masterPassword } = await inquirer.prompt([
      {
        type: "password",
        name: "masterPassword",
        message: "Enter your master password:",
        mask: "*",
      },
    ]);
    return masterPassword;
  } catch (error) {
    throw new PasswordManagerError(
      red(error.message),
      bold(red(ERROR_CODES.INTERNAL_ERROR))
    );
  }
}

/**
 * Prompts the user for their new master password.
 *
 * @param {string} oldPassword - The user's old master password.
 * @returns {Promise<string>} The user's new master password.
 */
export async function promptNewPassword(oldPassword) {
  try {
    const { newPassword } = await inquirer.prompt([
      {
        type: "password",
        name: "newPassword",
        message: "Enter your new master password:",
        validate: (value) => validationTools.validatePassword(value, oldPassword),
        mask: "*",
      },
      {
        type: "password",
        name: "confirmPassword",
        message: "Confirm your new master password:",
        validate: (value, answers) =>
          validationTools.checkPasswordMatch(value, answers.newPassword),
        mask: "*",
      },
    ]);
    return newPassword;
  } catch (error) {
    throw new PasswordManagerError(
      red(error.message),
      bold(red(ERROR_CODES.INTERNAL_ERROR))
    );
  }
}
