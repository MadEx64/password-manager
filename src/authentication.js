import inquirer from "inquirer";
import chalk from "chalk";
import { readMasterPassword, writeMasterPassword } from "./fileOperations.js";
import { decryptPassword, encryptPassword } from "./utils.js";
import {
  PasswordManagerError,
  validatePassword,
  handleError,
  checkPasswordMatch,
} from "./errorHandler.js";
import { ERROR_CODES } from "./constants.js";
import {
  promptNavigation,
  NavigationAction,
} from "./navigation.js";

// Chalk variables
const log = console.log;
const blue = chalk.blue;
const green = chalk.green;
const red = chalk.red;

/**
 * The authentication status of the user
 * @type {boolean}
 * @description This variable is used to store the authentication status of the user.
 */
let isAuthenticated = false;

// Used for caching the master password
let validatedMasterPassword = false;
// Timestamp of last validation
let lastValidationTime = null;
const SESSION_TIMEOUT = 1000 * 60 * 1; // 1 minute

/**
 * Authenticates the user by checking the master password
 * @returns {Promise<boolean>} True if authentication is successful, false otherwise
 * @throws {PasswordManagerError} If the master password is not found or invalid
 * @description This function handles the authentication process for the user.
 * It first checks if the master password file exists. If not, it prompts the user to set up a new master password.
 * If the file exists, it prompts the user to enter their current master password.
 * If the entered password is correct, it sets the authentication flag to true.
 * Otherwise, it throws an error.
 */
export const authenticateUser = async () => {
  try {
    // Check if the master password file exists and read it if it does, otherwise return an empty string (for first time use)
    const storedMasterPassword = await readMasterPassword();

    // If the master password file is empty, set up a new one
    if (storedMasterPassword === "") {
      log(blue("\nNo master password found. Setting up master password...\n"));
      const { newPassword, confirmPassword } = await inquirer.prompt([
        {
          type: "password",
          name: "newPassword",
          message: "Enter your new master password:",
          validate: (value) => {
            return validatePassword(value);
          },
          mask: "*",
        },
        {
          type: "password",
          name: "confirmPassword",
          message: "Confirm your new master password:",
          validate: (value, answers) => {
            return checkPasswordMatch(value, answers.newPassword);
          },
          mask: "*",
        },
      ]);

      // Encrypt the password before storing it
      await writeMasterPassword(encryptPassword(newPassword));

      log(green("✓ Master password set successfully!\n"));
      // Set user to authenticated after setting up a new master password (considered authenticated after setting up a new master password for the first time)
      isAuthenticated = true;
      return true;
    }

    // Validate the master password for the current session
    if (!(await validateMasterPassword())) {
      return false;
    }

    isAuthenticated = true;
    return true;
  } catch (error) {
    handleError(error);
    throw new PasswordManagerError(
      "✗ Failed to authenticate user",
      ERROR_CODES.AUTHENTICATION_FAILED
    );
  }
};

/**
 * Checks if the user is authenticated
 * @returns {boolean} True if the user is authenticated, false otherwise
 * @description This function returns the authentication status of the user.
 */
export const isUserAuthenticated = () => isAuthenticated;

/**
 * This function validates the master password and returns the authentication status of the user
 * @returns {Promise<boolean>} True if the master password is validated, false otherwise
 */
export const validateMasterPassword = async () => {
  try {
    const currentTime = Date.now();

    // Check if we have a cached validated master password and it hasn't expired
    if (
      validatedMasterPassword &&
      lastValidationTime &&
      currentTime - lastValidationTime < SESSION_TIMEOUT
    ) {
      return true;
    }

    if (currentTime - lastValidationTime > SESSION_TIMEOUT) {
      clearSession();
    }

    const storedMasterPassword = await readMasterPassword();
    const decryptedMasterPassword = decryptPassword(storedMasterPassword);

    const { masterPassword } = await inquirer.prompt([
      {
        type: "password",
        name: "masterPassword",
        message: "Enter your master password:",
        mask: "*",
        validate: (value) => {
          return checkPasswordMatch(value, decryptedMasterPassword);
        },
      },
    ]);

    if (masterPassword === decryptedMasterPassword) {
      validatedMasterPassword = true;
      lastValidationTime = currentTime;
      log(green("Access granted!\n"));
      return true;
    }

    log(red("✗ Invalid master password. Please try again.\n"));
    return false;
  } catch (error) {
    handleError(error);
    return false;
  }
};

export const clearSession = () => {
  validatedMasterPassword = false;
  lastValidationTime = null;
};

/**
 * Gets the remaining session time
 * @returns {number} The remaining session time in milliseconds
 */
export const getSessionTimeRemaining = () => {
  if (!lastValidationTime) return 0;
  const elapsed = Date.now() - lastValidationTime;
  return Math.max(0, SESSION_TIMEOUT - elapsed);
};

/**
 * Updates the master password
 * @returns {Promise<boolean|string>} True if the master password is updated successfully,
 * false otherwise, or a NavigationAction if navigation was requested
 * @throws {PasswordManagerError} If the old password is incorrect or the new password does not match the confirmation
 * @description This function allows the user to update their master password.
 * It prompts the user to enter their current master password, then their new password and a confirmation of the new password.
 * If the old password is incorrect, it throws an error.
 * If the new password and confirmation do not match, it throws an error.
 * If the update is successful, it logs a success message and returns true.
 */
export const updateMasterPassword = async () => {
  try {
    const currentMasterPassword = await readMasterPassword();
    const decryptedMasterPassword = decryptPassword(currentMasterPassword);

    // First prompt for current password and verify it
    const { oldPassword } = await inquirer.prompt([
      {
        type: "password",
        name: "oldPassword",
        message: "Enter your current master password:",
        validate: (value) => {
          return checkPasswordMatch(value, decryptedMasterPassword);
        },
        mask: "*",
      },
    ]);

    // If current password verified, prompt for new password
    const { newPassword } = await inquirer.prompt([
      {
        type: "password",
        name: "newPassword",
        message: "Enter your new master password:",
        validate: (value) => {
          return validatePassword(value);
        },
        mask: "*",
      },
      {
        type: "password",
        name: "confirmPassword",
        message: "Confirm your new master password:",
        validate: (value, answers) => {
          return checkPasswordMatch(value, answers.newPassword);
        },
        mask: "*",
      },
    ]);

    // Ask if the user wants to continue, go back, or return to main menu
    // Only add navigation prompt here after collecting all password information
    const navigationAction = await promptNavigation();
    if (navigationAction === NavigationAction.GO_BACK) {
      return await updateMasterPassword(); // Let the user start over
    } else if (navigationAction === NavigationAction.MAIN_MENU) {
      return NavigationAction.MAIN_MENU;
    }

    await writeMasterPassword(encryptPassword(newPassword));

    log(green("✓ Master password updated successfully!\n"));
    return true;
  } catch (error) {
    if (error instanceof PasswordManagerError) {
      throw error;
    }
    throw new PasswordManagerError(
      "✗ Failed to update master password",
      ERROR_CODES.AUTHENTICATION_FAILED
    );
  }
};
