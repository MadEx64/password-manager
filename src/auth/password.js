import {
  readMasterPassword,
  writeMasterPassword,
} from "../fileOperations/index.js";
import { decryptPassword, encryptPassword } from "../utils.js";
import { promptMasterPassword, promptNewPassword } from "./prompts.js";
import { NavigationAction, promptNavigation } from "../navigation.js";
import { PasswordManagerError } from "../errorHandler.js";
import { log, red, green, bold, yellow } from "../logger.js";
import { clearSession } from "./session.js";
import { ERROR_CODES, NEWLINE } from "../constants.js";

/**
 * Validates the user's input against the master password.
 *
 * @param {string} inputPassword - The password to validate.
 * @returns {Promise<boolean>} True if the password is valid, false otherwise.
 */
export async function validateMasterPassword(inputPassword) {
  try {
    const storedPassword = await readMasterPassword();
    const decryptedPassword = decryptPassword(storedPassword);
    return inputPassword === decryptedPassword;
  } catch (error) {
    throw new PasswordManagerError(
      red(error.message),
      bold(red(ERROR_CODES.INTERNAL_ERROR))
    );
  }
}

/**
 * Handles the updating of the master password.
 *
 * Prompts the user for the old master password, validates it, and then prompts for the new master password.
 *
 * @returns {Promise<boolean>} True if the password is updated, false otherwise.
 */
export async function handlePasswordUpdate() {
  try {
    const MAX_ATTEMPTS = 3;
    let attempts = 0;
    let isValid = false;
    let oldPassword;

    while (!isValid && attempts < MAX_ATTEMPTS) {
      oldPassword = await promptMasterPassword();
      isValid = await validateMasterPassword(oldPassword);
      if (!isValid) {
        attempts++;
        log(
          red(
            `✗ Invalid master password. Please try again. (${attempts}/${MAX_ATTEMPTS})${NEWLINE}`
          )
        );
        if (attempts >= MAX_ATTEMPTS) {
          log(
            red(
              "✗ Maximum attempts reached." + NEWLINE + "Run the program to try again or run the recovery tool to attempt a reset of the master password." + NEWLINE + "Exiting..."
            )
          );
          process.exit(1);
        }
      }
    }

    const newPassword = await promptNewPassword(oldPassword);

    const navigationAction = await promptNavigation();
    if (navigationAction === NavigationAction.GO_BACK) {
      return await handlePasswordUpdate();
    } else if (navigationAction === NavigationAction.MAIN_MENU) {
      log(yellow("Aborting..."));
      return NavigationAction.MAIN_MENU;
    }

    await writeMasterPassword(encryptPassword(newPassword));

    clearSession();
    log(green("✓ Master password updated successfully!" + NEWLINE));
    return true;
  } catch (error) {
    throw new PasswordManagerError(
      red(error.message),
      bold(red(ERROR_CODES.INTERNAL_ERROR))
    );
  }
}
