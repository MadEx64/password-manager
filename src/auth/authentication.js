import {
  updateSession,
  isSessionValid,
  clearSession,
  sessionState,
} from "./session.js";
import { validateMasterPassword } from "./password.js";
import { promptMasterPassword, promptNewPassword } from "./prompts.js";
import {
  readMasterPassword,
  writeMasterPassword,
} from "../fileOperations/index.js";
import { PasswordManagerError } from "../errorHandler.js";
import { log, blue, green, red, bold } from "../logger.js";
import { ERROR_CODES, NEWLINE } from "../constants.js";

/**
 * Authenticates the user with the master password.
 *
 * If the master password is not set, it will prompt the user to set it.
 * If the master password is set, it will validate the user's input against the master password and update the session state if the master password is validated.
 *
 * @returns {Promise<boolean>} True if the master password is validated and the user is logged in, false otherwise.
 */
export async function authenticateUser() {
  try {
    if (isSessionValid(sessionState)) {
      return true;
    } else {
      clearSession(sessionState);
    }

    const storedMasterPassword = await readMasterPassword();
    if (storedMasterPassword === "") {
      return await handleNoStoredMasterPassword();
    }

    const MAX_ATTEMPTS = 3;
    let attempts = 0;

    while (attempts < MAX_ATTEMPTS) {
      const password = await promptMasterPassword();
      const isValid = await validateMasterPassword(password);

      if (isValid) {
        loginUser();
        return true;
      }

      attempts++;
      handleFailedLoginAttempt(attempts, MAX_ATTEMPTS);
    }

    return false;
  } catch (error) {
    throw new PasswordManagerError(
      red(error.message),
      bold(red(ERROR_CODES.INTERNAL_ERROR))
    );
  }
}

/**
 * Updates the session state and logs a success message.
 *
 * @returns {Promise<void>}
 */
function loginUser() {
  updateSession(sessionState);
  log(green("Access granted!" + NEWLINE));
}

/**
 * Handles failed login attempts and displays a message to the user.
 *
 * @param {number} attempts - The number of failed attempts.
 * @param {number} MAX_ATTEMPTS - The maximum number of allowed attempts.
 */
function handleFailedLoginAttempt(attempts, MAX_ATTEMPTS) {
  if (attempts >= MAX_ATTEMPTS) {
    log(
      red(
        `✗ Invalid master password. Maximum attempts reached (${attempts}/${MAX_ATTEMPTS}).` +
          NEWLINE +
          "Run the program to try again or run the recovery tool to reset or recover your master password." +
          NEWLINE +
          "Exiting..."
      )
    );
    process.exit(1);
  } else {
    log(
      red(
        `✗ Invalid master password. Please try again. (${attempts}/${MAX_ATTEMPTS})${NEWLINE}`
      )
    );
  }
}

/**
 * Handles the case when no master password is stored.
 * Prompts the user to set a new master password, writes it, and logs the user in.
 *
 * @returns {Promise<boolean>} True if the master password is set successfully.
 */
async function handleNoStoredMasterPassword() {
  log(
    blue(`No master password found. Setting up master password...${NEWLINE}`)
  );
  const newPassword = await promptNewPassword();
  await writeMasterPassword(newPassword);
  log(green("✓ Master password set successfully!" + NEWLINE));
  loginUser();
  return true;
}
