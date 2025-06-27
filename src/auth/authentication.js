import {
  updateSession,
  isSessionValid,
  clearSession,
  getSessionState,
} from "./session.js";
import { validateMasterPassword } from "./password.js";
import { promptMasterPassword, promptNewPassword } from "./prompts.js";
import { PasswordManagerError } from "../errorHandler.js";
import { log, blue, green, red, bold, yellow } from "../logger.js";
import { ERROR_CODES, NEWLINE } from "../constants.js";
import { 
  isAuthSystemInitialized, 
  setupMasterPassword as secureSetupMasterPassword,
  deriveAuthenticationKey 
} from "./secureAuth.js";

/**
 * Authenticates the user with the master password using the enhanced security system.
 *
 * If the master password is not set, it will prompt the user to set it.
 * If the master password is set, it will validate the user's input against the master password and update the session state if the master password is validated.
 *
 * @returns {Promise<boolean>} True if the master password is validated and the user is logged in, false otherwise.
 */
export async function authenticateUser() {
  try {
    if (isSessionValid(getSessionState())) {
      return true;
    } else {
      clearSession(getSessionState());
    }

    // Check if secure auth system is initialized, if not set it up
    if (!(await isAuthSystemInitialized())) {
      const result = await handleNoStoredMasterPassword();
      if (result) {
        return true;
      } else {
        return false;
      }
    }

    const MAX_ATTEMPTS = 3;
    let attempts = 0;

    while (attempts < MAX_ATTEMPTS) {
      const password = await promptMasterPassword();
      const isValid = await validateMasterPassword(password);

      if (isValid) {
        await loginUser(password);
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
 * Also caches the master password and encryption key for the session.
 *
 * @param {string} masterPassword - The master password to cache.
 * @returns {Promise<void>}
 */
async function loginUser(masterPassword) {
  const encryptionKey = await deriveAuthenticationKey(masterPassword);
  updateSession(getSessionState(), masterPassword, encryptionKey);
  log(green("✓ Access granted!" + NEWLINE));
}

/**
 * Handles failed login attempts and displays a message to the user.
 *
 * @param {number} attempts - The number of failed attempts.
 * @param {number} MAX_ATTEMPTS - The maximum number of allowed attempts.
 * @throws {PasswordManagerError} If maximum attempts are reached.
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
 * Sets up a new master password using the enhanced security system.
 *
 * @returns {Promise<boolean>} True if the master password is set successfully.
 */
async function handleNoStoredMasterPassword() {
  try {
    log(blue("Welcome! You will be asked to set a master password to access the application."));
    log(yellow("⚠ This will also create a secure application key stored in your system's credential store. This is essential for the application to work."));
    
    const newPassword = await promptNewPassword();
    await secureSetupMasterPassword(newPassword);
    
    log(green("✓ Master password set successfully." + NEWLINE));
    log(green("🔐 Your credentials are now securely stored in the system credential store."));
    log(green("You can now access the application with your master password."));
    
    await loginUser(newPassword);
    return true;
  } catch (error) {
    throw new PasswordManagerError(
      red("Failed to setup master password: " + error.message),
      bold(red(ERROR_CODES.INTERNAL_ERROR))
    );
  }
}
