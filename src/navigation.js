import inquirer from "inquirer";
import { log, green, yellow } from "./logger.js";

/**
 * Navigation status flags
 */
const NavigationAction = {
  CONTINUE: 'CONTINUE',
  GO_BACK: 'GO_BACK',
  MAIN_MENU: 'MAIN_MENU'
};

/**
 * Prompts the user for navigation options.
 * @param {Array<Object>} navigationOptions - The navigation options to present to the user.
 * @returns {Promise<string>} The navigation action chosen by the user.
 */
export async function promptNavigation(navigationOptions = [
  { name: "Continue with current operation", value: NavigationAction.CONTINUE },
  { name: "Go back to previous step", value: NavigationAction.GO_BACK },
  { name: "Abort, return to main menu", value: NavigationAction.MAIN_MENU }
]) {
  const { action } = await inquirer.prompt([
    {
      type: "list",
      name: "action",
      message: "What would you like to do next?",
      choices: navigationOptions,
    },
  ]);
  return action;
}

/**
 * Handles the navigation action selected by the user.
 * @param {string} action - The navigation action to handle.
 * @returns {boolean} True if the action was handled successfully, false otherwise.
 */
export async function handleNavigation(action) {
  switch (action) {
    case NavigationAction.CONTINUE:
      return false; // No navigation needed
    case NavigationAction.GO_BACK:
      log(yellow("\nGoing back to previous step...\n"));
      return true;
    case NavigationAction.MAIN_MENU:
      log(green("\nReturning to main menu...\n"));
      return false;
    default:
      return false;
  }
}

export { NavigationAction }; 