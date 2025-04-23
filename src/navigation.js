import inquirer from "inquirer";
import chalk from "chalk";

// Chalk variables
const log = console.log;
const green = chalk.green;
const yellow = chalk.yellow;

/**
 * Navigation status flags
 */
const NavigationAction = {
  CONTINUE: 'CONTINUE',
  GO_BACK: 'GO_BACK',
  MAIN_MENU: 'MAIN_MENU'
};

/**
 * Prompt the user for navigation options
 * @returns {Promise<string>} The navigation action chosen by the user
 */
export const promptNavigation = async () => {
  const { action } = await inquirer.prompt([
    {
      type: "list",
      name: "action",
      message: "What would you like to do next?",
      choices: [
        { name: "Continue with current operation", value: NavigationAction.CONTINUE },
        { name: "Go back to previous step", value: NavigationAction.GO_BACK },
        { name: "Return to main menu", value: NavigationAction.MAIN_MENU }
      ],
    },
  ]);

  return action;
};

/**
 * Handle navigation action
 * @param {string} action - The navigation action to handle
 * @returns {boolean} True if the action was handled successfully, false otherwise
 */
export const handleNavigation = async (action) => {
  switch (action) {
    case NavigationAction.CONTINUE:
      return false; // No navigation needed
    case NavigationAction.GO_BACK:
      log(yellow("\nGoing back to previous step...\n"));
      return true;
    case NavigationAction.MAIN_MENU:
      log(green("\nReturning to main menu...\n"));
      return true;
    default:
      return false;
  }
};

export { NavigationAction }; 