import inquirer from "inquirer";
import validationTools from "./validation.js";
import { red } from "./logger.js";

/**
 * Prompts the user to enter an identifier for a service.
 * @param {string} service - The name of the service.
 * @param {Object[]} entries - The password entries to validate against.
 * @returns {Promise<string>} The identifier.
 */
export async function promptIdentifier(service, entries) {
  const { identifier } = await inquirer.prompt([
    {
      type: "input",
      name: "identifier",
      message: `Enter the identifier for ${service}:`,
      validate: (value) => {
        const inputValidation = validationTools.validateInput(
          value,
          "identifier"
        );
        if (inputValidation !== true) return inputValidation;

        const identifierValidation =
          validationTools.validateNonDuplicateIdentifier(
            value.trim(),
            service,
            entries
          );
        if (identifierValidation !== true) return identifierValidation;

        return true;
      },
    },
  ]);

  return identifier;
}

/**
 * Prompts the user to enter a password.
 * @returns {Promise<string>} The password.
 */
export async function promptPassword() {
  const { password } = await inquirer.prompt([
    {
      type: "password",
      name: "password",
      message: "Enter your password:",
    },
  ]);

  return password;
}
