import fs from "fs";
import os from "os";
import inquirer from "inquirer";
import { encryptPassword, decryptPassword } from "./utils.js";
import { validateMasterPassword } from "./authentication.js";
import { handleError, validateNonEmptyInput } from "./errorHandler.js";
import { sortLines, writeLines } from "./fileOperations.js";

// Chalk variables
import chalk from "chalk";
const log = console.log;
const green = chalk.green;
const yellow = chalk.yellow;
const red = chalk.red;

const EXPECTED_FORMAT = "app - identifier - password";

/**
 * Exports all passwords to a JSON file (decrypted)
 * @param {string[]} lines - The password lines to export
 * @returns {Promise<boolean>} True if export was successful, false otherwise
 */
export const exportPasswordsToJSON = async (lines) => {
  try {
    if (!(await validateMasterPassword())) {
      return false;
    }

    if (lines.length === 0) {
      log(yellow("No passwords to export.\n"));
      return false;
    }

    const { exportPath } = await inquirer.prompt([
      {
        type: "input",
        name: "exportPath",
        message:
          "Enter the path to export passwords (e.g. ./passwords-export.json):",
        default: "./passwords-export.json",
        validate: (value) => validateNonEmptyInput(value),
      },
    ]);
    
    const data = lines.map((line) => {
          const parts = line.split(" - ");
          if (parts.length !== 3) {
            throw new Error(`Invalid line format: "${line}". Expected format: "${EXPECTED_FORMAT}".`);
          }
          const [app, identifier, encryptedPassword] = parts;
          let decryptedPassword;
          try {
            decryptedPassword = decryptPassword(encryptedPassword);
          } catch (error) {
            log(red(`Failed to decrypt password for "${app} - ${identifier}": ${error.message}`));
            handleError(error);
            return null; // Skip this entry if decryption fails
          }
          return {
            application: app,
            identifier,
            password: decryptedPassword,
          };
        }).filter(entry => entry !== null); // Filter out any null entries

    await fs.promises.writeFile(exportPath, JSON.stringify(data, null, 2), "utf8");

    log(green(`Passwords exported to ${exportPath}`));
    log(
      yellow(
        "Please make sure to protect this file as it contains sensitive information.\n"
      )
    );

    log(green("Export completed successfully.\n"));
    return true;
  } catch (error) {
    handleError(error);

    return false;
  }
};

/**
 * Imports passwords from a JSON file
 * @param {string[]} lines - The current password lines
 * @returns {Promise<boolean>} True if import was successful, false otherwise
 */
export const importPasswordsFromJSON = async (lines) => {
  try {
    if (!(await validateMasterPassword())) {
      return false;
    }

    const { importPath } = await inquirer.prompt([
      {
        type: "input",
        name: "importPath",
        message:
          "Enter the path to import passwords from (e.g. ./passwords-export.json):",
        default: "./passwords-export.json",
        validate: (value) => value.trim() !== "" || "Path cannot be empty.",
      },
    ]);

    let fileContent;
    try {
      fileContent = fs.readFileSync(importPath, "utf8");
    } catch (error) {
      if (error.code === "ENOENT") {
        log(red("File does not exist."));
      } else {
        log(red("An error occurred while reading the file."));
      }
      return false;
    }
    let importedData;

    try {
      importedData = JSON.parse(fileContent);
    } catch (e) {
      log(red(`Invalid JSON format: ${e.message}`));
      return false;
    }

    if (!Array.isArray(importedData)) {
      log(red("JSON must be an array of password objects."));
      return false;
    }

    let imported = 0;

    // Create a Set for faster duplicate checks
    const existingEntries = new Set(
      lines.map((line) => {
        const [app, identifier] = line.split(" - ");
        return `${app}-${identifier}`;
      })
    );

    for (const entry of importedData) {
      if (!entry.application || !entry.identifier || !entry.password) continue;
      // Check for duplicates using the Set
      const entryKey = `${entry.application}-${entry.identifier}`;
      if (existingEntries.has(entryKey)) continue;

      const encryptedPassword = encryptPassword(entry.password);
      lines.push(
        `${entry.application} - ${entry.identifier} - ${encryptedPassword}`
      );
      existingEntries.add(entryKey); // Add to Set after adding to lines
      imported++;
    }

    if (imported > 0) {
      const sortedLines = sortLines(lines);
      await writeLines(sortedLines);
      log(green(`Imported ${imported} passwords from ${importPath}\n`));
      return true;
    } else {
      log(
        yellow(
          "No new passwords were imported (all were duplicates or invalid).\n"
        )
      );
      return false;
    }
  } catch (error) {
    handleError(error);
    return false;
  }
};

/**
 * Exports all passwords to a CSV file (decrypted)
 * @param {string[]} lines - The password lines to export
 * @returns {Promise<boolean>} True if export was successful, false otherwise
 */
export const exportPasswordsToCSV = async (lines) => {
  try {
    if (!(await validateMasterPassword())) {
      return false;
    }

    if (lines.length === 0) {
      log(yellow("No passwords to export.\n"));
      return false;
    }

    const { exportPath } = await inquirer.prompt([
      {
        type: "input",
        name: "exportPath",
        message:
          "Enter the path to export passwords (e.g. ./passwords-export.csv):",
        default: "./passwords-export.csv",
        validate: (value) => validateNonEmptyInput(value),
      },
    ]);
    
    const data = lines.map((line) => {
      const [app, identifier, encryptedPassword] = line.split(" - ");
      return {
        application: app,
        identifier,
        password: decryptPassword(encryptedPassword),
      };
    });

    const csvContent = data
      .map((row) => `${row.application},${row.identifier},${row.password}`)
      .join("\n");

    await fs.promises.writeFile(exportPath, csvContent, "utf8");
    
    log(green(`Passwords exported to ${exportPath}`));
    log(
      yellow(
        "Please make sure to protect this file as it contains sensitive information.\n"
      )
    );

    log(green("Export completed successfully.\n"));
    return true;
  } catch (error) {
    handleError(error);
    return false;
  }
};

/**
 * Imports passwords from a CSV file
 * @param {string[]} lines - The current password lines
 * @returns {Promise<boolean>} True if import was successful, false otherwise
 */
export const importPasswordsFromCSV = async (lines) => {
  try {
    if (!(await validateMasterPassword())) {
      return false;
    }
    
    const { importPath } = await inquirer.prompt([
      {
        type: "input",
        name: "importPath",
        message:
          "Enter the path to import passwords from (e.g. ./passwords-export.csv):",
        default: "./passwords-export.csv",
        validate: (value) => validateNonEmptyInput(value),
      },
    ]);

    let fileContent;
    try {
      fileContent = fs.readFileSync(importPath, "utf8");
    } catch (error) {
      if (error.code === "ENOENT") {
        log(red("File does not exist."));
      } else {
        log(red("An error occurred while reading the file."));
      }
      return false;
    }

    const linesArray = fileContent
      .split(os.EOL)
      .map((line) => line.trim())
      .filter((line) => line !== "");
    let imported = 0;

    // Create a Set for faster duplicate checks
    const existingEntries = new Set(
      lines.map((line) => {
        const [app, identifier] = line.split(" - ");
        return `${app}-${identifier}`;
      })
    );

    for (const csvLine of linesArray) {
      const [app, identifier, password] = csvLine.split(",");
      if (!app || !identifier || !password) continue;
      // Check for duplicates using the Set
      const entryKey = `${app}-${identifier}`;
      if (existingEntries.has(entryKey)) continue;
      const encryptedPassword = encryptPassword(password);
      lines.push(`${app} - ${identifier} - ${encryptedPassword}`);
      existingEntries.add(entryKey);
      imported++;
    }
    
    if (imported > 0) {
      const sortedLines = sortLines(lines);
      await writeLines(sortedLines);
      log(green(`Imported ${imported} passwords from ${importPath}\n`));
      return true;
    } else {
      log(
        yellow(
          "No new passwords were imported (all were duplicates or invalid).\n"
        )
      );
      return false;
    }
  } catch (error) {
    handleError(error);
    return false;
  }
};

/**
 * Handles the export of passwords based on the selected format
 * @param {string} format - The format to export to (JSON or CSV)
 * @param {string[]} lines - The password lines to export
 * @returns {Promise<boolean>} True if export was successful, false otherwise
 */
export const handleExportPasswords = async (format, lines) => {
  try {
    if (format === "JSON") {
      return await exportPasswordsToJSON(lines);
    } else if (format === "CSV") {
      return await exportPasswordsToCSV(lines);
    } else if (format === "CANCEL") {
      log(yellow("Export cancelled.\n"));
      return false;
    } else {
      log(red("Invalid format selected.\n"));
      return false;
    }
  } catch (error) {
    handleError(error);
    return false;
  }
};
/**
 * Handles the import of passwords based on the selected format
 * @param {string} format - The format to import from (JSON or CSV)
 * @param {string[]} lines - The current password lines
 * @returns {Promise<boolean>} True if import was successful, false otherwise
 */
export const handleImportPasswords = async (format, lines) => {
  try {
    if (format === "JSON") {
      return await importPasswordsFromJSON(lines);
    } else if (format === "CSV") {
      return await importPasswordsFromCSV(lines);
    } else if (format === "CANCEL") {
      log(yellow("Import cancelled.\n"));
      return false;
    } else {
      log(red("Invalid format selected.\n"));
      return false;
    }
  } catch (error) {
    handleError(error);
    return false;
  }
};
