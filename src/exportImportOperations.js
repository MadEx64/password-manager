import fs from "fs";
import os from "os";
import inquirer from "inquirer";
import { encryptPassword, decryptPassword } from "./utils.js";
import { validateMasterPassword } from "./authentication.js";
import { handleError } from "./errorHandler.js";
import { sortLines, writeLines } from "./fileOperations.js";

// Chalk variables
import chalk from "chalk";
const log = console.log;
const green = chalk.green;
const yellow = chalk.yellow;
const red = chalk.red;

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
        validate: (value) => value.trim() !== "" || "Path cannot be empty.",
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
    fs.writeFileSync(exportPath, JSON.stringify(data, null, 2), "utf8");
    log(green(`Passwords exported to ${exportPath}`));
    log(
      yellow(
        "Please make sure to protect this file as it contains sensitive information.\n"
      )
    );
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

    if (!fs.existsSync(importPath)) {
      log(red("File does not exist."));
      return false;
    }
    const fileContent = fs.readFileSync(importPath, "utf8");
    let importedData;
    try {
      importedData = JSON.parse(fileContent);
    } catch (e) {
      log(red("Invalid JSON format."));
      return false;
    }
    if (!Array.isArray(importedData)) {
      log(red("JSON must be an array of password objects."));
      return false;
    }
    let imported = 0;
    for (const entry of importedData) {
      if (!entry.application || !entry.identifier || !entry.password) continue;
      // Check for duplicates
      if (
        lines.some((line) => {
          const [app, identifier] = line.split(" - ");
          return app === entry.application && identifier === entry.identifier;
        })
      )
        continue;
      const encryptedPassword = encryptPassword(entry.password);
      lines.push(
        `${entry.application} - ${entry.identifier} - ${encryptedPassword}`
      );
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
        validate: (value) => value.trim() !== "" || "Path cannot be empty.",
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
    fs.writeFileSync(exportPath, csvContent, "utf8");
    log(green(`Passwords exported to ${exportPath}`));
    log(
      yellow(
        "Please make sure to protect this file as it contains sensitive information.\n"
      )
    );
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
        validate: (value) => value.trim() !== "" || "Path cannot be empty.",
      },
    ]);
    if (!fs.existsSync(importPath)) {
      log(red("File does not exist."));
      return false;
    }
    const fileContent = fs.readFileSync(importPath, "utf8");
    const linesArray = fileContent
      .split(os.EOL)
      .map((line) => line.trim())
      .filter((line) => line !== "");
    let imported = 0;
    for (const line of linesArray) {
      const [app, identifier, password] = line.split(",");
      if (!app || !identifier || !password) continue;
      // Check for duplicates
      if (
        lines.some(
          (line) => line.startsWith(app) && line.includes(` - ${identifier} - `)
        )
      )
        continue;
      const encryptedPassword = encryptPassword(password);
      lines.push(`${app} - ${identifier} - ${encryptedPassword}`);
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
