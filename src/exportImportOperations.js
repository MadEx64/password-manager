import fs from "fs";
import os from "os";
import inquirer from "inquirer";
import { withAuthentication } from "./auth/authWrapper.js";
import { getEncryptionKey } from "./auth/masterPasswordCache.js";
import { decryptPassword, encryptPassword } from "./encryption/index.js";
import { handleError } from "./errorHandler.js";
import { NEWLINE } from "./constants.js";
import validationTools from "./validation.js";
import {
  readPasswordEntries,
  writePasswordEntries,
} from "./fileOperations/index.js";
import { green, yellow, red, log } from "./logger.js";

/**
 * Exports all passwords to a JSON file.
 * @returns {Promise<boolean>} True if export was successful, false otherwise.
 */
export const exportPasswordsToJSON = withAuthentication(async () => {
  try {
    const entries = await readPasswordEntries();

    if (entries.length === 0) {
      log(yellow("No passwords to export." + NEWLINE));
      return false;
    }

    const defaultExportPath = `${os.homedir()}/passwords-export-${
      new Date().toISOString().split("T")[0]
    }.json`;

    let exportPath;
    let shouldProceed = false;

    while (!shouldProceed) {
      const pathPrompt = await inquirer.prompt([
        {
          type: "input",
          name: "exportPath",
          message:
            "Enter the path to export passwords (e.g. ./passwords-export.json):",
          default: defaultExportPath,
          validate: (value) => {
            if (value.trim() === "") {
              return "Path cannot be empty.";
            }
            if (!value.endsWith(".json")) {
              return "File must have a .json extension.";
            }
            return true;
          },
        },
      ]);

      exportPath = pathPrompt.exportPath;

      try {
        await fs.promises.access(exportPath);
        const { action } = await inquirer.prompt([
          {
            type: "list",
            name: "action",
            message: `File "${exportPath}" already exists. What would you like to do?`,
            choices: [
              "Replace existing file",
              "Choose different path",
              "Cancel export",
            ],
          },
        ]);

        if (action === "Replace existing file") {
          shouldProceed = true;
        } else if (action === "Choose different path") {
          continue;
        } else if (action === "Cancel export") {
          log(yellow("Export cancelled." + NEWLINE));
          return false;
        }
      } catch (error) {
        shouldProceed = true;
      }
    }

    const key = await getEncryptionKey();

    const data = await Promise.all(
      entries.map(async (entry) => {
        try {
          return {
            service: entry.service,
            identifier: entry.identifier,
            password: await decryptPassword(entry.password, key),
            createdAt: entry.createdAt,
            updatedAt: entry.updatedAt,
          };
        } catch (error) {
          log(
            red(
              `Failed to decrypt password for "${entry.service} - ${entry.identifier}": ${error.message}`
            )
          );
          handleError(error);
          return null;
        }
      })
    ).then((results) => results.filter((entry) => entry !== null));

    await fs.promises.writeFile(
      exportPath,
      JSON.stringify(data, null, 2),
      "utf8"
    );

    const numberOfPasswordsExported = data.length;
    const numberOfPasswordsNotExported =
      entries.length - numberOfPasswordsExported;

    log(
      yellow(
        `Make sure to protect this file as it contains sensitive information.${NEWLINE}`
      )
    );

    log(
      green(
        `✔ Export completed successfully. ${numberOfPasswordsExported} password${
          numberOfPasswordsExported === 1 ? "" : "s"
        } exported.${NEWLINE}`
      )
    );

    if (numberOfPasswordsNotExported > 0) {
      log(
        yellow(
          `${numberOfPasswordsNotExported} password${
            numberOfPasswordsNotExported === 1 ? "" : "s"
          } failed to export.${NEWLINE}`
        )
      );
    }

    return true;
  } catch (error) {
    handleError(error);
    return false;
  }
});

/**
 * Imports passwords from a JSON file.
 * @returns {Promise<boolean>} True if import was successful, false otherwise.
 */
export const importPasswordsFromJSON = withAuthentication(async () => {
  try {
    const defaultImportPath = `${os.homedir()}/passwords-export-${
      new Date().toISOString().split("T")[0]
    }.json`;

    const { importPath } = await inquirer.prompt([
      {
        type: "input",
        name: "importPath",
        message:
          "Enter the path to import passwords from (e.g. ./passwords-export.json):",
        default: defaultImportPath,
        validate: (value) => {
          if (value.trim() === "") {
            return "Path cannot be empty.";
          }
          if (!value.endsWith(".json")) {
            return "File must have a .json extension.";
          }
          return true;
        },
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

    const existingEntries = await readPasswordEntries();
    const existingKeys = new Set(
      existingEntries.map((entry) => `${entry.service}-${entry.identifier}`)
    );

    let imported = 0;
    const newEntries = [...existingEntries];

    for (const entry of importedData) {
      if (!entry.service || !entry.identifier || !entry.password) continue;

      const entryKey = `${entry.service}-${entry.identifier}`;
      if (existingKeys.has(entryKey)) continue;

      if (
        !validationTools.validatePasswordEntry({
          service: entry.service,
          identifier: entry.identifier,
          password: entry.password,
          createdAt: entry.createdAt || new Date().toISOString(),
          updatedAt: entry.updatedAt || new Date().toISOString(),
        })
      ) {
        log(red(`Invalid password entry structure: ${entryKey}`));
        continue;
      }

      const key = await getEncryptionKey();

      newEntries.push({
        service: entry.service,
        identifier: entry.identifier,
        password: await encryptPassword(entry.password, key),
        createdAt: entry.createdAt || new Date().toISOString(),
        updatedAt: entry.updatedAt || new Date().toISOString(),
      });

      existingKeys.add(entryKey);
      imported++;
    }

    if (imported > 0) {
      log(yellow("Importing passwords..." + NEWLINE));
      await writePasswordEntries(newEntries);
      const numberOfPasswordsImported = imported;
      const numberOfPasswordsNotImported =
        newEntries.length - numberOfPasswordsImported;

      log(
        green(
          "✔ Import completed successfully." + NEWLINE
        )
      );
      log(
        green(
          `✔ Imported ${numberOfPasswordsImported} password${
            numberOfPasswordsImported === 1 ? "" : "s"
          } from ${importPath}${NEWLINE}`
        )
      );

      if (numberOfPasswordsNotImported > 0) {
        log(
          yellow(
            `${numberOfPasswordsNotImported} password${
              numberOfPasswordsNotImported === 1 ? "" : "s"
            } failed to import.${NEWLINE}`
          )
        );
      }

      return true;
    } else {
      log(
        yellow(
          `No new passwords were imported (all were duplicates or invalid).${NEWLINE}`
        )
      );
      return false;
    }
  } catch (error) {
    handleError(error);
    return false;
  }
});

/**
 * Exports all passwords to a CSV file.
 * @returns {Promise<boolean>} True if export was successful, false otherwise.
 */
export const exportPasswordsToCSV = withAuthentication(async () => {
  try {
    const entries = await readPasswordEntries();

    if (entries.length === 0) {
      log(yellow("No passwords to export." + NEWLINE));
      return false;
    }

    const defaultExportPath = `${os.homedir()}/passwords-export-${
      new Date().toISOString().split("T")[0]
    }.csv`;

    let exportPath;
    let shouldProceed = false;

    while (!shouldProceed) {
      const pathPrompt = await inquirer.prompt([
        {
          type: "input",
          name: "exportPath",
          message:
            "Enter the path to export passwords (e.g. ./passwords-export.csv):",
          default: defaultExportPath,
          validate: (value) => {
            if (value.trim() === "") {
              return "Path cannot be empty.";
            }
            if (!value.endsWith(".csv")) {
              return "File must have a .csv extension.";
            }
            return true;
          },
        },
      ]);

      exportPath = pathPrompt.exportPath;

      try {
        await fs.promises.access(exportPath);
        const { action } = await inquirer.prompt([
          {
            type: "list",
            name: "action",
            message: `File "${exportPath}" already exists. What would you like to do?`,
            choices: [
              "Replace existing file",
              "Choose different path",
              "Cancel export",
            ],
          },
        ]);

        if (action === "Replace existing file") {
          shouldProceed = true;
        } else if (action === "Choose different path") {
          continue;
        } else if (action === "Cancel export") {
          log(yellow("Export cancelled." + NEWLINE));
          return false;
        }
      } catch (error) {
        shouldProceed = true;
      }
    }

    const key = await getEncryptionKey();

    const data = await Promise.all(
      entries.map(async (entry) => ({
        service: entry.service,
        identifier: entry.identifier,
        password: await decryptPassword(entry.password, key),
        createdAt: entry.createdAt,
        updatedAt: entry.updatedAt,
      }))
    );

    const csvHeader = "service,identifier,password,createdAt,updatedAt";

    const csvContent = data
      .map(
        (row) =>
          `${row.service},${row.identifier},${row.password},${row.createdAt},${row.updatedAt}`
      )
      .join(NEWLINE);

    await fs.promises.writeFile(
      exportPath,
      csvHeader + NEWLINE + csvContent,
      "utf8"
    );

    log(green(`✔ Passwords exported to ${exportPath}`));
    log(
      yellow(
        "Please make sure to protect this file as it contains sensitive information." +
          NEWLINE
      )
    );

    log(green("✔ Export completed successfully." + NEWLINE));
    return true;
  } catch (error) {
    handleError(error);
    return false;
  }
});

/**
 * Imports passwords from a CSV file.
 * @returns {Promise<boolean>} True if import was successful, false otherwise.
 */
export const importPasswordsFromCSV = withAuthentication(async () => {
  try {
    const { importPath } = await inquirer.prompt([
      {
        type: "input",
        name: "importPath",
        message:
          "Enter the path to import passwords from (e.g. ./passwords-export.csv):" +
          NEWLINE,
        default: "./passwords-export.csv",
        validate: (value) => validationTools.validateNonEmptyInput(value),
      },
    ]);

    let fileContent;
    try {
      fileContent = fs.readFileSync(importPath, "utf8");
    } catch (error) {
      if (error.code === "ENOENT") {
        log(red("File does not exist." + NEWLINE));
      } else {
        log(red("An error occurred while reading the file." + NEWLINE));
      }
      return false;
    }

    const fileHeader = fileContent.split(NEWLINE)[0];
    if (fileHeader !== "service,identifier,password,createdAt,updatedAt") {
      log(
        red(
          "Invalid CSV file format. Please ensure the file has the correct header." +
            NEWLINE
        )
      );
      return false;
    }

    const linesArray = fileContent
      .split(NEWLINE)
      .map((line) => line.trim())
      .filter((line) => line !== "" && line !== fileHeader);

    const existingEntries = await readPasswordEntries();
    const existingKeys = new Set(
      existingEntries.map((entry) => `${entry.service}-${entry.identifier}`)
    );

    let imported = 0;
    const newEntries = [...existingEntries];

    for (const csvLine of linesArray) {
      const [service, identifier, password, createdAt, updatedAt] =
        csvLine.split(",");
      if (!service || !identifier || !password) continue;

      const entryKey = `${service}-${identifier}`;
      if (existingKeys.has(entryKey)) continue;

      if (
        !validationTools.validatePasswordEntry({
          service,
          identifier,
          password,
          createdAt: createdAt || new Date().toISOString(),
          updatedAt: updatedAt || new Date().toISOString(),
        })
      ) {
        log(red(`Invalid password entry structure: ${entryKey}`));
        continue;
      }

      const key = await getEncryptionKey();

      newEntries.push({
        service,
        identifier,
        password: await encryptPassword(password, key),
        createdAt: createdAt || new Date().toISOString(),
        updatedAt: updatedAt || new Date().toISOString(),
      });

      existingKeys.add(entryKey);
      imported++;
    }

    const numberOfPasswordsImported = imported;
    const numberOfPasswordsNotImported =
      newEntries.length - numberOfPasswordsImported;

    if (numberOfPasswordsImported > 0) {
      await writePasswordEntries(newEntries);

      if (numberOfPasswordsNotImported > 0) {
        log(
          yellow(
            `${numberOfPasswordsNotImported} password${
              numberOfPasswordsNotImported === 1 ? "" : "s"
            } failed to import.${NEWLINE}`
          )
        );
      }

      log(
        green(
          `Imported ${numberOfPasswordsImported} password${
            numberOfPasswordsImported === 1 ? "" : "s"
          } from ${importPath}${NEWLINE}`
        )
      );
      return true;
    } else {
      log(
        yellow(
          `No new passwords were imported (all were duplicates or invalid).${NEWLINE}`
        )
      );
      return false;
    }
  } catch (error) {
    handleError(error);
    return false;
  }
});

/**
 * Handles the export of passwords based on the selected format.
 * @param {string} format - The format to export to (JSON or CSV).
 * @returns {Promise<boolean>} True if export was successful, false otherwise.
 */
export const handleExportPasswords = withAuthentication(async () => {
  try {
    const format = await inquirer.prompt([
      {
        type: "list",
        name: "format",
        message: "Select the format to export passwords:",
        choices: ["JSON", "CSV", "Cancel"],
      },
    ]);

    if (format.format === "JSON") {
      return await exportPasswordsToJSON();
    } else if (format.format === "CSV") {
      return await exportPasswordsToCSV();
    } else if (format.format === "Cancel") {
      log(yellow("Export cancelled." + NEWLINE));
      return false;
    } else {
      log(red("Invalid format selected." + NEWLINE));
      return false;
    }
  } catch (error) {
    handleError(error);
    return false;
  }
});

/**
 * Handles the import of passwords based on the selected format.
 * @param {string} format - The format to import from (JSON or CSV).
 * @returns {Promise<boolean>} True if import was successful, false otherwise.
 */
export const handleImportPasswords = withAuthentication(async () => {
  try {
    const format = await inquirer.prompt([
      {
        type: "list",
        name: "format",
        message: "Select the format to import passwords:",
        choices: ["JSON", "CSV", "Cancel"],
      },
    ]);

    if (format.format === "JSON") {
      return await importPasswordsFromJSON();
    } else if (format.format === "CSV") {
      return await importPasswordsFromCSV();
    } else if (format.format === "Cancel") {
      log(yellow("Import cancelled." + NEWLINE));
      return false;
    } else {
      log(red("Invalid format selected." + NEWLINE));
      return false;
    }
  } catch (error) {
    handleError(error);
    return false;
  }
});