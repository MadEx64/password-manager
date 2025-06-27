import fs from "fs";
import { promisify } from "util";

export const renameAsync = promisify(fs.rename);
export const copyFileAsync = promisify(fs.copyFile);
export const readdirAsync = promisify(fs.readdir);
export const readFileAsync = promisify(fs.readFile);
export const writeFileAsync = promisify(fs.writeFile);

export * from "./passwordVault.js";
export * from "./backupOperations/backupOperations.js";
export * from "./backupOperations/backupManager.js";
export * from "./utils.js";
export * from "./checksum.js";
export * from "./integrityCheck.js";
