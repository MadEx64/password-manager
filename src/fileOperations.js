import fs from "fs";
import { promisify } from "util";
import { join } from "path";
import { PATHS, ERROR_CODES, FILE_LOCK } from "./constants.js";
import { PasswordManagerError, handleError } from "./errorHandler.js";
import crypto from "crypto";
import chalk from "chalk";
import { encryptFile, decryptFile, isFileEncrypted } from "./utils.js";

const readFileAsync = promisify(fs.readFile);
const writeFileAsync = promisify(fs.writeFile);
const renameAsync = promisify(fs.rename);
const copyFileAsync = promisify(fs.copyFile);
const readdirAsync = promisify(fs.readdir);

const BASE_DIR = process.cwd();
const BACKUP_DIR = join(BASE_DIR, "backups");
const NEWLINE = "\n";
const FILE_LOCK_TIMEOUT = 30000;
const CHARSET = 'utf-8';

// Flag to control file encryption
export const FILE_ENCRYPTION_ENABLED = true;

/**
 * Creates the passwords file for the first time use
 * @returns {Promise<boolean>} True if the passwords file was created successfully, false if it already exists
 * @throws {PasswordManagerError} If the passwords file is not writable
 */
export const createPasswordsFile = async () => {
  try {
    if (!fs.existsSync(PATHS.PASSWORDS)) {
      await writeFileAsync(PATHS.PASSWORDS, "");
      return true;
    }
    return false;
  } catch (error) {
    handleError(error);
    throw new PasswordManagerError(
      "Failed to create passwords file",
      ERROR_CODES.PERMISSION_DENIED
    );
  }
};

/**
 * Parses the lines from the passwords file
 * @param {string} lines - The lines from the passwords file (e.g. 'TestApp - test@example.com - encryptedPass')
 * @returns {string[]} An array of parsed lines
 */
function parseLines(lines) {
  if (lines.trim() === "") return [];
  return lines.split(/\r?\n/).filter((line) => line.trim() !== "");
}

/**
 * Reads the encrypted lines from the passwords file
 * @param {Buffer} fileBuffer - The buffer of the passwords file
 * @returns {Promise<string[]>} An array of decrypted lines
 * @throws {PasswordManagerError} If the passwords file is not found or decryption fails
 */
async function readEncryptedLines(fileBuffer) {
  const encryptedMasterPassword = await readMasterPasswordRaw();
  if (!encryptedMasterPassword) {
    throw new PasswordManagerError(
      "Master password not found for file decryption",
      ERROR_CODES.AUTHENTICATION_FAILED
    );
  }

  try {
    const decryptedData = decryptFile(fileBuffer, encryptedMasterPassword);
    return parseLines(decryptedData);
  } catch (decryptError) {
    // Attempt to restore from backup if decryption fails
    return await tryRestoreFromBackup(
      encryptedMasterPassword,
      decryptError
    );
  }
}

/**
 * Attempts to restore the passwords file from a backup if decryption fails
 * @param {string} encryptedMasterPassword - The encrypted master password
 * @param {Error} decryptError - The error that occurred during decryption
 * @returns {Promise<string[]>} An array of decrypted lines
 * @throws {PasswordManagerError} If the backup decryption fails
 */
async function tryRestoreFromBackup(encryptedMasterPassword, decryptError) {
  if (fs.existsSync(PATHS.PASSWORDS_BACKUP)) {
    console.log(chalk.yellow("Primary password file corrupted, attempting to restore from backup..."));
    const backupBuffer = await fs.promises.readFile(PATHS.PASSWORDS_BACKUP);

    try {
      const decryptedBackup = decryptFile(backupBuffer, encryptedMasterPassword);
      await fs.promises.writeFile(PATHS.PASSWORDS, backupBuffer);
      console.log(chalk.green("Successfully restored from backup!"));
      return parseLines(decryptedBackup);
    } catch (backupDecryptError) {
      throw new PasswordManagerError(
        "Failed to decrypt password file and backup: " + backupDecryptError.message,
        ERROR_CODES.DECRYPTION_FAILED
      );
    }
  } else {
    throw new PasswordManagerError(
      "Failed to decrypt password file: " + decryptError.message,
      ERROR_CODES.DECRYPTION_FAILED
    );
  }
}

/**
 * Reads the lines from the passwords file
 * @returns {Promise<string[]>} Lines from the passwords file
 * @throws {PasswordManagerError} If the passwords file is not found
 */
export const readLines = async () => {
   try {
    if (!fs.existsSync(PATHS.PASSWORDS)) {
      return [];
    }
    // Read the file as a buffer first to detect if it's encrypted
    const fileBuffer = await fs.promises.readFile(PATHS.PASSWORDS);

    if (FILE_ENCRYPTION_ENABLED && isFileEncrypted(fileBuffer)) {
      return await readEncryptedLines(fileBuffer);
    } else {
      // Traditional plaintext file format
      const data = fileBuffer.toString(CHARSET);
      return parseLines(data);
    }
  }
  catch (error) {
    if (error instanceof PasswordManagerError) {
      throw error;
    }
    handleError(error);
    throw new PasswordManagerError(
      "Failed to read lines from passwords file: " + error.message,
      ERROR_CODES.PERMISSION_DENIED
    );
  }
};

/**
 * Writes a line to the passwords file (new line, updated line, or deleted line)
 * @param {string} line - The line (e.g. 'TestApp - test@example.com - encryptedPass')
 * @returns {Promise<void>}
 * @throws {PasswordManagerError} If the passwords file is not writable
 */
export const writeLine = async (line) => {
  try {
    // Make backup of existing file if it exists
    if (fs.existsSync(PATHS.PASSWORDS)) {
      await renameAsync(PATHS.PASSWORDS, PATHS.PASSWORDS_BACKUP);
    }

    await writeFileAsync(PATHS.PASSWORDS, line + NEWLINE);
  } catch (error) {
    handleError(error);
    throw new PasswordManagerError(
      "Failed to write line to passwords file",
      ERROR_CODES.PERMISSION_DENIED
    );
  }
};

/**
 * Writes multiple lines to the passwords file
 * @param {string[]} lines - The lines to write to the passwords file
 * @returns {Promise<void>}
 */
export const writeLines = async (lines) => {
  try {
    // Make backup of existing file if it exists
    if (fs.existsSync(PATHS.PASSWORDS)) {
      await renameAsync(PATHS.PASSWORDS, PATHS.PASSWORDS_BACKUP);
    }

    // Create the content string with newlines
    const content = lines.join(NEWLINE) + NEWLINE;
    
    if (FILE_ENCRYPTION_ENABLED) {
      // Get master password for encryption
      const encryptedMasterPassword = await readMasterPasswordRaw();
      if (!encryptedMasterPassword) {
        throw new PasswordManagerError(
          "Master password not found for file encryption",
          ERROR_CODES.AUTHENTICATION_FAILED
        );
      }
      
      // Encrypt the entire file content
      const encryptedData = encryptFile(content, encryptedMasterPassword);
      await writeFileAsync(PATHS.PASSWORDS, encryptedData);
    } else {
      // Write the plaintext file
      await writeFileAsync(PATHS.PASSWORDS, content);
    }
  } catch (error) {
    if (error instanceof PasswordManagerError) {
      throw error;
    }
    handleError(error);
    throw new PasswordManagerError(
      "Failed to write lines to passwords file: " + error.message,
      ERROR_CODES.PERMISSION_DENIED
    );
  }
};

/**
 * Rearranges the lines of the passwords file by application name (sort apps together)
 * @param {string[]} lines - The lines to rearrange
 * @returns {Promise<string[]>} The rearranged lines
 */
export const sortLines = (lines) => {
  return lines.slice().sort((a, b) => {
    const appA = a.split(" - ")[0];
    const appB = b.split(" - ")[0];
    return appA.localeCompare(appB);
  });
};

/**
 * Reads the master password from the master password file
 * @returns {Promise<string>} The master password
 * @returns {null} If the master password file is not found
 * @throws {PasswordManagerError} If the master password file is not found or is corrupted
 */
export const readMasterPassword = async () => {
  try {
    if (!(await acquireLock())) {
      throw new PasswordManagerError(
        "Could not acquire file lock",
        ERROR_CODES.PERMISSION_DENIED
      );
    }

    // Check if the master password file exists
    if (!fs.existsSync(PATHS.MASTER_PASSWORD)) {
      await releaseLock();
      // If the master password file doesn't exist, create it
      await writeMasterPassword("");
      await releaseLock();
      return "";
    }

    // Read the master password file as buffer to check if it's encrypted
    const fileBuffer = await fs.promises.readFile(PATHS.MASTER_PASSWORD);
    let data;
    
    // Check if the file is encrypted with our file encryption format
    if (FILE_ENCRYPTION_ENABLED && isFileEncrypted(fileBuffer)) {
      // We need a secret recovery key for the master password
      // This is a hash of system-specific identifiers that should be relatively stable
      const recoveryKey = await generateRecoveryKey();
      
      try {
        data = decryptFile(fileBuffer, recoveryKey);
      } catch (decryptError) {
        // Try to restore from backup if decryption fails
        if (fs.existsSync(PATHS.MASTER_PASSWORD_BACKUP)) {
          console.log(chalk.yellow("Primary master password file corrupted, attempting to restore from backup..."));
          const backupBuffer = await fs.promises.readFile(PATHS.MASTER_PASSWORD_BACKUP);
          
          try {
            data = decryptFile(backupBuffer, recoveryKey);
            // If successful, restore the backup to the main file
            await fs.promises.writeFile(PATHS.MASTER_PASSWORD, backupBuffer);
            console.log(chalk.green("Successfully restored master password from backup!"));
          } catch (backupDecryptError) {
            await releaseLock();
            throw new PasswordManagerError(
              "Failed to decrypt master password file and backup",
              ERROR_CODES.DECRYPTION_FAILED
            );
          }
        } else {
          await releaseLock();
          throw new PasswordManagerError(
            "Failed to decrypt master password file",
            ERROR_CODES.DECRYPTION_FAILED
          );
        }
      }
    } else {
      // Traditional plaintext file format
      data = fileBuffer.toString(CHARSET);
    }
    
    // Check if data contains a newline (indicating new format with checksum)
    if (data.includes(NEWLINE)) {
      const [password, checksum] = data.split(NEWLINE);

      if (!verifyChecksum(password, checksum)) {
        // Try to restore from backup
        if (fs.existsSync(PATHS.MASTER_PASSWORD_BACKUP)) {
          const backupData = await readFileAsync(
            PATHS.MASTER_PASSWORD_BACKUP,
            CHARSET
          );
          const [backupPassword, backupChecksum] = backupData.split(NEWLINE);

          if (verifyChecksum(backupPassword, backupChecksum)) {
            await writeFileAsync(PATHS.MASTER_PASSWORD, backupData);
            await releaseLock();
            return backupPassword;
          }
        }

        await releaseLock();
        throw new PasswordManagerError(
          "Master password file is corrupted",
          ERROR_CODES.FILE_NOT_FOUND
        );
      }

      await releaseLock();
      return password;
    } else {
      // Old format - just the password without checksum
      // Upgrade to new format
      const password = data.trim();
      await writeMasterPassword(password);
      await releaseLock();
      return password;
    }
  } catch (error) {
    await releaseLock();
    if (error instanceof PasswordManagerError) {
      throw error;
    }
    handleError(error);
    throw new PasswordManagerError(
      "Failed to read master password file",
      ERROR_CODES.FILE_NOT_FOUND
    );
  }
};

/**
 * Writes the master password to the master password file
 * @param {string} password - The master password
 * @returns {Promise<void>}
 */
export const writeMasterPassword = async (password) => {
  try {
    if (!(await acquireLock())) {
      throw new PasswordManagerError(
        "Could not acquire file lock",
        ERROR_CODES.PERMISSION_DENIED
      );
    }

    // Create backup of existing file if it exists
    if (fs.existsSync(PATHS.MASTER_PASSWORD)) {
      await renameAsync(PATHS.MASTER_PASSWORD, PATHS.MASTER_PASSWORD_BACKUP);
    }

    // Generate the content with checksum
    const checksum = createChecksum(password);
    const content = `${password}${NEWLINE}${checksum}`;
    
    if (FILE_ENCRYPTION_ENABLED) {
      // Get the recovery key for encryption
      const recoveryKey = await generateRecoveryKey();
      
      // Encrypt the master password file
      const encryptedData = encryptFile(content, recoveryKey);
      await writeFileAsync(PATHS.MASTER_PASSWORD, encryptedData);
    } else {
      // Write plaintext file
      await writeFileAsync(PATHS.MASTER_PASSWORD, content);
    }

    await releaseLock();
  } catch (error) {
    await releaseLock();
    if (error instanceof PasswordManagerError) {
      throw error;
    }
    handleError(error);
    throw new PasswordManagerError(
      "Failed to write master password",
      ERROR_CODES.PERMISSION_DENIED
    );
  }
};

/**
 * Generates a recovery key based on machine-specific identifiers
 * Used for master password file encryption/decryption
 * @returns {Promise<string>} The recovery key
 */
async function generateRecoveryKey() {
  try {
    // Create a recovery key based on various system identifiers
    // This should be relatively stable across reboots but unique to this machine
    const os = await import('os');
    
    // Combine system-specific values that should be stable
    const systemInfo = [
      os.hostname(),
      os.userInfo().username,
      os.platform(),
      os.arch(),
      os.cpus()[0]?.model,
      os.homedir(),
      // Add more stable identifiers if needed
    ].join('|');
    
    // Create a hash of the system info
    const hash = crypto.createHash('sha256').update(systemInfo).digest('hex');
    
    // Add a salt from a special recovery file, or create it if it doesn't exist
    const RECOVERY_SALT_PATH = join(BASE_DIR, '.recovery_salt');
    let salt;
    
    if (fs.existsSync(RECOVERY_SALT_PATH)) {
      salt = await readFileAsync(RECOVERY_SALT_PATH, 'utf8');
    } else {
      // Create a new salt and save it
      salt = crypto.randomBytes(16).toString('hex');
      await writeFileAsync(RECOVERY_SALT_PATH, salt);
      
      // Make a backup of the salt file
      const RECOVERY_SALT_BACKUP = join(BASE_DIR, '.recovery_salt.bak');
      await writeFileAsync(RECOVERY_SALT_BACKUP, salt);
      
      console.log(chalk.yellow("Created new recovery key. Please back up the .recovery_salt file for emergency recovery."));
    }
    
    // Combine hash and salt to create the final recovery key
    return crypto.createHash('sha256').update(hash + salt).digest('hex');
  } catch (error) {
    // Fallback to a simpler method if something fails
    console.error("Error generating recovery key:", error);
    return "fallback_recovery_key_please_update";
  }
}

/**
 * Gets the application names from the passwords file
 * @param {string[]} lines - The lines from the passwords file (e.g. ['TestApp - test@example.com - encryptedPass'])
 * @returns {string[]} The application names (e.g. ['TestApp'])
 */
export const getAppNames = (lines) => {
  const appNames = [];
  lines.forEach((line) => {
    const [app] = line.split(" - ");
    // If app appears more than once, only add it once
    if (!appNames.includes(app)) {
      appNames.push(app);
    }
  });
  return appNames;
};

/**
 * Acquires a file lock
 * @param {number} maxRetries - Maximum number of retries (default: FILE_LOCK.MAX_RETRIES)
 * @returns {Promise<boolean>} True if lock was acquired, false otherwise
 * @description This function acquires a file lock to prevent multiple instances of the program from accessing the same file at the same time.
 */
const acquireLock = async (maxRetries = FILE_LOCK.MAX_RETRIES) => {
  let retries = 0;

  // First check if lock is stale and clear it if needed
  try {
    if (fs.existsSync(FILE_LOCK.LOCK_FILE)) {
      const lockContent = await readFileAsync(FILE_LOCK.LOCK_FILE, CHARSET);
      const lockTime = parseInt(lockContent, 10) || 0;

      // If the lock is older than the defined timeout, consider it stale
      if (Date.now() - lockTime > FILE_LOCK_TIMEOUT) {
        console.log("Stale lock file detected, clearing...");
        try {
          fs.unlinkSync(FILE_LOCK.LOCK_FILE);
          console.log("Cleared stale lock file");
        } catch (e) {
          console.error("Failed to clear stale lock:", e.message);
        }
      }
    }
  } catch (e) {
    // If we can't read the lock file, it might be corrupted
    try {
      fs.unlinkSync(FILE_LOCK.LOCK_FILE);
    } catch (e2) {
      // Ignore errors when clearing corrupt lock
    }
  }

  while (retries < maxRetries) {
    try {
      if (!fs.existsSync(FILE_LOCK.LOCK_FILE)) {
        const timestamp = Date.now().toString();
        await writeFileAsync(FILE_LOCK.LOCK_FILE, timestamp);

        // Verify the lock was created successfully
        const lockContent = await readFileAsync(FILE_LOCK.LOCK_FILE, CHARSET);
        if (lockContent === timestamp) {
          return true;
        }
      }

      await new Promise((resolve) =>
        setTimeout(resolve, FILE_LOCK.LOCK_TIMEOUT)
      );
      retries++;
    } catch (error) {
      console.error("Lock acquisition error:", error.message);
      retries++;
    }
  }
  return false;
};

/**
 * Releases a file lock
 * @returns {Promise<void>}
 * @description This function releases a file lock to allow other instances of the program to access the file.
 */
const releaseLock = async () => {
  try {
    if (fs.existsSync(FILE_LOCK.LOCK_FILE)) {
      // Delete the lock file completely
      fs.unlinkSync(FILE_LOCK.LOCK_FILE);
    }
  } catch (error) {
    // Ignore errors when releasing lock
    console.error("Error releasing lock:", error);
  }
};

/**
 * Creates a checksum for the given data
 * @param {string} data - The data to create a checksum for
 * @returns {string} The checksum
 * @description This function creates a checksum for the given data using the SHA-256 algorithm.
 */
const createChecksum = (data) => {
  return crypto.createHash("sha256").update(data).digest("hex");
};

/**
 * Verifies the checksum of the given data
 * @param {string} data - The data to verify
 * @param {string} checksum - The expected checksum
 * @returns {boolean} True if the checksum is valid, false otherwise
 * @description This function verifies the checksum of the given data using the SHA-256 algorithm.
 */
const verifyChecksum = (data, checksum) => {
  return createChecksum(data) === checksum;
};

/**
 * Creates a backup of the passwords file
 * @param {boolean} encrypt - Whether to encrypt the backup (default: true)
 * @param {string} masterPasswordOverride - Optional master password to avoid lock conflicts
 * @returns {Promise<string|boolean>} The path to the backup file if successful, false otherwise
 * @throws {PasswordManagerError} If the backup fails
 * @description This function creates a backup of the passwords file in the backups directory.
 * The backup is encrypted using the same encryption as the passwords file.
 * Returns the path to the backup file if successful.
 */
export const createBackup = async (
  encrypt = true,
  masterPasswordOverride = null
) => {
  let lockAcquired = false;

  try {
    if (!fs.existsSync(BACKUP_DIR)) {
      fs.mkdirSync(BACKUP_DIR, { recursive: true });
    }

    // Timestamp for the backup filename
    const timestamp = new Date()
      .toISOString()
      .replace(/:/g, "-")
      .replace(/\./g, "-");
    const backupFilename = `passwords_backup_${timestamp}.bak`;
    const backupPath = join(BACKUP_DIR, backupFilename);

    if (!fs.existsSync(PATHS.PASSWORDS)) {
      return false;
    }

    // Only acquire a lock if we're not provided a master password override
    if (!masterPasswordOverride) {
      // Acquire file lock with increased timeout for backup operation
      if (!(await acquireLock(10))) {
        // 10 retries instead of default 3
        throw new PasswordManagerError(
          "Could not acquire file lock for backup",
          ERROR_CODES.PERMISSION_DENIED
        );
      }
      lockAcquired = true;
    }

    const data = await readFileAsync(PATHS.PASSWORDS, CHARSET);

    if (encrypt) {
      let masterPassword;

      // Use provided master password or read it (avoiding lock conflicts)
      if (masterPasswordOverride) {
        masterPassword = masterPasswordOverride;
      } else {
        try {
          // Read master password file directly without locking
          if (fs.existsSync(PATHS.MASTER_PASSWORD)) {
            const passwordData = await readFileAsync(
              PATHS.MASTER_PASSWORD,
              CHARSET
            );
            // Extract just the password part (before newline)
            masterPassword = passwordData.split(NEWLINE)[0];
          } else {
            masterPassword = "";
          }
        } catch (mpError) {
          console.error("Error reading master password for backup:", mpError);
          masterPassword = "";
        }
      }

      if (!masterPassword) {
        if (lockAcquired) await releaseLock();
        throw new PasswordManagerError(
          "Master password not found for backup encryption",
          ERROR_CODES.AUTHENTICATION_FAILED
        );
      }

      const encryptionKey = crypto
        .createHash("sha256")
        .update(masterPassword)
        .digest();

      // Add a metadata header to know this is an encrypted backup
      // Include timestamp and checksum of original data for integrity checking
      const originalChecksum = createChecksum(data);
      const metadata = JSON.stringify({
        timestamp: Date.now(),
        checksum: originalChecksum,
        encrypted: true,
        version: "1.0",
      });

      // Encrypt the metadata and data
      const iv = crypto.randomBytes(16);
      const cipher = crypto.createCipheriv("aes-256-cbc", encryptionKey, iv);

      let encryptedData = cipher.update(
        Buffer.from(metadata + NEWLINE + data, CHARSET)
      );
      encryptedData = Buffer.concat([encryptedData, cipher.final()]);

      const finalData = Buffer.concat([iv, encryptedData]);

      await writeFileAsync(backupPath, finalData);
    } else {
      // Simply copy the file if no encryption is needed
      await copyFileAsync(PATHS.PASSWORDS, backupPath);
    }

    if (lockAcquired) await releaseLock();

    return backupPath;
  } catch (error) {
    if (lockAcquired) await releaseLock();

    if (error instanceof PasswordManagerError) {
      throw error;
    }

    throw new PasswordManagerError(
      "Failed to create backup: " + error.message,
      ERROR_CODES.PERMISSION_DENIED
    );
  }
};

/**
 * Restores a backup file
 * @param {string} backupPath - The path to the backup file
 * @param {string} masterPasswordOverride - Optional master password to avoid lock conflicts
 * @returns {Promise<boolean>} True if the restore was successful, false otherwise
 * @throws {PasswordManagerError} If the restore fails
 * @description This function restores a backup file to the passwords file.
 * If the backup is encrypted, it decrypts it using the master password.
 */
export const restoreBackup = async (
  backupPath,
  masterPasswordOverride = null
) => {
  let lockAcquired = false;

  try {
    if (!fs.existsSync(backupPath)) {
      throw new PasswordManagerError(
        "Backup file not found",
        ERROR_CODES.FILE_NOT_FOUND
      );
    }

    const backupData = await readFileAsync(backupPath);

    // Try to detect if the backup is encrypted
    // Encrypted backups will have the IV at the beginning (16 bytes)
    const isEncrypted =
      backupData.length > 16 &&
      !backupData.toString(CHARSET, 0, 5).match(/^[A-Za-z]/);

    let dataToRestore;

    if (isEncrypted) {
      let masterPassword;

      // Use provided master password or read it (avoiding lock conflicts)
      if (masterPasswordOverride) {
        masterPassword = masterPasswordOverride;
      } else {
        try {
          if (fs.existsSync(PATHS.MASTER_PASSWORD)) {
            const passwordData = await readFileAsync(
              PATHS.MASTER_PASSWORD,
              CHARSET
            );
            masterPassword = passwordData.split("\n")[0];
          } else {
            masterPassword = "";
          }
        } catch (mpError) {
          console.error("Error reading master password for restore:", mpError);
          masterPassword = "";
        }
      }

      if (!masterPassword) {
        throw new PasswordManagerError(
          "Master password not found for backup decryption",
          ERROR_CODES.AUTHENTICATION_FAILED
        );
      }

      const decryptionKey = crypto
        .createHash("sha256")
        .update(masterPassword)
        .digest();

      // Buffer.slice is deprecated, using subarray instead 
      // const iv = backupData.slice(0, 16);
      // const encryptedData = backupData.slice(16);
      const iv = backupData.subarray(0, 16);
      const encryptedData = backupData.subarray(16);

      const decipher = crypto.createDecipheriv(
        "aes-256-cbc",
        decryptionKey,
        iv
      );

      try {
        let decryptedData = decipher.update(encryptedData);
        decryptedData = Buffer.concat([decryptedData, decipher.final()]);

        const decryptedStr = decryptedData.toString(CHARSET);
        const [metadataStr, ...dataParts] = decryptedStr.split(NEWLINE);

        const metadata = JSON.parse(metadataStr);

        if (!metadata.encrypted || !metadata.checksum) {
          throw new Error("Invalid backup metadata");
        }

        dataToRestore = dataParts.join(NEWLINE);

        const dataChecksum = createChecksum(dataToRestore);
        if (dataChecksum !== metadata.checksum) {
          throw new Error("Backup data integrity check failed");
        }
      } catch (decryptError) {
        throw new PasswordManagerError(
          "Failed to decrypt backup: " + decryptError.message,
          ERROR_CODES.DECRYPTION_FAILED
        );
      }
    } else {
      // Not encrypted or old format, just use as-is
      dataToRestore = backupData.toString(CHARSET);
    }

    // Only acquire a lock now that we have done the expensive decryption work
    if (!(await acquireLock(10))) {
      throw new PasswordManagerError(
        "Could not acquire file lock for restore",
        ERROR_CODES.PERMISSION_DENIED
      );
    }
    lockAcquired = true;

    if (fs.existsSync(PATHS.PASSWORDS)) {
      await renameAsync(PATHS.PASSWORDS, PATHS.PASSWORDS_BACKUP);
    }

    await writeFileAsync(PATHS.PASSWORDS, dataToRestore);

    await releaseLock();
    lockAcquired = false;

    console.log(chalk.green("✓ Backup restored successfully!" + NEWLINE));
    return true;
  } catch (error) {
    if (lockAcquired) {
      await releaseLock();
    }

    if (error instanceof PasswordManagerError) {
      throw error;
    }

    throw new PasswordManagerError(
      "Failed to restore backup: " + error.message,
      ERROR_CODES.PERMISSION_DENIED
    );
  }
};

/**
 * Lists all available backups
 * @returns {Promise<string[]>} Array of backup file paths
 * @description This function lists all available backups in the backup directory.
 */
export const listBackups = async () => {
  try {
    if (!fs.existsSync(BACKUP_DIR)) {
      fs.mkdirSync(BACKUP_DIR, { recursive: true });
      return [];
    }

    const files = await readdirAsync(BACKUP_DIR);

    // Filter for backup files and return full paths
    return files
      .filter((file) => file.endsWith(".bak"))
      .map((file) => join(BACKUP_DIR, file))
      .sort((a, b) => {
        // Sort by modification time (most recent first)
        const statA = fs.statSync(a);
        const statB = fs.statSync(b);
        return statB.mtime.getTime() - statA.mtime.getTime();
      });
  } catch (error) {
    console.error("Error listing backups:", error);
    return [];
  }
};

/**
 * Deletes a backup file
 * @param {string} backupPath - The path to the backup file to delete
 * @returns {Promise<boolean>} True if the backup was deleted successfully, false otherwise
 * @throws {PasswordManagerError} If the backup deletion fails
 * @description This function deletes a backup file from the backups directory.
 */
export const deleteBackup = async (backupPath) => {
  try {
    if (!fs.existsSync(backupPath)) {
      throw new PasswordManagerError(
        "Backup file not found",
        ERROR_CODES.FILE_NOT_FOUND
      );
    }

    // Verify that the file is within the backups directory by checking its absolute path
    const absoluteBackupPath = fs.realpathSync(backupPath);
    const absoluteBackupDir = fs.realpathSync(BACKUP_DIR);
    
    if (!absoluteBackupPath.startsWith(absoluteBackupDir)) {
      throw new PasswordManagerError(
        "Invalid backup path - not in backups directory",
        ERROR_CODES.PERMISSION_DENIED
      );
    }
    
    fs.unlinkSync(backupPath);
    console.log(chalk.green(`✓ Backup deleted successfully!` + NEWLINE));
    return true;
  } catch (error) {
    // Handle errors
    if (error instanceof PasswordManagerError) {
      throw error;
    }
    
    throw new PasswordManagerError(
      "Failed to delete backup: " + error.message,
      ERROR_CODES.PERMISSION_DENIED
    );
  }
};

/**
 * Reads the raw master password from file (without lock)
 * Used internally for file encryption/decryption
 * @returns {Promise<string>} The master password or empty string
 */
async function readMasterPasswordRaw() {
  try {
    if (!fs.existsSync(PATHS.MASTER_PASSWORD)) {
      return "";
    }
    
    const data = await readFileAsync(PATHS.MASTER_PASSWORD, CHARSET);
    
    // Check if data contains a newline (indicating new format with checksum)
    if (data.includes(NEWLINE)) {
      const [password, checksum] = data.split(NEWLINE);
      
      if (!verifyChecksum(password, checksum)) {
        // Try to restore from backup
        if (fs.existsSync(PATHS.MASTER_PASSWORD_BACKUP)) {
          const backupData = await readFileAsync(
            PATHS.MASTER_PASSWORD_BACKUP,
            CHARSET
          );
          const [backupPassword, backupChecksum] = backupData.split(NEWLINE);
          
          if (verifyChecksum(backupPassword, backupChecksum)) {
            await writeFileAsync(PATHS.MASTER_PASSWORD, backupData);
            return backupPassword;
          }
        }
        
        throw new PasswordManagerError(
          "Master password file is corrupted",
          ERROR_CODES.FILE_NOT_FOUND
        );
      }
      
      return password;
    } else {
      // Old format - just the password without checksum
      return data.trim();
    }
  } catch (error) {
    console.error("Error reading master password (raw)", error);
    return "";
  }
}
