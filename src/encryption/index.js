import crypto from "crypto";
import { NEWLINE, ERROR_CODES } from "../constants.js";
import { PasswordManagerError } from "../errorHandler.js";
import { red, bold } from "../logger.js";

/**
 * Encryption and cryptographic utilities for the password manager.
 * This module provides all encryption, decryption, and cryptographic functions
 * used throughout the application.
 */

// Encryption/Decryption functions
// ------------------------------------------------------------

/**
 * Derives a persistent key for encryption/decryption from the master password.
 * This ensures the same key is used across application restarts.
 * @param {string} masterPassword - The master password to derive the key from.
 * @returns {Promise<Buffer>} The derived key for encryption/decryption.
 */
export async function generateEncryptionKey(masterPassword) {
  try {
    const { deriveAuthenticationKey, isAuthSystemInitialized } = await import(
      "../auth/secureAuth.js"
    );

    if (await isAuthSystemInitialized()) {
      return await deriveAuthenticationKey(masterPassword);
    }

    // Fallback to the legacy system for backward compatibility during migration
    const fs = await import("fs");
    const { PATHS } = await import("../constants.js");

    if (fs.default.existsSync(PATHS.MASTER_PASSWORD_SALT)) {
      const salt = await fs.promises.readFile(
        PATHS.MASTER_PASSWORD_SALT,
        "utf8"
      );

      // Validate the salt
      if (salt && salt.length >= 64 && /^[a-f0-9]+$/i.test(salt)) {
        // Derive a key from the salt for password encryption
        const key = crypto.pbkdf2Sync(
          masterPassword,
          salt,
          100000,
          32,
          "sha256"
        );
        return key;
      }
    }

    // Fallback: create a basic key from master password with fixed salt
    // This is not ideal but better than a random key that changes every restart
    const fallbackKey = crypto.pbkdf2Sync(
      masterPassword,
      "FALLBACK_ENCRYPTION_SALT_2024",
      100000,
      32,
      "sha256"
    );
    return fallbackKey;
  } catch (error) {
    // Last resort fallback
    const emergencyKey = crypto
      .createHash("sha256")
      .update("EMERGENCY_PASSWORD_ENCRYPTION_KEY_" + masterPassword)
      .digest();
    return emergencyKey;
  }
}

/**
 * Encrypts a password using AES-256-GCM mode with a derived key.
 *
 * @param {string} password - The password to encrypt.
 * @param {Buffer} key - The key to use for encryption.
 * @returns {Promise<string>} The encrypted password.
 */
export async function encryptPassword(password, key) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);

  const encrypted = Buffer.concat([
    cipher.update(password, "utf8"),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();

  const encryptedPayload = Buffer.concat([iv, authTag, encrypted]);

  return encryptedPayload.toString("base64");
}

/**
 * Decrypts a password using AES-256-GCM mode with a derived key.
 *
 * @param {string} password - The encrypted password.
 * @param {Buffer} key - The key to use for decryption.
 * @returns {Promise<string>} The decrypted password.
 */
export async function decryptPassword(password, key) {
  try {
    const encryptedPayload = Buffer.from(password, "base64");
    if (encryptedPayload.length < 12 + 16) {
      throw new PasswordManagerError(
        red("Invalid encrypted password format (too short)"),
        bold(red(ERROR_CODES.INVALID_ENCRYPTION_FORMAT))
      );
    }

    const iv = encryptedPayload.subarray(0, 12);
    const authTag = encryptedPayload.subarray(12, 28);
    const encryptedData = encryptedPayload.subarray(28);

    const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(authTag);

    const decrypted = Buffer.concat([
      decipher.update(encryptedData),
      decipher.final(),
    ]);

    return decrypted.toString("utf8");
  } catch (error) {
    throw new PasswordManagerError(
      red("Failed to decrypt password"),
      bold(red(ERROR_CODES.DECRYPTION_FAILED))
    );
  }
}

/**
 * Encrypts data using AES-256-GCM with a derived key.
 *
 * @param {string} data - The data to encrypt.
 * @param {Buffer} key - The key to use for encryption.
 * @returns {Buffer} The encrypted data with IV and metadata.
 * @throws {PasswordManagerError} If encryption fails.
 */
export function encryptData(data, key) {
  try {
    const iv = crypto.randomBytes(12); // AES-256-GCM uses 12-byte IV
    const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);

    const hmac = crypto.createHmac("sha256", key);
    hmac.update(data);
    const dataHmac = hmac.digest();

    const metadata = {
      version: "1.0",
      encryption: "aes-256-gcm",
      kdf: "pbkdf2",
      iterations: 100000,
      timestamp: Date.now(),
      contentType: "password-store",
    };

    const metadataStr = JSON.stringify(metadata);

    const encryptedData = Buffer.concat([
      cipher.update(Buffer.from(data, "utf8")),
      cipher.final(),
    ]);
    const authTag = cipher.getAuthTag(); // Get the authentication tag for GCM mode

    // Combine all parts: VERSION(1) + IV(12) + AUTH_TAG(16) + HMAC(32) + METADATA_LENGTH(4) + METADATA + ENCRYPTED_DATA
    const versionByte = Buffer.from([1]); // Version 1 of the file format
    const metadataLengthBuf = Buffer.alloc(4);
    metadataLengthBuf.writeUInt32BE(metadataStr.length, 0);

    return Buffer.concat([
      versionByte,
      iv,
      authTag,
      dataHmac,
      metadataLengthBuf,
      Buffer.from(metadataStr, "utf8"),
      encryptedData,
    ]);
  } catch (error) {
    throw new PasswordManagerError(
      red("Failed to encrypt data: " + error.message),
      bold(red(ERROR_CODES.ENCRYPTION_FAILED))
    );
  }
}

/**
 * Decrypts data using AES-256-GCM with a derived key.
 *
 * @param {Buffer} encryptedData - The encrypted data with IV and metadata.
 * @param {Buffer} key - The key to use for decryption.
 * @returns {string} The decrypted data.
 * @throws {PasswordManagerError} If decryption fails.
 */
export function decryptData(encryptedData, key) {
  try {
    // Check minimum length for header: VERSION(1) + IV(12) + AUTH_TAG(16) + HMAC(32) + METADATA_LENGTH(4) = 65 minimum
    if (encryptedData.length < 65) {
      throw new PasswordManagerError(
        red("Invalid encrypted file format (too short)"),
        bold(red(ERROR_CODES.INVALID_ENCRYPTION_FORMAT))
      );
    }

    const version = encryptedData[0];
    if (version !== 1) {
      throw new PasswordManagerError(
        red(`Unsupported file format version: ${version}`),
        bold(red(ERROR_CODES.INVALID_ENCRYPTION_FORMAT))
      );
    }

    const iv = encryptedData.subarray(1, 13); // 12-byte IV for AES-256-GCM
    const authTag = encryptedData.subarray(13, 29); // 16-byte authentication tag
    const storedHmac = encryptedData.subarray(29, 61); // 32-byte HMAC
    const metadataLengthBuf = encryptedData.subarray(61, 65); // 4-byte metadata length
    const metadataLength = metadataLengthBuf.readUInt32BE(0);

    if (encryptedData.length < 65 + metadataLength) {
      throw new PasswordManagerError(
        red("Invalid encrypted file format (metadata size error)"),
        ERROR_CODES.INVALID_ENCRYPTION_FORMAT
      );
    }

    const metadataStr = encryptedData
      .subarray(65, 65 + metadataLength)
      .toString("utf8");
    const encryptedContent = encryptedData.subarray(65 + metadataLength);

    const metadata = JSON.parse(metadataStr);

    const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(authTag); // Set the authentication tag for GCM mode

    try {
      const decrypted = Buffer.concat([
        decipher.update(encryptedContent),
        decipher.final(),
      ]);
      const decryptedData = decrypted.toString("utf8");

      const hmac = crypto.createHmac("sha256", key);
      hmac.update(decryptedData);
      const calculatedHmac = hmac.digest();

      if (!crypto.timingSafeEqual(storedHmac, calculatedHmac)) {
        throw new PasswordManagerError(
          red(
            "Data integrity check failed: the file may be corrupted or tampered with"
          ),
          bold(red(ERROR_CODES.FILE_CORRUPTED))
        );
      }

      return decryptedData;
    } catch (decryptError) {
      throw new PasswordManagerError(
        red("Decryption failed: incorrect master password or corrupted data") +
          NEWLINE +
          decryptError.message,
        bold(red(ERROR_CODES.DECRYPTION_FAILED))
      );
    }
  } catch (error) {
    throw new PasswordManagerError(
      red("Failed to decrypt data: " + NEWLINE + error.message),
      bold(red(ERROR_CODES.DECRYPTION_FAILED))
    );
  }
}

/**
 * Checks if a file is encrypted with our file encryption format.
 *
 * @param {Buffer} data - The file data to check.
 * @returns {boolean} True if the file appears to be encrypted with our format.
 */
export function isFileEncrypted(data) {
  return data.length > 0 && data[0] === 1;
}

// Cryptographic utility functions
// ------------------------------------------------------------

/**
 * Generates a cryptographically secure random integer between min and max (inclusive).
 *
 * @param {number} min - Minimum value (inclusive)
 * @param {number} max - Maximum value (inclusive)
 * @returns {number} Secure random integer
 */
export function getSecureRandomInt(min, max) {
  const range = max - min + 1;
  const bytesNeeded = Math.ceil(Math.log2(range) / 8);
  const maxValidValue = Math.floor(256 ** bytesNeeded / range) * range - 1;

  let randomValue;
  do {
    const randomBytes = crypto.randomBytes(bytesNeeded);
    randomValue = 0;
    for (let i = 0; i < bytesNeeded; i++) {
      randomValue = (randomValue << 8) + randomBytes[i];
    }
  } while (randomValue > maxValidValue);

  return min + (randomValue % range);
}

/**
 * Gets a cryptographically secure random character from a given character set.
 *
 * @param {string} charset - The character set to choose from
 * @returns {string} A random character from the set
 *
 * @example
 * const char = getSecureRandomChar("abcdefghijklmnopqrstuvwxyz");
 * console.log(char); // "a" (random character from the set)
 */
export function getSecureRandomChar(charset) {
  const randomIndex = getSecureRandomInt(0, charset.length - 1);
  return charset[randomIndex];
}

/**
 * Shuffles an array in place using the Fisher-Yates algorithm with cryptographically secure randomness.
 *
 * @param {Array} array - The array to shuffle
 *
 * @example
 * const array = ["a", "b", "c", "d", "e"];
 * secureShuffleArray(array);
 * console.log(array); // ["c", "b", "a", "e", "d"] (shuffled array)
 */
export function secureShuffleArray(array) {
  for (let i = array.length - 1; i > 0; i--) {
    const j = getSecureRandomInt(0, i);
    [array[i], array[j]] = [array[j], array[i]];
  }
}

/**
 * Creates a SHA-256 hash of the given data.
 * @param {string} data - The data to hash.
 * @returns {string} The SHA-256 hash as a hex string.
 */
export function createHash(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

/**
 * Creates a SHA-256 hash of the given data and returns it as a Buffer.
 * @param {string} data - The data to hash.
 * @returns {Buffer} The SHA-256 hash as a Buffer.
 */
export function createHashBuffer(data) {
  return crypto.createHash("sha256").update(data).digest();
}

/**
 * Creates an HMAC-SHA256 hash of the given data with the provided key.
 * @param {string|Buffer} key - The key to use for HMAC.
 * @param {string} data - The data to hash.
 * @returns {string} The HMAC-SHA256 hash as a hex string.
 */
export function createHmac(key, data) {
  return crypto.createHmac("sha256", key).update(data).digest("hex");
}

/**
 * Performs a timing-safe comparison of two values.
 * @param {Buffer|string} a - First value to compare.
 * @param {Buffer|string} b - Second value to compare.
 * @returns {boolean} True if the values are equal.
 */
export function timingSafeEqual(a, b) {
  const bufferA = Buffer.isBuffer(a) ? a : Buffer.from(a, 'hex');
  const bufferB = Buffer.isBuffer(b) ? b : Buffer.from(b, 'hex');
  
  if (bufferA.length !== bufferB.length) {
    return false;
  }
  
  return crypto.timingSafeEqual(bufferA, bufferB);
}

/**
 * Generates cryptographically secure random bytes.
 * @param {number} size - The number of bytes to generate.
 * @returns {Buffer} The random bytes.
 */
export function generateRandomBytes(size) {
  return crypto.randomBytes(size);
}

/**
 * Derives a key using PBKDF2 with the specified parameters.
 * @param {string|Buffer} password - The password to derive from.
 * @param {string|Buffer} salt - The salt to use.
 * @param {number} iterations - The number of iterations.
 * @param {number} keyLength - The desired key length in bytes.
 * @param {string} digest - The digest algorithm to use.
 * @returns {Buffer} The derived key.
 */
export function deriveKeyPBKDF2(password, salt, iterations, keyLength, digest = 'sha256') {
  return crypto.pbkdf2Sync(password, salt, iterations, keyLength, digest);
}

/**
 * Encrypts data using AES-256-CBC encryption.
 * @param {string} data - The data to encrypt.
 * @param {Buffer} key - The encryption key.
 * @param {Buffer} iv - The initialization vector.
 * @returns {string} The encrypted data as hex string.
 */
export function encryptAESCBC(data, key, iv) {
  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  let encrypted = cipher.update(data, "utf8", "hex");
  encrypted += cipher.final("hex");
  return encrypted;
}

/**
 * Decrypts data using AES-256-CBC encryption.
 * @param {string} encryptedData - The encrypted data as hex string.
 * @param {Buffer} key - The decryption key.
 * @param {Buffer} iv - The initialization vector.
 * @returns {string} The decrypted data.
 */
export function decryptAESCBC(encryptedData, key, iv) {
  const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
  let decrypted = decipher.update(encryptedData, "hex", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
} 