import aesjs from "aes-js";
import crypto from "crypto";
import { KEY, NEWLINE, ERROR_CODES } from "./constants.js";
import { PasswordManagerError } from "./errorHandler.js";
import { red, bold } from "./logger.js";

/**
 * Generates a cryptographically secure random password with specified or random length (8-32 characters),
 * guaranteed to contain at least one lowercase letter, one uppercase letter, one number, and one special character.
 *
 * @param {number} [userLength=0] - Optional. The desired password length (8-32). If 0 or invalid, uses random length between 12-16.
 * @returns {string} The generated password.
 * 
 * @example
 * const password = generateRandomPassword();
 * console.log(password); // "aB3!kL9@mP1$" (random length 12-16)
 * 
 * const password = generateRandomPassword(20);
 * console.log(password); // "aB3!kL9@mP1$nR5%qT8&" (exactly 20 characters)
 */
export function generateRandomPassword(userLength = 0) {
  const charSets = {
    lowercase: "abcdefghijklmnopqrstuvwxyz",
    uppercase: "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 
    numbers: "0123456789",
    special: "-.!@#$%^&*_+=/?",
  };

  const minLength = 8;
  const maxLength = 32;
  const defaultMinLength = 12;
  const defaultMaxLength = 16;
  
  let length;
  if (userLength >= minLength && userLength <= maxLength) {
    length = Math.floor(userLength);
  } else {
    length = getSecureRandomInt(defaultMinLength, defaultMaxLength);
  }

  if (length < 4) {
    throw new Error("Password length must be at least 4 characters to include all required character types");
  }

  const allChars = Object.values(charSets).join("");
  
  const requiredChars = [
    getSecureRandomChar(charSets.lowercase),
    getSecureRandomChar(charSets.uppercase),
    getSecureRandomChar(charSets.numbers),
    getSecureRandomChar(charSets.special),
  ];

  const remainingLength = length - requiredChars.length;
  const randomChars = [];
  
  for (let i = 0; i < remainingLength; i++) {
    randomChars.push(getSecureRandomChar(allChars));
  }

  const allPasswordChars = [...requiredChars, ...randomChars];
  secureShuffleArray(allPasswordChars);

  return allPasswordChars.join("");
}

/**
 * Generates a cryptographically secure random integer between min and max (inclusive).
 * 
 * @param {number} min - Minimum value (inclusive)
 * @param {number} max - Maximum value (inclusive) 
 * @returns {number} Secure random integer
 */
function getSecureRandomInt(min, max) {
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
function getSecureRandomChar(charset) {
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
function secureShuffleArray(array) {
  for (let i = array.length - 1; i > 0; i--) {
    const j = getSecureRandomInt(0, i);
    [array[i], array[j]] = [array[j], array[i]];
  }
}

// Encryption/Decryption functions
// ------------------------------------------------------------

/**
 * Encrypts a password using AES-256-CTR mode with a derived key.
 *
 * @param {string} password - The password to encrypt.
 * @returns {string} The encrypted password.
 */
export function encryptPassword(password) {
  const textBytes = aesjs.utils.utf8.toBytes(password);
  const aesCtr = new aesjs.ModeOfOperation.ctr(KEY, new aesjs.Counter(5));
  const encryptedBytes = aesCtr.encrypt(textBytes);
  const encryptedHex = aesjs.utils.hex.fromBytes(encryptedBytes);

  return encryptedHex;
}

/**
 * Decrypts a password using AES-256-CTR mode with a derived key.
 *
 * @param {string} password - The encrypted password.
 * @returns {string} The decrypted password.
 */
export function decryptPassword(password) {
  try {
    const encryptedBytes = aesjs.utils.hex.toBytes(password);
    const aesCtr = new aesjs.ModeOfOperation.ctr(KEY, new aesjs.Counter(5));
    const decryptedBytes = aesCtr.decrypt(encryptedBytes);
    const decryptedText = aesjs.utils.utf8.fromBytes(decryptedBytes);

    return decryptedText;
  } catch (error) {
    throw new PasswordManagerError(
      red("Failed to decrypt password"),
      bold(red(ERROR_CODES.DECRYPTION_FAILED))
    );
  }
}

/**
 * Encrypts an entire file using AES-256-CBC with a derived key.
 *
 * @param {string} data - The data to encrypt.
 * @param {string} masterPassword - The master password used to derive the encryption key.
 * @returns {Buffer} The encrypted data with IV and metadata.
 * @throws {PasswordManagerError} If encryption fails.
 */
export function encryptFile(data, masterPassword) {
  try {
    // Generate a random 16-byte IV
    const iv = crypto.randomBytes(16);

    // Derive a key from the master password using PBKDF2
    const salt = crypto.randomBytes(16);
    const key = crypto.pbkdf2Sync(masterPassword, salt, 100000, 32, "sha256");

    const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);

    // Add integrity verification
    const hmac = crypto.createHmac("sha256", key);
    hmac.update(data);
    const dataHmac = hmac.digest();

    // Create metadata
    const metadata = {
      version: "1.0",
      encryption: "aes-256-cbc",
      kdf: "pbkdf2",
      iterations: 100000,
      timestamp: Date.now(),
      contentType: "password-store",
    };

    const metadataStr = JSON.stringify(metadata);

    // Encrypt the data
    let encryptedData = cipher.update(Buffer.from(data, "utf8"));
    encryptedData = Buffer.concat([encryptedData, cipher.final()]);

    // Combine all parts: VERSION(1) + IV(16) + SALT(16) + HMAC(32) + METADATA_LENGTH(4) + METADATA + ENCRYPTED_DATA
    const versionByte = Buffer.from([1]); // Version 1 of the file format
    const metadataLengthBuf = Buffer.alloc(4);
    metadataLengthBuf.writeUInt32BE(metadataStr.length, 0);

    return Buffer.concat([
      versionByte,
      iv,
      salt,
      dataHmac,
      metadataLengthBuf,
      Buffer.from(metadataStr, "utf8"),
      encryptedData,
    ]);
  } catch (error) {
    throw new PasswordManagerError(
      red("Failed to encrypt file: " + error.message),
      bold(red(ERROR_CODES.ENCRYPTION_FAILED))
    );
  }
}

/**
 * Decrypts an entire file using AES-256-CBC with a derived key.
 *
 * @param {Buffer} encryptedData - The encrypted data with IV and metadata.
 * @param {string} masterPassword - The master password used to derive the decryption key.
 * @returns {string} The decrypted data.
 * @throws {PasswordManagerError} If decryption fails.
 */
export function decryptFile(encryptedData, masterPassword) {
  try {
    // Check minimum length for header
    if (encryptedData.length < 70) {
      // 1 + 16 + 16 + 32 + 4 + 1
      throw new PasswordManagerError(red('Invalid encrypted file format (too short)'), bold(red(ERROR_CODES.INVALID_ENCRYPTION_FORMAT)));
    }

    // Extract version
    const version = encryptedData[0];
    if (version !== 1) {
      throw new PasswordManagerError(red(`Unsupported file format version: ${version}`), bold(red(ERROR_CODES.INVALID_ENCRYPTION_FORMAT)));
    }

    // Extract parts
    const iv = encryptedData.subarray(1, 17);
    const salt = encryptedData.subarray(17, 33);
    const storedHmac = encryptedData.subarray(33, 65);
    const metadataLengthBuf = encryptedData.subarray(65, 69);
    const metadataLength = metadataLengthBuf.readUInt32BE(0);


    // Check if there's enough data for metadata
    if (encryptedData.length < 69 + metadataLength) {
      throw new PasswordManagerError(red('Invalid encrypted file format (metadata size error)'), ERROR_CODES.INVALID_ENCRYPTION_FORMAT);
    }

    const metadataStr = encryptedData
      .subarray(69, 69 + metadataLength)
      .toString("utf8");
    const encryptedContent = encryptedData.subarray(69 + metadataLength);

    // Parse metadata
    const metadata = JSON.parse(metadataStr);

    // Derive key using the same method used for encryption
    const key = crypto.pbkdf2Sync(
      masterPassword,
      salt,
      metadata.iterations || 100000,
      32,
      "sha256"
    );

    // Create decipher
    const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);

    // Decrypt data
    let decryptedData;
    try {
      let decrypted = decipher.update(encryptedContent);
      decrypted = Buffer.concat([decrypted, decipher.final()]);
      decryptedData = decrypted.toString("utf8");
    } catch (decryptError) {
      throw new PasswordManagerError(
        red("Decryption failed: incorrect master password or corrupted data") + NEWLINE + decryptError.message,
        bold(red(ERROR_CODES.DECRYPTION_FAILED))
      );
    }

    // Verify data integrity
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
  } catch (error) {
    throw new PasswordManagerError(
      red("Failed to decrypt file: " + NEWLINE + error.message),
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
