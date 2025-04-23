import aesjs from "aes-js";
import { KEY } from "./constants.js";
import { PasswordManagerError, handleError } from "./errorHandler.js";
import { ERROR_CODES } from "./constants.js";
import crypto from "crypto";


/**
 * Generates a random password with specified or random length (8-16 characters),
 * with at least one number, one capital letter, and one special character
 * @param {number} [userLength=0] - The desired password length (0 means random length)
 * @returns {string} The generated password
 */
const generateRandomPassword = (userLength = 0) => {
  const charset =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-.!@#$%^&*_+=/?";
  let password = "";
  // Use provided length if valid, otherwise use random length between 8-16
  let length = userLength >= 8 ? userLength : Math.floor(Math.random() * 9) + 8;

  while (length--) {
    password += charset[Math.floor(Math.random() * charset.length)];

    // check if the password has at least one number, one capital letter or one special character
    if (length === 0) {
      if (!password.match(/[A-Z]/)) {
        password += charset[Math.floor(Math.random() * 26) + 26];
      } else if (!password.match(/[0-9]/)) {
        password += charset[Math.floor(Math.random() * 10) + 52];
      } else if (!password.match(/[-.!@#$%^&*_+=/?]/)) {
        password += charset[Math.floor(Math.random() * 16) + 62];
      }
    }

    // shuffle the password
    password = password
      .split("")
      .sort(() => Math.random() - 0.5)
      .join("");
  }

  return password;
};

/**
 * Encrypts a password using AES-256-CTR mode
 * @param {string} password - The password to encrypt
 * @returns {string} The encrypted password
 */
const encryptPassword = (password) => {
  const textBytes = aesjs.utils.utf8.toBytes(password);
  const aesCtr = new aesjs.ModeOfOperation.ctr(KEY, new aesjs.Counter(5));
  const encryptedBytes = aesCtr.encrypt(textBytes);
  const encryptedHex = aesjs.utils.hex.fromBytes(encryptedBytes);

  return encryptedHex;
};

/**
 * Decrypts a password using AES-256-CTR mode
 * @param {string} password - The encrypted password
 * @returns {string} The decrypted password
 */
const decryptPassword = (password) => {
  try {
    const encryptedBytes = aesjs.utils.hex.toBytes(password);
    const aesCtr = new aesjs.ModeOfOperation.ctr(KEY, new aesjs.Counter(5));
    const decryptedBytes = aesCtr.decrypt(encryptedBytes);
    const decryptedText = aesjs.utils.utf8.fromBytes(decryptedBytes);

    return decryptedText;
  } catch (error) {
    handleError(error);
    throw new PasswordManagerError(
      'Failed to decrypt password',
      ERROR_CODES.DECRYPTION_FAILED
    );
  }
};

/**
 * Encrypts an entire file using AES-256-CBC with a derived key
 * @param {string} data - The data to encrypt
 * @param {string} masterPassword - The master password used to derive the encryption key
 * @returns {Buffer} The encrypted data with IV and metadata
 * @throws {PasswordManagerError} If encryption fails
 */
export const encryptFile = (data, masterPassword) => {
  try {
    // Generate a random 16-byte IV
    const iv = crypto.randomBytes(16);
    
    // Derive a key from the master password using PBKDF2
    const salt = crypto.randomBytes(16);
    const key = crypto.pbkdf2Sync(masterPassword, salt, 100000, 32, 'sha256');
    
    // Create cipher
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    
    // Add integrity verification
    const hmac = crypto.createHmac('sha256', key);
    hmac.update(data);
    const dataHmac = hmac.digest();
    
    // Create metadata
    const metadata = {
      version: "1.0",
      encryption: "aes-256-cbc",
      kdf: "pbkdf2",
      iterations: 100000,
      timestamp: Date.now(),
      contentType: "password-store"
    };
    
    const metadataStr = JSON.stringify(metadata);
    
    // Encrypt the data
    let encryptedData = cipher.update(Buffer.from(data, 'utf8'));
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
      Buffer.from(metadataStr, 'utf8'),
      encryptedData
    ]);
  } catch (error) {
    throw new PasswordManagerError(
      'Failed to encrypt file: ' + error.message,
      ERROR_CODES.ENCRYPTION_FAILED
    );
  }
};

/**
 * Decrypts an entire file using AES-256-CBC with a derived key
 * @param {Buffer} encryptedData - The encrypted data with IV and metadata
 * @param {string} masterPassword - The master password used to derive the decryption key
 * @returns {string} The decrypted data
 * @throws {PasswordManagerError} If decryption fails
 */
export const decryptFile = (encryptedData, masterPassword) => {
  try {
    // Check minimum length for header
    if (encryptedData.length < 70) { // 1 + 16 + 16 + 32 + 4 + 1
      throw new Error('Invalid encrypted file format (too short)');
    }
    
    // Extract version
    const version = encryptedData[0];
    if (version !== 1) {
      throw new Error(`Unsupported file format version: ${version}`);
    }
    
    // Extract parts
    const iv = encryptedData.subarray(1, 17);
    const salt = encryptedData.subarray(17, 33);
    const storedHmac = encryptedData.subarray(33, 65);
    const metadataLengthBuf = encryptedData.subarray(65, 69);
    const metadataLength = metadataLengthBuf.readUInt32BE(0);
    
    // Check if there's enough data for metadata
    if (encryptedData.length < 69 + metadataLength) {
      throw new Error('Invalid encrypted file format (metadata size error)');
    }
    
    const metadataStr = encryptedData.subarray(69, 69 + metadataLength).toString('utf8');
    const encryptedContent = encryptedData.subarray(69 + metadataLength);
    
    // Parse metadata
    const metadata = JSON.parse(metadataStr);
    
    // Derive key using the same method used for encryption
    const key = crypto.pbkdf2Sync(masterPassword, salt, metadata.iterations || 100000, 32, 'sha256');
    
    // Create decipher
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    
    // Decrypt data
    let decryptedData;
    try {
      let decrypted = decipher.update(encryptedContent);
      decrypted = Buffer.concat([decrypted, decipher.final()]);
      decryptedData = decrypted.toString('utf8');
    } catch (decryptError) {
      throw new Error('Decryption failed: incorrect master password or corrupted data');
    }
    
    // Verify data integrity
    const hmac = crypto.createHmac('sha256', key);
    hmac.update(decryptedData);
    const calculatedHmac = hmac.digest();
    
    if (!crypto.timingSafeEqual(storedHmac, calculatedHmac)) {
      throw new Error('Data integrity check failed: the file may be corrupted or tampered with');
    }
    
    return decryptedData;
  } catch (error) {
    throw new PasswordManagerError(
      'Failed to decrypt file: ' + error.message,
      ERROR_CODES.DECRYPTION_FAILED
    );
  }
};

/**
 * Checks if a file is encrypted with our file encryption format
 * @param {Buffer} data - The file data to check
 * @returns {boolean} True if the file appears to be encrypted with our format
 */
export const isFileEncrypted = (data) => {
  try {
    // Check if data is a buffer
    if (!Buffer.isBuffer(data)) {
      return false;
    }
    
    // Check minimum length and version byte
    if (data.length < 70 || data[0] !== 1) {
      return false;
    }
    
    // Try to extract and parse metadata length
    const metadataLengthBuf = data.subarray(65, 69);
    const metadataLength = metadataLengthBuf.readUInt32BE(0);
    
    // Sanity check on metadata length
    return metadataLength > 0 && metadataLength < 1000;
  } catch (e) {
    return false;
  }
};

export { generateRandomPassword, encryptPassword, decryptPassword };
