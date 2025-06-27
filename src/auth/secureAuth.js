import { ERROR_CODES } from "../constants.js";
import { PasswordManagerError } from "../errorHandler.js";
import { log, yellow, green, red, bold } from "../logger.js";
import { 
  generateRandomBytes, 
  deriveKeyPBKDF2, 
  createHashBuffer, 
  createHmac, 
  timingSafeEqual 
} from "../encryption/index.js";
import {
  storeAppSecretKey,
  retrieveAppSecretKey,
  storeAuthHash,
  retrieveAuthHash,
  deleteAppSecretKey,
  deleteAuthHash,
  getSecureStorageInfo
} from './secureStorage.js';

/**
 * Security Configuration
 */
const SECURITY_CONFIG = {
  SECRET_KEY_LENGTH: 64, // 512 bits
  AUTH_KEY_LENGTH: 32,   // 256 bits
  PBKDF2_ITERATIONS: 100000,
  HASH_ALGORITHM: 'sha256',
  HMAC_ALGORITHM: 'sha256',
};

/**
 * Generates and stores the application secret key using secure storage.
 * This key is combined with the master password to derive the authentication key.
 * 
 * @returns {Promise<string>} The generated secret key as hex string.
 * @throws {PasswordManagerError} If the secret key generation fails.
 */
export async function generateAndStoreAppSecretKey() {
  try {
    const existingKey = await retrieveAppSecretKey();
    if (existingKey && existingKey.length === SECURITY_CONFIG.SECRET_KEY_LENGTH * 2) {
      return existingKey;
    }

    const secretKey = generateRandomBytes(SECURITY_CONFIG.SECRET_KEY_LENGTH).toString('hex');
    
    await storeAppSecretKey(secretKey);
    
    log(green("✓ Application secret key generated and secured."));
    
    return secretKey;
  } catch (error) {
    throw new PasswordManagerError(
      red("Failed to generate application secret key: " + error.message),
      bold(red(ERROR_CODES.APP_SECRET_KEY_GENERATION_FAILED))
    );
  }
}

/**
 * Reads the application secret key from secure storage.
 * 
 * @returns {Promise<string>} The secret key as hex string.
 * @throws {PasswordManagerError} If the secret key cannot be read.
 */
export async function getAppSecretKey() {
  try {
    let secretKey = await retrieveAppSecretKey();
    
    if (!secretKey) {
      return await generateAndStoreAppSecretKey();
    }
    
    if (!secretKey || secretKey.length !== SECURITY_CONFIG.SECRET_KEY_LENGTH * 2 || !/^[a-f0-9]+$/i.test(secretKey)) {
      throw new Error("Invalid or corrupted application secret key in secure storage");
    }
    
    return secretKey;
  } catch (error) {
    throw new PasswordManagerError(
      red("Failed to read application secret key: " + error.message),
      bold(red(ERROR_CODES.APP_SECRET_KEY_GENERATION_FAILED))
    );
  }
}

/**
 * Derives an authentication key from the master password and application secret key.
 * This key is used for all cryptographic operations.
 * 
 * @param {string} masterPassword - The user's master password
 * @returns {Promise<Buffer>} The derived authentication key.
 * @throws {PasswordManagerError} If key derivation fails.
 */
export async function deriveAuthenticationKey(masterPassword) {
  try {
    const secretKey = await getAppSecretKey();
    
    const combinedSecret = masterPassword + secretKey;

    // Use a deterministic salt derived from the secret key to ensure
    // the same master password + secret key always produces the same authentication key
    const salt = createHashBuffer(secretKey).subarray(0, 16);
    
    const authKey = deriveKeyPBKDF2(
      combinedSecret,
      salt,
      SECURITY_CONFIG.PBKDF2_ITERATIONS,
      SECURITY_CONFIG.AUTH_KEY_LENGTH,
      SECURITY_CONFIG.HASH_ALGORITHM
    );
    
    return authKey;
  } catch (error) {
    throw new PasswordManagerError(
      red("Failed to derive authentication key: " + error.message),
      bold(red(ERROR_CODES.AUTH_KEY_DERIVATION_FAILED))
    );
  }
}

/**
 * Creates and stores a hash of the authentication key for password verification.
 * This hash is used to verify the master password without storing it.
 * 
 * @param {Buffer} authKey - The authentication key to hash.
 * @returns {Promise<void>}
 * @throws {PasswordManagerError} If hash creation fails.
 */
export async function storeAuthenticationHash(authKey) {
  try {
    const secretKey = await getAppSecretKey();
    const authHash = createHmac(secretKey, authKey);    
    await storeAuthHash(authHash);
  } catch (error) {
    throw new PasswordManagerError(
      red("Failed to store authentication hash: " + error.message),
      bold(red(ERROR_CODES.INTERNAL_ERROR))
    );
  }
}

/**
 * Verifies a master password by comparing the derived authentication key hash.
 * 
 * @param {string} masterPassword - The master password to verify.
 * @returns {Promise<boolean>} True if the password is valid.
 * @throws {PasswordManagerError} If verification fails.
 */
export async function verifyMasterPassword(masterPassword) {
  try {
    const storedHash = await retrieveAuthHash();
    
    if (!storedHash) {
      log(red("No authentication hash found in secure storage"));
      return false;
    }
    
    const authKey = await deriveAuthenticationKey(masterPassword);
    
    const secretKey = await getAppSecretKey();
    const inputHash = createHmac(secretKey, authKey);
    
    return timingSafeEqual(inputHash, storedHash.trim());
  } catch (error) {
    throw new PasswordManagerError(
      red("Failed to verify master password: " + error.message),
      bold(red(ERROR_CODES.AUTHENTICATION_FAILED))
    );
  }
}

/**
 * Sets up a new master password by creating the authentication hash.
 * This is called when setting up a new master password.
 * 
 * @param {string} masterPassword - The new master password.
 * @returns {Promise<Buffer>} The derived authentication key.
 * @throws {PasswordManagerError} If setup fails.
 */
export async function setupMasterPassword(masterPassword) {
  try {
    const secretKey = await generateAndStoreAppSecretKey();
    
    const authKey = await deriveAuthenticationKey(masterPassword);
    await storeAuthenticationHash(authKey);

    log(yellow("⚠ Your secret key is: " + secretKey));
    log(yellow("⚠ Make sure to store both the master password and the secret key in a secure location."));
    
    return authKey;
  } catch (error) {
    throw new PasswordManagerError(
      red("Failed to setup master password: " + error.message),
      bold(red(ERROR_CODES.INTERNAL_ERROR))
    );
  }
}

/**
 * Updates the master password by creating a new authentication hash.
 * 
 * @param {string} newMasterPassword - The new master password.
 * @returns {Promise<Buffer>} The new authentication key.
 * @throws {PasswordManagerError} If update fails.
 */
export async function updateMasterPassword(newMasterPassword) {
  try {
    const newAuthKey = await deriveAuthenticationKey(newMasterPassword);
    await storeAuthenticationHash(newAuthKey);
    return newAuthKey;
  } catch (error) {
    throw new PasswordManagerError(
      red("Failed to update master password: " + error.message),
      bold(red(ERROR_CODES.INTERNAL_ERROR))
    );
  }
}

/**
 * Checks if the authentication system is initialized by checking secure storage.
 * 
 * @returns {Promise<boolean>} True if initialized.
 */
export async function isAuthSystemInitialized() {
  try {
    const secretKey = await retrieveAppSecretKey();
    const authHash = await retrieveAuthHash();
    return !!(secretKey && authHash);
  } catch (error) {
    return false;
  }
}



/**
 * Resets the authentication hash for a new master password.
 * This is useful when the user knows their secret key but has forgotten their master password.
 * 
 * @param {string} newMasterPassword - The new master password.
 * @returns {Promise<Buffer>} The new authentication key.
 * @throws {PasswordManagerError} If reset fails.
 */
export async function resetAuthenticationHash(newMasterPassword) {
  try {
    const newAuthKey = await deriveAuthenticationKey(newMasterPassword);
    
    await storeAuthenticationHash(newAuthKey);
    
    log(green("✓ Authentication hash reset successfully"));
    
    return newAuthKey;
  } catch (error) {
    throw new PasswordManagerError(
      red("Failed to reset authentication hash: " + error.message),
      bold(red(ERROR_CODES.INTERNAL_ERROR))
    );
  }
}

/**
 * Completely removes all secure credentials (for emergency reset).
 * 
 * @returns {Promise<boolean>} True if successful.
 */
export async function clearSecureCredentials() {
  try {
    const deletedSecret = await deleteAppSecretKey();
    const deletedHash = await deleteAuthHash();
    
    if (deletedSecret || deletedHash) {
      log(green("✓ Secure credentials cleared"));
      return true;
    }
    
    return false;
  } catch (error) {
    throw new PasswordManagerError(
      red("Failed to clear secure credentials: " + error.message),
      bold(red(ERROR_CODES.INTERNAL_ERROR))
    );
  }
}

/**
 * Gets detailed information about the secure storage system.
 * 
 * @returns {Promise<Object>} Storage information.
 */
export async function getAuthSystemInfo() {
  try {
    const storageInfo = await getSecureStorageInfo();
    const hasSecretKey = !!(await retrieveAppSecretKey());
    const hasAuthHash = !!(await retrieveAuthHash());
    
    return {
      ...storageInfo,
      isInitialized: hasSecretKey && hasAuthHash,
      hasSecretKey,
      hasAuthHash
    };
  } catch (error) {
    return {
      platform: process.platform,
      secureStorageAvailable: false,
      storageType: 'Error',
      isInitialized: false,
      hasSecretKey: false,
      hasAuthHash: false,
      error: error.message
    };
  }
} 