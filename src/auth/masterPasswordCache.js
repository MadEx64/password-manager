import { 
  getCachedMasterPassword, 
  getCachedEncryptionKey, 
  cacheMasterPasswordAndKey,
  isSessionValid,
  getSessionState
} from "./session.js";
import { 
  deriveAuthenticationKey
} from "./secureAuth.js";

// Re-export session functions for convenience
export { getCachedMasterPassword, getCachedEncryptionKey, cacheMasterPasswordAndKey } from "./session.js";

/**
 * Gets the encryption key for password operations, using cache if available.
 * For the new secure authentication system, this requires the master password.
 * 
 * @param {string} masterPassword - The master password (required for new auth system).
 * @returns {Promise<Buffer>} The encryption key.
 * @throws {Error} If master password is not provided.
 */
export async function getEncryptionKey(masterPassword = null) {
  const cachedKey = getCachedEncryptionKey();
  if (cachedKey) {
    return cachedKey;
  }

  if (!masterPassword) {
    throw new Error("Master password required for secure authentication system");
  }
  
  const encryptionKey = await deriveAuthenticationKey(masterPassword);
  
  if (isSessionValid(getSessionState())) {
    cacheMasterPasswordAndKey(masterPassword, encryptionKey);
  }
  
  return encryptionKey;
}

/**
 * Convenience function to get both master password and encryption key from cache.
 * 
 * @returns {Promise<{masterPassword: string|null, encryptionKey: Buffer|null}>} The cached credentials or null values if not available.
 */
export async function getMasterPasswordAndKey() {
  const cachedPassword = getCachedMasterPassword();
  const cachedKey = getCachedEncryptionKey();
  
  if (cachedKey && cachedPassword) {
    return {
      masterPassword: cachedPassword,
      encryptionKey: cachedKey
    };
  }
  
  return {
    masterPassword: null,
    encryptionKey: null
  };
} 