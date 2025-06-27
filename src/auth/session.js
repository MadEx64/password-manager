import crypto from "crypto";

// Memory encryption key for protecting cached passwords
let memoryEncryptionKey = null;

/**
 * Initializes or gets the memory encryption key for protecting sensitive data in memory.
 * 
 * @returns {Buffer} The memory encryption key.
 */
function getMemoryEncryptionKey() {
  if (!memoryEncryptionKey) {
    memoryEncryptionKey = crypto.randomBytes(32);
  }
  return memoryEncryptionKey;
}

/**
 * Encrypts a string for secure storage in memory using XOR encryption.
 * 
 * @param {string} data - The data to encrypt.
 * @returns {Buffer|null} The encrypted data or null if input is null.
 */
function encryptForMemory(data) {
  if (!data) return null;
  
  const key = getMemoryEncryptionKey();
  const dataBuffer = Buffer.from(data, 'utf8');
  const encrypted = Buffer.alloc(dataBuffer.length);
  
  for (let i = 0; i < dataBuffer.length; i++) {
    encrypted[i] = dataBuffer[i] ^ key[i % key.length];
  }
  
  return encrypted;
}

/**
 * Decrypts data from memory storage using XOR encryption.
 * 
 * @param {Buffer} encryptedData - The encrypted data to decrypt.
 * @returns {string|null} The decrypted string or null if input is null.
 */
function decryptFromMemory(encryptedData) {
  if (!encryptedData) return null;
  
  const key = getMemoryEncryptionKey();
  const decrypted = Buffer.alloc(encryptedData.length);
  
  for (let i = 0; i < encryptedData.length; i++) {
    decrypted[i] = encryptedData[i] ^ key[i % key.length];
  }
  
  return decrypted.toString('utf8');
}

/**
 * The session state object.
 * @type {Object}
 * @property {number} lastValidationTime - The time of the last validation in milliseconds.
 * @property {boolean} isAuthenticated - Whether the user is authenticated.
 * @property {Buffer|null} cachedMasterPassword - The cached master password (encrypted in memory).
 * @property {Buffer|null} cachedEncryptionKey - The cached encryption key for password operations.
 */
let sessionState = {
  lastValidationTime: null,
  isAuthenticated: false,
  cachedMasterPassword: null,
  cachedEncryptionKey: null,
};

/**
 * Gets the session state.
 * @returns {Object} The session state object.
 */
export function getSessionState() {
  return sessionState;
}

/**
 * Clears the session state by resetting all values to their initial state.
 * This securely clears sensitive data from memory.
 */
export function clearSession(sessionState) {
  if (sessionState.cachedMasterPassword) {
    sessionState.cachedMasterPassword.fill(0);
    sessionState.cachedMasterPassword = null;
  }
  if (sessionState.cachedEncryptionKey) {
    sessionState.cachedEncryptionKey.fill(0);
    sessionState.cachedEncryptionKey = null;
  }
  
  sessionState.lastValidationTime = null;
  sessionState.isAuthenticated = false;
}

/**
 * Checks if the session is still valid (user is authenticated and session has not timed out).
 * @param {Object} sessionState - The session state object.
 * @returns {boolean} True if the session is valid, false otherwise.
 */
export function isSessionValid(sessionState) {
  if (
    sessionState.isAuthenticated &&
    getSessionTimeRemaining(sessionState) > 0
  ) {
    return true;
  }
  return false;
};

/**
 * Updates the session state to indicate that the session is valid.
 * 
 * @param {Object} sessionState - The session state object.
 * @param {string} masterPassword - The master password to cache (will be encrypted in memory).
 * @param {Buffer} encryptionKey - The encryption key to cache.
 */
export function updateSession(sessionState, masterPassword = null, encryptionKey = null) {
  sessionState.lastValidationTime = Date.now();
  sessionState.isAuthenticated = true;
  
  if (masterPassword) {
    sessionState.cachedMasterPassword = encryptForMemory(masterPassword);
  }
  if (encryptionKey) {
    sessionState.cachedEncryptionKey = encryptionKey;
  }
}

/**
 * Gets the cached master password from the session.
 * @returns {string|null} The cached master password or null if not cached or session invalid.
 */
export function getCachedMasterPassword() {
  if (isSessionValid(sessionState)) {
    return decryptFromMemory(sessionState.cachedMasterPassword);
  }
  return null;
}

/**
 * Gets the cached encryption key from the session.
 * @returns {Buffer|null} The cached encryption key or null if not cached or session invalid.
 */
export function getCachedEncryptionKey() {
  if (isSessionValid(sessionState)) {
    return sessionState.cachedEncryptionKey;
  }
  return null;
}

/**
 * Caches the master password and encryption key in the session.
 * Only works if the session is valid.
 * 
 * @param {string} masterPassword - The master password to cache (will be encrypted in memory).
 * @param {Buffer} encryptionKey - The encryption key to cache.
 */
export function cacheMasterPasswordAndKey(masterPassword, encryptionKey) {
  if (isSessionValid(sessionState)) {
    sessionState.cachedMasterPassword = encryptForMemory(masterPassword);
    sessionState.cachedEncryptionKey = encryptionKey;
  }
}

/**
 * Gets the session timeout from environment variables.
 * @returns {number} The session timeout in milliseconds.
 */
function getSessionTimeout() {
  return parseInt(process.env.PASSWORD_MANAGER_SESSION_TIMEOUT, 10) || 1000 * 60 * 5;
}

/**
 * Gets the time remaining in the session.
 * @param {Object} sessionState - The session state object.
 * @returns {number} The time remaining in the session in milliseconds.
 *
 * @example
 * getSessionTimeRemaining()
 * // returns 1000 * 60 * 5 - (Date.now() - sessionState.lastValidationTime)
 */
export function getSessionTimeRemaining(sessionState) {
  if (!sessionState.lastValidationTime) return 0;
  const elapsed = Date.now() - sessionState.lastValidationTime;
  return Math.max(0, getSessionTimeout() - elapsed);
}
