import fs from 'fs';
import { FILE_LOCK, FILE_LOCK_TIMEOUT, CHARSET } from './constants.js';
import { readFileAsync, writeFileAsync } from './fileOperations/index.js';
import crypto from 'crypto';
import { join } from 'path';
import { BASE_DIR } from './constants.js';

/**
 * Acquires a file lock.
 * @param {number} maxRetries - Maximum number of retries (default: FILE_LOCK.MAX_RETRIES).
 * @returns {Promise<boolean>} True if lock was acquired, false otherwise.
 * @description This function acquires a file lock to prevent multiple instances of the program from accessing the same file at the same time.
 */
export async function acquireLock(maxRetries = FILE_LOCK.MAX_RETRIES) {
  let retries = 0;

  // First check if lock is stale and clear it if needed
  try {
    if (fs.existsSync(FILE_LOCK.LOCK_FILE)) {
      const lockContent = await readFileAsync(FILE_LOCK.LOCK_FILE, CHARSET);
      const lockTime = parseInt(lockContent, 10);
      const now = Date.now();
      if (isNaN(lockTime)) {
        try {
          fs.unlinkSync(FILE_LOCK.LOCK_FILE);
        } catch (e) {
          console.error("Failed to clear lock with invalid timestamp:", e.message);
        }
      } else if (lockTime > now) {
        // Timestamp in the future, treat as stale
        try {
          fs.unlinkSync(FILE_LOCK.LOCK_FILE);
        } catch (e) {
          console.error("Failed to clear lock with future timestamp:", e.message);
        }
      } else if (now - lockTime > FILE_LOCK_TIMEOUT) {
        try {
          fs.unlinkSync(FILE_LOCK.LOCK_FILE);
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
}

/**
 * Releases a file lock.
 * @returns {Promise<void>}
 * @description This function releases a file lock to allow other instances of the program to access the file.
 */
export async function releaseLock() {
  try {
    if (fs.existsSync(FILE_LOCK.LOCK_FILE)) {
      // Delete the lock file completely
      fs.unlinkSync(FILE_LOCK.LOCK_FILE);
    }
  } catch (error) {
    // Ignore errors when releasing lock
    console.error("Error releasing lock:", error);
  }
}