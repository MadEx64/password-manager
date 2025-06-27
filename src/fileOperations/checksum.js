import { createHash } from "../encryption/index.js";

/**
 * Creates a checksum for the given data.
 * @param {string} data - The data to create a checksum for.
 * @returns {string} The checksum.
 * @description This function creates a checksum for the given data using the SHA-256 algorithm.
 */
export function createChecksum(data) {
  return createHash(data);
};

/**
 * Verifies the checksum of the given data.
 * @param {string} data - The data to verify.
 * @param {string} checksum - The expected checksum.
 * @returns {boolean} True if the checksum is valid, false otherwise.
 * @description This function verifies the checksum of the given data using the SHA-256 algorithm.
 */
export function verifyChecksum(data, checksum) {
  return createChecksum(data) === checksum;
};