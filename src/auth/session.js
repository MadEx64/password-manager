import { getSessionTimeout } from "../constants.js";

/**
 * The session state object.
 * @type {Object}
 * @property {number} lastValidationTime - The time of the last validation in milliseconds.
 */
export let sessionState = {
  lastValidationTime: null,
  isAuthenticated: false,
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
 */
export function clearSession(sessionState) {
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
 * Updates the session state to indicate that the master password has been validated.
 * Essentially authorizes the user to access the application and logs them in.
 */
export function updateSession(sessionState) {
  sessionState.lastValidationTime = Date.now();
  sessionState.isAuthenticated = true;
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
