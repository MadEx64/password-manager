import { authenticateUser } from "./authentication.js";

/**
 * A higher-order function that wraps an asynchronous function with an authentication check.
 * It ensures that the user is authenticated before executing the function.
 *
 * @param {Function} fn - The asynchronous function to wrap.
 * @returns {Function} A new function that will perform the authentication check before execution.
 */
export function withAuthentication(fn) {
  return async function(...args) {
    if (!(await authenticateUser())) {
      return false;
    }
    return await fn(...args);
  };
}
