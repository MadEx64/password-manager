/**
 * Parses the lines from the passwords file
 * @param {string} lines - The lines from the passwords file (e.g. 'TestApp - test@example.com - encryptedPass')
 * @returns {string[]} An array of parsed lines
 */
export function parseLines(lines) {
  if (lines.trim() === "") return [];
  return lines.split(/\r?\n/).filter((line) => line.trim() !== "");
}

/**
 * Sorts the entries of the passwords file by application name (sort apps together).
 * @param {Object[]} entries - The entries to sort.
 * @returns {Object[]} The sorted entries.
 * 
 * @example
 * sortEntries([{ service: "TestApp", identifier: "test@example.com", password: "encryptedPass" }, { service: "BestApp", identifier: "test2@example.com", password: "encryptedPass2" }])
 * // returns [{ service: "BestApp", identifier: "test2@example.com", password: "encryptedPass2" }, { service: "TestApp", identifier: "test@example.com", password: "encryptedPass" }]
 */
export function sortEntries(entries) {
  return entries.slice().sort((a, b) => a.service.localeCompare(b.service));
}

/**
 * Converts line-based password data to JSON format.
 * @param {string[]} lines - The lines from the passwords file.
 * @returns {Object[]} Array of password entries in JSON format.
 */
export function convertToJsonFormat(lines) {
  return lines.map(line => {
    const [service, identifier, password] = line.split(" - ");
    return {
      service,
      identifier,
      password,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };
  });
}