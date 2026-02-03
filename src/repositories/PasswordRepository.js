import { runQuery, getRow, getAllRows, runTransaction, count } from "../database/index.js";
import { ERROR_CODES } from "../constants.js";
import { PasswordManagerError } from "../errorHandler.js";
import { red, bold } from "../logger.js";

/**
 * Repository for password entry database operations.
 * Provides data access layer for password CRUD operations.
 */

/**
 * Converts a database row to a password entry object.
 * @param {Object} row - The database row.
 * @returns {Object} The password entry object.
 */
function rowToEntry(row) {
  if (!row) return null;

  return {
    id: row.id,
    service: row.service,
    identifier: row.identifier,
    password: row.encrypted_password,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    lastAccessed: row.last_accessed,
  };
}

/**
 * Converts a password entry object to database parameters.
 * @param {Object} entry - The password entry object.
 * @returns {Object} The database parameters.
 */
function entryToParams(entry) {
  return {
    service: entry.service,
    identifier: entry.identifier,
    encrypted_password: entry.password,
    created_at: entry.createdAt || new Date().toISOString(),
    updated_at: entry.updatedAt || new Date().toISOString(),
    last_accessed: entry.lastAccessed || null,
  };
}

/**
 * Retrieves all password entries from the database.
 * @returns {Promise<Object[]>} Array of password entries.
 * @throws {PasswordManagerError} If the query fails.
 */
export async function findAll() {
  try {
    const rows = await getAllRows(
      "SELECT * FROM passwords ORDER BY service ASC, identifier ASC"
    );
    return rows.map(rowToEntry);
  } catch (error) {
    throw new PasswordManagerError(
      red("Failed to retrieve password entries: " + error.message),
      bold(red(ERROR_CODES.DATABASE_ERROR))
    );
  }
}

/**
 * Retrieves a password entry by ID.
 * @param {number} id - The entry ID.
 * @returns {Promise<Object|null>} The password entry or null if not found.
 * @throws {PasswordManagerError} If the query fails.
 */
export async function findById(id) {
  try {
    const row = await getRow("SELECT * FROM passwords WHERE id = ?", [id]);
    return rowToEntry(row);
  } catch (error) {
    throw new PasswordManagerError(
      red("Failed to retrieve password entry: " + error.message),
      bold(red(ERROR_CODES.DATABASE_ERROR))
    );
  }
}

/**
 * Retrieves password entries by service name.
 * @param {string} service - The service name.
 * @returns {Promise<Object[]>} Array of password entries for the service.
 * @throws {PasswordManagerError} If the query fails.
 */
export async function findByService(service) {
  try {
    const rows = await getAllRows(
      "SELECT * FROM passwords WHERE service = ? ORDER BY identifier ASC",
      [service]
    );
    return rows.map(rowToEntry);
  } catch (error) {
    throw new PasswordManagerError(
      red("Failed to retrieve password entries: " + error.message),
      bold(red(ERROR_CODES.DATABASE_ERROR))
    );
  }
}

/**
 * Retrieves a password entry by service and identifier.
 * @param {string} service - The service name.
 * @param {string} identifier - The identifier (username/email).
 * @returns {Promise<Object|null>} The password entry or null if not found.
 * @throws {PasswordManagerError} If the query fails.
 */
export async function findByServiceAndIdentifier(service, identifier) {
  try {
    const row = await getRow(
      "SELECT * FROM passwords WHERE service = ? AND identifier = ?",
      [service, identifier]
    );
    return rowToEntry(row);
  } catch (error) {
    throw new PasswordManagerError(
      red("Failed to retrieve password entry: " + error.message),
      bold(red(ERROR_CODES.DATABASE_ERROR))
    );
  }
}

/**
 * Searches for password entries matching a query.
 * @param {string} query - The search query.
 * @returns {Promise<Object[]>} Array of matching password entries.
 * @throws {PasswordManagerError} If the query fails.
 */
export async function search(query) {
  try {
    const searchPattern = `%${query}%`;
    const rows = await getAllRows(
      `SELECT * FROM passwords 
       WHERE service LIKE ? OR identifier LIKE ? 
       ORDER BY service ASC, identifier ASC`,
      [searchPattern, searchPattern]
    );
    return rows.map(rowToEntry);
  } catch (error) {
    throw new PasswordManagerError(
      red("Failed to search password entries: " + error.message),
      bold(red(ERROR_CODES.DATABASE_ERROR))
    );
  }
}

/**
 * Creates a new password entry.
 * @param {Object} entry - The password entry to create.
 * @returns {Promise<Object>} The created password entry with ID.
 * @throws {PasswordManagerError} If creation fails.
 */
export async function create(entry) {
  try {
    const params = entryToParams(entry);

    const result = await runQuery(
      `INSERT INTO passwords (service, identifier, encrypted_password, created_at, updated_at, last_accessed)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [
        params.service,
        params.identifier,
        params.encrypted_password,
        params.created_at,
        params.updated_at,
        params.last_accessed,
      ]
    );

    return {
      id: result.lastID,
      ...entry,
    };
  } catch (error) {
    if (error.message && error.message.includes("UNIQUE constraint failed")) {
      throw new PasswordManagerError(
        red(
          `Password entry for ${entry.service} (${entry.identifier}) already exists`
        ),
        bold(red(ERROR_CODES.DUPLICATE_IDENTIFIER))
      );
    }
    throw new PasswordManagerError(
      red("Failed to create password entry: " + error.message),
      bold(red(ERROR_CODES.DATABASE_ERROR))
    );
  }
}

/**
 * Updates an existing password entry.
 * @param {number} id - The entry ID to update.
 * @param {Object} entry - The updated password entry data.
 * @returns {Promise<Object>} The updated password entry.
 * @throws {PasswordManagerError} If update fails.
 */
export async function update(id, entry) {
  try {
    const params = entryToParams(entry);

    await runQuery(
      `UPDATE passwords 
       SET service = ?, identifier = ?, encrypted_password = ?, updated_at = ?, last_accessed = ?
       WHERE id = ?`,
      [
        params.service,
        params.identifier,
        params.encrypted_password,
        new Date().toISOString(),
        params.last_accessed,
        id,
      ]
    );

    return await findById(id);
  } catch (error) {
    if (error.message && error.message.includes("UNIQUE constraint failed")) {
      throw new PasswordManagerError(
        red(
          `Password entry for ${entry.service} (${entry.identifier}) already exists`
        ),
        bold(red(ERROR_CODES.DUPLICATE_IDENTIFIER))
      );
    }
    throw new PasswordManagerError(
      red("Failed to update password entry: " + error.message),
      bold(red(ERROR_CODES.DATABASE_ERROR))
    );
  }
}

/**
 * Updates a password entry by service and identifier.
 * @param {Object} entry - The updated password entry data (must include service, identifier).
 * @returns {Promise<Object>} The updated password entry.
 * @throws {PasswordManagerError} If update fails.
 */
export async function updateByServiceAndIdentifier(entry) {
  try {
    const oldIdentifier = entry.oldIdentifier || entry.identifier;

    await runQuery(
      `UPDATE passwords 
       SET identifier = ?, encrypted_password = ?, updated_at = ?
       WHERE service = ? AND identifier = ?`,
      [
        entry.identifier,
        entry.password,
        entry.updatedAt || new Date().toISOString(),
        entry.service,
        oldIdentifier,
      ]
    );

    return await findByServiceAndIdentifier(entry.service, entry.identifier);
  } catch (error) {
    if (error.message && error.message.includes("UNIQUE constraint failed")) {
      throw new PasswordManagerError(
        red(
          `Password entry for ${entry.service} (${entry.identifier}) already exists`
        ),
        bold(red(ERROR_CODES.DUPLICATE_IDENTIFIER))
      );
    }
    throw new PasswordManagerError(
      red("Failed to update password entry: " + error.message),
      bold(red(ERROR_CODES.DATABASE_ERROR))
    );
  }
}

/**
 * Deletes a password entry by ID.
 * @param {number} id - The entry ID to delete.
 * @returns {Promise<boolean>} True if deletion was successful.
 * @throws {PasswordManagerError} If deletion fails.
 */
export async function deleteById(id) {
  try {
    const result = await runQuery("DELETE FROM passwords WHERE id = ?", [id]);
    return result.changes > 0;
  } catch (error) {
    throw new PasswordManagerError(
      red("Failed to delete password entry: " + error.message),
      bold(red(ERROR_CODES.DATABASE_ERROR))
    );
  }
}

/**
 * Deletes a password entry by service and identifier.
 * @param {string} service - The service name.
 * @param {string} identifier - The identifier.
 * @returns {Promise<boolean>} True if deletion was successful.
 * @throws {PasswordManagerError} If deletion fails.
 */
export async function deleteByServiceAndIdentifier(service, identifier) {
  try {
    const result = await runQuery(
      "DELETE FROM passwords WHERE service = ? AND identifier = ?",
      [service, identifier]
    );
    return result.changes > 0;
  } catch (error) {
    throw new PasswordManagerError(
      red("Failed to delete password entry: " + error.message),
      bold(red(ERROR_CODES.DATABASE_ERROR))
    );
  }
}

/**
 * Inserts multiple password entries in a transaction.
 * @param {Object[]} entries - Array of password entries to insert.
 * @returns {Promise<number>} The number of entries inserted.
 * @throws {PasswordManagerError} If insertion fails.
 */
export async function bulkCreate(entries) {
  let insertedCount = 0;

  await runTransaction(async () => {
    for (const entry of entries) {
      const params = entryToParams(entry);
      await runQuery(
        `INSERT INTO passwords (service, identifier, encrypted_password, created_at, updated_at, last_accessed)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [
          params.service,
          params.identifier,
          params.encrypted_password,
          params.created_at,
          params.updated_at,
          params.last_accessed,
        ]
      );
      insertedCount++;
    }
  });

  return insertedCount;
}

/**
 * Gets the total count of password entries.
 * @returns {Promise<number>} The total count.
 */
export async function getCount() {
  return await count("passwords");
}

/**
 * Updates the last_accessed timestamp for an entry.
 * @param {number} id - The entry ID.
 * @returns {Promise<void>}
 */
export async function updateLastAccessed(id) {
  await runQuery("UPDATE passwords SET last_accessed = ? WHERE id = ?", [
    new Date().toISOString(),
    id,
  ]);
}

/**
 * Gets all unique service names.
 * @returns {Promise<string[]>} Array of unique service names.
 */
export async function getUniqueServices() {
  const rows = await getAllRows(
    "SELECT DISTINCT service FROM passwords ORDER BY service ASC"
  );
  return rows.map((row) => row.service);
}

