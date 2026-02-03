import sqlite3 from "@journeyapps/sqlcipher";
import fs from "fs";
import { PATHS, ERROR_CODES, DATABASE_CONFIG } from "../constants.js";
import { PasswordManagerError } from "../errorHandler.js";
import { red, bold, log, yellow } from "../logger.js";

/**
 * Database connection instance.
 * @type {sqlite3.Database|null}
 */
let db = null;

/**
 * Database initialization state.
 * @type {boolean}
 */
let isInitialized = false;

/**
 * Checks if the database file exists.
 * @returns {boolean} True if database file exists.
 */
export function databaseExists() {
  return fs.existsSync(PATHS.DATABASE);
}

/**
 * Checks if the legacy passwords file exists.
 * @returns {boolean} True if legacy passwords file exists.
 */
export function legacyFileExists() {
  return fs.existsSync(PATHS.PASSWORDS);
}

/**
 * Checks if the migrated passwords file exists.
 * @returns {boolean} True if migrated passwords file exists.
 */
export function migratedFileExists() {
  return fs.existsSync(PATHS.PASSWORDS_MIGRATED);
}

/**
 * Checks if migration is needed (legacy file exists but database doesn't).
 * @returns {boolean} True if migration is needed.
 */
export function needsMigration() {
  return (legacyFileExists() || migratedFileExists()) && !databaseExists();
}

/**
 * Gets the current database instance.
 * @returns {sqlite3.Database|null} The database instance or null if not initialized.
 */
export function getDatabase() {
  return db;
}

/**
 * Checks if the database is initialized.
 * @returns {boolean} True if database is initialized.
 */
export function isDatabaseInitialized() {
  return isInitialized && db !== null;
}

/**
 * Converts encryption key to hex string for SQLCipher.
 * @param {Buffer} key - The encryption key buffer.
 * @returns {string} Hex-encoded key string.
 */
function keyToHex(key) {
  return key.toString("hex");
}

/**
 * Opens and initializes the database connection with SQLCipher encryption.
 * @param {Buffer} encryptionKey - The encryption key for SQLCipher.
 * @returns {Promise<sqlite3.Database>} The initialized database instance.
 * @throws {PasswordManagerError} If database connection fails.
 */
export async function openDatabase(encryptionKey) {
  if (db && isInitialized) {
    return db;
  }

  return new Promise((resolve, reject) => {
    const dbPath = PATHS.DATABASE;
    const hexKey = keyToHex(encryptionKey);

    db = new sqlite3.Database(dbPath, (err) => {
      if (err) {
        reject(
          new PasswordManagerError(
            red("Failed to open database: " + err.message),
            bold(red(ERROR_CODES.DATABASE_CONNECTION_FAILED))
          )
        );
        return;
      }

      // Configure SQLCipher encryption
      db.serialize(() => {
        db.run(`PRAGMA key = "x'${hexKey}'"`, (err) => {
          if (err) {
            reject(
              new PasswordManagerError(
                red("Failed to set database encryption key: " + err.message),
                bold(red(ERROR_CODES.DATABASE_CONNECTION_FAILED))
              )
            );
            return;
          }
        });

        // Verify encryption is working
        db.get("SELECT count(*) FROM sqlite_master", (err) => {
          if (err) {
            reject(
              new PasswordManagerError(
                red("Database encryption verification failed: " + err.message),
                bold(red(ERROR_CODES.DATABASE_CONNECTION_FAILED))
              )
            );
            return;
          }

          isInitialized = true;
          resolve(db);
        });
      });
    });
  });
}

/**
 * Creates a new encrypted database with the initial schema.
 * @param {Buffer} encryptionKey - The encryption key for SQLCipher.
 * @returns {Promise<sqlite3.Database>} The initialized database instance.
 * @throws {PasswordManagerError} If database creation fails.
 */
export async function createDatabase(encryptionKey) {
  return new Promise((resolve, reject) => {
    const dbPath = PATHS.DATABASE;
    const hexKey = keyToHex(encryptionKey);

    db = new sqlite3.Database(dbPath, (err) => {
      if (err) {
        reject(
          new PasswordManagerError(
            red("Failed to create database: " + err.message),
            bold(red(ERROR_CODES.DATABASE_ERROR))
          )
        );
        return;
      }

      db.serialize(() => {
        // Set encryption key
        db.run(`PRAGMA key = "x'${hexKey}'"`, (err) => {
          if (err) {
            reject(
              new PasswordManagerError(
                red("Failed to set database encryption key: " + err.message),
                bold(red(ERROR_CODES.DATABASE_ERROR))
              )
            );
            return;
          }
        });

        // Create passwords table
        db.run(
          `CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            service TEXT NOT NULL,
            identifier TEXT NOT NULL,
            encrypted_password TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            last_accessed TEXT,
            UNIQUE(service, identifier)
          )`,
          (err) => {
            if (err) {
              reject(
                new PasswordManagerError(
                  red("Failed to create passwords table: " + err.message),
                  bold(red(ERROR_CODES.DATABASE_ERROR))
                )
              );
              return;
            }
          }
        );

        // Create indexes
        db.run(
          "CREATE INDEX IF NOT EXISTS idx_passwords_service ON passwords(service)",
          (err) => {
            if (err) {
              log(yellow("Warning: Failed to create service index"));
            }
          }
        );

        db.run(
          "CREATE INDEX IF NOT EXISTS idx_passwords_identifier ON passwords(identifier)",
          (err) => {
            if (err) {
              log(yellow("Warning: Failed to create identifier index"));
            }
          }
        );

        db.run(
          "CREATE INDEX IF NOT EXISTS idx_passwords_updated ON passwords(updated_at)",
          (err) => {
            if (err) {
              log(yellow("Warning: Failed to create updated_at index"));
            }
          }
        );

        // Create migrations table for tracking schema versions
        db.run(
          `CREATE TABLE IF NOT EXISTS migrations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            version INTEGER NOT NULL UNIQUE,
            applied_at TEXT NOT NULL,
            description TEXT
          )`,
          (err) => {
            if (err) {
              reject(
                new PasswordManagerError(
                  red("Failed to create migrations table: " + err.message),
                  bold(red(ERROR_CODES.DATABASE_ERROR))
                )
              );
              return;
            }
          }
        );

        // Insert initial migration record
        db.run(
          `INSERT OR IGNORE INTO migrations (version, applied_at, description) VALUES (?, ?, ?)`,
          [
            DATABASE_CONFIG.SCHEMA_VERSION,
            new Date().toISOString(),
            "Initial schema creation",
          ],
          (err) => {
            if (err) {
              log(yellow("Warning: Failed to record initial migration"));
            }

            isInitialized = true;
            resolve(db);
          }
        );
      });
    });
  });
}

/**
 * Closes the database connection.
 * @returns {Promise<void>}
 */
export async function closeDatabase() {
  return new Promise((resolve, reject) => {
    if (!db) {
      resolve();
      return;
    }

    db.close((err) => {
      if (err) {
        reject(
          new PasswordManagerError(
            red("Failed to close database: " + err.message),
            bold(red(ERROR_CODES.DATABASE_ERROR))
          )
        );
        return;
      }

      db = null;
      isInitialized = false;
      resolve();
    });
  });
}

/**
 * Runs a SQL query with parameters.
 * @param {string} sql - The SQL query to run.
 * @param {Array} params - The parameters for the query.
 * @returns {Promise<{lastID: number, changes: number}>} The result of the query.
 * @throws {PasswordManagerError} If the query fails.
 */
export async function runQuery(sql, params = []) {
  return new Promise((resolve, reject) => {
    if (!db) {
      reject(
        new PasswordManagerError(
          red("Database not initialized"),
          bold(red(ERROR_CODES.DATABASE_ERROR))
        )
      );
      return;
    }

    db.run(sql, params, function (err) {
      if (err) {
        reject(
          new PasswordManagerError(
            red("Database query failed: " + err.message),
            bold(red(ERROR_CODES.DATABASE_ERROR))
          )
        );
        return;
      }

      resolve({ lastID: this.lastID, changes: this.changes });
    });
  });
}

/**
 * Gets a single row from a SQL query.
 * @param {string} sql - The SQL query to run.
 * @param {Array} params - The parameters for the query.
 * @returns {Promise<Object|undefined>} The result row or undefined.
 * @throws {PasswordManagerError} If the query fails.
 */
export async function getRow(sql, params = []) {
  return new Promise((resolve, reject) => {
    if (!db) {
      reject(
        new PasswordManagerError(
          red("Database not initialized"),
          bold(red(ERROR_CODES.DATABASE_ERROR))
        )
      );
      return;
    }

    db.get(sql, params, (err, row) => {
      if (err) {
        reject(
          new PasswordManagerError(
            red("Database query failed: " + err.message),
            bold(red(ERROR_CODES.DATABASE_ERROR))
          )
        );
        return;
      }

      resolve(row);
    });
  });
}

/**
 * Gets all rows from a SQL query.
 * @param {string} sql - The SQL query to run.
 * @param {Array} params - The parameters for the query.
 * @returns {Promise<Array>} The result rows.
 * @throws {PasswordManagerError} If the query fails.
 */
export async function getAllRows(sql, params = []) {
  return new Promise((resolve, reject) => {
    if (!db) {
      reject(
        new PasswordManagerError(
          red("Database not initialized"),
          bold(red(ERROR_CODES.DATABASE_ERROR))
        )
      );
      return;
    }

    db.all(sql, params, (err, rows) => {
      if (err) {
        reject(
          new PasswordManagerError(
            red("Database query failed: " + err.message),
            bold(red(ERROR_CODES.DATABASE_ERROR))
          )
        );
        return;
      }

      resolve(rows || []);
    });
  });
}

/**
 * Executes multiple SQL statements in a transaction.
 * @param {Function} callback - The callback function that executes queries.
 * @returns {Promise<void>}
 * @throws {PasswordManagerError} If the transaction fails.
 */
export async function runTransaction(callback) {
  await runQuery("BEGIN TRANSACTION");

  try {
    await callback();
    await runQuery("COMMIT");
  } catch (error) {
    await runQuery("ROLLBACK");
    throw error;
  }
}

/**
 * Gets the count of rows in a table.
 * @param {string} table - The table name.
 * @returns {Promise<number>} The count of rows.
 */
export async function count(table) {
  const result = await getRow(`SELECT COUNT(*) as count FROM ${table}`);
  return result ? result.count : 0;
}

/**
 * Deletes the database file.
 * @returns {Promise<void>}
 * @throws {PasswordManagerError} If deletion fails.
 */
export async function deleteDatabase() {
  await closeDatabase();

  return new Promise((resolve, reject) => {
    if (!fs.existsSync(PATHS.DATABASE)) {
      resolve();
      return;
    }

    fs.unlink(PATHS.DATABASE, (err) => {
      if (err) {
        reject(
          new PasswordManagerError(
            red("Failed to delete database file: " + err.message),
            bold(red(ERROR_CODES.DATABASE_ERROR))
          )
        );
        return;
      }

      resolve();
    });
  });
}

