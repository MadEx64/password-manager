import { runQuery, getRow } from "../index.js";
import { DATABASE_CONFIG } from "../../constants.js";

export const VERSION = DATABASE_CONFIG.SCHEMA_VERSION;
export const DESCRIPTION = "Initial schema creation with passwords table";

/**
 * Applies the migration (creates initial schema).
 * @returns {Promise<void>}
 */
export async function up() {
  // Create passwords table
  await runQuery(`
    CREATE TABLE IF NOT EXISTS passwords (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      service TEXT NOT NULL,
      identifier TEXT NOT NULL,
      encrypted_password TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      last_accessed TEXT,
      UNIQUE(service, identifier)
    )
  `);

  // Create indexes for performance
  await runQuery(
    "CREATE INDEX IF NOT EXISTS idx_passwords_service ON passwords(service)"
  );
  await runQuery(
    "CREATE INDEX IF NOT EXISTS idx_passwords_identifier ON passwords(identifier)"
  );
  await runQuery(
    "CREATE INDEX IF NOT EXISTS idx_passwords_updated ON passwords(updated_at)"
  );

  // Create migrations tracking table
  await runQuery(`
    CREATE TABLE IF NOT EXISTS migrations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      version INTEGER NOT NULL UNIQUE,
      applied_at TEXT NOT NULL,
      description TEXT
    )
  `);

  // Record this migration
  await runQuery(
    `INSERT OR IGNORE INTO migrations (version, applied_at, description) VALUES (?, ?, ?)`,
    [VERSION, new Date().toISOString(), DESCRIPTION]
  );
}

/**
 * Rolls back the migration (drops tables).
 * @returns {Promise<void>}
 */
export async function down() {
  // Drop indexes first
  await runQuery("DROP INDEX IF EXISTS idx_passwords_service");
  await runQuery("DROP INDEX IF EXISTS idx_passwords_identifier");
  await runQuery("DROP INDEX IF EXISTS idx_passwords_updated");

  // Drop passwords table
  await runQuery("DROP TABLE IF EXISTS passwords");

  // Remove migration record (but keep migrations table for tracking)
  await runQuery("DELETE FROM migrations WHERE version = ?", [VERSION]);
}

/**
 * Checks if this migration has been applied.
 * @returns {Promise<boolean>} True if migration has been applied.
 */
export async function isApplied() {
  try {
    const result = await getRow(
      "SELECT version FROM migrations WHERE version = ?",
      [VERSION]
    );
    return result !== undefined;
  } catch (error) {
    // If migrations table doesn't exist, migration hasn't been applied
    return false;
  }
}

/**
 * Gets the current schema version from the database.
 * @returns {Promise<number>} The current schema version (0 if no migrations applied).
 */
export async function getCurrentVersion() {
  try {
    const result = await getRow(
      "SELECT MAX(version) as version FROM migrations"
    );
    return result?.version || 0;
  } catch (error) {
    return 0;
  }
}
