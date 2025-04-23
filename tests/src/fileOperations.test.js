import { jest } from "@jest/globals";
import fs from "fs";
import path from "path";

// Set NODE_ENV to test to use test paths
process.env.NODE_ENV = "test";

// Create the test directory if it doesn't exist
const TEST_DIR = path.join(process.cwd(), "test_data");
if (!fs.existsSync(TEST_DIR)) {
  fs.mkdirSync(TEST_DIR, { recursive: true });
}

// Import after setting NODE_ENV
import { PATHS, FILE_LOCK } from "../../src/constants.js";

// Verify we're using test paths
// console.log("Test paths being used:", PATHS);

// Create spies for fs functions
jest.spyOn(fs, "existsSync");
jest.spyOn(fs, "readFile");
jest.spyOn(fs, "writeFile");
jest.spyOn(fs, "rename");
jest.spyOn(fs, "unlinkSync");

// Mock error handler
jest.mock("../../src/errorHandler.js", () => {
  const orig = jest.requireActual("../../src/errorHandler.js");
  return {
    ...orig,
    handleError: jest.fn(),
  };
});

// Now import the file operations module
import {
  readLines,
  writeLines,
  readMasterPassword,
  writeMasterPassword,
  getAppNames,
  createPasswordsFile,
} from "../../src/fileOperations";

describe("File Operations", () => {
  beforeEach(() => {
    // Reset all mocks
    jest.clearAllMocks();

    // Clean up any test files from previous runs
    [
      PATHS.PASSWORDS,
      PATHS.PASSWORDS_BACKUP,
      PATHS.MASTER_PASSWORD,
      PATHS.MASTER_PASSWORD_BACKUP,
      FILE_LOCK.LOCK_FILE,
    ].forEach((filePath) => {
      if (fs.existsSync(filePath)) {
        try {
          fs.unlinkSync(filePath);
        } catch (error) {
          console.error(`Failed to clean up file: ${filePath}`, error);
        }
      }
    });
  });

  afterAll(() => {
    // Clean up the test directory
    try {
      if (fs.existsSync(TEST_DIR)) {
        const files = fs.readdirSync(TEST_DIR);
        files.forEach((file) => {
          const filePath = path.join(TEST_DIR, file);
          if (fs.existsSync(filePath)) {
            fs.unlinkSync(filePath);
          }
        });

        // Try to remove the test directory itself
        try {
          fs.rmdirSync(TEST_DIR);
        } catch (error) {
          console.error("Failed to remove test directory", error);
        }
      }
    } catch (error) {
      console.error("Error cleaning up test directory:", error);
    }
  });

  // --- Tests for createPasswordsFile ---
  describe("createPasswordsFile", () => {
    it("should create the passwords file if it doesn't exist", async () => {
      const result = await createPasswordsFile();

      expect(result).toBe(true);
      expect(fs.existsSync(PATHS.PASSWORDS)).toBe(true);
      const fileContent = fs.readFileSync(PATHS.PASSWORDS, "utf8");
      expect(fileContent).toBe("");
    });

    it("should return false if the passwords file already exists", async () => {
      // Create the file first
      await fs.promises.writeFile(PATHS.PASSWORDS, "some content");

      const result = await createPasswordsFile();

      expect(result).toBe(false);
      expect(fs.existsSync(PATHS.PASSWORDS)).toBe(true);
    });
  });

  // --- Tests for readLines ---
  describe("readLines", () => {
    it("should read passwords from the file if it exists", async () => {
      // Create test data
      const testData = "App1 - user1 - pass1\nApp2 - user2 - pass2\n";
      await fs.promises.writeFile(PATHS.PASSWORDS, testData);

      const result = await readLines();

      expect(result).toEqual(["App1 - user1 - pass1", "App2 - user2 - pass2"]);
    });

    it("should return an empty array if the passwords file is empty", async () => {
      // Create empty file
      await fs.promises.writeFile(PATHS.PASSWORDS, "");

      const result = await readLines();

      expect(result).toEqual([]);
    });

    it("should filter out empty lines from the passwords file", async () => {
      // Create test data with empty lines
      const testData = "App1 - user1 - pass1\n\nApp2 - user2 - pass2\n  \n";
      await fs.promises.writeFile(PATHS.PASSWORDS, testData);

      const result = await readLines();

      expect(result).toEqual(["App1 - user1 - pass1", "App2 - user2 - pass2"]);
    });
  });

  // --- Tests for writeLines ---
  describe("writeLines", () => {
    it("should write passwords to the file", async () => {
      const passwordsToWrite = ["App1 - user1 - pass1", "App2 - user2 - pass2"];
      const expectedData = "App1 - user1 - pass1\nApp2 - user2 - pass2\n";

      await writeLines(passwordsToWrite);

      expect(fs.existsSync(PATHS.PASSWORDS)).toBe(true);
      const fileContent = fs.readFileSync(PATHS.PASSWORDS, "utf8");
      expect(fileContent).toBe(expectedData);
    });

    it("should create a backup if the file already exists", async () => {
      // Create original file
      const originalData = "Original - data - value\n";
      await fs.promises.writeFile(PATHS.PASSWORDS, originalData);

      // Now write new data
      const passwordsToWrite = ["App1 - user1 - pass1"];
      await writeLines(passwordsToWrite);

      // Check backup exists with original content
      expect(fs.existsSync(PATHS.PASSWORDS_BACKUP)).toBe(true);
      const backupContent = fs.readFileSync(PATHS.PASSWORDS_BACKUP, "utf8");
      expect(backupContent).toBe(originalData);

      // Check main file has new content
      const fileContent = fs.readFileSync(PATHS.PASSWORDS, "utf8");
      expect(fileContent).toBe("App1 - user1 - pass1\n");
    });

    it("should handle an empty passwords array", async () => {
      const passwordsToWrite = [];

      await writeLines(passwordsToWrite);

      expect(fs.existsSync(PATHS.PASSWORDS)).toBe(true);
      const fileContent = fs.readFileSync(PATHS.PASSWORDS, "utf8");
      expect(fileContent).toBe("\n");
    });
  });

  // --- Tests for readMasterPassword ---
  describe("readMasterPassword", () => {
    it("should return empty string if master password file does not exist", async () => {
      // Make sure the file doesn't exist
      if (fs.existsSync(PATHS.MASTER_PASSWORD)) {
        fs.unlinkSync(PATHS.MASTER_PASSWORD);
      }

      const result = await readMasterPassword();

      expect(result).toBe("");
      // After calling the function, it should create an empty file
      expect(fs.existsSync(PATHS.MASTER_PASSWORD)).toBe(true);
    });

    it("should read the master password from the file", async () => {
      // Create a test file with a password and checksum
      const password = "testMasterPassword";
      // We need to properly format the file with password and checksum
      // For simplicity, we'll call writeMasterPassword to create it
      await writeMasterPassword(password);

      const result = await readMasterPassword();

      expect(result).toBe(password);
    });
  });

  // --- Tests for writeMasterPassword ---
  describe("writeMasterPassword", () => {
    it("should write the master password to the file", async () => {
      const password = "newMasterPassword";

      await writeMasterPassword(password);

      expect(fs.existsSync(PATHS.MASTER_PASSWORD)).toBe(true);
      // Should contain the password (and checksum)
      const fileContent = fs.readFileSync(PATHS.MASTER_PASSWORD, "utf8");
      expect(fileContent.includes(password)).toBe(true);
    });

    it("should create a backup if master password file exists", async () => {
      // Create the original file
      const originalPassword = "originalMasterPass";
      await writeMasterPassword(originalPassword);

      // Now update with new password
      const newPassword = "updatedMasterPass";
      await writeMasterPassword(newPassword);

      // Check backup exists
      expect(fs.existsSync(PATHS.MASTER_PASSWORD_BACKUP)).toBe(true);
      const backupContent = fs.readFileSync(
        PATHS.MASTER_PASSWORD_BACKUP,
        "utf8"
      );
      expect(backupContent.includes(originalPassword)).toBe(true);
    });
  });

  // --- Tests for getAppNames ---
  describe("getAppNames", () => {
    it("should extract unique app names from password lines", () => {
      const lines = [
        "App1 - user1 - pass1",
        "App2 - user2 - pass2",
        "App1 - user3 - pass3", // Duplicate app name
        "App3 - user4 - pass4",
      ];

      const result = getAppNames(lines);

      expect(result).toEqual(["App1", "App2", "App3"]);
      expect(result.length).toBe(3); // Should only have unique app names
    });

    it("should return an empty array for empty input", () => {
      const result = getAppNames([]);

      expect(result).toEqual([]);
    });

    it("should handle malformed input lines gracefully", () => {
      const lines = [
        "App1 - user1 - pass1",
        "MalformedLine", // No separator
        " - user2 - pass2", // Missing app name
      ];

      const result = getAppNames(lines);

      expect(result).toContain("App1");
      expect(result).toContain("MalformedLine");
      expect(result).toContain("");
    });
  });
});
