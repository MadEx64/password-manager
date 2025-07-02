import { jest } from "@jest/globals";
import fs from "fs";
import os from "os";
import path from "path";

// Set NODE_ENV to test to use test paths
process.env.NODE_ENV = "test";

// Create the test directory if it doesn't exist
const TEST_DIR = path.join(process.cwd(), "test_data");
if (!fs.existsSync(TEST_DIR)) {
  fs.mkdirSync(TEST_DIR, { recursive: true });
}

// Mock external dependencies before importing the module
jest.mock("inquirer");
jest.mock("fs", () => ({
  promises: {
    access: jest.fn().mockRejectedValue(new Error("File not found")),
    writeFile: jest.fn().mockResolvedValue(undefined),
  },
  readFileSync: jest.fn().mockReturnValue(""),
}));
jest.mock("os");

// Mock the auth and file operations modules
jest.mock("../../src/auth/index.js", () => ({
  authenticateUser: jest.fn().mockResolvedValue(true),
}));

jest.mock("../../src/auth/masterPasswordCache.js", () => ({
  getEncryptionKey: jest.fn().mockResolvedValue("test-encryption-key"),
}));

jest.mock("../../src/encryption/index.js", () => ({
  decryptPassword: jest.fn().mockImplementation(async (encrypted, key) => `decrypted-${encrypted}`),
  encryptPassword: jest.fn().mockImplementation(async (password, key) => `encrypted-${password}`),
}));

jest.mock("../../src/fileOperations/index.js", () => ({
  readPasswordEntries: jest.fn().mockResolvedValue([]),
  writePasswordEntries: jest.fn().mockResolvedValue(undefined),
}));

jest.mock("../../src/logger.js", () => ({
  green: jest.fn(text => text),
  yellow: jest.fn(text => text),
  red: jest.fn(text => text),
  log: jest.fn(),
}));

jest.mock("../../src/errorHandler.js", () => ({
  handleError: jest.fn(),
}));

jest.mock("../../src/validation.js", () => ({
  default: {
    validatePasswordEntry: jest.fn().mockReturnValue(true),
    validateNonEmptyInput: jest.fn().mockReturnValue(true),
  },
}));

// Import after mocking
import {
  exportPasswordsToJSON,
  importPasswordsFromJSON,
  exportPasswordsToCSV,
  importPasswordsFromCSV,
  handleExportPasswords,
  handleImportPasswords,
} from "../../src/exportImportOperations.js";

import inquirer from "inquirer";
import { authenticateUser } from "../../src/auth/index.js";
import { readPasswordEntries, writePasswordEntries } from "../../src/fileOperations/index.js";
import { log } from "../../src/logger.js";
import { handleError } from "../../src/errorHandler.js";

describe("ExportImportOperations", () => {
  beforeEach(() => {
    // Reset mock call counts but keep implementations
    jest.clearAllMocks();
  });

  describe("exportPasswordsToJSON", () => {
    it("should return false if user authentication fails", async () => {
      authenticateUser.mockResolvedValueOnce(false);

      const result = await exportPasswordsToJSON();

      expect(result).toBe(false);
      expect(authenticateUser).toHaveBeenCalled();
    });

    it("should return false when no passwords exist to export", async () => {
      authenticateUser.mockResolvedValueOnce(true);
      readPasswordEntries.mockResolvedValueOnce([]);

      const result = await exportPasswordsToJSON();

      expect(result).toBe(false);
      expect(log).toHaveBeenCalledWith(expect.stringContaining("No passwords to export"));
    });

    it("should successfully export passwords to JSON format", async () => {
      const mockEntries = [
        {
          service: "Gmail",
          identifier: "user@example.com",
          password: "encrypted-password-1",
          createdAt: "2023-01-01T00:00:00.000Z",
          updatedAt: "2023-01-01T00:00:00.000Z",
        },
      ];

      authenticateUser.mockResolvedValueOnce(true);
      readPasswordEntries.mockResolvedValueOnce(mockEntries);
      inquirer.prompt.mockResolvedValueOnce({ exportPath: "/tmp/export.json" });

      const result = await exportPasswordsToJSON();

      expect(result).toBe(true);
      expect(fs.promises.writeFile).toHaveBeenCalledWith(
        "/tmp/export.json",
        expect.stringContaining('"service": "Gmail"'),
        "utf8"
      );
    });

    it("should handle user canceling the export operation", async () => {
      const mockEntries = [
        {
          service: "Gmail",
          identifier: "user@example.com",
          password: "encrypted-password-1",
          createdAt: "2023-01-01T00:00:00.000Z",
          updatedAt: "2023-01-01T00:00:00.000Z",
        },
      ];

      authenticateUser.mockResolvedValueOnce(true);
      readPasswordEntries.mockResolvedValueOnce(mockEntries);
      inquirer.prompt
        .mockResolvedValueOnce({ exportPath: "/tmp/export.json" })
        .mockResolvedValueOnce({ action: "Cancel export" });
      
      fs.promises.access.mockResolvedValueOnce(undefined); // File exists

      const result = await exportPasswordsToJSON();

      expect(result).toBe(false);
      expect(log).toHaveBeenCalledWith(expect.stringContaining("Export cancelled"));
    });
  });

  describe("importPasswordsFromJSON", () => {
    it("should return false if user authentication fails", async () => {
      authenticateUser.mockResolvedValueOnce(false);

      const result = await importPasswordsFromJSON();

      expect(result).toBe(false);
      expect(authenticateUser).toHaveBeenCalled();
    });

    it("should return false when JSON file does not exist", async () => {
      authenticateUser.mockResolvedValueOnce(true);
      inquirer.prompt.mockResolvedValueOnce({ importPath: "/tmp/nonexistent.json" });
      
      fs.readFileSync.mockImplementation(() => {
        const error = new Error("File not found");
        error.code = "ENOENT";
        throw error;
      });

      const result = await importPasswordsFromJSON();

      expect(result).toBe(false);
      expect(log).toHaveBeenCalledWith(expect.stringContaining("File does not exist"));
    });

    it("should return false when JSON format is invalid", async () => {
      authenticateUser.mockResolvedValueOnce(true);
      inquirer.prompt.mockResolvedValueOnce({ importPath: "/tmp/invalid.json" });
      fs.readFileSync.mockReturnValue("invalid json content");

      const result = await importPasswordsFromJSON();

      expect(result).toBe(false);
      expect(log).toHaveBeenCalledWith(expect.stringContaining("Invalid JSON format"));
    });

    it("should successfully import new passwords from valid JSON", async () => {
      const importData = [
        {
          service: "NewService",
          identifier: "new@example.com",
          password: "new-password",
          createdAt: "2023-01-01T00:00:00.000Z",
          updatedAt: "2023-01-01T00:00:00.000Z",
        },
      ];

      authenticateUser.mockResolvedValueOnce(true);
      readPasswordEntries.mockResolvedValueOnce([]);
      inquirer.prompt.mockResolvedValueOnce({ importPath: "/tmp/import.json" });
      fs.readFileSync.mockReturnValue(JSON.stringify(importData));

      const result = await importPasswordsFromJSON();

      expect(result).toBe(true);
      expect(writePasswordEntries).toHaveBeenCalledWith([
        expect.objectContaining({
          service: "NewService",
          identifier: "new@example.com",
          password: "encrypted-new-password",
        }),
      ]);
    });
  });

  describe("exportPasswordsToCSV", () => {
    it("should return false if user authentication fails", async () => {
      authenticateUser.mockResolvedValueOnce(false);

      const result = await exportPasswordsToCSV();

      expect(result).toBe(false);
      expect(authenticateUser).toHaveBeenCalled();
    });

    it("should successfully export passwords to CSV format", async () => {
      const mockEntries = [
        {
          service: "Gmail",
          identifier: "user@example.com",
          password: "encrypted-password-1",
          createdAt: "2023-01-01T00:00:00.000Z",
          updatedAt: "2023-01-01T00:00:00.000Z",
        },
      ];

      authenticateUser.mockResolvedValueOnce(true);
      readPasswordEntries.mockResolvedValueOnce(mockEntries);
      inquirer.prompt.mockResolvedValueOnce({ exportPath: "/tmp/export.csv" });

      const result = await exportPasswordsToCSV();

      expect(result).toBe(true);
      expect(fs.promises.writeFile).toHaveBeenCalledWith(
        "/tmp/export.csv",
        expect.stringContaining("service,identifier,password,createdAt,updatedAt"),
        "utf8"
      );
    });
  });

  describe("importPasswordsFromCSV", () => {
    it("should return false if user authentication fails", async () => {
      authenticateUser.mockResolvedValueOnce(false);

      const result = await importPasswordsFromCSV();

      expect(result).toBe(false);
      expect(authenticateUser).toHaveBeenCalled();
    });

    it("should successfully import passwords from valid CSV", async () => {
      const csvContent = 
        "service,identifier,password,createdAt,updatedAt\n" +
        "Gmail,user@example.com,password123,2023-01-01T00:00:00.000Z,2023-01-01T00:00:00.000Z";

      authenticateUser.mockResolvedValueOnce(true);
      readPasswordEntries.mockResolvedValueOnce([]);
      inquirer.prompt.mockResolvedValueOnce({ importPath: "/tmp/import.csv" });
      fs.readFileSync.mockReturnValue(csvContent);

      const result = await importPasswordsFromCSV();

      expect(result).toBe(true);
      expect(writePasswordEntries).toHaveBeenCalledWith([
        expect.objectContaining({
          service: "Gmail",
          identifier: "user@example.com",
          password: "encrypted-password123",
        }),
      ]);
    });
  });

  describe("handleExportPasswords", () => {
    it("should return false if user authentication fails", async () => {
      authenticateUser.mockResolvedValueOnce(false);

      const result = await handleExportPasswords();

      expect(result).toBe(false);
      expect(authenticateUser).toHaveBeenCalled();
    });

    it("should handle JSON export format selection", async () => {
      authenticateUser.mockResolvedValueOnce(true);
      inquirer.prompt.mockResolvedValueOnce({ format: "JSON" });
      readPasswordEntries.mockResolvedValueOnce([]);

      const result = await handleExportPasswords();

      expect(result).toBe(false); // No passwords to export
    });

    it("should handle export cancellation", async () => {
      authenticateUser.mockResolvedValueOnce(true);
      inquirer.prompt.mockResolvedValueOnce({ format: "Cancel" });

      const result = await handleExportPasswords();

      expect(result).toBe(false);
      expect(log).toHaveBeenCalledWith(expect.stringContaining("Export cancelled"));
    });
  });

  describe("handleImportPasswords", () => {
    it("should return false if user authentication fails", async () => {
      authenticateUser.mockResolvedValueOnce(false);

      const result = await handleImportPasswords();

      expect(result).toBe(false);
      expect(authenticateUser).toHaveBeenCalled();
    });

    it("should handle JSON import format selection", async () => {
      authenticateUser.mockResolvedValueOnce(true);
      inquirer.prompt
        .mockResolvedValueOnce({ format: "JSON" })
        .mockResolvedValueOnce({ importPath: "/tmp/nonexistent.json" });
      
      fs.readFileSync.mockImplementation(() => {
        const error = new Error("File not found");
        error.code = "ENOENT";
        throw error;
      });

      const result = await handleImportPasswords();

      expect(result).toBe(false);
    });

    it("should handle import cancellation", async () => {
      authenticateUser.mockResolvedValueOnce(true);
      inquirer.prompt.mockResolvedValueOnce({ format: "Cancel" });

      const result = await handleImportPasswords();

      expect(result).toBe(false);
      expect(log).toHaveBeenCalledWith(expect.stringContaining("Import cancelled"));
    });
  });

  describe("Error Handling", () => {
    it("should handle errors gracefully in export operations", async () => {
      authenticateUser.mockResolvedValueOnce(true);
      readPasswordEntries.mockRejectedValueOnce(new Error("Database error"));

      const result = await exportPasswordsToJSON();

      expect(result).toBe(false);
      expect(handleError).toHaveBeenCalledWith(expect.any(Error));
    });

    it("should handle errors gracefully in import operations", async () => {
      authenticateUser.mockResolvedValueOnce(true);
      inquirer.prompt.mockRejectedValueOnce(new Error("Input error"));

      const result = await importPasswordsFromJSON();

      expect(result).toBe(false);
      expect(handleError).toHaveBeenCalledWith(expect.any(Error));
    });
  });

  describe("Integration Tests", () => {
    it("should perform a complete export-import cycle", async () => {
      // Setup: Export some data
      const originalEntries = [
        {
          service: "TestService",
          identifier: "test@example.com",
          password: "encrypted-original-password",
          createdAt: "2023-01-01T00:00:00.000Z",
          updatedAt: "2023-01-01T00:00:00.000Z",
        },
      ];

      const exportedData = JSON.stringify([
        {
          service: "TestService",
          identifier: "test@example.com",
          password: "original-password",
          createdAt: "2023-01-01T00:00:00.000Z",
          updatedAt: "2023-01-01T00:00:00.000Z",
        },
      ]);

      // Test export phase
      authenticateUser.mockResolvedValue(true);
      readPasswordEntries.mockResolvedValueOnce(originalEntries);
      inquirer.prompt.mockResolvedValueOnce({ exportPath: "/tmp/test-export.json" });

      const exportResult = await exportPasswordsToJSON();
      expect(exportResult).toBe(true);

      // Test import phase
      readPasswordEntries.mockResolvedValueOnce([]);
      inquirer.prompt.mockResolvedValueOnce({ importPath: "/tmp/test-export.json" });
      fs.readFileSync.mockReturnValue(exportedData);

      const importResult = await importPasswordsFromJSON();
      expect(importResult).toBe(true);
      expect(writePasswordEntries).toHaveBeenCalledWith([
        expect.objectContaining({
          service: "TestService",
          identifier: "test@example.com",
          password: "encrypted-original-password",
        }),
      ]);
    });
  });
});