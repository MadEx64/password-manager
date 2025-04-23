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
import { PATHS } from "../../src/constants.js";

// Verify we're using test paths
console.log("Test paths being used:", PATHS);

import {
  authenticateUser,
  updateMasterPassword,
} from "../../src/authentication.js";
import { readMasterPassword } from "../../src/fileOperations.js";

// Mock inquirer prompt
const mockPrompt = jest.fn();
jest.mock("inquirer", () => ({
  prompt: mockPrompt
}));

describe("Authentication", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe("Set Up Master Password", () => {
    it("should set up master password if it doesn't exist", async () => {
      // Mock inquirer prompt
      mockPrompt.mockResolvedValue({
        newPassword: "password",
        confirmPassword: "password",
      });

      const result = await authenticateUser();
      // Check that the master password was set
      const masterPassword = await readMasterPassword();
      expect(masterPassword).toBe("password");
      expect(result).toBe(true);
      expect(mockPrompt).toHaveBeenCalledWith([
        {
          type: "password",
          name: "newPassword",
          message: "Enter your master password:",
          mask: "*",
        },
        {
          type: "password",
          name: "confirmPassword",
          message: "Confirm your new master password:",
          mask: "*",
        },
      ]);
    });
  });

  describe("Authenticate User", () => {
    it("should authenticate user with correct master password", async () => {
      // Mock inquirer prompt
      mockPrompt.mockResolvedValue({
        newPassword: "password",
      });

      const result = await authenticateUser();
      expect(result).toBe(true);
      expect(mockPrompt).toHaveBeenCalledWith([
        {
          type: "password",
          name: "newPassword",
          message: "Enter your master password:",
          mask: "*",
        },
      ]);
    });
  });

  describe("Authenticate User", () => {
    it("should not authenticate user with incorrect master password", async () => {
      // Mock inquirer prompt
      mockPrompt.mockResolvedValue({
        newPassword: "incorrectPassword",
      });

      const result = await authenticateUser();
      expect(result).toBe(false);
      expect(mockPrompt).toHaveBeenCalledWith([
        {
          type: "password",
          name: "newPassword",
          message: "Enter your master password:",
          mask: "*",
        },
      ]);
    });
  });

  describe("Update Master Password", () => {
    it("should update master password", async () => {
      // Mock inquirer prompt
      mockPrompt.mockResolvedValue({
        oldPassword: "oldPassword",
        newPassword: "newPassword",
        confirmPassword: "newPassword",
      });

      const result = await updateMasterPassword();
      // Check that the master password was updated
      const masterPassword = await readMasterPassword();
      expect(masterPassword).toBe("newPassword");
      expect(result).toBe(true);
      expect(mockPrompt).toHaveBeenCalledWith([
        {
          type: "password",
          name: "oldPassword",
          message: "Enter your current master password:",
          mask: "*",
        },
        {
          type: "password",
          name: "newPassword",
          message: "Enter your new master password:",
          mask: "*",
        },
        {
          type: "password",
          name: "confirmPassword",
          message: "Confirm your new master password:",
          mask: "*",
        },
      ]);
    });

    it("should not update master password with incorrect old password", async () => {
      // Mock inquirer prompt
      mockPrompt.mockResolvedValue({
        oldPassword: "incorrectPassword",
        newPassword: "newPassword",
        confirmPassword: "newPassword",
      });

      const result = await updateMasterPassword();
      expect(result).toBe(false);
      expect(mockPrompt).toHaveBeenCalledWith([
        {
          type: "password",
          name: "oldPassword",
          message: "Enter your current master password:",
          mask: "*",
        },
        {
          type: "password",
          name: "newPassword",
          message: "Enter your new master password:",
          mask: "*",
        },
        {
          type: "password",
          name: "confirmPassword",
          message: "Confirm your new master password:",
          mask: "*",
        },
      ]);
    });
  });
});
