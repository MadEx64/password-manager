import fs from "fs";
import os from "os";
import path from "path";
import { log, yellow, red } from "../logger.js";
import { PasswordManagerError } from "../errorHandler.js";
import { ERROR_CODES } from "../constants.js";
import { spawn } from "child_process";
import {
  generateRandomBytes,
  deriveKeyPBKDF2,
  createHashBuffer,
  encryptPassword,
  decryptPassword,
} from "../encryption/index.js";

/**
 * Secure Storage Configuration.
 * 
 * Uses different service names and paths for test vs production to prevent data conflicts.
 */
function getStorageConfig() {
  const isTestMode = process.env.NODE_ENV === "test";

  return {
    SERVICE_NAME: isTestMode
      ? "password-manager-cli-test"
      : "password-manager-cli",
    SECRET_KEY_ACCOUNT: isTestMode ? "test-secret-key" : "secret-key",
    AUTH_HASH_ACCOUNT: isTestMode ? "test-auth-hash" : "auth-hash",
    FALLBACK_DIR: path.join(
      os.homedir(),
      isTestMode ? ".password-manager-secure-test" : ".password-manager-secure"
    ),
    ENCRYPTION_KEY_LENGTH: 32, // 256 bits for AES-256
  };
}

/**
 * Cross-platform secure credential storage using system keychains/credential stores.
 */
class SecureStorage {
  constructor() {
    this.platform = process.platform;
    this.isAvailable = null;
    this.fallbackEncryptionKey = null;
    this.loggedMessages = new Set();
  }

  logOnce(message) {
    if (this.loggedMessages.has(message)) {
      return;
    }
    this.loggedMessages.add(message);
    log(yellow(message));
  }

  /**
   * Checks if secure storage is available on the current platform.
   * @returns {Promise<boolean>}
   */
  async checkAvailability() {
    if (this.isAvailable !== null) {
      return this.isAvailable;
    }

    try {
      switch (this.platform) {
        case "win32":
          this.isAvailable = await this.checkWindowsCredentialManager();
          break;
        case "darwin":
          this.isAvailable = await this.checkMacOSKeychain();
          break;
        case "linux":
          this.isAvailable = await this.checkLinuxSecretService();
          break;
        default:
          this.isAvailable = false;
      }
    } catch (error) {
      this.isAvailable = false;
    }

    return this.isAvailable;
  }

  /**
   * Stores a credential securely using the system's credential store.
   * @param {string} account - The account identifier.
   * @param {string} credential - The credential to store.
   * @returns {Promise<boolean>}
   */
  async storeCredential(account, credential) {
    const isAvailable = await this.checkAvailability();

    if (!isAvailable) {
      log(yellow("⚠️  Secure storage not available, using encrypted file fallback"));
      return await this.storeFallback(account, credential);
    }

    try {
      let stored = false;

      switch (this.platform) {
        case "win32":
          stored = await this.storeWindows(account, credential);
          break;
        case "darwin":
          stored = await this.storeMacOS(account, credential);
          break;
        case "linux":
          stored = await this.storeLinux(account, credential);
          break;
        default:
          log(yellow("⚠️  Platform not supported for secure storage, using encrypted file fallback"));
          return await this.storeFallback(account, credential);
      }

      if (stored) {
        return true;
      }

      this.logOnce("⚠️  Secure storage write failed, falling back to encrypted file storage");
      return await this.storeFallback(account, credential);
    } catch (error) {
      this.logOnce("⚠️  Secure storage failed, falling back to encrypted file storage");
      return await this.storeFallback(account, credential);
    }
  }

  /**
   * Retrieves a credential from the system's credential store.
   * @param {string} account - The account identifier.
   * @returns {Promise<string|null>}
   */
  async retrieveCredential(account) {
    const isAvailable = await this.checkAvailability();

    if (!isAvailable) {
      return await this.retrieveFallback(account);
    }

    try {
      let credential;

      switch (this.platform) {
        case "win32":
          credential = await this.retrieveWindows(account);
          break;
        case "darwin":
          credential = await this.retrieveMacOS(account);
          break;
        case "linux":
          credential = await this.retrieveLinux(account);
          break;
        default:
          return await this.retrieveFallback(account);
      }

      if (credential === null || credential === undefined) {
        this.logOnce("⚠️  Secure storage returned no credential, checking encrypted file fallback");
        return await this.retrieveFallback(account);
      }

      return credential;
    } catch (error) {
      return await this.retrieveFallback(account);
    }
  }

  /**
   * Deletes a credential from the system's credential store.
   * @param {string} account - The account identifier.
   * @returns {Promise<boolean>}
   */
  async deleteCredential(account) {
    const isAvailable = await this.checkAvailability();

    if (!isAvailable) {
      return await this.deleteFallback(account);
    }

    try {
      switch (this.platform) {
        case "win32":
          return await this.deleteWindows(account);
        case "darwin":
          return await this.deleteMacOS(account);
        case "linux":
          return await this.deleteLinux(account);
        default:
          return await this.deleteFallback(account);
      }
    } catch (error) {
      return await this.deleteFallback(account);
    }
  }

  // Windows Credential Manager implementation
  // ----------------------------------------

  /**
   * Checks if Windows Credential Manager is available using PowerShell and DPAPI.
   * @returns {Promise<boolean>}
   */
  async checkWindowsCredentialManager() {
    const testScript = `try { Add-Type -AssemblyName System.Security; $testData = [System.Text.Encoding]::UTF8.GetBytes('test'); $encrypted = [System.Security.Cryptography.ProtectedData]::Protect($testData, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser); Write-Output 'SUCCESS' } catch { Write-Output 'FAILED' }`;

    return new Promise((resolve, reject) => {
      const process = spawn("powershell", [
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-Command", testScript
      ]);

      let result = "";

      process.stdout.on("data", (data) => {
        result += data.toString();
      });

      process.on("close", (code) => {
        resolve(result.trim() === "SUCCESS");
      });

      process.on("error", () => {
        resolve(false);
      });

      // Set timeout
      setTimeout(() => {
        process.kill();
        resolve(false);
      }, 5000);
    });
  }

  /**
   * Stores a credential in Windows Credential Manager using PowerShell and DPAPI.
   * @param {string} account - The account identifier.
   * @param {string} credential - The credential to store.
   * @returns {Promise<boolean>}
   */
  async storeWindows(account, credential) {
    const config = getStorageConfig();
    const storageKey = `${config.SERVICE_NAME}_${account}`;

    const escapeForPowershell = (value) => value.replace(/"/g, "`\"");

    // Create PowerShell script with proper parameter handling
    const script = `
      param([string]$Credential, [string]$StorageKey, [string]$ServiceName, [string]$Account)
      function Ensure-DPApiTypes {
        if (-not ([Type]::GetType('System.Security.Cryptography.DataProtectionScope'))) {
          try { Add-Type -AssemblyName System.Security } catch {}
          try { [System.Reflection.Assembly]::Load('System.Security') | Out-Null } catch {}
          try { [System.Reflection.Assembly]::Load('System.Security.Cryptography.ProtectedData') | Out-Null } catch {}
        }
      }
      try {
        Ensure-DPApiTypes
        $data = [System.Text.Encoding]::UTF8.GetBytes($Credential)
        $entropy = [System.Text.Encoding]::UTF8.GetBytes($StorageKey)
        $encryptedData = [System.Security.Cryptography.ProtectedData]::Protect(
          $data,
          $entropy,
          [System.Security.Cryptography.DataProtectionScope]::CurrentUser
        )
        $base64 = [System.Convert]::ToBase64String($encryptedData)
        $regPath = "HKCU:\\Software\\$ServiceName"
        if (!(Test-Path $regPath)) {
          New-Item -Path $regPath -Force | Out-Null
        }
        Set-ItemProperty -Path $regPath -Name $Account -Value $base64
        Write-Output 'SUCCESS'
      } catch {
        Write-Output "FAILED: $($_.Exception.Message)"
      }
    `;

    const command = `& { ${script} } "${escapeForPowershell(credential)}" "${escapeForPowershell(storageKey)}" "${escapeForPowershell(config.SERVICE_NAME)}" "${escapeForPowershell(account)}"`;

    return new Promise((resolve, reject) => {
      const process = spawn("powershell", [
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-Command", command
      ]);

      let result = "";

      process.stdout.on("data", (data) => {
        result += data.toString();
      });

      process.on("close", (code) => {
        resolve(result.trim().startsWith("SUCCESS"));
      });

      process.on("error", () => {
        resolve(false);
      });

      // Set timeout
      setTimeout(() => {
        process.kill();
        resolve(false);
      }, 10000);
    });
  }

  /**
   * Retrieves a credential from Windows Credential Manager using PowerShell and DPAPI.
   * @param {string} account - The account identifier.
   * @returns {Promise<string|null>}
   */
  async retrieveWindows(account) {
    const config = getStorageConfig();
    const storageKey = `${config.SERVICE_NAME}_${account}`;

    const script = `
      try {
        if (-not ([Type]::GetType('System.Security.Cryptography.DataProtectionScope'))) {
          try { Add-Type -AssemblyName System.Security } catch {}
          try { [System.Reflection.Assembly]::Load('System.Security') | Out-Null } catch {}
          try { [System.Reflection.Assembly]::Load('System.Security.Cryptography.ProtectedData') | Out-Null } catch {}
        }
        $regPath = "HKCU:\\Software\\${config.SERVICE_NAME}"
        if (!(Test-Path $regPath)) {
          Write-Output 'NOT_FOUND'
          exit
        }
        $property = Get-ItemProperty -Path $regPath -ErrorAction Stop
        $base64 = $property."${account}"
        if (!$base64) {
          Write-Output 'NOT_FOUND'
          exit
        }
        $encryptedData = [System.Convert]::FromBase64String($base64)
        $entropy = [System.Text.Encoding]::UTF8.GetBytes("${storageKey}")
        $decryptedData = [System.Security.Cryptography.ProtectedData]::Unprotect(
          $encryptedData,
          $entropy,
          [System.Security.Cryptography.DataProtectionScope]::CurrentUser
        )
        $credential = [System.Text.Encoding]::UTF8.GetString($decryptedData)
        Write-Output $credential
      } catch {
        Write-Output "ERROR: $($_.Exception.Message)"
      }
    `;

    return new Promise((resolve, reject) => {
      const process = spawn("powershell", [
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-Command", script
      ]);

      let result = "";

      process.stdout.on("data", (data) => {
        result += data.toString();
      });

      process.on("close", (code) => {
        const output = result.trim();
        if (output === "NOT_FOUND" || output.startsWith("ERROR:") || output === "") {
          resolve(null);
        } else {
          resolve(output);
        }
      });

      process.on("error", () => {
        resolve(null);
      });

      // Set timeout
      setTimeout(() => {
        process.kill();
        resolve(null);
      }, 10000);
    });
  }

  /**
   * Deletes a credential from Windows Credential Manager using PowerShell and DPAPI.
   * @param {string} account - The account identifier.
   * @returns {Promise<boolean>}
   */
  async deleteWindows(account) {
    const config = getStorageConfig();
    
    const escapeForPowershell = (value) => value.replace(/"/g, "`\"");
    const script = `param([string]$ServiceName, [string]$Account) try { $regPath = "HKCU:\\Software\\$ServiceName" if (!(Test-Path $regPath)) { Write-Output 'NOT_FOUND' exit } Remove-ItemProperty -Path $regPath -Name $Account -ErrorAction Stop Write-Output 'SUCCESS' } catch { Write-Output 'NOT_FOUND' }`;
    const command = `& { ${script} } "${escapeForPowershell(config.SERVICE_NAME)}" "${escapeForPowershell(account)}"`;

    return new Promise((resolve, reject) => {
      const process = spawn("powershell", [
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-Command", command
      ]);

      let result = "";

      process.stdout.on("data", (data) => {
        result += data.toString();
      });

      process.on("close", (code) => {
        resolve(result.trim().startsWith("SUCCESS"));
      });

      process.on("error", () => {
        resolve(false);
      });

      // Set timeout
      setTimeout(() => {
        process.kill();
        resolve(false);
      }, 5000);
    });
  }

  /**
   * macOS Keychain implementation
   * -----------------------------
   */

  /**
   * Checks if macOS Keychain is available.
   * @returns {Promise<boolean>}
   */
  async checkMacOSKeychain() {
    return new Promise((resolve, reject) => {
      const process = spawn("security", ["--help"]);
      
      process.on("close", (code) => {
        resolve(code === 0);
      });
      
      process.on("error", () => {
        resolve(false);
      });
    });
  }

  /**
   * Stores a credential in macOS Keychain.
   * @param {string} account - The account identifier.
   * @param {string} credential - The credential to store.
   * @returns {Promise<boolean>}
   */
  async storeMacOS(account, credential) {
    const config = getStorageConfig();

    try {
      const success = await new Promise((resolve, reject) => {
        const process = spawn("security", [
          "add-generic-password",
          "-s",
          config.SERVICE_NAME,
          "-a",
          account,
          "-w",
          credential,
          "-U",
        ]);

        let errorOutput = "";

        process.stderr.on("data", (data) => {
          errorOutput += data.toString();
        });

        process.on("close", (code) => {
          if (code === 0) {
            resolve(true);
          } else {
            resolve(false);
          }
        });

        process.on("error", (error) => {
          reject(
            new PasswordManagerError(
              red(
                `Failed to store credential in macOS Keychain: ${error.message}`
              ),
              ERROR_CODES.INTERNAL_ERROR
            )
          );
        });
      });

      if (success) {
        return true;
      }
    } catch (error) {
      throw new PasswordManagerError(
        red(`Failed to store credential in macOS Keychain: ${error.message}`),
        ERROR_CODES.INTERNAL_ERROR
      );
    }

    // If update didn't succeed, try adding new entry
    return new Promise((resolve, reject) => {
      const process = spawn("security", [
        "add-generic-password",
        "-s",
        config.SERVICE_NAME,
        "-a",
        account,
        "-w",
        credential,
      ]);

      let errorOutput = "";

      process.stderr.on("data", (data) => {
        errorOutput += data.toString();
      });

      process.on("close", (code) => {
        if (code === 0) {
          resolve(true);
        } else {
          reject(
            new PasswordManagerError(
              red(`Failed to add keychain entry: ${errorOutput}`),
              ERROR_CODES.INTERNAL_ERROR
            )
          );
        }
      });

      process.on("error", (err) => {
        reject(
          new PasswordManagerError(
            red(`Failed to add keychain entry: ${err.message}`),
            ERROR_CODES.INTERNAL_ERROR
          )
        );
      });
    });
  }

  /**
   * Retrieves a credential from macOS Keychain.
   * @param {string} account - The account identifier.
   * @returns {Promise<string|null>}
   */
  async retrieveMacOS(account) {
    const config = getStorageConfig();

    return new Promise((resolve, reject) => {
      const process = spawn("security", [
        "find-generic-password",
        "-s",
        config.SERVICE_NAME,
        "-a",
        account,
        "-w",
      ]);

      let result = "";
      let errorOutput = "";

      process.stdout.on("data", (data) => {
        result += data.toString();
      });

      process.stderr.on("data", (data) => {
        errorOutput += data.toString();
      });

      process.on("close", (code) => {
        if (code === 0) {
          resolve(result.trim());
        } else {
          resolve(null);
        }
      });

      process.on("error", (err) => {
        reject(
          new PasswordManagerError(
            red(`Failed to retrieve credential from macOS Keychain: ${err.message}`),
            ERROR_CODES.INTERNAL_ERROR
          )
        );
      });
    });
  }

  /**
   * Deletes a credential from macOS Keychain.
   * @param {string} account - The account identifier.
   * @returns {Promise<boolean>}
   */
  async deleteMacOS(account) {
    const config = getStorageConfig();

    return new Promise((resolve, reject) => {
      const process = spawn("security", [
        "delete-generic-password",
        "-s",
        config.SERVICE_NAME,
        "-a",
        account,
      ]);

      let errorOutput = "";

      process.stderr.on("data", (data) => {
        errorOutput += data.toString();
      });

      process.on("close", (code) => {
        if (code === 0) {
          resolve(true);
        } else {
          reject(
            new PasswordManagerError(
              red(`Failed to delete credential from macOS Keychain: ${errorOutput}`),
              ERROR_CODES.INTERNAL_ERROR
            )
          );
        }
      });

      process.on("error", (err) => {
        reject(
          new PasswordManagerError(
            red(`Failed to delete credential from macOS Keychain: ${err.message}`),
            ERROR_CODES.INTERNAL_ERROR
          )
        );
      });
    });
  }

  // Linux Secret Service implementation
  // ------------------------------------

  /**
   * Checks if Linux Secret Service is available.
   * @returns {Promise<boolean>}
   */
  async checkLinuxSecretService() {
    return new Promise((resolve, reject) => {
      const process = spawn("which", ["secret-tool"]);
      
      process.on("close", (code) => {
        resolve(code === 0);
      });
      
      process.on("error", () => {
        resolve(false);
      });
    });
  }

  /**
   * Stores a credential in Linux Secret Service.
   * @param {string} account - The account identifier.
   * @param {string} credential - The credential to store.
   * @returns {Promise<boolean>}
   */
  async storeLinux(account, credential) {
    const config = getStorageConfig();
    const process = spawn("secret-tool", [
      "store",
      "--label",
      `${config.SERVICE_NAME}:${account}`,
      "service",
      config.SERVICE_NAME,
      "account",
      account,
    ]);

    process.stdin.write(credential);
    process.stdin.end();

    return new Promise((resolve, reject) => {
      process.on("close", (code) => {
        resolve(code === 0);
      });
      process.on("error", reject);
    });
  }

  /**
   * Retrieves a credential from Linux Secret Service.
   * @param {string} account - The account identifier.
   * @returns {Promise<string|null>}
   */
  async retrieveLinux(account) {
    const config = getStorageConfig();
    
    return new Promise((resolve, reject) => {
      const process = spawn("secret-tool", [
        "lookup",
        "service", config.SERVICE_NAME,
        "account", account
      ]);

      let result = "";
      let errorOutput = "";

      process.stdout.on("data", (data) => {
        result += data.toString();
      });

      process.stderr.on("data", (data) => {
        errorOutput += data.toString();
      });

      process.on("close", (code) => {
        if (code === 0) {
          resolve(result.trim() || null);
        } else {
          resolve(null);
        }
      });

      process.on("error", (err) => {
        reject(new PasswordManagerError(
          red(`Failed to retrieve credential from Linux Secret Service: ${err.message}`),
          ERROR_CODES.INTERNAL_ERROR
        ));
      });
    });
  }

  /**
   * Deletes a credential from Linux Secret Service.
   * @param {string} account - The account identifier.
   * @returns {Promise<boolean>}
   */
  async deleteLinux(account) {
    const config = getStorageConfig();
    
    return new Promise((resolve, reject) => {
      const process = spawn("secret-tool", [
        "clear",
        "service", config.SERVICE_NAME,
        "account", account
      ]);

      let errorOutput = "";

      process.stderr.on("data", (data) => {
        errorOutput += data.toString();
      });

      process.on("close", (code) => {
        if (code === 0) {
          resolve(true);
        } else {
          resolve(false);
        }
      });

      process.on("error", (err) => {
        reject(new PasswordManagerError(
          red(`Failed to delete credential from Linux Secret Service: ${err.message}`),
          ERROR_CODES.INTERNAL_ERROR
        ));
      });
    });
  }

  // Fallback encrypted file storage
  // -------------------------------

  /**
   * Gets the fallback encryption key.
   * @description This is a fallback encryption key for when secure storage is not available.
   * It is stored in a file in the fallback directory.
   * @returns {Promise<Buffer>}
   */
  async getFallbackEncryptionKey() {
    if (this.fallbackEncryptionKey) {
      return this.fallbackEncryptionKey;
    }

    const config = getStorageConfig();
    const keyPath = path.join(config.FALLBACK_DIR, ".storage_key");

    try {
      try {
        await fs.promises.access(config.FALLBACK_DIR);
      } catch (error) {
        if (error.code === 'ENOENT') {
          await this.createFallbackDirectorySafely(config.FALLBACK_DIR);
        } else {
          throw error;
        }
      }

      try {
        await fs.promises.access(keyPath);
        this.fallbackEncryptionKey = await fs.promises.readFile(keyPath);
        
        if (this.fallbackEncryptionKey.length !== config.ENCRYPTION_KEY_LENGTH) {
          log(yellow("Invalid fallback encryption key length, regenerating..."));
          throw new Error("Invalid key length");
        }
      } catch (error) {
        if (error.code === 'ENOENT' || error.message === "Invalid key length") {
          // Generate new key
          const baseKey = generateRandomBytes(config.ENCRYPTION_KEY_LENGTH);
          const systemSalt = createHashBuffer(
            os.hostname() + os.userInfo().username + process.platform
          );
          const derivedKey = deriveKeyPBKDF2(
            baseKey,
            systemSalt,
            100000,
            32,
            "sha256"
          );

          this.fallbackEncryptionKey = derivedKey;
          await this.writeFileSafely(keyPath, this.fallbackEncryptionKey, { mode: 0o600 });
          log(yellow("Created fallback encryption key for secure storage"));
        } else {
          throw error;
        }
      }
    } catch (error) {
      throw new PasswordManagerError(
        red(`Failed to initialize fallback encryption key: ${error.message}`),
        ERROR_CODES.INTERNAL_ERROR
      );
    }

    return this.fallbackEncryptionKey;
  }

  /**
   * Stores a credential in fallback encrypted file storage.
   * @param {string} account - The account identifier.
   * @param {string} credential - The credential to store.
   * @returns {Promise<boolean>}
   */
  async storeFallback(account, credential) {
    try {
      const config = getStorageConfig();
      const key = await this.getFallbackEncryptionKey();

      // Use authenticated encryption (AES-GCM) instead of CBC
      const encrypted = await encryptPassword(credential, key);

      const data = {
        encrypted,
        mode: "aes-256-gcm",
        version: "2.0",
        timestamp: Date.now(),
      };

      try {
        await fs.promises.access(config.FALLBACK_DIR);
      } catch (error) {
        if (error.code === 'ENOENT') {
          await this.createFallbackDirectorySafely(config.FALLBACK_DIR);
        } else {
          throw error;
        }
      }

      const filePath = path.join(config.FALLBACK_DIR, `${account}.enc`);
      await this.writeFileSafely(filePath, JSON.stringify(data), { mode: 0o600 });

      return true;
    } catch (error) {
      throw new PasswordManagerError(
        red(`Failed to store credential in fallback storage: ${error.message}`),
        ERROR_CODES.INTERNAL_ERROR
      );
    }
  }

  /**
   * Retrieves a credential from fallback encrypted file storage.
   * @param {string} account - The account identifier.
   * @returns {Promise<string|null>}
   */
  async retrieveFallback(account) {
    try {
      const config = getStorageConfig();
      const filePath = path.join(config.FALLBACK_DIR, `${account}.enc`);

      try {
        await fs.promises.access(filePath);
      } catch (error) {
        if (error.code === 'ENOENT') {
          return null;
        }
        throw error;
      }

      const key = await this.getFallbackEncryptionKey();
      const fileData = await fs.promises.readFile(filePath, "utf8");
      const data = JSON.parse(fileData);

      // Use authenticated decryption (AES-GCM)
      const decrypted = await decryptPassword(data.encrypted, key);
      return decrypted;
    } catch (error) {
      return null;
    }
  }

  /**
   * Deletes a credential from fallback encrypted file storage.
   * @param {string} account - The account identifier.
   * @returns {Promise<boolean>}
   */
  async deleteFallback(account) {
    try {
      const config = getStorageConfig();
      const filePath = path.join(config.FALLBACK_DIR, `${account}.enc`);

      try {
        await fs.promises.access(filePath);
        await fs.promises.unlink(filePath);
        return true;
      } catch (error) {
        if (error.code === 'ENOENT') {
          return true; // File doesn't exist, consider it deleted
        }
        return false;
      }
    } catch (error) {
      return false;
    }
  }

  /**
   * Lists all stored credentials (for debugging/management)
   * @returns {Promise<string[]>}
   */
  async listCredentials() {
    const config = getStorageConfig();
    const isAvailable = await this.checkAvailability();

    if (!isAvailable) {
      try {
        await fs.promises.access(config.FALLBACK_DIR);
        const files = await fs.promises.readdir(config.FALLBACK_DIR);
        return files
          .filter((file) => file.endsWith(".enc"))
          .map((file) => file.replace(".enc", ""));
      } catch (error) {
        return [];
      }
    }

    return [config.SECRET_KEY_ACCOUNT, config.AUTH_HASH_ACCOUNT];
  }

  /**
   * Gets storage information and status.
   * @returns {Promise<Object>}
   */
  async getStorageInfo() {
    const config = getStorageConfig();
    const isAvailable = await this.checkAvailability();

    return {
      platform: this.platform,
      secureStorageAvailable: isAvailable,
      storageType: isAvailable
        ? this.getStorageTypeName()
        : "Encrypted File Fallback",
      fallbackDir: config.FALLBACK_DIR,
      serviceName: config.SERVICE_NAME,
    };
  }

  getStorageTypeName() {
    switch (this.platform) {
      case "win32":
        return "Windows DPAPI + Registry";
      case "darwin":
        return "macOS Keychain";
      case "linux":
        return "Linux Secret Service";
      default:
        return "Unknown";
    }
  }

  /**
   * Creates the fallback directory safely with proper error handling.
   * @param {string} dirPath - The directory path to create.
   * @returns {Promise<void>}
   */
  async createFallbackDirectorySafely(dirPath) {
    try {
      // Use recursive mkdir with proper error handling
      await fs.promises.mkdir(dirPath, { 
        mode: 0o700, 
        recursive: true 
      });

      // Verify the directory was created and has correct permissions
      const stats = await fs.promises.stat(dirPath);
      
      if (!stats.isDirectory()) {
        throw new Error("Path exists but is not a directory");
      }

      // Check if it's a symlink (potential security issue)
      const realPath = await fs.promises.realpath(dirPath);
      if (realPath !== dirPath) {
        throw new Error("Directory path is a symlink, which is not allowed for security reasons");
      }

      // Set permissions explicitly (in case umask affected the initial creation)
      await fs.promises.chmod(dirPath, 0o700);
      
      log(yellow(`Created secure storage directory: ${dirPath}`));
    } catch (error) {
      if (error.code === 'EEXIST') {
        // Directory already exists, verify it's safe
        try {
          const stats = await fs.promises.stat(dirPath);
          if (!stats.isDirectory()) {
            throw new Error("Path exists but is not a directory");
          }
          
          const realPath = await fs.promises.realpath(dirPath);
          if (realPath !== dirPath) {
            throw new Error("Directory path is a symlink, which is not allowed for security reasons");
          }
          
          // Ensure proper permissions
          await fs.promises.chmod(dirPath, 0o700);
        } catch (verifyError) {
          throw new PasswordManagerError(
            red(`Fallback directory verification failed: ${verifyError.message}`),
            ERROR_CODES.PERMISSION_DENIED
          );
        }
      } else {
        throw new PasswordManagerError(
          red(`Failed to create fallback directory: ${error.message}`),
          ERROR_CODES.PERMISSION_DENIED
        );
      }
    }
  }

  /**
   * Safely writes a file with atomic operations.
   * @param {string} filePath - The file path to write to.
   * @param {string|Buffer} data - The data to write.
   * @param {object} options - File options.
   * @returns {Promise<void>}
   */
  async writeFileSafely(filePath, data, options = {}) {
    const tempPath = `${filePath}.tmp.${Date.now()}.${Math.random().toString(36).substring(2)}`;
    
    try {
      // Write to temporary file first
      await fs.promises.writeFile(tempPath, data, { 
        mode: options.mode || 0o600,
        flag: 'wx' // Fail if file exists
      });
      
      // Atomic rename
      await fs.promises.rename(tempPath, filePath);
    } catch (error) {
      // Clean up temp file if it exists
      try {
        await fs.promises.unlink(tempPath);
      } catch (cleanupError) {
        // Ignore cleanup errors
      }
      
      throw new PasswordManagerError(
        red(`Failed to write file safely: ${error.message}`),
        ERROR_CODES.INTERNAL_ERROR
      );
    }
  }
}

// Secure Storage Instance
// -----------------------

const secureStorage = new SecureStorage();

// High-level API for secure credential storage
// --------------------------------------------

/**
 * Stores the application secret key securely.
 * @param {string} secretKey - The secret key to store.
 * @returns {Promise<boolean>}
 */
export async function storeAppSecretKey(secretKey) {
  try {
    const config = getStorageConfig();
    const success = await secureStorage.storeCredential(
      config.SECRET_KEY_ACCOUNT,
      secretKey
    );

    return success;
  } catch (error) {
    throw new PasswordManagerError(
      red(`Failed to store application secret key: ${error.message}`),
      ERROR_CODES.INTERNAL_ERROR
    );
  }
}

/**
 * Retrieves the application secret key securely.
 * @returns {Promise<string|null>}
 */
export async function retrieveAppSecretKey() {
  try {
    const config = getStorageConfig();
    return await secureStorage.retrieveCredential(config.SECRET_KEY_ACCOUNT);
  } catch (error) {
    throw new PasswordManagerError(
      red(`Failed to retrieve application secret key: ${error.message}`),
      ERROR_CODES.INTERNAL_ERROR
    );
  }
}

/**
 * Stores the authentication hash securely.
 * @param {string} authHash - The authentication hash to store.
 * @returns {Promise<boolean>}
 */
export async function storeAuthHash(authHash) {
  try {
    const config = getStorageConfig();
    await secureStorage.storeCredential(config.AUTH_HASH_ACCOUNT, authHash);
  } catch (error) {
    throw new PasswordManagerError(
      red(`Failed to store authentication hash: ${error.message}`),
      ERROR_CODES.INTERNAL_ERROR
    );
  }
}

/**
 * Retrieves the authentication hash securely.
 * @returns {Promise<string|null>}
 */
export async function retrieveAuthHash() {
  try {
    const config = getStorageConfig();
    return await secureStorage.retrieveCredential(config.AUTH_HASH_ACCOUNT);
  } catch (error) {
    throw new PasswordManagerError(
      red(`Failed to retrieve authentication hash: ${error.message}`),
      ERROR_CODES.INTERNAL_ERROR
    );
  }
}

/**
 * Deletes the application secret key.
 * @returns {Promise<boolean>}
 */
export async function deleteAppSecretKey() {
  try {
    const config = getStorageConfig();
    return await secureStorage.deleteCredential(config.SECRET_KEY_ACCOUNT);
  } catch (error) {
    throw new PasswordManagerError(
      red(`Failed to delete application secret key: ${error.message}`),
      ERROR_CODES.INTERNAL_ERROR
    );
  }
}

/**
 * Deletes the authentication hash.
 * @returns {Promise<boolean>}
 */
export async function deleteAuthHash() {
  try {
    const config = getStorageConfig();
    return await secureStorage.deleteCredential(config.AUTH_HASH_ACCOUNT);
  } catch (error) {
    throw new PasswordManagerError(
      red(`Failed to delete authentication hash: ${error.message}`),
      ERROR_CODES.INTERNAL_ERROR
    );
  }
}

/**
 * Gets information about the secure storage system.
 * @returns {Promise<Object>}
 */
export async function getSecureStorageInfo() {
  return await secureStorage.getStorageInfo();
}

/**
 * Lists all stored credentials (for debugging).
 * @returns {Promise<string[]>}
 */
export async function listStoredCredentials() {
  return await secureStorage.listCredentials();
}

export default secureStorage;
