import fs from "fs";
import os from "os";
import path from "path";
import { exec } from "child_process";
import { promisify } from "util";
import { log, yellow, green, red, bold } from "../logger.js";
import { PasswordManagerError } from "../errorHandler.js";
import { ERROR_CODES } from "../constants.js";
import { spawn } from "child_process";
import { 
  generateRandomBytes, 
  deriveKeyPBKDF2, 
  createHashBuffer,
  encryptAESCBC,
  decryptAESCBC
} from "../encryption/index.js";

const execAsync = promisify(exec);

/**
 * Secure Storage Configuration.
 * Uses different service names and paths for test vs production to prevent data conflicts.
 */
function getStorageConfig() {
  const isTestMode = process.env.NODE_ENV === "test";
  
  return {
    SERVICE_NAME: isTestMode ? "password-manager-cli-test" : "password-manager-cli",
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
    this.isAvailable = null; // Whether secure storage is available on the current platform
    this.fallbackEncryptionKey = null;
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
      return await this.storeFallback(account, credential);
    }

    try {
      switch (this.platform) {
        case "win32":
          return await this.storeWindows(account, credential);
        case "darwin":
          return await this.storeMacOS(account, credential);
        case "linux":
          return await this.storeLinux(account, credential);
        default:
          return await this.storeFallback(account, credential);
      }
    } catch (error) {
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
      switch (this.platform) {
        case "win32":
          return await this.retrieveWindows(account);
        case "darwin":
          return await this.retrieveMacOS(account);
        case "linux":
          return await this.retrieveLinux(account);
        default:
          return await this.retrieveFallback(account);
      }
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
    try {
      const testScript = `try { Add-Type -AssemblyName System.Security; $testData = [System.Text.Encoding]::UTF8.GetBytes('test'); $encrypted = [System.Security.Cryptography.ProtectedData]::Protect($testData, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser); Write-Output 'SUCCESS' } catch { Write-Output 'FAILED' }`;

      const cmd = `powershell -NoProfile -ExecutionPolicy Bypass -Command "${testScript}"`;
      const { stdout } = await execAsync(cmd, { timeout: 5000 });

      if (stdout.trim() === "SUCCESS") {
        return true;
      }

      return false;
    } catch (error) {
      return false;
    }
  }

  /**
   * Stores a credential in Windows Credential Manager using PowerShell and DPAPI.
   * @param {string} account - The account identifier.
   * @param {string} credential - The credential to store.
   * @returns {Promise<boolean>}
   */
  async storeWindows(account, credential) {
    try {
      const config = getStorageConfig();
      const storageKey = `${config.SERVICE_NAME}_${account}`;

      const escapedCredential = credential
        .replace(/'/g, "''")
        .replace(/"/g, '""')
        .replace(/`/g, '``')
        .replace(/\$/g, '`$');

      const script = `try { Add-Type -AssemblyName System.Security; $data = [System.Text.Encoding]::UTF8.GetBytes('${escapedCredential}'); $entropy = [System.Text.Encoding]::UTF8.GetBytes('${storageKey}'); $encryptedData = [System.Security.Cryptography.ProtectedData]::Protect($data, $entropy, [System.Security.Cryptography.DataProtectionScope]::CurrentUser); $base64 = [System.Convert]::ToBase64String($encryptedData); $regPath = 'HKCU:\\Software\\${config.SERVICE_NAME}'; if (!(Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }; Set-ItemProperty -Path $regPath -Name '${account}' -Value $base64; Write-Output 'SUCCESS' } catch { Write-Output "FAILED: $($_.Exception.Message)" }`;

      const cmd = `powershell -NoProfile -ExecutionPolicy Bypass -Command "${script}"`;
      const { stdout } = await execAsync(cmd, { timeout: 10000 });

      if (stdout.trim().startsWith("SUCCESS")) {
        return true;
      } else {
        return false;
      }
    } catch (error) {
      return false;
    }
  }

  /**
   * Retrieves a credential from Windows Credential Manager using PowerShell and DPAPI.
   * @param {string} account - The account identifier.
   * @returns {Promise<string|null>}
   */
  async retrieveWindows(account) {
    try {
      const config = getStorageConfig();
      const storageKey = `${config.SERVICE_NAME}_${account}`;

      const script = `try { Add-Type -AssemblyName System.Security; $regPath = 'HKCU:\\Software\\${config.SERVICE_NAME}'; if (!(Test-Path $regPath)) { Write-Output 'NOT_FOUND'; exit }; $base64 = Get-ItemProperty -Path $regPath -Name '${account}' -ErrorAction Stop | Select-Object -ExpandProperty '${account}'; if (!$base64) { Write-Output 'NOT_FOUND'; exit }; $encryptedData = [System.Convert]::FromBase64String($base64); $entropy = [System.Text.Encoding]::UTF8.GetBytes('${storageKey}'); $decryptedData = [System.Security.Cryptography.ProtectedData]::Unprotect($encryptedData, $entropy, [System.Security.Cryptography.DataProtectionScope]::CurrentUser); $credential = [System.Text.Encoding]::UTF8.GetString($decryptedData); Write-Output $credential } catch { Write-Output 'NOT_FOUND' }`;

      const cmd = `powershell -NoProfile -ExecutionPolicy Bypass -Command "${script}"`;
      const { stdout } = await execAsync(cmd, { timeout: 10000 });

      const result = stdout.trim();
      if (
        result === "NOT_FOUND" ||
        result.startsWith("FAILED:") ||
        result === ""
      ) {
        return null;
      }

      return result;
    } catch (error) {
      return null;
    }
  }

  /**
   * Deletes a credential from Windows Credential Manager using PowerShell and DPAPI.
   * @param {string} account - The account identifier.
   * @returns {Promise<boolean>}
   */
  async deleteWindows(account) {
    try {
      const config = getStorageConfig();
      const script = `try { $regPath = 'HKCU:\\Software\\${config.SERVICE_NAME}'; if (!(Test-Path $regPath)) { Write-Output 'NOT_FOUND'; exit }; Remove-ItemProperty -Path $regPath -Name '${account}' -ErrorAction Stop; Write-Output 'SUCCESS' } catch { Write-Output 'NOT_FOUND' }`;

      const cmd = `powershell -NoProfile -ExecutionPolicy Bypass -Command "${script}"`;
      const { stdout } = await execAsync(cmd, { timeout: 5000 });

      return stdout.trim().startsWith("SUCCESS");
    } catch (error) {
      return false;
    }
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
    try {
      await execAsync("security --help");
      return true;
    } catch (error) {
      return false;
    }
  }

  /**
   * Stores a credential in macOS Keychain.
   * @param {string} account - The account identifier.
   * @param {string} credential - The credential to store.
   * @returns {Promise<boolean>}
   */
  async storeMacOS(account, credential) {
    try {
      const config = getStorageConfig();
      // Try to update existing entry first
      const updateCmd = `security add-generic-password -s "${config.SERVICE_NAME}" -a "${account}" -w "${credential}" -U`;
      await execAsync(updateCmd);
    } catch (error) {
      // If update fails, try to add new entry
      const addCmd = `security add-generic-password -s "${config.SERVICE_NAME}" -a "${account}" -w "${credential}"`;
      await execAsync(addCmd);
    }
    return true;
  }

  /**
   * Retrieves a credential from macOS Keychain.
   * @param {string} account - The account identifier.
   * @returns {Promise<string|null>}
   */
  async retrieveMacOS(account) {
    try {
      const config = getStorageConfig();
      const cmd = `security find-generic-password -s "${config.SERVICE_NAME}" -a "${account}" -w`;
      const { stdout } = await execAsync(cmd);
      return stdout.trim() || null;
    } catch (error) {
      return null;
    }
  }

  /**
   * Deletes a credential from macOS Keychain.
   * @param {string} account - The account identifier.
   * @returns {Promise<boolean>}
   */
  async deleteMacOS(account) {
    try {
      const config = getStorageConfig();
      const cmd = `security delete-generic-password -s "${config.SERVICE_NAME}" -a "${account}"`;
      await execAsync(cmd);
      return true;
    } catch (error) {
      return false;
    }
  }

  // Linux Secret Service implementation
  // ------------------------------------

  /**
   * Checks if Linux Secret Service is available.
   * @returns {Promise<boolean>}
   */
  async checkLinuxSecretService() {
    try {
      await execAsync("which secret-tool");
      return true;
    } catch (error) {
      return false;
    }
  }

  /**
   * Stores a credential in Linux Secret Service.
   * @param {string} account - The account identifier.
   * @param {string} credential - The credential to store.
   * @returns {Promise<boolean>}
   */
  async storeLinux(account, credential) {
    const config = getStorageConfig();
    const process = spawn('secret-tool', [
      'store',
      '--label', `${config.SERVICE_NAME}:${account}`,
      'service', config.SERVICE_NAME,
      'account', account
    ]);
    
    process.stdin.write(credential);
    process.stdin.end();
    
    return new Promise((resolve, reject) => {
      process.on('close', (code) => {
        resolve(code === 0);
      });
      process.on('error', reject);
    });
  }

  /**
   * Retrieves a credential from Linux Secret Service.
   * @param {string} account - The account identifier.
   * @returns {Promise<string|null>}
   */
  async retrieveLinux(account) {
    try {
      const config = getStorageConfig();
      const cmd = `secret-tool lookup service "${config.SERVICE_NAME}" account "${account}"`;
      const { stdout } = await execAsync(cmd);
      return stdout.trim() || null;
    } catch (error) {
      return null;
    }
  }

  /**
   * Deletes a credential from Linux Secret Service.
   * @param {string} account - The account identifier.
   * @returns {Promise<boolean>}
   */
  async deleteLinux(account) {
    try {
      const config = getStorageConfig();
      const cmd = `secret-tool clear service "${config.SERVICE_NAME}" account "${account}"`;
      await execAsync(cmd);
      return true;
    } catch (error) {
      return false;
    }
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
      if (!fs.existsSync(config.FALLBACK_DIR)) {
        fs.mkdirSync(config.FALLBACK_DIR, {
          mode: 0o700,
          recursive: true,
        });
        log(
          yellow(
            `Created secure storage directory: ${config.FALLBACK_DIR}`
          )
        );
      }

      if (fs.existsSync(keyPath)) {
        this.fallbackEncryptionKey = fs.readFileSync(keyPath);
        if (
          this.fallbackEncryptionKey.length !==
          config.ENCRYPTION_KEY_LENGTH
        ) {
          log(
            yellow("Invalid fallback encryption key length, regenerating...")
          );
          throw new Error("Invalid key length");
        }
      } else {
        const baseKey = generateRandomBytes(config.ENCRYPTION_KEY_LENGTH);
        const systemSalt = createHashBuffer(os.hostname() + os.userInfo().username + process.platform);
        const derivedKey = deriveKeyPBKDF2(baseKey, systemSalt, 10000, 32, 'sha256');

        this.fallbackEncryptionKey = derivedKey;

        fs.writeFileSync(keyPath, this.fallbackEncryptionKey, { mode: 0o600 });
        log(yellow("Created fallback encryption key for secure storage"));
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
      const iv = generateRandomBytes(16);

      const encrypted = encryptAESCBC(credential, key, iv);

      const data = {
        encrypted,
        iv: iv.toString("hex"),
        mode: "cbc",
      };

      if (!fs.existsSync(config.FALLBACK_DIR)) {
        fs.mkdirSync(config.FALLBACK_DIR, {
          mode: 0o700,
          recursive: true,
        });
      }

      const filePath = path.join(config.FALLBACK_DIR, `${account}.enc`);
      fs.writeFileSync(filePath, JSON.stringify(data), { mode: 0o600 });

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

      if (!fs.existsSync(filePath)) {
        return null;
      }

      const key = await this.getFallbackEncryptionKey();
      const data = JSON.parse(fs.readFileSync(filePath, "utf8"));

      const decrypted = decryptAESCBC(
        data.encrypted,
        key,
        Buffer.from(data.iv, "hex")
      );

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

      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
      }

      return true;
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
        if (!fs.existsSync(config.FALLBACK_DIR)) {
          return [];
        }

        const files = fs.readdirSync(config.FALLBACK_DIR);
        return files
          .filter((file) => file.endsWith(".enc"))
          .map((file) => file.replace(".enc", ""));
      } catch (error) {
        return [];
      }
    }

    return [
      config.SECRET_KEY_ACCOUNT,
      config.AUTH_HASH_ACCOUNT,
    ];
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
    return await secureStorage.retrieveCredential(
      config.SECRET_KEY_ACCOUNT
    );
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
    await secureStorage.storeCredential(
      config.AUTH_HASH_ACCOUNT,
      authHash
    );
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
    return await secureStorage.retrieveCredential(
      config.AUTH_HASH_ACCOUNT
    );
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
    return await secureStorage.deleteCredential(
      config.SECRET_KEY_ACCOUNT
    );
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
    return await secureStorage.deleteCredential(
      config.AUTH_HASH_ACCOUNT
    );
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
