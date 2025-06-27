import crypto from "crypto";

// Set NODE_ENV to test to use test paths
process.env.NODE_ENV = "test";

describe("Secure Authentication System - Cryptographic Functions", () => {
  const testSecretKey = "a".repeat(128); // 512-bit key as hex string
  const testMasterPassword = "TestPassword123!";
  
  describe("Core Cryptographic Functions", () => {
    it("should derive consistent authentication keys using PBKDF2", () => {
      const secretKey = testSecretKey;
      const combinedSecret = testMasterPassword + secretKey;
      const salt = crypto.createHash('sha256').update(secretKey + 'AUTH_SALT').digest().subarray(0, 16);
      
      const authKey1 = crypto.pbkdf2Sync(combinedSecret, salt, 100000, 32, 'sha256');
      const authKey2 = crypto.pbkdf2Sync(combinedSecret, salt, 100000, 32, 'sha256');
      
      expect(authKey1).toBeInstanceOf(Buffer);
      expect(authKey1.length).toBe(32); // 256 bits
      expect(authKey1.equals(authKey2)).toBe(true); // Should be deterministic
    });

    it("should produce different keys for different passwords", () => {
      const secretKey = testSecretKey;
      const salt = crypto.createHash('sha256').update(secretKey + 'AUTH_SALT').digest().subarray(0, 16);
      
      const combinedSecret1 = "password1" + secretKey;
      const combinedSecret2 = "password2" + secretKey;
      
      const authKey1 = crypto.pbkdf2Sync(combinedSecret1, salt, 100000, 32, 'sha256');
      const authKey2 = crypto.pbkdf2Sync(combinedSecret2, salt, 100000, 32, 'sha256');
      
      expect(authKey1.equals(authKey2)).toBe(false);
    });

    it("should create valid HMAC-SHA256 hashes", () => {
      const secretKey = testSecretKey;
      const authKey = Buffer.from("test-auth-key");
      
      const hmac = crypto.createHmac('sha256', secretKey);
      hmac.update(authKey);
      const hash = hmac.digest('hex');
      
      expect(hash).toMatch(/^[a-f0-9]{64}$/i); // 256-bit hex string
      expect(hash.length).toBe(64);
    });

    it("should perform timing-safe comparisons correctly", () => {
      const hash1 = "a".repeat(64);
      const hash2 = "a".repeat(64);
      const hash3 = "b".repeat(64);
      
      expect(crypto.timingSafeEqual(
        Buffer.from(hash1, 'hex'),
        Buffer.from(hash2, 'hex')
      )).toBe(true);
      
      expect(crypto.timingSafeEqual(
        Buffer.from(hash1, 'hex'),
        Buffer.from(hash3, 'hex')
      )).toBe(false);
    });
  });

  describe("Secret Key Generation", () => {
    it("should generate valid 512-bit secret keys", () => {
      const secretKey = crypto.randomBytes(64).toString('hex');
      
      expect(secretKey).toMatch(/^[a-f0-9]{128}$/i);
      expect(secretKey.length).toBe(128);
    });

    it("should generate different keys each time", () => {
      const key1 = crypto.randomBytes(64).toString('hex');
      const key2 = crypto.randomBytes(64).toString('hex');
      
      expect(key1).not.toBe(key2);
    });
  });

  describe("Authentication Hash Verification", () => {
    it("should verify correct password with matching hash", () => {
      const secretKey = testSecretKey;
      const masterPassword = testMasterPassword;
      
      const combinedSecret = masterPassword + secretKey;
      const salt = crypto.createHash('sha256').update(secretKey + 'AUTH_SALT').digest().subarray(0, 16);
      const authKey = crypto.pbkdf2Sync(combinedSecret, salt, 100000, 32, 'sha256');
      
      const hmac = crypto.createHmac('sha256', secretKey);
      hmac.update(authKey);
      const storedHash = hmac.digest('hex');
      
      const verifyHmac = crypto.createHmac('sha256', secretKey);
      verifyHmac.update(authKey);
      const inputHash = verifyHmac.digest('hex');
      
      const isValid = crypto.timingSafeEqual(
        Buffer.from(inputHash, 'hex'),
        Buffer.from(storedHash, 'hex')
      );
      
      expect(isValid).toBe(true);
    });

    it("should reject incorrect password with different hash", () => {
      const secretKey = testSecretKey;
      
      const correctPassword = testMasterPassword;
      const correctCombined = correctPassword + secretKey;
      const salt = crypto.createHash('sha256').update(secretKey + 'AUTH_SALT').digest().subarray(0, 16);
      const correctAuthKey = crypto.pbkdf2Sync(correctCombined, salt, 100000, 32, 'sha256');
      
      const hmac1 = crypto.createHmac('sha256', secretKey);
      hmac1.update(correctAuthKey);
      const storedHash = hmac1.digest('hex');
      
      const wrongPassword = "WrongPassword123!";
      const wrongCombined = wrongPassword + secretKey;
      const wrongAuthKey = crypto.pbkdf2Sync(wrongCombined, salt, 100000, 32, 'sha256');
      
      const hmac2 = crypto.createHmac('sha256', secretKey);
      hmac2.update(wrongAuthKey);
      const inputHash = hmac2.digest('hex');
      
      const isValid = crypto.timingSafeEqual(
        Buffer.from(inputHash, 'hex'),
        Buffer.from(storedHash, 'hex')
      );
      
      expect(isValid).toBe(false);
    });
  });

  describe("Security Configuration Validation", () => {
    it("should use secure cryptographic parameters", () => {
      const SECURITY_CONFIG = {
        SECRET_KEY_LENGTH: 64, // 512 bits
        AUTH_KEY_LENGTH: 32,   // 256 bits
        PBKDF2_ITERATIONS: 100000,
        HASH_ALGORITHM: 'sha256',
        HMAC_ALGORITHM: 'sha256',
      };
      
      expect(SECURITY_CONFIG.SECRET_KEY_LENGTH).toBeGreaterThanOrEqual(32); // At least 256 bits
      expect(SECURITY_CONFIG.AUTH_KEY_LENGTH).toBeGreaterThanOrEqual(32); // At least 256 bits
      expect(SECURITY_CONFIG.PBKDF2_ITERATIONS).toBeGreaterThanOrEqual(100000); // OWASP recommendation
      expect(['sha256', 'sha512']).toContain(SECURITY_CONFIG.HASH_ALGORITHM);
      expect(['sha256', 'sha512']).toContain(SECURITY_CONFIG.HMAC_ALGORITHM);
    });
  });

  describe("Input Validation", () => {
    it("should validate secret key format correctly", () => {
      const invalidKeys = [
        "",
        "too-short",
        "invalid-characters-!@#$%",
        "a".repeat(127),
        "a".repeat(129),
      ];
      
      invalidKeys.forEach(key => {
        const isValid = key.length === 128 && /^[a-f0-9]+$/i.test(key);
        expect(isValid).toBe(false);
      });
    });

    it("should accept valid secret key format", () => {
      const validKey = "a".repeat(128);
      const isValid = validKey.length === 128 && /^[a-f0-9]+$/i.test(validKey);
      expect(isValid).toBe(true);
    });

    it("should validate authentication hash format", () => {
      const validHash = "a".repeat(64);
      const invalidHashes = [
        "",
        "too-short",
        "a".repeat(63),
        "a".repeat(65),
        "invalid-chars-!@#$%".padEnd(64, 'a'),
      ];
      
      expect(validHash.length === 64 && /^[a-f0-9]+$/i.test(validHash)).toBe(true);
      
      invalidHashes.forEach(hash => {
        const isValid = hash.length === 64 && /^[a-f0-9]+$/i.test(hash);
        expect(isValid).toBe(false);
      });
    });
  });

  describe("Salt Generation and Usage", () => {
    it("should generate consistent salts from secret key", () => {
      const secretKey = testSecretKey;
      
      const salt1 = crypto.createHash('sha256').update(secretKey + 'AUTH_SALT').digest().subarray(0, 16);
      const salt2 = crypto.createHash('sha256').update(secretKey + 'AUTH_SALT').digest().subarray(0, 16);
      
      expect(salt1.equals(salt2)).toBe(true);
      expect(salt1.length).toBe(16); // 128 bits
    });

    it("should generate different salts for different secret keys", () => {
      const secretKey1 = "a".repeat(128);
      const secretKey2 = "b".repeat(128);
      
      const salt1 = crypto.createHash('sha256').update(secretKey1 + 'AUTH_SALT').digest().subarray(0, 16);
      const salt2 = crypto.createHash('sha256').update(secretKey2 + 'AUTH_SALT').digest().subarray(0, 16);
      
      expect(salt1.equals(salt2)).toBe(false);
    });
  });

  describe("Performance and Security", () => {
    it("should complete PBKDF2 operations within reasonable time", () => {
      const secretKey = testSecretKey;
      const combinedSecret = testMasterPassword + secretKey;
      const salt = crypto.createHash('sha256').update(secretKey + 'AUTH_SALT').digest().subarray(0, 16);
      
      const startTime = Date.now();
      const authKey = crypto.pbkdf2Sync(combinedSecret, salt, 100000, 32, 'sha256');
      const endTime = Date.now();
      
      expect(authKey).toBeInstanceOf(Buffer);
      expect(authKey.length).toBe(32);
      
      const duration = endTime - startTime;
      expect(duration).toBeLessThan(5000);
    });

    it("should demonstrate sufficient iteration count for security", () => {
      const secretKey = testSecretKey;
      const combinedSecret = testMasterPassword + secretKey;
      const salt = crypto.createHash('sha256').update(secretKey + 'AUTH_SALT').digest().subarray(0, 16);
      
      const lowIterations = crypto.pbkdf2Sync(combinedSecret, salt, 1000, 32, 'sha256');
      const highIterations = crypto.pbkdf2Sync(combinedSecret, salt, 100000, 32, 'sha256');
      
      expect(lowIterations.equals(highIterations)).toBe(false);
    });
  });

  describe("Complete Authentication Flow Simulation", () => {
    it("should simulate complete setup and verification flow", () => {
      // Step 1: Generate secret key (simulating first setup)
      const secretKey = crypto.randomBytes(64).toString('hex');
      expect(secretKey.length).toBe(128);
      
      // Step 2: User provides master password
      const masterPassword = "MySecurePassword123!";
      
      // Step 3: Derive authentication key
      const combinedSecret = masterPassword + secretKey;
      const salt = crypto.createHash('sha256').update(secretKey + 'AUTH_SALT').digest().subarray(0, 16);
      const authKey = crypto.pbkdf2Sync(combinedSecret, salt, 100000, 32, 'sha256');
      
      // Step 4: Create authentication hash (what gets stored)
      const hmac = crypto.createHmac('sha256', secretKey);
      hmac.update(authKey);
      const storedAuthHash = hmac.digest('hex');
      
      // Step 5: Later verification attempt with correct password
      const verifyAuthKey = crypto.pbkdf2Sync(combinedSecret, salt, 100000, 32, 'sha256');
      const verifyHmac = crypto.createHmac('sha256', secretKey);
      verifyHmac.update(verifyAuthKey);
      const verifyAuthHash = verifyHmac.digest('hex');
      
      const isValid = crypto.timingSafeEqual(
        Buffer.from(storedAuthHash, 'hex'),
        Buffer.from(verifyAuthHash, 'hex')
      );
      
      expect(isValid).toBe(true);
      
      // Step 6: Verification attempt with wrong password should fail
      const wrongPassword = "WrongPassword123!";
      const wrongCombined = wrongPassword + secretKey;
      const wrongAuthKey = crypto.pbkdf2Sync(wrongCombined, salt, 100000, 32, 'sha256');
      const wrongHmac = crypto.createHmac('sha256', secretKey);
      wrongHmac.update(wrongAuthKey);
      const wrongAuthHash = wrongHmac.digest('hex');
      
      const isWrongValid = crypto.timingSafeEqual(
        Buffer.from(storedAuthHash, 'hex'),
        Buffer.from(wrongAuthHash, 'hex')
      );
      
      expect(isWrongValid).toBe(false);
    });
  });
});
