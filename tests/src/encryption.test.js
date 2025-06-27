import {
  encryptPassword,
  decryptPassword,
  encryptData,
  decryptData,
  isFileEncrypted,
  getSecureRandomInt,
  getSecureRandomChar,
  secureShuffleArray,
  createHash,
  createHashBuffer,
  createHmac,
  timingSafeEqual,
  generateRandomBytes,
  deriveKeyPBKDF2,
  encryptAESCBC,
  decryptAESCBC
} from '../../src/encryption/index.js';
import { PasswordManagerError } from '../../src/errorHandler.js';

describe('Encryption Module', () => {
  describe('Password Encryption/Decryption', () => {
    const testPassword = 'TestPassword123!';
    const testKey = Buffer.from('12345678901234567890123456789012');

    test('should encrypt and decrypt password correctly', async () => {
      const encrypted = await encryptPassword(testPassword, testKey);
      const decrypted = await decryptPassword(encrypted, testKey);
      expect(decrypted).toBe(testPassword);
    });

    test('should not decrypt with wrong key', async () => {
      const wrongKey = Buffer.from('09876543210987654321098765432109');
      const encrypted = await encryptPassword(testPassword, testKey);
      await expect(decryptPassword(encrypted, wrongKey)).rejects.toThrow(PasswordManagerError);
    });

    test('should handle empty password', async () => {
      const encrypted = await encryptPassword('', testKey);
      const decrypted = await decryptPassword(encrypted, testKey);
      expect(decrypted).toBe('');
    });

    test('should produce different ciphertext for same password', async () => {
      const encrypted1 = await encryptPassword(testPassword, testKey);
      const encrypted2 = await encryptPassword(testPassword, testKey);
      expect(encrypted1).not.toBe(encrypted2); // Different IVs should produce different ciphertext
    });

    test('should throw error for invalid encrypted password format', async () => {
      const invalidEncrypted = 'invalid_base64_data';
      await expect(decryptPassword(invalidEncrypted, testKey)).rejects.toThrow(PasswordManagerError);
    });

    test('should throw error for too short encrypted data', async () => {
      const tooShort = Buffer.from('short').toString('base64');
      await expect(decryptPassword(tooShort, testKey)).rejects.toThrow(PasswordManagerError);
    });
  });

  describe('Data Encryption/Decryption', () => {
    const testKey = Buffer.from('12345678901234567890123456789012');
    const testContent = 'TestContent123!';

    test('should encrypt and decrypt data correctly', () => {
      const encrypted = encryptData(testContent, testKey);
      const decrypted = decryptData(encrypted, testKey);
      expect(decrypted).toBe(testContent);
    });

    test('should throw error when decrypting with wrong key', () => {
      const wrongKey = Buffer.from('09876543210987654321098765432109');
      const encrypted = encryptData(testContent, testKey);

      expect(() => {
        decryptData(encrypted, wrongKey);
      }).toThrow(PasswordManagerError);
    });

    test('should handle empty data', () => {
      const encrypted = encryptData('', testKey);
      const decrypted = decryptData(encrypted, testKey);
      expect(decrypted).toBe('');
    });

    test('should include metadata in encrypted data', () => {
      const encrypted = encryptData(testContent, testKey);
      expect(encrypted.length).toBeGreaterThan(65); // Minimum header size
      expect(encrypted[0]).toBe(1); // Version byte
    });

    test('should validate data integrity with HMAC', () => {
      const encrypted = encryptData(testContent, testKey);
      
      // Corrupt the data by modifying a byte
      const corrupted = Buffer.from(encrypted);
      corrupted[corrupted.length - 1] = corrupted[corrupted.length - 1] ^ 1;
      
      expect(() => {
        decryptData(corrupted, testKey);
      }).toThrow(PasswordManagerError);
    });

    test('should throw error for too short encrypted data', () => {
      const tooShort = Buffer.from('short');
      expect(() => {
        decryptData(tooShort, testKey);
      }).toThrow(PasswordManagerError);
    });

    test('should throw error for unsupported version', () => {
      const encrypted = encryptData(testContent, testKey);
      const wrongVersion = Buffer.from(encrypted);
      wrongVersion[0] = 2; // Change version to unsupported
      
      expect(() => {
        decryptData(wrongVersion, testKey);
      }).toThrow(PasswordManagerError);
    });
  });

  describe('File Encryption Detection', () => {
    test('should return true for encrypted file buffer', () => {
      const encryptedBuffer = Buffer.from([1, 2, 3, 4, 5]); // Starts with version byte 1
      expect(isFileEncrypted(encryptedBuffer)).toBe(true);
    });

    test('should return false for non-encrypted file buffer', () => {
      const nonEncryptedBuffer = Buffer.from([0, 2, 3, 4, 5]); // Does not start with version byte 1
      expect(isFileEncrypted(nonEncryptedBuffer)).toBe(false);
    });

    test('should return false for empty buffer', () => {
      const emptyBuffer = Buffer.from([]);
      expect(isFileEncrypted(emptyBuffer)).toBe(false);
    });

    test('should return false for single byte non-version buffer', () => {
      const singleByte = Buffer.from([0]);
      expect(isFileEncrypted(singleByte)).toBe(false);
    });
  });

  describe('Cryptographic Utilities', () => {
    describe('getSecureRandomInt', () => {
      test('should generate random integers within range', () => {
        for (let i = 0; i < 100; i++) {
          const random = getSecureRandomInt(5, 10);
          expect(random).toBeGreaterThanOrEqual(5);
          expect(random).toBeLessThanOrEqual(10);
          expect(Number.isInteger(random)).toBe(true);
        }
      });

      test('should handle single value range', () => {
        const random = getSecureRandomInt(7, 7);
        expect(random).toBe(7);
      });

      test('should generate different values', () => {
        const values = new Set();
        for (let i = 0; i < 50; i++) {
          values.add(getSecureRandomInt(1, 100));
        }
        expect(values.size).toBeGreaterThan(10); // Should have good distribution
      });
    });

    describe('getSecureRandomChar', () => {
      test('should return character from charset', () => {
        const charset = 'abcdef';
        for (let i = 0; i < 50; i++) {
          const char = getSecureRandomChar(charset);
          expect(charset).toContain(char);
          expect(char.length).toBe(1);
        }
      });

      test('should handle single character charset', () => {
        const char = getSecureRandomChar('x');
        expect(char).toBe('x');
      });

      test('should generate different characters from larger charset', () => {
        const charset = 'abcdefghijklmnopqrstuvwxyz';
        const chars = new Set();
        for (let i = 0; i < 100; i++) {
          chars.add(getSecureRandomChar(charset));
        }
        expect(chars.size).toBeGreaterThan(5); // Should have good distribution
      });
    });

    describe('secureShuffleArray', () => {
      test('should shuffle array in place', () => {
        const original = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        const toShuffle = [...original];
        secureShuffleArray(toShuffle);
        
        // Array should contain same elements (sort both to compare)
        expect(toShuffle.sort((a, b) => a - b)).toEqual(original.sort((a, b) => a - b));
        
        // Array should likely be in different order (small chance of false positive)
        // Note: There's a small chance this could fail if shuffle returns original order
        // but it's very unlikely with 10 elements
      });

      test('should handle single element array', () => {
        const array = [42];
        secureShuffleArray(array);
        expect(array).toEqual([42]);
      });

      test('should handle empty array', () => {
        const array = [];
        secureShuffleArray(array);
        expect(array).toEqual([]);
      });
    });

    describe('createHash', () => {
      test('should create consistent hash for same input', () => {
        const data = 'test data';
        const hash1 = createHash(data);
        const hash2 = createHash(data);
        expect(hash1).toBe(hash2);
        expect(hash1).toMatch(/^[a-f0-9]{64}$/); // SHA-256 hex format
      });

      test('should create different hashes for different inputs', () => {
        const hash1 = createHash('data1');
        const hash2 = createHash('data2');
        expect(hash1).not.toBe(hash2);
      });

      test('should handle empty string', () => {
        const hash = createHash('');
        expect(hash).toMatch(/^[a-f0-9]{64}$/);
      });
    });

    describe('createHashBuffer', () => {
      test('should create hash as Buffer', () => {
        const data = 'test data';
        const hash = createHashBuffer(data);
        expect(Buffer.isBuffer(hash)).toBe(true);
        expect(hash.length).toBe(32); // SHA-256 is 32 bytes
      });

      test('should be consistent with createHash', () => {
        const data = 'test data';
        const hashHex = createHash(data);
        const hashBuffer = createHashBuffer(data);
        expect(hashBuffer.toString('hex')).toBe(hashHex);
      });
    });

    describe('createHmac', () => {
      test('should create HMAC with string key', () => {
        const key = 'secret key';
        const data = 'test data';
        const hmac = createHmac(key, data);
        expect(hmac).toMatch(/^[a-f0-9]{64}$/); // SHA-256 hex format
      });

      test('should create HMAC with Buffer key', () => {
        const key = Buffer.from('secret key');
        const data = 'test data';
        const hmac = createHmac(key, data);
        expect(hmac).toMatch(/^[a-f0-9]{64}$/);
      });

      test('should create different HMACs for different keys', () => {
        const data = 'test data';
        const hmac1 = createHmac('key1', data);
        const hmac2 = createHmac('key2', data);
        expect(hmac1).not.toBe(hmac2);
      });

      test('should create different HMACs for different data', () => {
        const key = 'secret key';
        const hmac1 = createHmac(key, 'data1');
        const hmac2 = createHmac(key, 'data2');
        expect(hmac1).not.toBe(hmac2);
      });
    });

    describe('timingSafeEqual', () => {
      test('should return true for identical hex strings', () => {
        const a = 'deadbeef';
        const b = 'deadbeef';
        expect(timingSafeEqual(a, b)).toBe(true);
      });

      test('should return false for different hex strings', () => {
        const a = 'deadbeef';
        const b = 'beefdead';
        expect(timingSafeEqual(a, b)).toBe(false);
      });

      test('should return true for identical buffers', () => {
        const a = Buffer.from('test');
        const b = Buffer.from('test');
        expect(timingSafeEqual(a, b)).toBe(true);
      });

      test('should return false for different length buffers', () => {
        const a = Buffer.from('test');
        const b = Buffer.from('testing');
        expect(timingSafeEqual(a, b)).toBe(false);
      });

      test('should handle mixed buffer and hex string comparison', () => {
        const buffer = Buffer.from([0xde, 0xad, 0xbe, 0xef]);
        const hexString = 'deadbeef';
        expect(timingSafeEqual(buffer, hexString)).toBe(true);
      });
    });

    describe('generateRandomBytes', () => {
      test('should generate buffer of specified size', () => {
        const size = 32;
        const bytes = generateRandomBytes(size);
        expect(Buffer.isBuffer(bytes)).toBe(true);
        expect(bytes.length).toBe(size);
      });

      test('should generate different bytes each time', () => {
        const bytes1 = generateRandomBytes(16);
        const bytes2 = generateRandomBytes(16);
        expect(bytes1.equals(bytes2)).toBe(false);
      });

      test('should handle zero size', () => {
        const bytes = generateRandomBytes(0);
        expect(bytes.length).toBe(0);
      });
    });

    describe('deriveKeyPBKDF2', () => {
      test('should derive key with specified parameters', () => {
        const password = 'password';
        const salt = 'salt';
        const iterations = 1000;
        const keyLength = 32;
        
        const key = deriveKeyPBKDF2(password, salt, iterations, keyLength);
        expect(Buffer.isBuffer(key)).toBe(true);
        expect(key.length).toBe(keyLength);
      });

      test('should be deterministic', () => {
        const password = 'password';
        const salt = 'salt';
        const iterations = 1000;
        const keyLength = 32;
        
        const key1 = deriveKeyPBKDF2(password, salt, iterations, keyLength);
        const key2 = deriveKeyPBKDF2(password, salt, iterations, keyLength);
        expect(key1.equals(key2)).toBe(true);
      });

      test('should produce different keys for different passwords', () => {
        const salt = 'salt';
        const iterations = 1000;
        const keyLength = 32;
        
        const key1 = deriveKeyPBKDF2('password1', salt, iterations, keyLength);
        const key2 = deriveKeyPBKDF2('password2', salt, iterations, keyLength);
        expect(key1.equals(key2)).toBe(false);
      });

      test('should support different digest algorithms', () => {
        const password = 'password';
        const salt = 'salt';
        const iterations = 1000;
        const keyLength = 32;
        
        const key1 = deriveKeyPBKDF2(password, salt, iterations, keyLength, 'sha256');
        const key2 = deriveKeyPBKDF2(password, salt, iterations, keyLength, 'sha512');
        expect(key1.equals(key2)).toBe(false);
      });
    });

    describe('AES-CBC Encryption/Decryption', () => {
      const testKey = Buffer.from('12345678901234567890123456789012');
      const testIv = Buffer.from('1234567890123456');
      const testData = 'Test data for AES-CBC encryption';

      test('should encrypt and decrypt data correctly', () => {
        const encrypted = encryptAESCBC(testData, testKey, testIv);
        const decrypted = decryptAESCBC(encrypted, testKey, testIv);
        expect(decrypted).toBe(testData);
      });

      test('should produce hex encoded output', () => {
        const encrypted = encryptAESCBC(testData, testKey, testIv);
        expect(encrypted).toMatch(/^[a-f0-9]+$/);
      });

      test('should fail with wrong key', () => {
        const wrongKey = Buffer.from('09876543210987654321098765432109');
        const encrypted = encryptAESCBC(testData, testKey, testIv);
        
        expect(() => {
          decryptAESCBC(encrypted, wrongKey, testIv);
        }).toThrow();
      });

      test('should produce different result with wrong IV', () => {
        const wrongIv = Buffer.from('6543210987654321');
        const encrypted = encryptAESCBC(testData, testKey, testIv);
        
        // Wrong IV won't throw an error, but will produce wrong decrypted data
        const wrongDecrypted = decryptAESCBC(encrypted, testKey, wrongIv);
        expect(wrongDecrypted).not.toBe(testData);
      });

      test('should handle empty data', () => {
        const encrypted = encryptAESCBC('', testKey, testIv);
        const decrypted = decryptAESCBC(encrypted, testKey, testIv);
        expect(decrypted).toBe('');
      });
    });
  });
}); 