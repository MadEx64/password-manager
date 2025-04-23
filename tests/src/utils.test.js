import { generateRandomPassword, encryptPassword, decryptPassword } from '../../src/utils.js';

describe('Utils', () => {
  describe('generateRandomPassword', () => {
    test('should generate a password between 8 and 16 characters', () => {
      const password = generateRandomPassword();
      expect(password.length).toBeGreaterThanOrEqual(8);
      expect(password.length).toBeLessThanOrEqual(16);
    });

    test('should generate a password with required character types', () => {
      const password = generateRandomPassword();
      expect(password).toMatch(/[A-Z]/); // Uppercase
      expect(password).toMatch(/[0-9]/); // Number
      expect(password).toMatch(/[-.!@#$%^&*_+=/?]/); // Special character
    });
  });

  describe('encryptPassword and decryptPassword', () => {
    const testPassword = 'TestPassword123!';

    test('should encrypt and decrypt password correctly', () => {
      const encrypted = encryptPassword(testPassword);
      const decrypted = decryptPassword(encrypted);
      expect(decrypted).toBe(testPassword);
    });

    test('should not decrypt with wrong master password', () => {
      const wrongMasterPassword = 'WrongPassword123!';
      const encrypted = encryptPassword(wrongMasterPassword);
      const decrypted = decryptPassword(encrypted);
      expect(decrypted).not.toBe(testPassword);
    });

    test('should handle empty password', () => {
      const encrypted = encryptPassword('');
      const decrypted = decryptPassword(encrypted);
      expect(decrypted).toBe('');
    });
  });
}); 