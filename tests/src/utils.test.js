import { generateRandomPassword } from '../../src/utils.js';
import { PasswordManagerError } from '../../src/errorHandler.js';

describe('Utils', () => {
  describe('generateRandomPassword', () => {
    test('should generate a password between 12 and 16 characters by default', () => {
      const password = generateRandomPassword();
      expect(password.length).toBeGreaterThanOrEqual(12);
      expect(password.length).toBeLessThanOrEqual(16);
    });

    test('should generate a password with specified length when valid', () => {
      const length = 20;
      const password = generateRandomPassword(length);
      expect(password.length).toBe(length);
    });

    test('should respect minimum and maximum length bounds', () => {
      // Test minimum valid length
      const minPassword = generateRandomPassword(8);
      expect(minPassword.length).toBe(8);

      // Test maximum valid length
      const maxPassword = generateRandomPassword(32);
      expect(maxPassword.length).toBe(32);
    });

    test('should use default random length for invalid inputs', () => {
      // Test length too small
      const tooSmallPassword = generateRandomPassword(5);
      expect(tooSmallPassword.length).toBeGreaterThanOrEqual(12);
      expect(tooSmallPassword.length).toBeLessThanOrEqual(16);

      // Test length too large
      const tooLargePassword = generateRandomPassword(50);
      expect(tooLargePassword.length).toBeGreaterThanOrEqual(12);
      expect(tooLargePassword.length).toBeLessThanOrEqual(16);

      // Test zero length
      const zeroLengthPassword = generateRandomPassword(0);
      expect(zeroLengthPassword.length).toBeGreaterThanOrEqual(12);
      expect(zeroLengthPassword.length).toBeLessThanOrEqual(16);
    });

    test('should guarantee all required character types', () => {
      // Test multiple passwords to ensure consistency
      for (let i = 0; i < 10; i++) {
        const password = generateRandomPassword(12);
        
        // Check for lowercase letter
        expect(password).toMatch(/[a-z]/);
        
        // Check for uppercase letter
        expect(password).toMatch(/[A-Z]/);
        
        // Check for number
        expect(password).toMatch(/[0-9]/);
        
        // Check for special character
        expect(password).toMatch(/[-.!@#$%^&*_+=/?]/);
      }
    });

    test('should generate different passwords each time', () => {
      const passwords = new Set();
      
      // Generate 50 passwords and ensure they're all different
      for (let i = 0; i < 50; i++) {
        const password = generateRandomPassword(15);
        expect(passwords.has(password)).toBe(false);
        passwords.add(password);
      }
      
      expect(passwords.size).toBe(50);
    });

    test('should handle edge case lengths properly', () => {
      // Test minimum possible length that satisfies all requirements
      const minRequiredPassword = generateRandomPassword(4);
      expect(minRequiredPassword.length).toBeGreaterThanOrEqual(12); // Should use default since 4 is invalid
      
      // Test that passwords at boundary lengths work correctly
      const boundaryPassword = generateRandomPassword(8);
      expect(boundaryPassword.length).toBe(8);
      expect(boundaryPassword).toMatch(/[a-z]/);
      expect(boundaryPassword).toMatch(/[A-Z]/);
      expect(boundaryPassword).toMatch(/[0-9]/);
      expect(boundaryPassword).toMatch(/[-.!@#$%^&*_+=/?]/);
    });

    test('should only contain valid characters', () => {
      const validChars = /^[a-zA-Z0-9\-.!@#$%^&*_+=/?]+$/;
      
      for (let i = 0; i < 10; i++) {
        const password = generateRandomPassword(20);
        expect(password).toMatch(validChars);
      }
    });

    test('should maintain character distribution for longer passwords', () => {
      const longPassword = generateRandomPassword(32);
      
      // For longer passwords, we should still have all character types
      expect(longPassword).toMatch(/[a-z]/);
      expect(longPassword).toMatch(/[A-Z]/);
      expect(longPassword).toMatch(/[0-9]/);
      expect(longPassword).toMatch(/[-.!@#$%^&*_+=/?]/);
      
      // And the length should be exactly what we requested
      expect(longPassword.length).toBe(32);
    });

    test('should handle non-integer and negative lengths gracefully', () => {
      // Test floating point number
      const floatPassword = generateRandomPassword(10.5);
      expect(floatPassword.length).toBe(10);

      // Test negative number
      const negativePassword = generateRandomPassword(-5);
      expect(negativePassword.length).toBeGreaterThanOrEqual(12);
      expect(negativePassword.length).toBeLessThanOrEqual(16);
    });

    test('should handle very small lengths gracefully', () => {
      // Test that very small lengths are handled by using default length
      const smallLengthPassword = generateRandomPassword(3);
      expect(smallLengthPassword.length).toBeGreaterThanOrEqual(12);
      expect(smallLengthPassword.length).toBeLessThanOrEqual(16);
      
      // Ensure it still has all required character types
      expect(smallLengthPassword).toMatch(/[a-z]/);
      expect(smallLengthPassword).toMatch(/[A-Z]/);
      expect(smallLengthPassword).toMatch(/[0-9]/);
      expect(smallLengthPassword).toMatch(/[-.!@#$%^&*_+=/?]/);
    });
  });
});