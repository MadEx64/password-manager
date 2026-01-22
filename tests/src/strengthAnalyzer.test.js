import { analyzePasswordStrength } from '../../src/security/strengthAnalyzer.js';

describe('Password Strength Analyzer', () => {
  describe('analyzePasswordStrength', () => {
    test('should return score 0 for empty password', () => {
      const result = analyzePasswordStrength('');
      expect(result.score).toBe(0);
      expect(result.crackTime).toBe('instant');
      expect(result.feedback.warning).toBe('Password cannot be empty.');
    });

    test('should return score 0 for invalid input', () => {
      const result = analyzePasswordStrength(null);
      expect(result.score).toBe(0);
      expect(result.crackTime).toBe('instant');
      expect(result.feedback.warning).toBe('Invalid password input.');
    });

    test('should identify very weak passwords (score 0)', () => {
      const result = analyzePasswordStrength('123');
      expect(result.score).toBe(0);
      expect(result.feedback.warning).toBeTruthy();
    });

    test('should identify weak passwords (score 1)', () => {
      const result = analyzePasswordStrength('password');
      expect(result.score).toBeLessThanOrEqual(1);
      expect(result.feedback.warning).toBeTruthy();
    });

    test('should identify common passwords', () => {
      const result = analyzePasswordStrength('password123');
      expect(result.score).toBeLessThanOrEqual(2);
      expect(result.feedback.warning).toContain('common');
    });

    test('should identify passwords with repeated characters', () => {
      const result = analyzePasswordStrength('aaaabbbbcccc');
      expect(result.score).toBeLessThan(4);
      expect(result.feedback.warning).toContain('repeated');
    });

    test('should identify passwords with sequential patterns', () => {
      const result = analyzePasswordStrength('abcdef123');
      expect(result.score).toBeLessThan(4);
      expect(result.feedback.warning).toContain('sequential');
    });

    test('should identify medium strength passwords (score 2-3)', () => {
      const result = analyzePasswordStrength('SecurePass123');
      expect(result.score).toBeGreaterThanOrEqual(2);
      expect(result.score).toBeLessThanOrEqual(3);
    });

    test('should identify strong passwords (score 4)', () => {
      const result = analyzePasswordStrength('MyV3ry$tr0ng!P@ssw0rd#2024');
      expect(result.score).toBe(4);
      expect(result.crackTime).not.toBe('instant');
    });

    test('should provide suggestions for improvement', () => {
      const result = analyzePasswordStrength('short');
      expect(result.feedback.suggestions).toBeInstanceOf(Array);
      expect(result.feedback.suggestions.length).toBeGreaterThan(0);
    });

    test('should calculate crack time for strong passwords', () => {
      const result = analyzePasswordStrength('MyV3ry$tr0ng!P@ssw0rd#2024');
      expect(result.crackTime).toBeTruthy();
      expect(typeof result.crackTime).toBe('string');
      expect(result.crackTime).not.toBe('instant');
    });

    test('should detect missing character types', () => {
      const noUpper = analyzePasswordStrength('password123!');
      expect(noUpper.feedback.suggestions.some(s => s.includes('uppercase'))).toBe(true);

      const noLower = analyzePasswordStrength('PASSWORD123!');
      expect(noLower.feedback.suggestions.some(s => s.includes('lowercase'))).toBe(true);

      const noNumber = analyzePasswordStrength('Password!');
      expect(noNumber.feedback.suggestions.some(s => s.includes('number'))).toBe(true);

      const noSpecial = analyzePasswordStrength('Password123');
      expect(noSpecial.feedback.suggestions.some(s => s.includes('special'))).toBe(true);
    });

    test('should handle very long passwords', () => {
      const longPassword = 'A'.repeat(50) + 'b'.repeat(50) + '1'.repeat(50) + '!'.repeat(50);
      const result = analyzePasswordStrength(longPassword);
      expect(result.score).toBeGreaterThanOrEqual(3);
    });

    test('should return valid feedback structure', () => {
      const result = analyzePasswordStrength('Test123!');
      expect(result).toHaveProperty('score');
      expect(result).toHaveProperty('crackTime');
      expect(result).toHaveProperty('feedback');
      expect(result.feedback).toHaveProperty('warning');
      expect(result.feedback).toHaveProperty('suggestions');
      expect(Array.isArray(result.feedback.suggestions)).toBe(true);
      expect(result.score).toBeGreaterThanOrEqual(0);
      expect(result.score).toBeLessThanOrEqual(4);
    });

    test('should identify keyboard patterns', () => {
      const result = analyzePasswordStrength('qwerty123');
      expect(result.score).toBeLessThan(4);
    });
  });
});

