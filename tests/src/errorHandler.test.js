import { PasswordManagerError, validateInput, validatePassword, handleError } from '../../src/errorHandler.js';
import { jest } from '@jest/globals';
import chalk from 'chalk';

describe('PasswordManagerError', () => {
  test('should create an error with the correct message and code', () => {
    const error = new PasswordManagerError('Test error', 'TEST_ERROR');
    expect(error.message).toBe('Test error');
    expect(error.code).toBe('TEST_ERROR');
    expect(error.name).toBe('Error');
  });
});

describe('handleError', () => {
  test('should log the error message and exit with code 1', () => {
    const consoleSpy = jest.spyOn(console, 'log').mockImplementation();
    const processSpy = jest.spyOn(process, 'exit').mockImplementation();

    const error = new PasswordManagerError('Test error', 'TEST_ERROR');
    handleError(error);

    // check if the error message is logged in red color
    expect(consoleSpy).toHaveBeenCalledWith(chalk.red(`\nError (${error.code}): ${error.message}\n`));

    // check if the process exits with code 1
    expect(processSpy).toHaveBeenCalledWith(1);

    // restore the console and process spies
    consoleSpy.mockRestore();
    processSpy.mockRestore();
  });
});

describe('validateInput', () => {
  test('should throw error for empty input', () => {
    expect(() => validateInput('', 'test')).toThrow(PasswordManagerError);
    expect(() => validateInput('   ', 'test')).toThrow(PasswordManagerError);
    expect(() => validateInput(' ', 'password')).toThrow(PasswordManagerError);
  });

  test('should return true for valid input', () => {
    expect(validateInput('valid', 'test')).toBe(true);
    expect(validateInput('password123!', 'password')).toBe(true);
  });
});

describe('validatePassword', () => {

  test('should return error message for password less than 8 characters', () => {
    expect(validatePassword('short')).toBe('✗ Password must be at least 8 characters long. Please try again.');
  });

  test('should return error message for password without uppercase letter', () => {
    expect(validatePassword('password123!')).toBe('✗ Password must contain at least one uppercase letter. Please try again.');
  });

  test('should return error message for password without number', () => {
    expect(validatePassword('Password!')).toBe('✗ Password must contain at least one number. Please try again.');
  });

  test('should return error message for password without special character', () => {
    expect(validatePassword('Password123')).toBe('✗ Password must contain at least one special character. Please try again.');
  });

  test('should return true for valid password', () => {
    const validPassword = 'Password123!';
    expect(validatePassword(validPassword)).toBe(true);
  });
}); 