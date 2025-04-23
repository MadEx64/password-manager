import { addPassword, viewPassword, deletePassword, updatePassword } from '../../src/passwordManager.js';
import { encryptPassword, decryptPassword } from '../../src/utils.js';
import { readLines as readPasswords, writeLines as writePasswords } from '../../src/fileOperations.js';

jest.mock('inquirer');
jest.mock('clipboardy');
const mockPrompt = jest.fn();
inquirer.prompt.mockImplementation(mockPrompt);
const mockClipboardWriteSync = jest.fn();
clipboard.writeSync.mockImplementation(mockClipboardWriteSync);

describe('PasswordManager', () => {
  describe('addPassword', () => {
    beforeEach(() => {
      jest.clearAllMocks();
    });

    test('should add a new password entry', async () => {
      const result = await addPassword();
      expect(result).toBe(true);
      expect(writePasswords).toHaveBeenCalledWith([
        'TestApp - test@example.com - encryptedPass'
      ]);
      expect(mockPrompt).toHaveBeenCalledWith([
        {
          type: 'input',
          name: 'name',
          message: 'Enter the name of the application:',
        },
      ]);
    });

    test('should add password with user-provided password', async () => {
      const inquirer = require('inquirer');
      inquirer.prompt.mockResolvedValueOnce({
        name: 'TestApp',
        identifier: 'test@example.com',
        generatePassword: false,
        userPassword: 'UserPass123!'
      });

      encryptPassword.mockReturnValueOnce('encryptedPass');
      readPasswords.mockResolvedValueOnce([]);
      writePasswords.mockResolvedValueOnce(Promise.resolve());

      await addPassword();

      expect(writePasswords).toHaveBeenCalledWith([
        'TestApp - test@example.com - encryptedPass'
      ]);
    });
  });

  describe('viewPassword', () => {
    beforeEach(() => {
      jest.clearAllMocks();
    });

    test('should handle empty password list', async () => {
      readPasswords.mockResolvedValueOnce([]);
      const result = await viewPassword();
      expect(result).toBe(false);
    });

    test('should view and copy password', async () => {
      const inquirer = require('inquirer');
      const clipboard = require('clipboardy');

      readPasswords.mockResolvedValueOnce([
        'TestApp - test@example.com - encryptedPass'
      ]);
      inquirer.prompt
        .mockResolvedValueOnce({ selectedApp: 'TestApp' })
        .mockResolvedValueOnce({ copyToClipboard: true });
      decryptPassword.mockReturnValueOnce('decryptedPass');

      await viewPassword();

      expect(clipboard.writeSync).toHaveBeenCalledWith('decryptedPass');
    });
  });

  describe('deletePassword', () => {
    beforeEach(() => {
      jest.clearAllMocks();
    });

    test('should handle empty password list', async () => {
      readPasswords.mockResolvedValueOnce([]);
      const result = await deletePassword();
      expect(result).toBe(false);
    });

    test('should delete password when confirmed', async () => {
      const inquirer = require('inquirer');
      readPasswords.mockResolvedValueOnce([
        'TestApp - test@example.com - encryptedPass',
        'OtherApp - other@example.com - otherPass'
      ]);
      inquirer.prompt
        .mockResolvedValueOnce({ selectedApp: 'TestApp' })
        .mockResolvedValueOnce({ confirmDelete: true });

      await deletePassword();

      expect(writePasswords).toHaveBeenCalledWith([
        'OtherApp - other@example.com - otherPass'
      ]);
    });
  });

  describe('updatePassword', () => {
    beforeEach(() => {
      jest.clearAllMocks();
    });

    test('should handle empty password list', async () => {
      readPasswords.mockResolvedValueOnce([]);
      const result = await updatePassword();
      expect(result).toBe(false);
    });

    test('should update password with new identifier', async () => {
      const inquirer = require('inquirer');
      readPasswords.mockResolvedValueOnce([
        'TestApp - old@example.com - encryptedPass'
      ]);
      inquirer.prompt
        .mockResolvedValueOnce({ selectedApp: 'TestApp' })
        .mockResolvedValueOnce({
          newIdentifier: 'new@example.com',
          generatePassword: false,
          newPassword: 'NewPass123!'
        });
      encryptPassword.mockReturnValueOnce('newEncryptedPass');

      await updatePassword();

      expect(writePasswords).toHaveBeenCalledWith([
        'TestApp - new@example.com - newEncryptedPass'
      ]);
    });
  });
});
