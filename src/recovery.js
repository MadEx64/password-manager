import fs from 'fs';
import { join } from 'path';
import { promisify } from 'util';
import crypto from 'crypto';
import { yellow, green, red, blue, bold } from './logger.js';
import inquirer from 'inquirer';
import { PATHS, ERROR_CODES } from './constants.js';
import { PasswordManagerError } from './errorHandler.js';
import { decryptFile, isFileEncrypted, encryptFile, decryptPassword } from './utils.js';

const readFileAsync = promisify(fs.readFile);
const writeFileAsync = promisify(fs.writeFile);

/**
 * Emergency recovery tool for password manager.
 * This tool helps recover data when the normal password manager can't access files.
 * @returns {Promise<boolean>} True if recovery was successful, false otherwise.
 */
export async function emergencyRecovery() {
  console.log(yellow('\n=== EMERGENCY RECOVERY TOOL ==='));
  console.log(yellow('This tool will help you recover your password manager data'));
  console.log(yellow('in case of critical errors or file corruption.\n'));
  
  const { action } = await inquirer.prompt([
    {
      type: 'list',
      name: 'action',
      message: 'What would you like to recover?',
      choices: [
        'Master password',
        'Password entries',
        'Recovery key',
        'Exit recovery'
      ]
    }
  ]);
  
  switch (action) {
    case 'Master password':
      return await recoverMasterPasswordFile();
    case 'Password entries':
      return await recoverPasswordsFile();
    case 'Recovery key':
      return await recoverKeyFile();
    case 'Exit recovery':
      console.log(green('Exiting recovery tool...'));
      return false;
    default:
      return false;
  }
};

/**
 * Generates a recovery key based on machine-specific identifiers.
 * Used for master password file encryption/decryption and recovery.
 * @returns {Promise<string>} The recovery key.
 */
export async function generateRecoveryKey() {
  try {
    // Create a recovery key based on various system identifiers
    // This should be relatively stable across reboots but unique to this machine
    const os = await import('os');

    // Combine system-specific values that should be stable
    const systemInfo = [
      os.hostname(),
      os.userInfo().username,
      os.platform(),
      os.arch(),
      os.cpus()[0]?.model,
      os.homedir(),
      // Add more stable identifiers if needed
    ].join('|');

    // Create a hash of the system info
    const hash = crypto.createHash('sha256').update(systemInfo).digest('hex');

    // Add a salt from a special recovery file, or create it if it doesn't exist
    const BASE_DIR = process.cwd();
    const RECOVERY_SALT_PATH = join(BASE_DIR, '.recovery_salt');
    let salt;

    if (fs.existsSync(RECOVERY_SALT_PATH)) {
      salt = await readFileAsync(RECOVERY_SALT_PATH, 'utf8');
    } else {
      // Create a new salt and save it
      salt = crypto.randomBytes(16).toString('hex');
      await writeFileAsync(RECOVERY_SALT_PATH, salt);

      // Make a backup of the salt file
      const RECOVERY_SALT_BACKUP = join(BASE_DIR, '.recovery_salt.bak');
      await writeFileAsync(RECOVERY_SALT_BACKUP, salt);

      console.log("Created new recovery key. Please back up the .recovery_salt file for emergency recovery.");
    }

    // Combine hash and salt to create the final recovery key
    return crypto.createHash('sha256').update(hash + salt).digest('hex');
  } catch (error) {
    // Fallback to a simpler method if something fails
    console.error("Error generating recovery key:", error);
    return "fallback_recovery_key_please_update";
  }
}

/**
 * Exports the recovery key to a file.
 * @returns {Promise<boolean>} True if export was successful.
 */
async function exportRecoveryKey() {
  try {
    const { recoveryKey, salt } = await generateAndSaveRecoveryKey();
    
    const exportData = {
      recoveryKey,
      salt,
      timestamp: new Date().toISOString(),
      version: '1.0',
      warning: 'KEEP THIS FILE SECURE! It can be used to recover your master password.'
    };
    
    const exportPath = join(process.cwd(), 'recovery_key.json');
    await writeFileAsync(exportPath, JSON.stringify(exportData, null, 2));
    
    console.log(green('\nRecovery key exported successfully!'));
    console.log(yellow(`\nIMPORTANT: The recovery key has been saved to: ${exportPath}`));
    console.log(yellow('Please store this file in a secure location.'));
    console.log(yellow('Anyone with access to this file can recover your master password.'));
    
    return true;
  } catch (error) {
    console.error(red('Failed to export recovery key:', error.message));
    return false;
  }
}

/**
 * Imports a recovery key from a file.
 * @param {string} filePath - Path to the recovery key file.
 * @returns {Promise<boolean>} True if import was successful.
 */
async function importRecoveryKey(filePath) {
  try {
    const data = await readFileAsync(filePath, 'utf8');
    const { recoveryKey, salt } = JSON.parse(data);
    
    if (!recoveryKey || !salt) {
      throw new Error('Invalid recovery key file format');
    }
    
    const BASE_DIR = process.cwd();
    const RECOVERY_SALT_PATH = join(BASE_DIR, '.recovery_salt');
    const RECOVERY_SALT_BACKUP = join(BASE_DIR, '.recovery_salt.bak');
    
    await writeFileAsync(RECOVERY_SALT_PATH, salt);
    await writeFileAsync(RECOVERY_SALT_BACKUP, salt);
    
    console.log(green('\nRecovery key imported successfully!'));
    return true;
  } catch (error) {
    console.error(red('Failed to import recovery key:', error.message));
    return false;
  }
}

/**
 * Recovers the master password file.
 * @returns {Promise<boolean>} True if recovery was successful, false otherwise.
 */
async function recoverMasterPasswordFile() {
  console.log(blue('\nMaster Password File Recovery'));
  
  try {
    // First check if we have a backup
    if (fs.existsSync(PATHS.MASTER_PASSWORD_BACKUP)) {
      console.log(green('Found master password backup file!'));
      
      const { restoreFromBackup } = await inquirer.prompt([
        {
          type: 'confirm',
          name: 'restoreFromBackup',
          message: 'Would you like to restore from the backup file?',
          default: true
        }
      ]);
      
      if (restoreFromBackup) {
        fs.copyFileSync(PATHS.MASTER_PASSWORD_BACKUP, PATHS.MASTER_PASSWORD);
        console.log(green('Master password file restored from backup!'));
        return true;
      }
    }
    
    // If no backup or user declined, try recovery key
    console.log(yellow('\nAttempting recovery using recovery key...'));
    
    const { recoveryMethod } = await inquirer.prompt([
      {
        type: 'list',
        name: 'recoveryMethod',
        message: 'How would you like to recover your master password?',
        choices: [
          'Use local recovery key',
          'Import recovery key from file',
          'Create new master password',
          'Exit recovery'
        ]
      }
    ]);
    
    switch (recoveryMethod) {
      case 'Use local recovery key':
        return await recoverWithLocalKey();
      case 'Import recovery key from file':
        return await recoverWithImportedKey();
      case 'Create new master password':
        return await createNewMasterPasswordFile();
      case 'Exit recovery':
        return false;
    }
  } catch (error) {
    console.log(red('Recovery failed:', error.message));
    return false;
  }
}

/**
 * Recovers master password using local recovery key.
 * @returns {Promise<boolean>} True if recovery was successful.
 */
async function recoverWithLocalKey() {
  try {
    const recoveryKey = await generateEmergencyRecoveryKey();
    
    if (fs.existsSync(PATHS.MASTER_PASSWORD)) {
      const fileBuffer = await readFileAsync(PATHS.MASTER_PASSWORD);
      
      if (!isFileEncrypted(fileBuffer)) {
        console.log(green('Master password file is not encrypted or is already accessible.'));
        return true;
      }
      
      try {
        const decryptedData = decryptFile(fileBuffer, recoveryKey);
        console.log(green('Successfully decrypted master password file!'));
        
        const [masterPassword, checksum] = decryptedData.split('\n');
        
        if (!masterPassword || !checksum) {
          throw new Error('Invalid master password file format');
        }
        
        const calculatedChecksum = crypto.createHash('sha256').update(masterPassword).digest('hex');
        if (calculatedChecksum !== checksum) {
          throw new Error('Master password file integrity check failed');
        }

        const decryptedMasterPassword = decryptPassword(masterPassword);
        
        console.log(yellow('\n=== IMPORTANT: MASTER PASSWORD RECOVERY ==='));
        console.log(yellow('Your master password is shown below.'));
        console.log(yellow('Please store it securely and delete it from your terminal history.'));
        console.log(yellow('Anyone with access to this password can access all your stored passwords.\n'));
        
        console.log(bold.green('Master Password:'));
        console.log(bold.white(decryptedMasterPassword));
        
        return true;
      } catch (error) {
        console.log(red('Failed to decrypt master password file with recovery key:'));
        console.log(red(error.message));
        
        const { createNew } = await inquirer.prompt([
          {
            type: 'confirm',
            name: 'createNew',
            message: 'Would you like to create a new master password?',
            default: true
          }
        ]);
        
        if (createNew) {
          return await createNewMasterPasswordFile();
        }
        return false;
      }
    } else {
      console.log(red('Master password file does not exist.'));
      return await createNewMasterPasswordFile();
    }
  } catch (error) {
    console.log(red('Error during recovery:', error.message));
    return false;
  }
}

/**
 * Recovers master password using imported recovery key.
 * @returns {Promise<boolean>} True if recovery was successful.
 */
async function recoverWithImportedKey() {
  try {
    const { filePath } = await inquirer.prompt([
      {
        type: 'input',
        name: 'filePath',
        message: 'Enter the path to your recovery key file:',
        validate: (value) => {
          if (!value || !fs.existsSync(value)) {
            return 'File does not exist';
          }
          return true;
        }
      }
    ]);
    
    if (await importRecoveryKey(filePath)) {
      return await recoverWithLocalKey();
    }
    return false;
  } catch (error) {
    console.log(red('Error during recovery:', error.message));
    return false;
  }
}

/**
 * Recovers the passwords file.
 * @returns {Promise<boolean>} True if recovery was successful, false otherwise.
 */
async function recoverPasswordsFile() {
  console.log(blue('\nPasswords File Recovery'));
  
  try {
    // Check if backup exists
    if (fs.existsSync(PATHS.PASSWORDS_BACKUP)) {
      console.log(green('Found passwords backup file!'));
      
      const { restoreFromBackup } = await inquirer.prompt([
        {
          type: 'confirm',
          name: 'restoreFromBackup',
          message: 'Would you like to restore from the backup file?',
          default: true
        }
      ]);
      
      if (restoreFromBackup) {
        // Copy backup to main file
        fs.copyFileSync(PATHS.PASSWORDS_BACKUP, PATHS.PASSWORDS);
        console.log(green('Passwords file restored from backup!'));
        return true;
      }
    }
    
    // If we get here, either no backup exists or user didn't want to use it
    if (fs.existsSync(PATHS.PASSWORDS)) {
      console.log(yellow('\nAttempting to decrypt passwords file...'));
      
      const { masterPassword } = await inquirer.prompt([
        {
          type: 'password',
          name: 'masterPassword',
          message: 'Enter your master password to decrypt the passwords file:',
          mask: '*'
        }
      ]);
      
      try {
        const fileBuffer = await readFileAsync(PATHS.PASSWORDS);
        
        if (!isFileEncrypted(fileBuffer)) {
          console.log(green('Passwords file is not encrypted or is already accessible.'));
          return true;
        }
        
        // Try to decrypt with provided master password
        try {
          const decryptedData = decryptFile(fileBuffer, masterPassword);
          console.log(green('Successfully decrypted passwords file!'));
          
          // Write the decrypted file for accessibility
          await writeFileAsync(PATHS.PASSWORDS + '.decrypted', decryptedData);
          console.log(green(`Decrypted passwords saved to ${PATHS.PASSWORDS}.decrypted`));
          
          return true;
        } catch (error) {
          console.log(red('Failed to decrypt passwords file with provided master password.'));
          console.log(yellow('The master password may be incorrect or the file may be corrupted.'));
          return false;
        }
      } catch (error) {
        console.log(red('Error reading passwords file:', error.message));
        return false;
      }
    } else {
      console.log(red('Passwords file does not exist.'));
      return false;
    }
  } catch (error) {
    console.log(red('Recovery failed:', error.message));
    return false;
  }
}

/**
 * Recovers or creates a new recovery key file.
 * @returns {Promise<boolean>} True if recovery was successful, false otherwise.
 */
async function recoverKeyFile() {
  console.log(blue('\nRecovery Key File Recovery'));
  
  try {
    const BASE_DIR = process.cwd();
    const RECOVERY_SALT_PATH = join(BASE_DIR, '.recovery_salt');
    const RECOVERY_SALT_BACKUP = join(BASE_DIR, '.recovery_salt.bak');
    
    // Helper to check if salt file is corrupt (empty or too short)
    function isSaltCorrupt(path) {
      try {
        const content = fs.readFileSync(path, 'utf8');
        return !content || content.length < 16;
      } catch {
        return true;
      }
    }

    // Check if either file exists and is valid
    const saltExists = fs.existsSync(RECOVERY_SALT_PATH) && !isSaltCorrupt(RECOVERY_SALT_PATH);
    const backupExists = fs.existsSync(RECOVERY_SALT_BACKUP) && !isSaltCorrupt(RECOVERY_SALT_BACKUP);

    if (saltExists) {
      console.log(green('Recovery key file exists!'));
      // Create a backup if it doesn't exist
      if (!backupExists) {
        fs.copyFileSync(RECOVERY_SALT_PATH, RECOVERY_SALT_BACKUP);
        console.log(green('Created backup of recovery key file.'));
      }
      return true;
    } else if (backupExists) {
      console.log(yellow('Recovery key file missing or corrupt, but backup found. Restoring...'));
      fs.copyFileSync(RECOVERY_SALT_BACKUP, RECOVERY_SALT_PATH);
      console.log(green('Recovery key file restored from backup!'));
      return true;
    } else {
      // Neither exists or both are corrupt
      console.log(yellow('No valid recovery key files found.'));
      const { action } = await inquirer.prompt([
        {
          type: 'list',
          name: 'action',
          message: 'How would you like to proceed?',
          choices: [
            'Import recovery key from file',
            'Create new recovery key (WARNING: will lose access to old data)',
            'Cancel'
          ]
        }
      ]);
      if (action === 'Import recovery key from file') {
        const { filePath } = await inquirer.prompt([
          {
            type: 'input',
            name: 'filePath',
            message: 'Enter the path to your recovery key file:',
            validate: (value) => {
              if (!value || !fs.existsSync(value)) {
                return 'File does not exist';
              }
              return true;
            }
          }
        ]);
        if (await importRecoveryKey(filePath)) {
          console.log(green('Recovery key imported and restored!'));
          return true;
        } else {
          console.log(red('Failed to import recovery key.'));
          return false;
        }
      } else if (action === 'Create new recovery key (WARNING: will lose access to old data)') {
        // Create a new salt and save it
        const salt = crypto.randomBytes(16).toString('hex');
        await writeFileAsync(RECOVERY_SALT_PATH, salt);
        await writeFileAsync(RECOVERY_SALT_BACKUP, salt);
        console.log(green('Created new recovery key files.'));
        console.log(yellow('WARNING: Your existing encrypted files may not be accessible with this new key.'));
        return true;
      } else {
        console.log(yellow('Recovery key restoration cancelled.'));
        return false;
      }
    }
  } catch (error) {
    console.log(red('Recovery failed:', error.message));
    return false;
  }
}

/**
 * Creates a new master password file.
 * @returns {Promise<boolean>} True if creation was successful, false otherwise.
 */
async function createNewMasterPasswordFile() {
  console.log(yellow('\nCreating new master password file...'));
  
  try {
    const { newPassword, confirmPassword } = await inquirer.prompt([
      {
        type: 'password',
        name: 'newPassword',
        message: 'Enter your new master password:',
        mask: '*',
        validate: (value) => {
          if (!value || value.trim() === '') {
            return 'Password cannot be empty';
          }
          if (value.length < 8) {
            return 'Password must be at least 8 characters long';
          }
          return true;
        }
      },
      {
        type: 'password',
        name: 'confirmPassword',
        message: 'Confirm your new master password:',
        mask: '*',
        validate: (value, answers) => {
          if (value !== answers.newPassword) {
            return 'Passwords do not match';
          }
          return true;
        }
      }
    ]);
    
    if (newPassword !== confirmPassword) {
      console.log(red('Passwords do not match!'));
      return false;
    }
    
    const checksum = crypto.createHash('sha256').update(newPassword).digest('hex');
    const content = `${newPassword}\n${checksum}`;
    
    const recoveryKey = await generateEmergencyRecoveryKey();
    const encryptedData = encryptFile(content, recoveryKey);
    
    await writeFileAsync(PATHS.MASTER_PASSWORD, encryptedData);
    
    console.log(green('New master password file created successfully!'));
    console.log(yellow('WARNING: Your existing encrypted files may not be accessible with this new password.'));
    
    return true;
  } catch (error) {
    console.log(red('Failed to create new master password file:', error.message));
    return false;
  }
}

/**
 * Generates the emergency recovery key based on machine-specific identifiers.
 * This should match the key generated by the main application.
 * @returns {Promise<string>} The recovery key.
 */
async function generateEmergencyRecoveryKey() {
  try {
    const os = await import('os');
    
    const systemInfo = [
      os.hostname(),
      os.userInfo().username,
      os.platform(),
      os.arch(),
      os.cpus()[0]?.model,
      os.homedir(),
    ].join('|');
    
    const hash = crypto.createHash('sha256').update(systemInfo).digest('hex');
    
    const BASE_DIR = process.cwd();
    const RECOVERY_SALT_PATH = join(BASE_DIR, '.recovery_salt');
    
    if (!fs.existsSync(RECOVERY_SALT_PATH)) {
      throw new Error('Recovery salt file not found');
    }
    
    const salt = await readFileAsync(RECOVERY_SALT_PATH, 'utf8');
    
    return crypto.createHash('sha256').update(hash + salt).digest('hex');
  } catch (error) {
    console.error('Error generating emergency recovery key:', error);
    throw new PasswordManagerError(
      'Failed to generate recovery key',
      ERROR_CODES.RECOVERY_KEY_GENERATION_FAILED
    );
  }
} 