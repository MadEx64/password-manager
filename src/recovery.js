import fs from 'fs';
import { join } from 'path';
import { promisify } from 'util';
import crypto from 'crypto';
import chalk from 'chalk';
import inquirer from 'inquirer';
import { PATHS, ERROR_CODES } from './constants.js';
import { PasswordManagerError } from './errorHandler.js';
import { decryptFile, isFileEncrypted } from './utils.js';

const readFileAsync = promisify(fs.readFile);
const writeFileAsync = promisify(fs.writeFile);

/**
 * Emergency recovery tool for password manager
 * This tool helps recover data when the normal password manager can't access files
 * @returns {Promise<boolean>} True if recovery was successful, false otherwise
 */
export const emergencyRecovery = async () => {
  console.log(chalk.yellow('\n=== EMERGENCY RECOVERY TOOL ==='));
  console.log(chalk.yellow('This tool will help you recover your password manager data'));
  console.log(chalk.yellow('in case of critical errors or file corruption.\n'));
  
  const { action } = await inquirer.prompt([
    {
      type: 'list',
      name: 'action',
      message: 'What would you like to recover?',
      choices: [
        'Master password file',
        'Passwords file',
        'Recovery key file',
        'Exit recovery'
      ]
    }
  ]);
  
  switch (action) {
    case 'Master password file':
      return await recoverMasterPasswordFile();
    case 'Passwords file': 
      return await recoverPasswordsFile();
    case 'Recovery key file':
      return await recoverKeyFile();
    case 'Exit recovery':
      console.log(chalk.green('Exiting recovery tool...'));
      return false;
    default:
      return false;
  }
};

/**
 * Recovers the master password file
 * @returns {Promise<boolean>} True if recovery was successful, false otherwise
 */
async function recoverMasterPasswordFile() {
  console.log(chalk.cyan('\nMaster Password File Recovery'));
  
  try {
    // Check if backup exists
    if (fs.existsSync(PATHS.MASTER_PASSWORD_BACKUP)) {
      console.log(chalk.green('Found master password backup file!'));
      
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
        fs.copyFileSync(PATHS.MASTER_PASSWORD_BACKUP, PATHS.MASTER_PASSWORD);
        console.log(chalk.green('Master password file restored from backup!'));
        return true;
      }
    }
    
    // If no backup or user doesn't want to use it, try recovery key method
    console.log(chalk.yellow('\nAttempting recovery using recovery key...'));
    
    // Check if recovery salt file exists
    const BASE_DIR = process.cwd();
    const RECOVERY_SALT_PATH = join(BASE_DIR, '.recovery_salt');
    const RECOVERY_SALT_BACKUP = join(BASE_DIR, '.recovery_salt.bak');
    
    if (!fs.existsSync(RECOVERY_SALT_PATH) && fs.existsSync(RECOVERY_SALT_BACKUP)) {
      console.log(chalk.yellow('Recovery salt file missing, but backup found. Restoring...'));
      fs.copyFileSync(RECOVERY_SALT_BACKUP, RECOVERY_SALT_PATH);
      console.log(chalk.green('Recovery salt file restored from backup!'));
    } else if (!fs.existsSync(RECOVERY_SALT_PATH) && !fs.existsSync(RECOVERY_SALT_BACKUP)) {
      console.log(chalk.red('Recovery key files are missing. Full recovery not possible.'));
      
      const { manualRecovery } = await inquirer.prompt([
        {
          type: 'confirm',
          name: 'manualRecovery',
          message: 'Would you like to create a new master password file?',
          default: false
        }
      ]);
      
      if (manualRecovery) {
        return await createNewMasterPasswordFile();
      }
      
      return false;
    }
    
    // Recovery key files exist, attempt auto-recovery
    try {
      if (fs.existsSync(PATHS.MASTER_PASSWORD)) {
        const fileBuffer = await readFileAsync(PATHS.MASTER_PASSWORD);
        if (!isFileEncrypted(fileBuffer)) {
          console.log(chalk.green('Master password file is not encrypted or is already accessible.'));
          return true;
        }
        
        // Try to recover with the recovery key
        const recoveryKey = await generateEmergencyRecoveryKey();
        
        try {
          const decryptedData = decryptFile(fileBuffer, recoveryKey);
          console.log(chalk.green('Successfully decrypted master password file!'));
          
          // Write the decrypted file for accessibility
          await writeFileAsync(PATHS.MASTER_PASSWORD + '.decrypted', decryptedData);
          console.log(chalk.green(`Decrypted master password saved to ${PATHS.MASTER_PASSWORD}.decrypted`));
          console.log(chalk.yellow('You can now manually recover your master password from this file.'));
          
          return true;
        } catch (error) {
          console.log(chalk.red('Failed to decrypt master password file with recovery key.'));
          return await createNewMasterPasswordFile();
        }
      } else {
        console.log(chalk.red('Master password file does not exist.'));
        return await createNewMasterPasswordFile();
      }
    } catch (error) {
      console.log(chalk.red('Error during master password recovery:', error.message));
      return false;
    }
  } catch (error) {
    console.log(chalk.red('Recovery failed:', error.message));
    return false;
  }
}

/**
 * Recovers the passwords file
 * @returns {Promise<boolean>} True if recovery was successful, false otherwise
 */
async function recoverPasswordsFile() {
  console.log(chalk.cyan('\nPasswords File Recovery'));
  
  try {
    // Check if backup exists
    if (fs.existsSync(PATHS.PASSWORDS_BACKUP)) {
      console.log(chalk.green('Found passwords backup file!'));
      
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
        console.log(chalk.green('Passwords file restored from backup!'));
        return true;
      }
    }
    
    // If we get here, either no backup exists or user didn't want to use it
    if (fs.existsSync(PATHS.PASSWORDS)) {
      console.log(chalk.yellow('\nAttempting to decrypt passwords file...'));
      
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
          console.log(chalk.green('Passwords file is not encrypted or is already accessible.'));
          return true;
        }
        
        // Try to decrypt with provided master password
        try {
          const decryptedData = decryptFile(fileBuffer, masterPassword);
          console.log(chalk.green('Successfully decrypted passwords file!'));
          
          // Write the decrypted file for accessibility
          await writeFileAsync(PATHS.PASSWORDS + '.decrypted', decryptedData);
          console.log(chalk.green(`Decrypted passwords saved to ${PATHS.PASSWORDS}.decrypted`));
          
          return true;
        } catch (error) {
          console.log(chalk.red('Failed to decrypt passwords file with provided master password.'));
          console.log(chalk.yellow('The master password may be incorrect or the file may be corrupted.'));
          return false;
        }
      } catch (error) {
        console.log(chalk.red('Error reading passwords file:', error.message));
        return false;
      }
    } else {
      console.log(chalk.red('Passwords file does not exist.'));
      return false;
    }
  } catch (error) {
    console.log(chalk.red('Recovery failed:', error.message));
    return false;
  }
}

/**
 * Recovers or creates a new recovery key file
 * @returns {Promise<boolean>} True if recovery was successful, false otherwise
 */
async function recoverKeyFile() {
  console.log(chalk.cyan('\nRecovery Key File Recovery'));
  
  try {
    const BASE_DIR = process.cwd();
    const RECOVERY_SALT_PATH = join(BASE_DIR, '.recovery_salt');
    const RECOVERY_SALT_BACKUP = join(BASE_DIR, '.recovery_salt.bak');
    
    // Check if either file exists
    if (fs.existsSync(RECOVERY_SALT_PATH)) {
      console.log(chalk.green('Recovery key file exists!'));
      
      // Create a backup if it doesn't exist
      if (!fs.existsSync(RECOVERY_SALT_BACKUP)) {
        fs.copyFileSync(RECOVERY_SALT_PATH, RECOVERY_SALT_BACKUP);
        console.log(chalk.green('Created backup of recovery key file.'));
      }
      
      return true;
    } else if (fs.existsSync(RECOVERY_SALT_BACKUP)) {
      console.log(chalk.yellow('Recovery key file missing, but backup found. Restoring...'));
      fs.copyFileSync(RECOVERY_SALT_BACKUP, RECOVERY_SALT_PATH);
      console.log(chalk.green('Recovery key file restored from backup!'));
      return true;
    } else {
      console.log(chalk.yellow('No recovery key files found. Creating new recovery key...'));
      
      // Create a new salt and save it
      const salt = crypto.randomBytes(16).toString('hex');
      await writeFileAsync(RECOVERY_SALT_PATH, salt);
      
      // Make a backup of the salt file
      await writeFileAsync(RECOVERY_SALT_BACKUP, salt);
      
      console.log(chalk.green('Created new recovery key files.'));
      console.log(chalk.yellow('WARNING: Your existing encrypted files may not be accessible with this new key.'));
      
      return true;
    }
  } catch (error) {
    console.log(chalk.red('Recovery failed:', error.message));
    return false;
  }
}

/**
 * Creates a new master password file
 * @returns {Promise<boolean>} True if creation was successful, false otherwise
 */
async function createNewMasterPasswordFile() {
  console.log(chalk.yellow('\nCreating new master password file...'));
  
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
      console.log(chalk.red('Passwords do not match!'));
      return false;
    }
    
    // Create checksum for new password
    const checksum = crypto.createHash('sha256').update(newPassword).digest('hex');
    const content = `${newPassword}\n${checksum}`;
    
    // Save the new master password file
    await writeFileAsync(PATHS.MASTER_PASSWORD, content);
    
    console.log(chalk.green('New master password file created successfully!'));
    console.log(chalk.yellow('WARNING: Your existing encrypted files may not be accessible with this new password.'));
    
    return true;
  } catch (error) {
    console.log(chalk.red('Failed to create new master password file:', error.message));
    return false;
  }
}

/**
 * Generates the emergency recovery key based on machine-specific identifiers
 * This should match the key generated by the main application
 * @returns {Promise<string>} The recovery key
 */
async function generateEmergencyRecoveryKey() {
  try {
    // Create a recovery key based on various system identifiers
    const os = await import('os');
    
    // Combine system-specific values that should be stable
    const systemInfo = [
      os.hostname(),
      os.userInfo().username,
      os.platform(),
      os.arch(),
      os.cpus()[0]?.model,
      os.homedir(),
    ].join('|');
    
    // Create a hash of the system info
    const hash = crypto.createHash('sha256').update(systemInfo).digest('hex');
    
    // Get the salt from the recovery file
    const BASE_DIR = process.cwd();
    const RECOVERY_SALT_PATH = join(BASE_DIR, '.recovery_salt');
    
    if (!fs.existsSync(RECOVERY_SALT_PATH)) {
      throw new Error('Recovery salt file not found');
    }
    
    const salt = await readFileAsync(RECOVERY_SALT_PATH, 'utf8');
    
    // Combine hash and salt to create the final recovery key
    return crypto.createHash('sha256').update(hash + salt).digest('hex');
  } catch (error) {
    console.error('Error generating emergency recovery key:', error);
    throw new PasswordManagerError(
      'Failed to generate recovery key',
      ERROR_CODES.AUTHENTICATION_FAILED
    );
  }
} 