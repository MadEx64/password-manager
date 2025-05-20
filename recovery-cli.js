#!/usr/bin/env node
import { emergencyRecovery } from './src/recovery.js';
import chalk from 'chalk';
import inquirer from 'inquirer';

/**
 * Emergency recovery CLI tool
 * This tool helps recover the password manager data in case of critical errors
 */
const runRecovery = async () => {
  console.log(chalk.cyan('\n========================================='));
  console.log(chalk.cyan('Password Manager Emergency Recovery Tool'));
  console.log(chalk.cyan('=========================================\n'));
  
  console.log(chalk.yellow('This tool will help you recover your password data'));
  console.log(chalk.yellow('in case of file corruption or other critical errors.\n'));
  
  console.log(chalk.red('SECURITY WARNINGS:'));
  console.log(chalk.red('1. This tool will display your master password in the terminal'));
  console.log(chalk.red('2. Make sure no one can see your screen'));
  console.log(chalk.red('3. Clear your terminal history after recovery'));
  console.log(chalk.red('4. Store your recovery key in a secure location'));
  console.log(chalk.red('5. Anyone with access to your recovery key can recover your master password\n'));
  
  const { proceed } = await inquirer.prompt([
    {
      type: 'confirm',
      name: 'proceed',
      message: 'Do you understand the security implications and wish to proceed?',
      default: false
    }
  ]);
  
  if (!proceed) {
    console.log(chalk.yellow('\nRecovery cancelled.'));
    process.exit(0);
  }
  
  try {
    const result = await emergencyRecovery();
    
    if (result) {
      console.log(chalk.green('\nRecovery process completed successfully.'));
      console.log(chalk.yellow('\nIMPORTANT:'));
      console.log(chalk.yellow('1. Clear your terminal history to remove the displayed password'));
      console.log(chalk.yellow('2. Store your master password securely'));
      console.log(chalk.yellow('3. Consider creating a new recovery key for future use'));
    } else {
      console.log(chalk.red('\nRecovery process failed or was cancelled.'));
    }
  } catch (error) {
    console.error(chalk.red('\nAn error occurred during recovery:'));
    console.error(chalk.red(error.message || error));
    process.exit(1);
  }
};

runRecovery(); 