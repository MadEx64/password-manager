#!/usr/bin/env node
import { emergencyRecovery } from './src/recovery.js';
import chalk from 'chalk';

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
  
  try {
    await emergencyRecovery();
    console.log(chalk.green('\nRecovery process completed.'));
  } catch (error) {
    console.error(chalk.red('\nAn error occurred during recovery:'));
    console.error(chalk.red(error.message || error));
    process.exit(1);
  }
};

runRecovery(); 