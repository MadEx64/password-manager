# Secure Password Manager

A robust command-line password manager that securely stores your credentials locally with strong encryption.

## Features

- **Secure Storage**: All passwords are encrypted using AES-256 encryption before being stored locally
- **File-Level Encryption**: Entire password database files are encrypted, not just individual passwords
- **Master Password Protection**: Access to stored passwords requires authentication with your master password
- **Password Generation**: Option to generate strong random passwords with customizable length and complexity
- **Session Management**: Time-limited authentication sessions to balance security and convenience
- **Backup & Restore**: Create and restore encrypted backups of your password database
- **Import/Export**: Import and export passwords in CSV/JSON file format for easy migration
- **Emergency Recovery**: Specialized tool to recover access in case of file corruption or issues
- **Navigation System**: Intuitive navigation with options to continue, go back, or return to the main menu
- **Search Functionality**: Quickly find stored credentials by searching for apps/websites or identifiers
- **Clipboard Integration**: Copy passwords to clipboard without displaying them on screen

## Security Measures

- **AES-256 Encryption**: Industry-standard encryption for all stored passwords
- **File-Level Encryption**: Entire database files (not just passwords) are encrypted with AES-256-CBC
- **Integrity Verification**: HMAC-SHA256 ensures file data hasn't been tampered with
- **System-Based Recovery Keys**: Master password files secured with system-specific recovery keys
- **Local Storage**: All data stored locally on your device, never transmitted over the internet
- **Automatic Timeouts**: Sessions automatically expire after 1 minute of inactivity
- **Checksum Verification**: File integrity checks to prevent tampering
- **File Locking**: Prevents concurrent access that could corrupt data
- **Encrypted Backups**: Backup files are encrypted with your master password

## Installation

1. Clone the repository:

```bash
git clone https://github.com/yourusername/password-manager.git
cd password-manager
```

2. Install dependencies:

```bash
npm install
```

## Usage

Start the application:

```bash
npm start
```

### First-Time Setup

On first launch, you'll be prompted to create a master password. Choose a strong, unique password you can remember - this will be required to access all your stored passwords.

### Main Menu Options

![image](https://github.com/user-attachments/assets/fcc705d1-f8d2-41ee-a534-997126de3528)

- **Add Password**: Store credentials for a new application or website
- **View Password**: Access your stored credentials
- **Delete Password**: Remove stored credentials
- **Update Password**: Modify existing credentials
- **Search Password**: Find credentials by application name or identifier
- **Update Master Password**: Change your master password
- **Create Backup**: Generate an encrypted backup of your password database
- **Restore Backup**: Restore from a previously created backup
- **Delete Backup**: Remove old backup files
- **Import Passwords**: Import credentials from a CSV/JSON file
- **Export Passwords**: Export your stored credentials to a CSV/JSON file
- **Exit**: Close the application

### Managing Passwords

![image](https://github.com/user-attachments/assets/894db961-1744-4a46-ad26-f9205d4e52a8)

When adding or updating passwords, you can either:
- Provide your own password
- Generate a random secure password
  - With default random length (8-16 characters)
  - With custom specified length (minimum 8 characters)

Each generated password includes a mix of uppercase letters, numbers, and special characters to ensure strong security.

### Navigation

At key points in each operation, you'll be presented with navigation options:
- **Continue with current operation**: Proceed with the current action
- **Go back to previous step**: Return to the previous input screen
- **Return to main menu**: Cancel the current operation and return to the main menu

## Security Best Practices

- Use a strong, unique master password
- Create regular backups and store them securely
- Don't share your master password with anyone
- Ensure your system is free from malware and keyloggers
- Consider backing up your encrypted database to another secure location
- Regularly update your master password and stored credentials

## Emergency Recovery Tool

The password manager includes an emergency recovery tool to help you recover access in case of file corruption or other critical issues.

To use the emergency recovery tool:

```bash
npm run recover
```

Or if installed globally:

```bash
password-manager-recovery
```

### Recovery Options

- **Master Password File Recovery**: Recover your master password file using system-based recovery keys
- **Passwords File Recovery**: Recover your encrypted passwords file
- **Recovery Key File Recovery**: Recover or reset your recovery key files

### How Recovery Works

The password manager uses a sophisticated multi-layered security system:

1. **Individual Passwords**: Encrypted with AES-256-CTR
2. **Password Database File**: The entire file is encrypted with AES-256-CBC
3. **Master Password File**: Encrypted with a system-specific recovery key derived from your computer's unique characteristics

This design ensures that even if an attacker gains access to your computer files, they would need:
- Your master password
- Physical access to your specific computer
- The recovery key salt file

### Recovery Key Backup

For additional safety, the system automatically creates backup copies of critical recovery files. It's recommended to keep a secure backup of your `.recovery_salt` file, as this is essential for recovering your master password file in case of system issues.

## Development

### Project Structure

- `index.js`: Main application entry point
- `src/authentication.js`: Handles master password and user authentication
- `src/constants.js`: Application-wide constants and configuration
- `src/errorHandler.js`: Error handling and validation
- `src/fileOperations.js`: File I/O operations for passwords and backups
- `src/navigation.js`: Navigation system for the application
- `src/passwordManager.js`: Core password management functions
- `src/utils.js`: Utility functions including encryption/decryption

### Running Tests

```bash
npm test
```

## License

ISC
