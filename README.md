# Password Manager
A command-line password manager that stores your credentials locally with **multi-layered encryption**.

## Features
- **Enhanced Security**: Multi-factor authentication using master password + application secret key
- AES-256 encryption for all data with unique device-specific keys
- Master password protection (session-based)
- Add, view, update, delete, and search passwords
- Generate strong random passwords (custom length supported)
- Encrypted backup/restore, import/export (CSV/JSON)
- Emergency recovery tool with multiple tiers

## Security Architecture
- **Two-Factor Authentication**: Combines your master password with a unique application secret key
- **Device-Specific Security**: Each installation generates a unique secret key that cannot be transferred
- **Secure Credential Storage**: Uses system credential stores (macOS Keychain, Windows DPAPI, Linux Secret Service) with encrypted fallback storage
- **Key Derivation**: Uses PBKDF2 with 100,000 iterations for secure key derivation
- **Hash-Based Verification**: Master passwords are never stored, only cryptographically secure hashes
- **Secure Session Management**: Authentication keys are cached securely in memory during sessions

## Security Details
- All data encrypted locally (AES-256-GCM)
- Session expires after 1 minute of inactivity (configurable)
- File integrity checking and secure file locking
- **Application Secret Key**: 512-bit cryptographically secure random key
- **Authentication Key**: Derived from master password + secret key using PBKDF2
- **HMAC Authentication**: Uses HMAC-SHA256 for password verification
- **Secure Storage**: Credentials stored in system credential stores or encrypted fallback storage
- Multiple backup systems for all security files

## Install & Usage
```bash
npm install
npm start
npm start -- --session-timeout 10 # Set session timeout to 10 minutes (default is 1 minute)
```

On first launch, the system will:
1. Generate a unique application secret key
2. Prompt you to set a master password
3. Create secure authentication hashes
4. Store credentials securely using system credential stores or encrypted fallback

**IMPORTANT**: Your credentials are now stored securely in the system credential store or encrypted fallback storage. The system automatically chooses the most secure option available.

## Secure Credential Storage
The password manager uses a multi-tier secure storage approach:

### Tier 1: System Credential Stores (Primary)
- **macOS**: Keychain Services
- **Windows**: DPAPI (Data Protection API) with Registry storage
- **Linux**: Secret Service API (libsecret)

### Tier 2: Encrypted Fallback Storage
- **Location**: `~/.password-manager-secure/` 
- **Encryption**: AES-256-CBC with unique device keys
- **Permissions**: Restricted to user access only (600/700)
- **Key Management**: Separate encryption key for fallback storage

### Security Files (AUTOMATICALLY MANAGED)
The system stores sensitive data securely:
- Application secret key and authentication hash are stored in secure credential storage
- Fallback encrypted files are created automatically when system storage is unavailable
- All sensitive data is encrypted with device-specific keys
- `.recovery_salt` - Recovery salt for emergency access (file-based for recovery purposes)

## Main Menu Options

![image](https://github.com/user-attachments/assets/6ad894a3-2a5e-4c03-bc48-61e1117eda5f)

- **Add/View/Update/Delete Password**: Create or manage your stored credentials
- **Search Password**: Find credentials by service name or identifier
- **Update Master Password**: Change your master password (maintains same secret key)
- **Backup & Restore**: Backup and restore your password vault locally
  
  	-  ***Create Backup***: Generate an encrypted backup of your password vault
	-  ***Restore Backup***: Restore from a previously created backup
	-  ***Delete Backup***: Remove old backup files

- **Export Passwords**: Export your stored credentials to a CSV/JSON file
- **Import Passwords**: Import credentials from a CSV/JSON file

### Managing Passwords

![Screenshot AddPassword](https://github.com/user-attachments/assets/ab7a7700-4136-45cd-a445-9f2061632500) 
![Screenshot AddPasswordHiding](https://github.com/user-attachments/assets/0acd8df2-6762-4126-8935-9d8c474931ec)

When adding or updating passwords, you can either:
- Provide your own password
- Generate a random secure password

  	- With default random length (8-16 characters)
	- Or specify a custom password length (minimum 8 characters)

Each generated password includes a mix of uppercase letters, numbers, and special characters to ensure strong security.

## Project Structure
- `index.js`: App entry point
- `src/`: Main code

  - `passwordManager.js`: Core password logic
  - `auth/`: Authentication/session management
    - `secureAuth.js`: Secure authentication system
    - `secureStorage.js`: Cross-platform secure credential storage
    - `authentication.js`: Main authentication flow
    - `password.js`: Password validation
    - `session.js`: Session management
    - `masterPasswordCache.js`: Secure key caching
  - `fileOperations/`: File I/O, backup, vault
  - `encryption/`: Encryption utilities
  - `recovery.js`: Multi-tier emergency recovery

- `recovery-cli.js`: Recovery CLI
- `tests/`: Automated tests

## Recovery System
The recovery system provides multiple tiers:

**Tier 1: Enhanced Security Recovery**
- For the secure authentication system
- Requires master password verification
- Fastest and most secure recovery method
- Allows resetting authentication hash with new master password

**Tier 2: Emergency Reset**
- Last resort when other methods fail
- Creates new security keys (data may be lost)
- Requires explicit confirmation

Run the recovery tool:
```bash
npm run recover
```

## First-Time Setup
When you first run the password manager:
1. The system generates a unique 512-bit application secret key
2. You'll be prompted to set a master password
3. Authentication hashes are created and stored securely
4. Your credentials are stored in the system credential store (or encrypted fallback)
5. The password vault is created and ready for use

## Testing
```bash
npm test
```

## License
ISC
