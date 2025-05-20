# Password Manager

A command-line password manager that stores your credentials locally with strong encryption.

## Features
- AES-256 encryption for all data
- Master password protection (session-based)
- Add, view, update, delete, and search passwords
- Generate strong random passwords (custom length supported)
- Encrypted backup/restore, import/export (CSV/JSON)
- Emergency recovery tool

## Security
- All data encrypted locally (AES-256)
- Session expires after 1 minute of inactivity
- File integrity and locking

## Install & Usage

```bash
npm install
npm start
```
On first launch, set a master password. Use the menu to manage credentials.

## Main Menu Options

![image](https://github.com/user-attachments/assets/fcc705d1-f8d2-41ee-a534-997126de3528)

- **Add/View/Update/Delete Password**: Create or manage your stored credentials
- **Search Password**: Find credentials by service name or identifier
- **Update Master Password**: Change your master password
- **Backup & Restore**: Backup and restore your password database
  -  ***Create Backup***: Generate an encrypted backup of your password database
	-  ***Restore Backup***: Restore from a previously created backup
	-  ***Delete Backup***: Remove old backup files
- **Import Passwords**: Import credentials from a CSV/JSON file
- **Export Passwords**: Export your stored credentials to a CSV/JSON file

### Managing Passwords

![image](https://github.com/user-attachments/assets/894db961-1744-4a46-ad26-f9205d4e52a8)

When adding or updating passwords, you can either:
- Provide your own password
- Generate a random secure password
  - With default random length (8-16 characters)
  - Or specify a custom password length (minimum 8 characters)

Each generated password includes a mix of uppercase letters, numbers, and special characters to ensure strong security. You will be prompted whether you want to specify the password length when 
generating a password.

## Project Structure
- `index.js`: App entry point
- `src/`: Main code
  - `passwordManager.js`: Core password logic
  - `auth/`: Authentication/session
  - `fileOperations/`: File I/O, backup, vault
  - `utils.js`: Encryption, helpers
  - `recovery.js`: Emergency recovery
- `recovery-cli.js`: Recovery CLI
- `tests/`: Automated tests

## Recovery
Run the recovery tool if you lose access:
```bash
npm run recover
```

## Testing
```bash
npm test
```

## License
ISC
