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
npm start -- --session-timeout 10 # Set session timeout to 10 minutes (default is 5 minutes)
```

On first launch, set a master password. Use the menu to manage credentials.

## Main Menu Options

![image](https://github.com/user-attachments/assets/6ad894a3-2a5e-4c03-bc48-61e1117eda5f)

- **Add/View/Update/Delete Password**: Create or manage your stored credentials
- **Search Password**: Find credentials by service name or identifier
- **Update Master Password**
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
