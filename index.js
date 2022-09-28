// modules
import inquirer from "inquirer";
import chalk from "chalk";
import { readFile, writeFile } from "fs";
import aesjs from "aes-js";

const log = console.log;

// password generator function
const generatePassword = () => {
  const charset =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let password = "";
  for (let i = 0; i < 16; i++) {
    password += charset.charAt(Math.floor(Math.random() * charset.length + 1));
  }

  return password;
};

// encrypt function
const encryptPassword = (password) => {
  const textBytes = aesjs.utils.utf8.toBytes(password);
  const aesCtr = new aesjs.ModeOfOperation.ctr(
    "my secret key123",
    new aesjs.Counter(5)
  );
  const encryptedBytes = aesCtr.encrypt(textBytes);
  const encryptedHex = aesjs.utils.hex.fromBytes(encryptedBytes);

  return encryptedHex;
};

// decrypt function
const decryptPassword = (password) => {
  const encryptedBytes = aesjs.utils.hex.toBytes(password);
  const aesCtr = new aesjs.ModeOfOperation.ctr(
    "my secret key123",
    new aesjs.Counter(5)
  );
  const decryptedBytes = aesCtr.decrypt(encryptedBytes);
  const decryptedText = aesjs.utils.utf8.fromBytes(decryptedBytes);

  return decryptedText;
};

// get passwords function
const getPasswords = () => {
  readFile("passwords.txt", "utf8", (err, data) => {
    if (err) {
      log(chalk.red("Error reading file from disk:", err));
    } else {
      // get the passwords from txt file
      const passwords = data.split(" ");

      // ask the user which password he wants to see
      inquirer
        .prompt([
          {
            type: "list",
            name: "password",
            message: "Which password do you want to see?",
            choices: passwords,
          },
        ])
        .then((answers) => {
          log(chalk.green(decryptPassword(answers.password)));
        });
    }
  });
};

const questions = [
  {
    type: "input",
    name: "name",
    message: "Enter the name of the site or application: ",

    validate: function (value) {
      if (value.length) {
        return true;
      } else {
        return "Please enter the name of the site or application";
      }
    },
  },
  {
    type: "input",
    name: "identifier",
    message:
      "Enter the identifier for the site or application(e.g. email address, username): ",

    validate: function (value) {
      if (value.length) {
        return true;
      } else {
        return "Please enter the identifier for the site or application";
      }
    },
  },
  {
    type: "input",
    name: "generatedPassword",
    message: "Would you like to generate a random password? (y/n)",
    default: "yes",

    validate: function (value) {
      var pass = value.match(/^(yes|y|no|n)$/i);
      if (pass) {
        return true;
      }

      return "Please enter a valid answer";
    },
    filter: function (value) {
      return value.toLowerCase();
    },
  },
  {
    type: "password",
    name: "userPassword",
    message: "Enter the password",
    when: (answers) =>
      answers.generatedPassword === "n" || answers.generatedPassword === "no",
  },
  {
    type: "confirm",
    name: "savePassword",
    message: "Would you like to save the password for the site or application?",
    default: true,

    validate: function (value) {
      var pass = value.match(/^(yes|y|no|n)$/i);
      if (pass) {
        return true;
      }

      return "Please enter a valid answer";
    },
    filter: function (value) {
      return value.toLowerCase();
    },
  },
];

// add password function
function addPassword() {
  inquirer
    .prompt(questions)
    .then((answers) => {
      // if user wants to generate password
      if (
        answers.generatedPassword === "yes" ||
        answers.generatedPassword === "y"
      ) {
        generatePassword();
      }
      // if user wants to save the password
      if (answers.savePassword) {
        // encrypt the password using aesjs
        const encryptedPassword = encryptPassword(answers.password);
        // save the password to a file
        writeFile("passwords.txt", encryptedPassword, (err) => {
          if (err) {
            log(chalk.red("Error writing file:", err));
          } else {
            log(chalk.green("Password saved successfully!"));
            log(chalk.green("Password: " + answers.password));
            log(chalk.green("Encrypted password: " + encryptedPassword));
          }
        });
      }
    })
    .catch((error) => {
      if (error.isTtyError) {
        log(
          chalk.red("Prompt couldn't be rendered in the current environment")
        );
      } else {
        log(chalk.red(error));
      }
    });
}

// delete passwords function
const deletePassword = () => {
  // get the passwords from the file
  readFile("passwords.txt", "utf8", (err, data) => {
    if (err) {
      log(chalk.red(err));
    } else {
      // split the passwords into an array without name and identifier
      const passwords = data.split(" - ");
      // get the name of the password to delete
      inquirer
        .prompt([
          {
            type: "list",
            name: "password",
            message: "Select the password to delete",
            choices: passwords,
          },
        ])
        .then((answer) => {
          // filter the passwords array to remove the password to delete
          const filteredPasswords = passwords.filter(
            (password) => password !== answer.password
          );

          // save the filtered passwords to the file
          writeFile("passwords.txt", filteredPasswords.join(""), (err) => {
            if (err) {
              log(chalk.red(err));
            } else {
              log(chalk.green("Password deleted"));
            }
          });
        })
        .catch((error) => {
          if (error.isTtyError) {
            log(
              chalk.red(
                "Prompt couldn't be rendered in the current environment"
              )
            );
          } else {
            log(chalk.red(error));
          }
        });
    }
  });
};

// manage the passwords
const managePasswords = () => {
  const manageQuestions = [
    {
      type: "list",
      name: "action",
      message: "What would you like to do?",
      choices: ["Add password", "View passwords", "Delete passwords", "Exit"],
    },
  ];

  inquirer.prompt(manageQuestions).then((answers) => {
    switch (answers.action) {
      case "Add password":
        addPassword();
        break;
      case "View passwords":
        // view passwords
        getPasswords();
        break;
      case "Delete passwords":
        // delete passwords
        deletePassword();
        break;
      case "Exit":
        // exit
        break;
    }
  });
};

managePasswords();
