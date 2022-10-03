// modules
import inquirer from "inquirer";
import chalk from "chalk";
import { readFile, writeFile } from "fs";

import { generatePassword, encryptPassword, decryptPassword } from "./utils.js";

const log = console.log;

const getPasswords = () => {
  readFile("passwords.txt", "utf8", (err, data) => {
    if (err) {
      log(chalk.red("Error reading file from disk:", err));
    } else if (!data) {
      log(chalk.red("No password saved, please add a new password"));
      managePasswords();
    } else {
      // get app names to display as choices
      const lines = data.split(/\r?\n/);
      const appNames = [];
      lines.forEach((line) => {
        const [app] = line.split(" - ");
        appNames.push(app);
      });

      // remove empty line
      appNames.pop();

      // ask user which app to get the password from
      inquirer
        .prompt([
          {
            type: "list",
            name: "app",
            message: "Which app do you want to get the password for?",
            choices: appNames,
          },
        ])
        .then((answer) => {
          lines.forEach((line) => {
            const [app, identifier, password] = line.split(" - ");
            if (app === answer.app) {
              const decryptedPassword = decryptPassword(password);
              log(
                chalk.green(`The password for ${app} is ${decryptedPassword}`)
              );

              managePasswords();
            }
          });
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
        return "Please enter the identifier for the site or application (e.g. email address, username)";
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

      return "Please enter a valid answer (y/n)";
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

      return "Please enter a valid answer (y/n)";
    },
    filter: function (value) {
      return value.toLowerCase();
    },
  },
];

const addPassword = () => {
  inquirer
    .prompt(questions)
    .then((answers) => {
      if (answers.savePassword) {
        // if user wants to generate password
        if (
          answers.generatedPassword === "yes" ||
          answers.generatedPassword === "y"
        ) {
          const encryptedPassword = encryptPassword(generatePassword());

          writeFile(
            "passwords.txt",
            `${answers.name} - ${answers.identifier} - ${encryptedPassword}` +
              "\n",
            { flag: "a" },
            (err) => {
              if (err) {
                log(chalk.red("Error trying to save password:", err));
              } else {
                log(chalk.green("Successfully saved password"));
              }

              managePasswords();
            }
          );
        } else {
          const encryptedUserPassword = encryptPassword(answers.userPassword);
          // write password to file
          writeFile(
            "passwords.txt",
            `${answers.name} - ${answers.identifier} - ${encryptedUserPassword}` +
              "\n",
            { flag: "a" },
            (err) => {
              if (err) {
                log(chalk.red("Error writing file:", err));
              } else {
                log(chalk.green("Successfully saved password"));
              }

              managePasswords();
            }
          );
        }
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
};

const deletePassword = () => {
  readFile("passwords.txt", "utf8", (err, data) => {
    if (err) {
      log(chalk.red(err));
    } else if (!data) {
      log(chalk.red("No password saved, please add a new password"));
      managePasswords();
    } else {
      const lines = data.split(/\r?\n/);
      // loop through lines to get app names
      const appNames = [];
      lines.forEach((line) => {
        const [app] = line.split(" - ");
        appNames.push(app);
      });

      // remove empty line
      appNames.pop();

      // ask user which app to delete password for
      inquirer
        .prompt([
          {
            type: "list",
            name: "password",
            message: "Select the password to delete",
            choices: appNames,
          },
        ])
        .then((answer) => {
          // filter the line to delete from the file
          const filteredPasswords = lines.filter(
            (line) => !line.includes(answer.password)
          );

          // save the filtered passwords to the file
          writeFile("passwords.txt", filteredPasswords.join("\n"), (err) => {
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
