// modules
import inquirer from "inquirer";
import chalk from "chalk";
import { readFile, writeFile, existsSync } from "fs";

import { generatePassword, encryptPassword, decryptPassword } from "./utils.js";

var log = console.log;
var isAuthenticated = false;

const getPasswords = () => {
  readFile("passwords.txt", "utf8", (err, data) => {
    if (err) {
      log(chalk.red("Error reading file from disk:", err + "\n"));
    } else if (!data) {
      log(
        chalk.red("\n" + "No password saved, please add a new password" + "\n")
      );
      managePasswords();
    } else {
      // get app names to display as choices for user to select from
      const lines = data.split(/\r?\n/);
      const appNames = [];
      lines.forEach((line) => {
        const [app] = line.split(" - ");
        appNames.push(app);
      });

      // remove empty line from app names
      appNames.pop();

      // ask user which app to get the password from
      inquirer
        .prompt([
          {
            type: "list",
            name: "app",
            message: "Which app do you want to get the password for?",
            choices: appNames,

            // choices: [appNames, new inquirer.Separator(), "Cancel"],
          },
        ])
        .then((answer) => {
          lines.forEach((line) => {
            const [app, identifier, password] = line.split(" - ");
            if (app === answer.app) {
              const decryptedPassword = decryptPassword(password);
              log(
                chalk.green.bold(
                  "\n" +
                    `Identifier: ${identifier}, Password: ${decryptedPassword}` +
                    "\n"
                )
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
                log(
                  chalk.red("\n" + "Error trying to save password:", err + "\n")
                );
              } else {
                log(
                  chalk.green.bold("\n" + "Successfully saved password" + "\n")
                );
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
                log(chalk.red("\n" + "Error writing file:", err + "\n"));
              } else {
                log(
                  chalk.green.bold("\n" + "Successfully saved password" + "\n")
                );
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
      log(
        chalk.red("\n" + "No password saved, please add a new password" + "\n")
      );
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
          // filter the line containing the password to delete
          const filteredPasswords = lines.filter(
            (line) => !line.includes(answer.password)
          );

          // save the filtered passwords to the file
          writeFile("passwords.txt", filteredPasswords.join("\n"), (err) => {
            if (err) {
              log(chalk.red(err));
            } else {
              log(chalk.green.bold("\n" + "Password deleted" + "\n"));

              managePasswords();
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

const modifyMasterPassword = () => {
  inquirer
    .prompt([
      {
        type: "password",
        name: "oldMasterPassword",
        message: "Enter your old master password",

        validate: function (value) {
          if (value.length) {
            return true;
          } else {
            return "Please enter your old master password";
          }
        },
      },
      {
        type: "password",
        name: "newMasterPassword",
        message: "Enter your new master password",

        validate: function (value) {
          if (value.length) {
            return true;
          } else {
            return "Please enter your new master password";
          }
        },
      },
      {
        type: "password",
        name: "confirmPassword",
        message: "Confirm password",

        validate: function (value) {
          if (value.length) {
            return true;
          } else {
            return "Please confirm your password";
          }
        },
      },
    ])
    .then((answers) => {
      const { oldMasterPassword, newMasterPassword, confirmPassword } = answers;

      // check if old master password is correct before changing it to new master password
      readFile("masterPassword.txt", "utf8", (err, data) => {
        if (err) {
          log(chalk.red(err));
        } else {
          const decryptedMasterPassword = decryptPassword(data);

          if (oldMasterPassword === decryptedMasterPassword) {
            if (newMasterPassword === confirmPassword) {
              // encrypt new master password
              const encryptedMasterPassword =
                encryptPassword(newMasterPassword);
              // save new master password to file
              writeFile(
                "masterPassword.txt",
                encryptedMasterPassword,
                (err) => {
                  if (err) {
                    log(chalk.red(err));
                  } else {
                    log(
                      chalk.green.bold("\n" + "Master password updated" + "\n")
                    );
                  }
                }
              );
            } else {
              log(chalk.red("\n" + "Passwords do not match" + "\n"));
            }
          } else {
            log(chalk.red("\n" + "Incorrect master password" + "\n"));

            modifyMasterPassword();
          }
        }
      });
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

const managePasswords = () => {
  if (existsSync("masterPassword.txt")) {
    if (!isAuthenticated) {
      // ask user for master password
      inquirer
        .prompt([
          {
            type: "password",
            name: "masterPassword",
            message: "Enter your master password",
          },
        ])
        .then((answer) => {
          readFile("masterPassword.txt", "utf8", (err, data) => {
            if (err) {
              log(chalk.red(err));
            } else {
              const decryptedMasterPassword = decryptPassword(data);

              if (answer.masterPassword === decryptedMasterPassword) {
                isAuthenticated = true;
                log(
                  chalk.green.bold(
                    "\n" + "Authentication successful" + " " + "👍" + "\n"
                  )
                );
                managePasswords();
              } else {
                log(
                  chalk.red(
                    "\n" +
                      "Wrong master password. Authentication failed" +
                      " " +
                      "👎" +
                      "\n"
                  )
                );
                managePasswords();
              }
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
    } else {
      const manageQuestions = [
        {
          type: "list",
          name: "action",
          message: "What would you like to do?",
          choices: [
            "Add password",
            "View passwords",
            "Delete passwords",
            "Modify master password",
            "Exit",
          ],
        },
      ];

      inquirer.prompt(manageQuestions).then((answers) => {
        switch (answers.action) {
          case "Add password":
            addPassword();
            break;
          case "View passwords":
            getPasswords();
            break;
          case "Delete passwords":
            deletePassword();
            break;
          case "Modify master password":
            modifyMasterPassword();
            break;
          case "Exit":
            break;
        }
      });
    }
  } else {
    // ask user to set a master password if not already set
    inquirer
      .prompt([
        {
          type: "password",
          name: "masterPassword",
          message: "Set a master password",
        },
      ])
      .then((answer) => {
        writeFile(
          "masterPassword.txt",
          encryptPassword(answer.masterPassword),
          (err) => {
            if (err) {
              log(chalk.red(err));
            } else {
              log(chalk.green.bold("\n " + "Master password saved" + "\n"));
              managePasswords();
            }
          }
        );
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
};

managePasswords();
