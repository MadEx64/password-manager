#!/usr/bin/env node

// modules
import inquirer from "inquirer";
import chalk from "chalk";
import { readFile, writeFile, existsSync } from "fs";
import clipboard from "clipboardy";

import { generatePassword, encryptPassword, decryptPassword } from "./utils.js";

var log = console.log;
var isAuthenticated = false;
var path = "./passwords.txt";
var masterPasswordPath = "./masterPassword.txt";

const getLines = (data) => {
  return data.split(/\r?\n/);
};

const getAppNames = (lines) => {
  const appNames = [];
  lines.forEach((line) => {
    const [app] = line.split(" - ");
    appNames.push(app);
  });

  // remove empty line from app names
  appNames.pop();

  return appNames;
};

const managePasswords = () => {
  authenticateUser();

  if (isAuthenticated) {
    const manageQuestions = [
      {
        type: "list",
        name: "action",
        message: "What would you like to do?",
        choices: [
          "Add password",
          "View password",
          "Delete password",
          "Update password",
          "Update master password",
          "Exit",
        ],
      },
    ];

    inquirer.prompt(manageQuestions).then((answers) => {
      switch (answers.action) {
        case "Add password":
          addPassword();
          break;
        case "View password":
          getPasswords();
          break;
        case "Delete password":
          deletePassword();
          break;
        case "Update password":
          updatePassword();
          break;
        case "Update master password":
          updateMasterPassword();
          break;
        case "Exit":
          log(chalk.green("Thank you for using password-manager !"));
          break;
      }
    });
  }
};

const authenticateUser = () => {
  if (existsSync(masterPasswordPath)) {
    if (!isAuthenticated) {
      inquirer
        .prompt([
          {
            type: "password",
            name: "masterPassword",
            message: "Enter your master password:",

            validate: (value) => {
              return value.length ? true : "Please enter your master password";
            },

            mask: "*",
          },
        ])
        .then((answer) => {
          readFile(masterPasswordPath, "utf8", (err, data) => {
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
                authenticateUser();
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
    }
  } else {
    // if master password file does not exist, create one
    // ask user to set a master password if not already set
    log(chalk.green("\n" + "Please set a master password to continue" + "\n"));
    inquirer
      .prompt([
        {
          type: "password",
          name: "masterPassword",
          message: "Set your master password:",

          validate: function (value) {
            if (value.length < 8) {
              return "Password must be at least 8 characters";
            }
            return true;
          },

          mask: "*",
        },
      ])
      .then((answer) => {
        writeFile(
          masterPasswordPath,
          encryptPassword(answer.masterPassword),
          (err) => {
            if (err) {
              log(chalk.red(err));
            } else {
              log(chalk.green.bold("\n " + "Master password saved !" + "\n"));
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

const getPasswords = () => {
  readFile(path, "utf8", (err, data) => {
    if (err) {
      log(
        chalk.red(
          "Error reading file from disk: file does not exist" +
            "\n" +
            "Please add a password first" +
            "\n"
        )
      );
      managePasswords();
    } else if (!data) {
      log(
        chalk.red("\n" + "No password saved, please add a new password" + "\n")
      );
      managePasswords();
    } else {
      // get app names to display as choices for user to select from
      const lines = getLines(data);
      const appNames = getAppNames(lines);
      // ask user which app to get the password from
      inquirer
        .prompt([
          {
            type: "list",
            name: "app",
            message: "Which app do you want to get the password for ?",
            choices: appNames,
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

              // ask user if they want to copy password to clipboard
              inquirer
                .prompt([
                  {
                    type: "confirm",
                    name: "copy",
                    message: "Do you want to copy password to clipboard ?",
                  },
                ])
                .then((answer) => {
                  if (answer.copy) {
                    // copy password to clipboard
                    clipboard.writeSync(decryptedPassword);
                    log(
                      chalk.green.bold(
                        "\n" + "Password copied to clipboard !" + "\n"
                      )
                    );

                    managePasswords();
                  } else {
                    log(chalk.red.bold("\n" + "Password not copied !" + "\n"));
                    managePasswords();
                  }
                });
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
    message: "Enter the password:",
    when: (answers) =>
      answers.generatedPassword === "n" || answers.generatedPassword === "no",

    validate: function (value) {
      return value.length > 0 || "Please enter a password";
    },

    mask: "*",
  },
  {
    type: "password",
    name: "confirmPassword",
    message: "Confirm the password:",
    when: (answers) =>
      answers.generatedPassword === "n" || answers.generatedPassword === "no",

    validate: function (value, answers) {
      if (value === answers.userPassword) {
        return true;
      } else {
        return "Passwords do not match";
      }
    },

    mask: "*",
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
            path,
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
                  chalk.green.bold(
                    "\n" + "Successfully saved password !" + "\n"
                  )
                );
              }

              managePasswords();
            }
          );
        } else {
          const encryptedUserPassword = encryptPassword(answers.userPassword);
          // write password to file
          writeFile(
            path,
            `${answers.name} - ${answers.identifier} - ${encryptedUserPassword}` +
              "\n",
            { flag: "a" },
            (err) => {
              if (err) {
                log(chalk.red("\n" + "Error writing file:", err + "\n"));
              } else {
                log(
                  chalk.green.bold(
                    "\n" + "Successfully saved password !" + "\n"
                  )
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
  readFile(path, "utf8", (err, data) => {
    if (err) {
      log(chalk.red(err));
    } else if (!data) {
      log(
        chalk.red("\n" + "No password saved, please add a new password" + "\n")
      );
      managePasswords();
    } else {
      const lines = getLines(data);
      const appNames = getAppNames(lines);

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
          writeFile(path, filteredPasswords.join("\n"), (err) => {
            if (err) {
              log(chalk.red(err));
            } else {
              log(chalk.green.bold("\n" + "Password deleted !" + "\n"));

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

const updatePassword = () => {
  readFile(path, "utf8", (err, data) => {
    if (err) {
      log(chalk.red(err));
    } else if (!data) {
      log(
        chalk.red("\n" + "No password saved, please add a new password" + "\n")
      );
    } else {
      const lines = getLines(data);
      const appNames = getAppNames(lines);

      // ask user which app to update password for
      inquirer
        .prompt([
          {
            type: "list",
            name: "password",
            message: "Select the password to update",
            choices: appNames,
          },
        ])
        .then((answer) => {
          const lineToUpdate = lines.find((line) =>
            line.includes(answer.password)
          );

          const index = lines.indexOf(lineToUpdate);

          // ask user for new password or generate one if user wants to
          inquirer
            .prompt([
              {
                type: "confirm",
                name: "generatedPassword",
                message: "Would you like to generate a password?",
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
              {
                type: "password",
                name: "newPassword",
                message: "Enter the new password:",
                when: (answers) =>
                  answers.generatedPassword === "n" ||
                  answers.generatedPassword === "no",
                validate: function (value) {
                  if (value.length < 8) {
                    return "Password must be at least 8 characters";
                  } else {
                    return true;
                  }
                },
                mask: "*",
              },
              {
                type: "password",
                name: "confirmPassword",
                message: "Confirm the password:",
                when: (answers) =>
                  answers.generatedPassword === "n" ||
                  answers.generatedPassword === "no",
                validate: function (value, answers) {
                  if (value === answers.newPassword) {
                    return true;
                  } else {
                    return "Passwords do not match";
                  }
                },
                mask: "*",
              },
            ])
            .then((answers) => {
              if (answers.generatedPassword === "yes" || "y") {
                const encryptedPassword = encryptPassword(generatePassword());

                lines[index] = lineToUpdate.replace(
                  lineToUpdate.split(" - ")[2],
                  encryptedPassword
                );
              } else {
                // update the line with the new password
                lines[index] = lineToUpdate.replace(
                  lineToUpdate.split(" - ")[2],
                  encryptPassword(answers.newPassword)
                );
              }

              writeFile(path, lines.join("\n"), (err) => {
                if (err) {
                  log(chalk.red(err));
                } else {
                  log(chalk.green.bold("\n" + "Password updated !" + "\n"));

                  managePasswords();
                }
              });
            });
        });
    }
  });
};

const updateMasterPassword = () => {
  inquirer
    .prompt([
      {
        type: "password",
        name: "oldMasterPassword",
        message: "Enter your old master password:",

        validate: function (value) {
          return value.length ? true : "Please enter your old master password";
        },

        mask: "*",
      },
      {
        type: "password",
        name: "newMasterPassword",
        message: "Enter your new master password:",

        validate: function (value) {
          if (value.length < 8) {
            return "Password must be at least 8 characters";
          }
          return true;
        },

        mask: "*",
      },
      {
        type: "password",
        name: "confirmPassword",
        message: "Confirm new password:",

        validate: function (value) {
          if (value.length) {
            return true;
          } else {
            return "Please confirm your password";
          }
        },

        mask: "*",
      },
    ])
    .then((answers) => {
      const { oldMasterPassword, newMasterPassword, confirmPassword } = answers;

      // check if old master password is correct before changing it to new master password
      readFile(masterPasswordPath, "utf8", (err, data) => {
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
              writeFile(masterPasswordPath, encryptedMasterPassword, (err) => {
                if (err) {
                  log(chalk.red(err));
                } else {
                  log(chalk.green.bold("\n" + "Master password updated !"));
                  managePasswords();
                }
              });
            } else {
              log(chalk.red("\n" + "Passwords do not match !"));
            }
          } else {
            log(chalk.red("\n" + "Incorrect master password !"));

            updateMasterPassword();
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

managePasswords();
