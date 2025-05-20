import chalk from 'chalk';

const bold = chalk.bold;
const underline = chalk.underline;
const green = chalk.green;
const yellow = chalk.yellow;
const red = chalk.red;
const blue = chalk.blue;

const log = console.log;
const info = (...args) => log(blue("[INFO]"), ...args);
const warn = (...args) => log(yellow("[WARN]"), ...args);
const error = (...args) => log(red("[ERROR]"), ...args);
const success = (...args) => log(green("[SUCCESS]"), ...args);

export {
  log,
  info,
  warn,
  error,
  success,
  bold,
  underline,
  green,
  yellow,
  red,
  blue,
}; 