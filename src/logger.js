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

const stripAnsi = (str) => typeof str === 'string' ? str.replace(/[\u001b\u009b][[()#;?]*(?:[0-9]{1,4}(?:;[0-9]{0,4})*)?[0-9A-ORZcf-nqry=><]/g, '') : String(str);

/**
 * Draws a formatted table in the console.
 * @param {Array<{label: string, value: string, type?: string}>} entries - The data to display.
 * @param {string} title - Optional title for the table.
 * @param {boolean} noBottom - If true, the bottom border will not be drawn.
 */
const drawTable = (entries, title = "", noBottom = false) => {
  if (!entries || entries.length === 0) return;

  const dataEntries = entries.filter(e => e.type !== 'separator');
  const maxLabelLen = Math.max(...dataEntries.map(e => stripAnsi(e.label).length), 0);
  const maxValueLen = Math.max(...dataEntries.map(e => stripAnsi(e.value).length), 0);

  const width = Math.max(maxLabelLen + maxValueLen + 5, title.length + 4);
  const horizontalLine = "─".repeat(width);

  // Spacing above
  log("");

  if (title) {
    const titlePadding = "─".repeat(Math.max(0, width - title.length - 3));
    log(blue(`┌─ ${bold(title)} ${titlePadding}┐`));
  } else {
    log(blue(`┌${horizontalLine}┐`));
  }

  entries.forEach(e => {
    if (e.type === 'separator') {
      log(blue(`├${horizontalLine}┤`));
      return;
    }

    const labelStr = stripAnsi(e.label);
    const valueStr = stripAnsi(e.value);
    const labelPadding = " ".repeat(Math.max(0, maxLabelLen - labelStr.length));
    const lineContent = ` ${underline(e.label)}${labelPadding} : ${e.value}`;
    const lineContentLen = 1 + labelStr.length + labelPadding.length + 3 + valueStr.length;
    const endPadding = " ".repeat(Math.max(0, width - lineContentLen));
    log(blue("│") + lineContent + endPadding + blue("│"));
  });

  if (!noBottom) {
    log(blue(`└${horizontalLine}┘`));
    log("");
  }
};

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
  drawTable,
  stripAnsi,
};