import crypto from "crypto";
import fetch from "node-fetch";

/**
 * 
 * @returns {string[]} an array of words
 * @description gets the word list from the EFF website
 */
const getWordList = async () => {
  const response = await fetch("https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt");
  const text = await response.text();
  const words = text.trim().split("\n").map((line) => line.split("\t")[1]);
  words.splice(240);
  return words;
};

/**
 * 
 * @param {string} lines
 * @returns {string[]} an array of app names
 */
const getAppNames = (lines) => {
  const appNames = [];
  lines.forEach((line) => {
    const [app] = line.split(" - ");
    appNames.push(app.trim());
  });

  return appNames;
};

/**
 * 
 * @returns {string} a random password
 * @description generates a random password using the Diceware method
 * @see https://en.wikipedia.org/wiki/Diceware
 * @see https://www.eff.org/dice
 * @see https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt
 */
const generatePassword = () => {
  const wordList = getWordList();
  console.log('wordList: ' + wordList.length)
  const password = [];
  for (let i = 0; i < 6; i++) {
    const index = crypto.randomInt(0, wordList.length);
    console.log('index' + index);
    password.push(wordList[index]);
  }

  return password.join("-");
};

/**
 * 
 * @param {string} password
 * @returns {object} an object with the encrypted password, key, and iv
 * @description encrypts a password using the crypto module
 * @see https://nodejs.org/api/crypto.html#crypto_crypto_createcipheriv_algorithm_key_iv_options
 * 
 * @example
 * const encryptedPassword = encryptPassword("correct-horse-battery-staple");
 * console.log(encryptedPassword); // "c89a391d7f44d3cf87"
*/
const encryptPassword = (password) => {
  const key = crypto.randomBytes(32);
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);

  const encrypted = cipher.update(password);
  const finalBuffer = Buffer.concat([encrypted, cipher.final()]);
  const encryptedPassword = finalBuffer.toString("hex");

  return { encryptedPassword, key, iv };
};

/**
 * 
 * @param {string} encryptedPassword
 * @param {Buffer} [key]
 * @param {Buffer} [iv]
 * @returns {string} a decrypted password
 * @description decrypts a password using the crypto module
 * 
 * @example
 * const decryptedPassword = decryptPassword("c89a391d7f44d3cf87", key, iv);
 * console.log(decryptedPassword); // "correct-horse-battery-staple"
*/
const decryptPassword = (encryptedPassword, key, iv) => {
  const encryptedBuffer = Buffer.from(encryptedPassword, "hex");
  const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);

  const decrypted = decipher.update(encryptedBuffer);
  const finalBuffer = Buffer.concat([decrypted, decipher.final()]);
  const decryptedPassword = finalBuffer.toString();

  return decryptedPassword;
};

export { generatePassword, encryptPassword, decryptPassword, getWordList, getAppNames };
