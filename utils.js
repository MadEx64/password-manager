import aesjs from "aes-js";

// 256-bit key
const key = [
  1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
  23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
];

const generatePassword = () => {
  // generate a random password between 8 and 16 characters, at least one number, one capital letter or one special character (e.g. !@#$%^&*)
  const charset =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-.!@#$%^&*_+=/?";
  let password = "";
  let length = Math.floor(Math.random() * 8) + 8;

  while (length--) {
    password += charset[Math.floor(Math.random() * charset.length)];

    if (length === 0) {
      if (!password.match(/[A-Z]/)) {
        password += charset[Math.floor(Math.random() * 26) + 26];
      } else if (!password.match(/[0-9]/)) {
        password += charset[Math.floor(Math.random() * 10) + 52];
      } else if (!password.match(/[-.!@#$%^&*_+=/?]/)) {
        password += charset[Math.floor(Math.random() * 16) + 62];
      }
    }

    // shuffle the password
    password = password
      .split("")
      .sort(() => Math.random() - 0.5)
      .join("");
  }

  return password;
};

const encryptPassword = (password) => {
  const textBytes = aesjs.utils.utf8.toBytes(password);
  const aesCtr = new aesjs.ModeOfOperation.ctr(key, new aesjs.Counter(5));
  const encryptedBytes = aesCtr.encrypt(textBytes);
  const encryptedHex = aesjs.utils.hex.fromBytes(encryptedBytes);

  return encryptedHex;
};

const decryptPassword = (password) => {
  const encryptedBytes = aesjs.utils.hex.toBytes(password);
  const aesCtr = new aesjs.ModeOfOperation.ctr(key, new aesjs.Counter(5));
  const decryptedBytes = aesCtr.decrypt(encryptedBytes);
  const decryptedText = aesjs.utils.utf8.fromBytes(decryptedBytes);

  return decryptedText;
};

// function writeToFile(path, data) {
//   return new Promise((resolve, reject) => {
//     fs.writeFile(path, data, (err) => {
//       if (err) {
//         reject(err);
//       } else {
//         resolve();
//       }
//     });
//   });
// }

// const readFromFile = (path) => {
//   return new Promise((resolve, reject) => {
//     fs.readFile(path, "utf8", (err, data) => {
//       if (err) {
//         reject(err);
//       } else {
//         resolve(data);
//       }
//     });
//   });
// };

export { generatePassword, encryptPassword, decryptPassword };
