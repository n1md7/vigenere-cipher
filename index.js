/**
 * @description Password-based encryption using Vigenère cipher
 * @param {{
 *   type?: 'alphanumeric' | 'numbers' | 'lowercase' | 'uppercase' | 'symbols' | 'ascii' | 'base64' | 'custom',
 *   strict?: boolean,
 *   characters?: string,
 *   secret?: string,
 * }} options
 * @constructor
 */
module.exports = function Vigenere(options = {}) {
  const secret = { value: null };
  const characterTypes = {
    numbers: "0123456789",
    custom: "CUSTOM_TYPE", // will be replaced by the custom type below
    lowercase: "abcdefghijklmnopqrstuvwxyz",
    uppercase: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    symbols: `!@#$%^&*()_+-=[]{}|;':",./<>?`,
    base64: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",
    alphanumeric:
      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
    ascii: `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;':",./<>? `,
  };

  options.strict = Boolean(options.strict);
  if (!options.type) options.type = "base64";
  if (!characterTypes[options.type]) {
    throw new TypeError(
      "Invalid type provided. Available options are: " +
        Object.keys(characterTypes).join(", ") +
        ";"
    );
  }

  if (options.type === "custom") {
    if (!options.characters) {
      throw new TypeError(
        "Characters must be specified when using custom character type."
      );
    }
    if (typeof options.characters !== "string") {
      throw new TypeError("Custom characters must be a non-empty string.");
    }
    options.characters = String(options.characters);
  }
  if (options.secret) secret.value = options.secret;

  function verifySecret(secret) {
    if (!secret) throw new TypeError("Secret must be specified.");
    if (!secret.length)
      throw new TypeError("Secret must be a non-empty string.");
    if (typeof secret.value !== "string")
      throw new TypeError("Secret key characters must be string type.");

    secret.split("").every((character) => {
      if (characterTypes[options.type].indexOf(character) === -1) {
        throw new TypeError(
          `Secret characters must contains only values from '${
            characterTypes[options.type]
          }'. ['${character}'] not allowed!`
        );
      }
      return true;
    });
  }

  function verifyMessage(message, strict = false) {
    if (!message) throw new TypeError("Message must be specified.");
    if (!message.length)
      throw new TypeError("Message must be a non-empty string.");
    if (!strict) return;
    message.split("").every((character) => {
      if (characterTypes[options.type].indexOf(character) === -1) {
        throw new TypeError(
          `Message characters must contains only values from '${
            characterTypes[options.type]
          }'. ['${character}'] not allowed in strict mode!`
        );
      }
      return true;
    });
  }

  /**
   * @description Encrypts|Decrypts a message using Vigenere cipher
   * @param {string} message
   * @param {string} secret
   * @param {'encrypt' | 'decrypt'} operation
   * @returns {string}
   */
  function encryptOrDecrypt(message, secret, operation) {
    verifySecret(secret);
    verifyMessage(message, options.strict);
    const charMap = characterTypes[options.type];
    const encryptedMessage = { value: "" };

    for (let i = 0; i < message.length; i++) {
      const messageLetter = message[i];
      const unknownLetter = charMap.indexOf(messageLetter) === -1;

      if (unknownLetter) {
        encryptedMessage.value += message[i];
        continue;
      }

      const secretLetter = secret[i % secret.length];
      const x = charMap.indexOf(secretLetter);
      const y = charMap.indexOf(messageLetter);
      if (operation === "encrypt") {
        encryptedMessage.value += charMap[(x + y) % charMap.length];
        continue;
      }

      // Decrypt
      encryptedMessage.value +=
        charMap[(y - x + charMap.length) % charMap.length];
    }

    return encryptedMessage.value;
  }

  /**
   * @description Encodes a message using Vigenere cipher
   * @param message
   * @param {string} secret
   * @returns {string}
   */
  function encode(message, secret = options.secret) {
    return encryptOrDecrypt(message, secret, "encrypt");
  }

  /**
   * @description Decodes a message using Vigenere cipher
   * @param message
   * @param {string} secret
   * @returns {string}
   */
  function decode(message, secret = options.secret) {
    return encryptOrDecrypt(message, secret, "decrypt");
  }

  this.encode = encode;
  this.decode = decode;
};
