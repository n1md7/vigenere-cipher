/**
 * @description Password-based encryption using Vigenère cipher
 * @param {{
 *   type: 'alphanumeric' | 'numbers' | 'lowercase' | 'uppercase' | 'symbols' | 'ascii' | 'base64' | 'custom',
 *   strict: boolean,
 *   characters: string,
 *   secret: string,
 * }} options
 * @constructor
 */
function Vigenere(options = {}) {
  const secret = {value: null};
  const characterTypes = {
    alphanumeric: 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
    numbers: '0123456789',
    lowercase: 'abcdefghijklmnopqrstuvwxyz',
    uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    symbols: `!@#$%^&*()_+-=[]{}|;':",./<>?`,
    // Ascii includes space, numbers, letters, and symbols
    ascii: `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;':",./<>? `,
    base64: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=',
    custom: options.characters,
  };

  options.strict = Boolean(options.strict);
  if (!options.type) options.type = 'base64';
  if (!characterTypes[options.type]) {
    throw new TypeError('Invalid character type. Available options are: ' + Object.keys(characterTypes).join(', ') + ';');
  }

  if (options.type === 'custom') {
    if (!options.characters) {
      throw new TypeError('Characters must be specified when using custom character type.');
    }
    if (!options.characters.length) {
      throw new TypeError('Custom characters must be a non-empty string.');
    }
  }
  if (options.secret) secret.value = options.secret;


  function verifySecret(secret) {
    if (!secret) throw new TypeError('Secret must be specified.');
    if (!secret.length) throw new TypeError('Secret must be a non-empty string.');

    secret.split('').every(character => {
      if ( characterTypes[options.type].indexOf(character) === -1) {
        throw new TypeError(`Secret characters must contains only values from '${characterTypes[options.type]}'. ['${character}'] not allowed!`);
      }
      return true;
    });
  }

  function verifyMessage(message, strict = false) {
    if (!message) throw new TypeError('Message must be specified.');
    if (!message.length) throw new TypeError('Message must be a non-empty string.');
    if(!strict) return;
    message.split('').every(character => {
      if (characterTypes[options.type].indexOf(character) === -1) {
        throw new TypeError(`Message characters must contains only values from '${characterTypes[options.type]}'. ['${character}'] not allowed in strict mode!`);
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
  function encryptOrDecrypt(message, secret , operation) {
    verifySecret(secret);
    verifyMessage(message, options.strict);
    const charMap = characterTypes[options.type];
    const encryptedMessage = {value: ''};

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
      if(operation === 'encrypt') {
        encryptedMessage.value += charMap[(x + y) % charMap.length];
        continue;
      }
      
      // Decrypt
      encryptedMessage.value += charMap[(y - x + charMap.length) % charMap.length];
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
    return encryptOrDecrypt(message, secret, 'encrypt');
  }

  /**
   * @description Decodes a message using Vigenere cipher
   * @param message
   * @param {string} secret
   * @returns {string}
   */
  function decode(message, secret = options.secret) {
    return encryptOrDecrypt(message, secret, 'decrypt');
  }

  this.encode = encode;
  this.decode = decode;
}

