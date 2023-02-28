var forge = require('node-forge');
// import { Buffer } from "buffer/";
const Buffer = require('buffer/').Buffer
const algorithm = "AES-GCM";
const ivLength = 16;
const tagLength = 16;
const defaultSaltLength = 64;
const defaultPbkdf2Iterations = 100000;

function Cryptr(secret, options) {
  if (!secret || typeof secret !== "string") {
    throw new Error("Cryptr: secret must be a non-0-length string");
  }

  let saltLength = defaultSaltLength;
  let pbkdf2Iterations = defaultPbkdf2Iterations;

  if (options) {
    if (options.pbkdf2Iterations) {
      pbkdf2Iterations = options.pbkdf2Iterations;
    }

    if (options.saltLength) {
      saltLength = options.saltLength;
    }
  }

  const tagPosition = saltLength + ivLength;
  const encryptedPosition = tagPosition + tagLength;

  function getKey(salt) {
    return forge.pkcs5.pbkdf2(secret, salt, pbkdf2Iterations, 32, "sha512");
  }

  this.encrypt = function encrypt(value) {
    if (value == null) {
      throw new Error("value must not be null or undefined");
    }

    const iv = forge.random.getBytesSync(ivLength);
    const salt = forge.random.getBytesSync(saltLength);

    const key = getKey(salt);

    const cipher = forge.cipher.createCipher(algorithm, key);
    cipher.start({ iv, tagLength });
    cipher.update(forge.util.createBuffer(String(value), "utf8"));
    cipher.finish();
    const encrypted = cipher.output.toHex();
    const tag = cipher.mode.tag.toHex();
    const result = Buffer.concat([
      Buffer.from(salt),
      Buffer.from(iv),
      Buffer.from(tag, "hex"),
      Buffer.from(encrypted, "hex")
    ]).toString('hex');
    return result;
  };

  this.decrypt = function decrypt(value) {
    if (value == null) {
      throw new Error("value must not be null or undefined");
    }

    const stringValue = Buffer.from(String(value), "hex");

    const salt = stringValue.slice(0, saltLength);
    const iv = stringValue.slice(saltLength, tagPosition);
    const tag = stringValue.slice(tagPosition, encryptedPosition);
    const encrypted = stringValue.slice(encryptedPosition);

    const key = getKey(salt);

    const decipher = forge.cipher.createDecipher(algorithm, key);
    decipher.start({ iv, tagLength, tag });
    decipher.update(encrypted);
    const result = decipher.finish();

    if (result) {
      return decipher.output.toString();
    } else return null;
  };
}

module.exports = Cryptr;