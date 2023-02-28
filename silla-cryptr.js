
var SimpleCrypto = require("simple-crypto-js").default

function Cryptr(secret) {
  if (!secret || typeof secret !== "string") {
    throw new Error("Cryptr: secret must be a non-0-length string");
  }

  const simpleCrypto = new SimpleCrypto(secret);


  this.encrypt = function encrypt(value) {
    if (value == null) {
      throw new Error("value must not be null or undefined");
    }
    return simpleCrypto.encrypt(value);
  };

  this.decrypt = function decrypt(value) {
    if (value == null) {
      throw new Error("value must not be null or undefined");
    }
    return simpleCrypto.decrypt(value);
  };
}

module.exports = Cryptr;