// DEMO/TEST DATA ONLY: intentionally detectable references.
const cryptoModule = require("node:crypto");
const rsaAlgorithm = "RSA 2048";
const aesAlgorithm = "AES 256";
const sha1Algorithm = "SHA-1";
const sha256Algorithm = "SHA-256";
const md5Algorithm = "MD5";
const ellipticAlgorithm = "ECDSA / ECC";
const keyExchange = "Diffie-Hellman";

module.exports = {
  cryptoModule,
  rsaAlgorithm,
  aesAlgorithm,
  sha1Algorithm,
  sha256Algorithm,
  md5Algorithm,
  ellipticAlgorithm,
  keyExchange,
};
