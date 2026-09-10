// Sample Node.js file demonstrating crypto usage (for testing).
const crypto = require("crypto");

// Weak hashing - legacy algorithm.
const md5Hash = crypto.createHash("md5").update("data").digest("hex");

// Stronger hashing.
const sha256Hash = crypto.createHash("sha256").update("data").digest("hex");

// Symmetric AES encryption.
const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);

// RSA public-key encryption.
const encrypted = crypto.publicEncrypt(publicKey, buffer);