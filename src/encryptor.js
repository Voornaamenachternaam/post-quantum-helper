/**
 * @fileoverview Post-quantum encryption and decryption
 * Uses ML-KEM for key encapsulation and ChaCha20-Poly1305 for message encryption
 */

import { MlKem1024, MlKem768 } from 'mlkem';
import {
  Base64,
  HKDF,
  ChaCha20Poly1305,
  SecureRandom,
  CryptoUtils,
} from './crypto-utils.js';

// Algorithm instances
const mlKem1024 = new MlKem1024();
const mlKem768 = new MlKem768();

/**
 * Encrypt a message for a recipient using post-quantum cryptography
 * @param {string} message - Plain text message to encrypt
 * @param {string} recipientPublicKey - Recipient's public key (Base64)
 * @param {string} [algorithm='ML-KEM-1024'] - Algorithm to use
 * @returns {Promise<string>} Encrypted message as JSON string
 */
export async function encrypt(
  message,
  recipientPublicKey,
  algorithm = 'ML-KEM-1024'
) {
  try {
    // Validate inputs
    if (!message && message !== '') {
      throw new Error('Message is required');
    }

    if (!recipientPublicKey || typeof recipientPublicKey !== 'string') {
      throw new Error('Invalid recipient public key');
    }

    // Validate Base64 format
    if (!/^[A-Za-z0-9+/]+=*$/.test(recipientPublicKey)) {
      throw new Error('Public key must be valid Base64');
    }

    // Decode recipient's public key
    const recipientPubKeyBytes = Base64.decode(recipientPublicKey);

    // Select KEM algorithm
    const kemInstance = algorithm === 'ML-KEM-768' ? mlKem768 : mlKem1024;

    // Encapsulate to get shared secret and KEM ciphertext
    const [kemCiphertext, sharedSecret] =
      await kemInstance.encap(recipientPubKeyBytes);

    // Derive encryption key using HKDF
    const salt = SecureRandom.generateSalt();
    const chachaKey = await HKDF.derive(
      sharedSecret,
      salt,
      'ChaCha20-Poly1305',
      32
    );

    // Generate nonce
    const nonce = SecureRandom.generateNonce();

    // Encrypt message
    const plaintext = new TextEncoder().encode(message);
    const messageCiphertext = await ChaCha20Poly1305.encrypt(
      chachaKey,
      nonce,
      plaintext
    );

    // Create encrypted message structure
    const encryptedMessage = {
      v: 3, // Version 3 for post-quantum
      alg: algorithm,
      kem: Base64.encode(kemCiphertext),
      s: Base64.encode(salt),
      n: Base64.encode(nonce),
      c: Base64.encode(messageCiphertext),
      t: Date.now(),
    };

    // Clear sensitive data
    CryptoUtils.secureClear(chachaKey);
    CryptoUtils.secureClear(sharedSecret);

    return JSON.stringify(encryptedMessage);
  } catch (error) {
    throw new Error(`Encryption failed: ${error.message}`);
  }
}

/**
 * Decrypt a message using private key
 * @param {string} encryptedContent - Encrypted message (JSON string)
 * @param {string} privateKey - Private key (Base64)
 * @param {string} [algorithm='ML-KEM-1024'] - Algorithm to use (optional, auto-detected)
 * @returns {Promise<string>} Decrypted message
 */
export async function decrypt(encryptedContent, privateKey, algorithm = null) {
  try {
    // Validate inputs
    if (!encryptedContent || typeof encryptedContent !== 'string') {
      throw new Error('Invalid encrypted content');
    }

    if (!privateKey || typeof privateKey !== 'string') {
      throw new Error('Invalid private key');
    }

    // Parse encrypted message
    let messageData;
    try {
      messageData = JSON.parse(encryptedContent);
    } catch {
      throw new Error('Invalid encrypted message format');
    }

    // Validate message structure
    if (
      !messageData.v ||
      !messageData.alg ||
      !messageData.kem ||
      !messageData.s ||
      !messageData.n ||
      !messageData.c
    ) {
      throw new Error('Missing required fields in encrypted message');
    }

    // Determine algorithm from message or parameter
    const detectedAlgorithm = algorithm || messageData.alg;

    // Select KEM algorithm
    const kemInstance =
      detectedAlgorithm === 'ML-KEM-768' ? mlKem768 : mlKem1024;

    // Decode private key and KEM ciphertext
    const privateKeyBytes = Base64.decode(privateKey);
    const kemCiphertext = Base64.decode(messageData.kem);

    // Decapsulate to recover shared secret
    const sharedSecret = await kemInstance.decap(
      kemCiphertext,
      privateKeyBytes
    );

    // Derive decryption key using HKDF
    const salt = Base64.decode(messageData.s);
    const chachaKey = await HKDF.derive(
      sharedSecret,
      salt,
      'ChaCha20-Poly1305',
      32
    );

    // Decrypt message
    const nonce = Base64.decode(messageData.n);
    const messageCiphertext = Base64.decode(messageData.c);

    const plaintext = await ChaCha20Poly1305.decrypt(
      chachaKey,
      nonce,
      messageCiphertext
    );

    // Clear sensitive data
    CryptoUtils.secureClear(chachaKey);
    CryptoUtils.secureClear(sharedSecret);

    // Decode message
    const messageText = new TextDecoder().decode(plaintext);

    return messageText;
  } catch (error) {
    throw new Error(`Decryption failed: ${error.message}`);
  }
}

/**
 * Verify if encrypted content is valid
 * @param {string} encryptedContent - Encrypted message to verify
 * @returns {boolean} True if valid
 */
export function isValidEncryptedMessage(encryptedContent) {
  try {
    if (!encryptedContent || typeof encryptedContent !== 'string') {
      return false;
    }

    const messageData = JSON.parse(encryptedContent);

    return !!(
      messageData.v &&
      messageData.alg &&
      messageData.kem &&
      messageData.s &&
      messageData.n &&
      messageData.c
    );
  } catch {
    return false;
  }
}
