/**
 * @fileoverview Core cryptographic utilities for post-quantum encryption
 * Provides Base64 encoding, HKDF, ChaCha20-Poly1305, and secure random generation
 * Node.js-only implementation (no browser dependencies)
 */

import { randomBytes } from 'node:crypto';
import { webcrypto } from 'node:crypto';
import { chacha20poly1305 } from '@noble/ciphers/chacha';

const { subtle } = webcrypto;

/**
 * Base64 encoding and decoding utilities
 */
export class Base64 {
  /**
   * Encode Uint8Array to Base64 string
   * @param {Uint8Array} bytes - Bytes to encode
   * @returns {string} Base64 encoded string
   */
  static encode(bytes) {
    return Buffer.from(bytes).toString('base64');
  }

  /**
   * Decode Base64 string to Uint8Array
   * @param {string} base64 - Base64 string to decode
   * @returns {Uint8Array} Decoded bytes
   */
  static decode(base64) {
    return new Uint8Array(Buffer.from(base64, 'base64'));
  }
}

/**
 * HKDF (HMAC-based Key Derivation Function) implementation
 */
export class HKDF {
  /**
   * Derive a key using HKDF-SHA256
   * @param {Uint8Array} inputKeyMaterial - Input key material
   * @param {Uint8Array} salt - Salt value
   * @param {string} info - Context and application specific information
   * @param {number} length - Desired output key length in bytes
   * @returns {Promise<Uint8Array>} Derived key
   */
  static async derive(inputKeyMaterial, salt, info, length) {
    // Import the input key material
    const key = await subtle.importKey(
      'raw',
      inputKeyMaterial,
      { name: 'HKDF' },
      false,
      ['deriveBits']
    );

    // Derive bits using HKDF
    const derivedBits = await subtle.deriveBits(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt,
        info: new TextEncoder().encode(info),
      },
      key,
      length * 8 // Convert bytes to bits
    );

    return new Uint8Array(derivedBits);
  }
}

/**
 * ChaCha20-Poly1305 AEAD encryption using Noble crypto library
 */
export class ChaCha20Poly1305 {
  /**
   * Encrypt data using ChaCha20-Poly1305
   * @param {Uint8Array} key - 256-bit encryption key
   * @param {Uint8Array} nonce - 96-bit or 192-bit nonce
   * @param {Uint8Array} plaintext - Data to encrypt
   * @param {Uint8Array} [additionalData] - Optional additional authenticated data
   * @returns {Promise<Uint8Array>} Ciphertext with authentication tag
   */
  static async encrypt(
    key,
    nonce,
    plaintext,
    additionalData = new Uint8Array(0)
  ) {
    try {
      const cipher = chacha20poly1305(key, nonce, additionalData);
      const ciphertext = cipher.encrypt(plaintext);
      return ciphertext;
    } catch (error) {
      throw new Error(`ChaCha20-Poly1305 encryption failed: ${error.message}`);
    }
  }

  /**
   * Decrypt data using ChaCha20-Poly1305
   * @param {Uint8Array} key - 256-bit encryption key
   * @param {Uint8Array} nonce - 96-bit or 192-bit nonce
   * @param {Uint8Array} ciphertext - Data to decrypt (includes auth tag)
   * @param {Uint8Array} [additionalData] - Optional additional authenticated data
   * @returns {Promise<Uint8Array>} Decrypted plaintext
   */
  static async decrypt(
    key,
    nonce,
    ciphertext,
    additionalData = new Uint8Array(0)
  ) {
    try {
      const cipher = chacha20poly1305(key, nonce, additionalData);
      const plaintext = cipher.decrypt(ciphertext);
      return plaintext;
    } catch (error) {
      throw new Error(`ChaCha20-Poly1305 decryption failed: ${error.message}`);
    }
  }
}

/**
 * Secure random number generation
 */
export class SecureRandom {
  /**
   * Generate random bytes
   * @param {number} length - Number of bytes to generate
   * @returns {Uint8Array} Random bytes
   */
  static getRandomBytes(length) {
    return new Uint8Array(randomBytes(length));
  }

  /**
   * Generate a 32-byte salt for HKDF
   * @returns {Uint8Array} 32-byte salt
   */
  static generateSalt() {
    return this.getRandomBytes(32);
  }

  /**
   * Generate a 12-byte nonce for ChaCha20-Poly1305
   * @returns {Uint8Array} 12-byte nonce
   */
  static generateNonce() {
    return this.getRandomBytes(12);
  }
}

/**
 * Cryptographic utility functions
 */
export class CryptoUtils {
  /**
   * Securely clear sensitive data from memory
   * @param {Uint8Array} data - Data to clear
   */
  static secureClear(data) {
    if (data && data.fill) {
      data.fill(0);
    }
  }

  /**
   * Compare two byte arrays in constant time
   * @param {Uint8Array} a - First array
   * @param {Uint8Array} b - Second array
   * @returns {boolean} True if arrays are equal
   */
  static constantTimeEqual(a, b) {
    if (a.length !== b.length) {
      return false;
    }

    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a[i] ^ b[i];
    }

    return result === 0;
  }
}
