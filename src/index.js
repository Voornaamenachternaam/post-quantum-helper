/**
 * @fileoverview Post-Quantum Helper - Main module exports
 * Provides a simple API for post-quantum encryption using ML-KEM + ChaCha20-Poly1305
 */

// Export key management functions
export {
  generateKeyPair,
  exportKeyPair,
  importKeyPair,
  validatePublicKey,
  getKeySizes,
} from './key-manager.js';

// Export encryption/decryption functions
export { encrypt, decrypt, isValidEncryptedMessage } from './encryptor.js';

// Export crypto utilities
export {
  Base64,
  HKDF,
  ChaCha20Poly1305,
  SecureRandom,
  CryptoUtils,
} from './crypto-utils.js';

// Version and metadata
export const VERSION = '1.0.0';
export const ALGORITHMS = ['ML-KEM-1024', 'ML-KEM-768'];
export const DEFAULT_ALGORITHM = 'ML-KEM-1024';
