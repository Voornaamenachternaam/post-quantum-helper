/**
 * @fileoverview Key management for post-quantum encryption
 * Handles ML-KEM key pair generation, import, export, and validation
 */

import { MlKem1024, MlKem768 } from 'mlkem';
import { Base64 } from './crypto-utils.js';

// Key size constants
const ML_KEM_1024_PUBLIC_KEY_SIZE = 1568;
const ML_KEM_1024_PRIVATE_KEY_SIZE = 3168;
const ML_KEM_768_PUBLIC_KEY_SIZE = 1184;
const ML_KEM_768_PRIVATE_KEY_SIZE = 2400;

// Supported algorithms
const SUPPORTED_ALGORITHMS = ['ML-KEM-1024', 'ML-KEM-768'];
const DEFAULT_ALGORITHM = 'ML-KEM-1024';

/**
 * Generate a post-quantum key pair
 * @param {string} [algorithm='ML-KEM-1024'] - Algorithm to use ('ML-KEM-1024' or 'ML-KEM-768')
 * @returns {Promise<{publicKey: string, privateKey: string, algorithm: string}>} Key pair
 */
export async function generateKeyPair(algorithm = DEFAULT_ALGORITHM) {
  if (!SUPPORTED_ALGORITHMS.includes(algorithm)) {
    throw new Error(
      `Unsupported algorithm: ${algorithm}. Supported: ${SUPPORTED_ALGORITHMS.join(', ')}`
    );
  }

  try {
    let kemInstance;
    if (algorithm === 'ML-KEM-1024') {
      kemInstance = new MlKem1024();
    } else {
      kemInstance = new MlKem768();
    }

    // Generate key pair [publicKey, privateKey]
    const keyPair = await kemInstance.generateKeyPair();

    return {
      publicKey: Base64.encode(keyPair[0]),
      privateKey: Base64.encode(keyPair[1]),
      algorithm,
    };
  } catch (error) {
    throw new Error(
      `Failed to generate ${algorithm} key pair: ${error.message}`
    );
  }
}

/**
 * Export key pair with metadata for storage
 * @param {{publicKey: string, privateKey: string, algorithm: string}} keyPair - Key pair to export
 * @returns {{publicKey: string, privateKey: string, algorithm: string, timestamp: number, version: string}}
 */
export function exportKeyPair(keyPair) {
  return {
    publicKey: keyPair.publicKey,
    privateKey: keyPair.privateKey,
    algorithm: keyPair.algorithm,
    timestamp: Date.now(),
    version: '1.0.0',
  };
}

/**
 * Import key pair from exported data
 * @param {Object} data - Exported key pair data
 * @returns {{publicKey: string, privateKey: string, algorithm: string}} Imported key pair
 */
export function importKeyPair(data) {
  // Validate required fields
  if (!data || typeof data !== 'object') {
    throw new Error('Invalid key pair data: must be an object');
  }

  if (!data.publicKey || typeof data.publicKey !== 'string') {
    throw new Error('Invalid key pair data: missing or invalid publicKey');
  }

  if (!data.privateKey || typeof data.privateKey !== 'string') {
    throw new Error('Invalid key pair data: missing or invalid privateKey');
  }

  // Handle legacy format without algorithm field
  const algorithm = data.algorithm || DEFAULT_ALGORITHM;

  // Validate algorithm
  if (!SUPPORTED_ALGORITHMS.includes(algorithm)) {
    throw new Error(
      `Unsupported algorithm: ${algorithm}. Supported: ${SUPPORTED_ALGORITHMS.join(', ')}`
    );
  }

  return {
    publicKey: data.publicKey,
    privateKey: data.privateKey,
    algorithm,
  };
}

/**
 * Validate a public key format and size
 * @param {string} publicKey - Base64 encoded public key
 * @param {string} [algorithm='ML-KEM-1024'] - Expected algorithm
 * @returns {boolean} True if valid
 */
export function validatePublicKey(publicKey, algorithm = DEFAULT_ALGORITHM) {
  try {
    // Check if publicKey is a valid string
    if (!publicKey || typeof publicKey !== 'string') {
      return false;
    }

    // Check if it's valid Base64
    if (!/^[A-Za-z0-9+/]+=*$/.test(publicKey)) {
      return false;
    }

    // Decode and check size
    const keyBytes = Base64.decode(publicKey);

    // Determine expected size based on algorithm
    let expectedSize;
    if (algorithm === 'ML-KEM-1024') {
      expectedSize = ML_KEM_1024_PUBLIC_KEY_SIZE;
    } else if (algorithm === 'ML-KEM-768') {
      expectedSize = ML_KEM_768_PUBLIC_KEY_SIZE;
    } else {
      return false;
    }

    // Check if size matches
    if (keyBytes.length !== expectedSize) {
      return false;
    }

    // Basic sanity check: key shouldn't be all zeros
    const allZeros = keyBytes.every((byte) => byte === 0);
    if (allZeros) {
      return false;
    }

    return true;
  } catch {
    return false;
  }
}

/**
 * Get key size information for an algorithm
 * @param {string} algorithm - Algorithm name
 * @returns {{publicKeySize: number, privateKeySize: number}} Key sizes in bytes
 */
export function getKeySizes(algorithm = DEFAULT_ALGORITHM) {
  if (algorithm === 'ML-KEM-1024') {
    return {
      publicKeySize: ML_KEM_1024_PUBLIC_KEY_SIZE,
      privateKeySize: ML_KEM_1024_PRIVATE_KEY_SIZE,
    };
  } else if (algorithm === 'ML-KEM-768') {
    return {
      publicKeySize: ML_KEM_768_PUBLIC_KEY_SIZE,
      privateKeySize: ML_KEM_768_PRIVATE_KEY_SIZE,
    };
  } else {
    throw new Error(`Unknown algorithm: ${algorithm}`);
  }
}
