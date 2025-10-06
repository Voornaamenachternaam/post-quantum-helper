/**
 * @fileoverview Tests for crypto utilities
 * Testing Framework: Mocha with Chai
 */

import { expect } from 'chai';
import {
  Base64,
  HKDF,
  ChaCha20Poly1305,
  SecureRandom,
  CryptoUtils,
} from '../src/crypto-utils.js';

describe('Base64', () => {
  describe('encode', () => {
    it('should encode Uint8Array to Base64 string', () => {
      const bytes = new Uint8Array([72, 101, 108, 108, 111]); // "Hello"
      const encoded = Base64.encode(bytes);
      expect(encoded).to.equal('SGVsbG8=');
    });

    it('should handle empty array', () => {
      const bytes = new Uint8Array([]);
      const encoded = Base64.encode(bytes);
      expect(encoded).to.equal('');
    });

    it('should handle binary data', () => {
      const bytes = new Uint8Array([0, 1, 2, 255, 254, 253]);
      const encoded = Base64.encode(bytes);
      expect(encoded).to.be.a('string');
      expect(encoded.length).to.be.greaterThan(0);
    });
  });

  describe('decode', () => {
    it('should decode Base64 string to Uint8Array', () => {
      const base64 = 'SGVsbG8=';
      const decoded = Base64.decode(base64);
      expect(decoded).to.be.instanceOf(Uint8Array);
      expect(Array.from(decoded)).to.deep.equal([72, 101, 108, 108, 111]);
    });

    it('should handle empty string', () => {
      const decoded = Base64.decode('');
      expect(decoded).to.be.instanceOf(Uint8Array);
      expect(decoded.length).to.equal(0);
    });

    it('should round-trip encode/decode', () => {
      const original = new Uint8Array([1, 2, 3, 4, 5, 255, 254, 253]);
      const encoded = Base64.encode(original);
      const decoded = Base64.decode(encoded);
      expect(Array.from(decoded)).to.deep.equal(Array.from(original));
    });
  });
});

describe('HKDF', () => {
  describe('derive', () => {
    it('should derive a key of specified length', async () => {
      const ikm = new Uint8Array(32).fill(1);
      const salt = new Uint8Array(32).fill(2);
      const info = 'test-context';
      const length = 32;

      const derived = await HKDF.derive(ikm, salt, info, length);

      expect(derived).to.be.instanceOf(Uint8Array);
      expect(derived.length).to.equal(length);
    });

    it('should produce different keys for different info', async () => {
      const ikm = new Uint8Array(32).fill(1);
      const salt = new Uint8Array(32).fill(2);

      const key1 = await HKDF.derive(ikm, salt, 'context1', 32);
      const key2 = await HKDF.derive(ikm, salt, 'context2', 32);

      expect(Array.from(key1)).to.not.deep.equal(Array.from(key2));
    });

    it('should produce different keys for different salts', async () => {
      const ikm = new Uint8Array(32).fill(1);
      const salt1 = new Uint8Array(32).fill(2);
      const salt2 = new Uint8Array(32).fill(3);
      const info = 'test-context';

      const key1 = await HKDF.derive(ikm, salt1, info, 32);
      const key2 = await HKDF.derive(ikm, salt2, info, 32);

      expect(Array.from(key1)).to.not.deep.equal(Array.from(key2));
    });

    it('should be deterministic with same inputs', async () => {
      const ikm = new Uint8Array(32).fill(1);
      const salt = new Uint8Array(32).fill(2);
      const info = 'test-context';

      const key1 = await HKDF.derive(ikm, salt, info, 32);
      const key2 = await HKDF.derive(ikm, salt, info, 32);

      expect(Array.from(key1)).to.deep.equal(Array.from(key2));
    });
  });
});

describe('ChaCha20Poly1305', () => {
  describe('encrypt and decrypt', () => {
    it('should encrypt and decrypt data successfully', async () => {
      const key = SecureRandom.getRandomBytes(32);
      const nonce = SecureRandom.getRandomBytes(12);
      const plaintext = new TextEncoder().encode('Hello, World!');

      const ciphertext = await ChaCha20Poly1305.encrypt(key, nonce, plaintext);
      const decrypted = await ChaCha20Poly1305.decrypt(key, nonce, ciphertext);

      expect(decrypted).to.be.instanceOf(Uint8Array);
      expect(new TextDecoder().decode(decrypted)).to.equal('Hello, World!');
    });

    it('should produce different ciphertext with different nonces', async () => {
      const key = SecureRandom.getRandomBytes(32);
      const nonce1 = SecureRandom.getRandomBytes(12);
      const nonce2 = SecureRandom.getRandomBytes(12);
      const plaintext = new TextEncoder().encode('Test message');

      const ciphertext1 = await ChaCha20Poly1305.encrypt(
        key,
        nonce1,
        plaintext
      );
      const ciphertext2 = await ChaCha20Poly1305.encrypt(
        key,
        nonce2,
        plaintext
      );

      expect(Array.from(ciphertext1)).to.not.deep.equal(
        Array.from(ciphertext2)
      );
    });

    it('should fail to decrypt with wrong key', async () => {
      const key1 = SecureRandom.getRandomBytes(32);
      const key2 = SecureRandom.getRandomBytes(32);
      const nonce = SecureRandom.getRandomBytes(12);
      const plaintext = new TextEncoder().encode('Secret message');

      const ciphertext = await ChaCha20Poly1305.encrypt(key1, nonce, plaintext);

      try {
        await ChaCha20Poly1305.decrypt(key2, nonce, ciphertext);
        expect.fail('Should have thrown an error');
      } catch (error) {
        expect(error).to.exist;
      }
    });

    it('should handle empty plaintext', async () => {
      const key = SecureRandom.getRandomBytes(32);
      const nonce = SecureRandom.getRandomBytes(12);
      const plaintext = new Uint8Array([]);

      const ciphertext = await ChaCha20Poly1305.encrypt(key, nonce, plaintext);
      const decrypted = await ChaCha20Poly1305.decrypt(key, nonce, ciphertext);

      expect(decrypted.length).to.equal(0);
    });
  });
});

describe('SecureRandom', () => {
  describe('getRandomBytes', () => {
    it('should generate random bytes of specified length', () => {
      const bytes = SecureRandom.getRandomBytes(32);
      expect(bytes).to.be.instanceOf(Uint8Array);
      expect(bytes.length).to.equal(32);
    });

    it('should generate different random values each time', () => {
      const bytes1 = SecureRandom.getRandomBytes(32);
      const bytes2 = SecureRandom.getRandomBytes(32);
      expect(Array.from(bytes1)).to.not.deep.equal(Array.from(bytes2));
    });
  });

  describe('generateSalt', () => {
    it('should generate 32-byte salt', () => {
      const salt = SecureRandom.generateSalt();
      expect(salt).to.be.instanceOf(Uint8Array);
      expect(salt.length).to.equal(32);
    });
  });

  describe('generateNonce', () => {
    it('should generate 12-byte nonce', () => {
      const nonce = SecureRandom.generateNonce();
      expect(nonce).to.be.instanceOf(Uint8Array);
      expect(nonce.length).to.equal(12);
    });
  });
});

describe('CryptoUtils', () => {
  describe('secureClear', () => {
    it('should clear sensitive data', () => {
      const data = new Uint8Array([1, 2, 3, 4, 5]);
      CryptoUtils.secureClear(data);
      expect(Array.from(data)).to.deep.equal([0, 0, 0, 0, 0]);
    });

    it('should handle null/undefined gracefully', () => {
      expect(() => CryptoUtils.secureClear(null)).to.not.throw();
      expect(() => CryptoUtils.secureClear(undefined)).to.not.throw();
    });
  });

  describe('constantTimeEqual', () => {
    it('should return true for equal arrays', () => {
      const a = new Uint8Array([1, 2, 3, 4]);
      const b = new Uint8Array([1, 2, 3, 4]);
      expect(CryptoUtils.constantTimeEqual(a, b)).to.be.true;
    });

    it('should return false for different arrays', () => {
      const a = new Uint8Array([1, 2, 3, 4]);
      const b = new Uint8Array([1, 2, 3, 5]);
      expect(CryptoUtils.constantTimeEqual(a, b)).to.be.false;
    });

    it('should return false for different length arrays', () => {
      const a = new Uint8Array([1, 2, 3]);
      const b = new Uint8Array([1, 2, 3, 4]);
      expect(CryptoUtils.constantTimeEqual(a, b)).to.be.false;
    });
  });
});
