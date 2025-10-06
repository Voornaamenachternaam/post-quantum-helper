/**
 * @fileoverview Tests for key manager
 * Testing Framework: Mocha with Chai
 */

import { expect } from 'chai';
import {
  generateKeyPair,
  exportKeyPair,
  importKeyPair,
  validatePublicKey,
} from '../src/key-manager.js';
import { Base64 } from '../src/crypto-utils.js';

describe('Key Manager', () => {
  describe('generateKeyPair', () => {
    it('should generate ML-KEM-1024 key pair by default', async () => {
      const keyPair = await generateKeyPair();

      expect(keyPair).to.have.property('publicKey');
      expect(keyPair).to.have.property('privateKey');
      expect(keyPair).to.have.property('algorithm');
      expect(keyPair.algorithm).to.equal('ML-KEM-1024');
      expect(keyPair.publicKey).to.be.a('string');
      expect(keyPair.privateKey).to.be.a('string');
    });

    it('should generate ML-KEM-1024 key pair when specified', async () => {
      const keyPair = await generateKeyPair('ML-KEM-1024');

      expect(keyPair.algorithm).to.equal('ML-KEM-1024');

      // Decode and check sizes
      const publicKeyBytes = Base64.decode(keyPair.publicKey);
      const privateKeyBytes = Base64.decode(keyPair.privateKey);

      expect(publicKeyBytes.length).to.equal(1568); // ML-KEM-1024 public key size
      expect(privateKeyBytes.length).to.equal(3168); // ML-KEM-1024 private key size
    });

    it('should generate ML-KEM-768 key pair when specified', async () => {
      const keyPair = await generateKeyPair('ML-KEM-768');

      expect(keyPair.algorithm).to.equal('ML-KEM-768');

      // Decode and check sizes
      const publicKeyBytes = Base64.decode(keyPair.publicKey);
      const privateKeyBytes = Base64.decode(keyPair.privateKey);

      expect(publicKeyBytes.length).to.equal(1184); // ML-KEM-768 public key size
      expect(privateKeyBytes.length).to.equal(2400); // ML-KEM-768 private key size
    });

    it('should generate different key pairs each time', async () => {
      const keyPair1 = await generateKeyPair();
      const keyPair2 = await generateKeyPair();

      expect(keyPair1.publicKey).to.not.equal(keyPair2.publicKey);
      expect(keyPair1.privateKey).to.not.equal(keyPair2.privateKey);
    });

    it('should throw error for unsupported algorithm', async () => {
      try {
        await generateKeyPair('INVALID-ALGORITHM');
        expect.fail('Should have thrown an error');
      } catch (error) {
        expect(error.message).to.include('Unsupported algorithm');
      }
    });
  });

  describe('exportKeyPair', () => {
    it('should export key pair with metadata', async () => {
      const keyPair = await generateKeyPair('ML-KEM-1024');
      const exported = exportKeyPair(keyPair);

      expect(exported).to.have.property('publicKey');
      expect(exported).to.have.property('privateKey');
      expect(exported).to.have.property('algorithm');
      expect(exported).to.have.property('timestamp');
      expect(exported).to.have.property('version');

      expect(exported.publicKey).to.equal(keyPair.publicKey);
      expect(exported.privateKey).to.equal(keyPair.privateKey);
      expect(exported.algorithm).to.equal('ML-KEM-1024');
      expect(exported.version).to.equal('1.0.0');
      expect(exported.timestamp).to.be.a('number');
    });

    it('should be JSON serializable', async () => {
      const keyPair = await generateKeyPair();
      const exported = exportKeyPair(keyPair);

      const json = JSON.stringify(exported);
      const parsed = JSON.parse(json);

      expect(parsed.publicKey).to.equal(exported.publicKey);
      expect(parsed.privateKey).to.equal(exported.privateKey);
      expect(parsed.algorithm).to.equal(exported.algorithm);
    });
  });

  describe('importKeyPair', () => {
    it('should import exported key pair', async () => {
      const original = await generateKeyPair('ML-KEM-1024');
      const exported = exportKeyPair(original);
      const imported = importKeyPair(exported);

      expect(imported.publicKey).to.equal(original.publicKey);
      expect(imported.privateKey).to.equal(original.privateKey);
      expect(imported.algorithm).to.equal(original.algorithm);
    });

    it('should validate required fields', () => {
      const invalidData = {
        publicKey: 'test',
        // missing privateKey
        algorithm: 'ML-KEM-1024',
      };

      try {
        importKeyPair(invalidData);
        expect.fail('Should have thrown an error');
      } catch (error) {
        expect(error.message).to.include('Invalid key pair data');
      }
    });

    it('should validate algorithm', () => {
      const invalidData = {
        publicKey: 'test',
        privateKey: 'test',
        algorithm: 'INVALID',
      };

      try {
        importKeyPair(invalidData);
        expect.fail('Should have thrown an error');
      } catch (error) {
        expect(error.message).to.include('Unsupported algorithm');
      }
    });

    it('should handle legacy format without algorithm field', () => {
      const legacyData = {
        publicKey: 'dGVzdA==', // base64 "test"
        privateKey: 'dGVzdA==',
      };

      const imported = importKeyPair(legacyData);
      expect(imported.algorithm).to.equal('ML-KEM-1024'); // Default
    });
  });

  describe('validatePublicKey', () => {
    it('should validate ML-KEM-1024 public key', async () => {
      const keyPair = await generateKeyPair('ML-KEM-1024');
      const isValid = validatePublicKey(keyPair.publicKey, 'ML-KEM-1024');
      expect(isValid).to.be.true;
    });

    it('should validate ML-KEM-768 public key', async () => {
      const keyPair = await generateKeyPair('ML-KEM-768');
      const isValid = validatePublicKey(keyPair.publicKey, 'ML-KEM-768');
      expect(isValid).to.be.true;
    });

    it('should reject invalid Base64', () => {
      const isValid = validatePublicKey('not-valid-base64!!!', 'ML-KEM-1024');
      expect(isValid).to.be.false;
    });

    it('should reject wrong size key', async () => {
      const keyPair = await generateKeyPair('ML-KEM-768');
      // Try to validate 768 key as 1024
      const isValid = validatePublicKey(keyPair.publicKey, 'ML-KEM-1024');
      expect(isValid).to.be.false;
    });

    it('should reject empty string', () => {
      const isValid = validatePublicKey('', 'ML-KEM-1024');
      expect(isValid).to.be.false;
    });

    it('should reject null/undefined', () => {
      expect(validatePublicKey(null, 'ML-KEM-1024')).to.be.false;
      expect(validatePublicKey(undefined, 'ML-KEM-1024')).to.be.false;
    });
  });
});
