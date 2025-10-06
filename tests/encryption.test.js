/**
 * @fileoverview Tests for encryption and decryption
 * Testing Framework: Mocha with Chai
 */

import { expect } from 'chai';
import { encrypt, decrypt } from '../src/encryptor.js';
import { generateKeyPair } from '../src/key-manager.js';

describe('Encryption and Decryption', () => {
  describe('encrypt', () => {
    it('should encrypt a message with ML-KEM-1024', async () => {
      const recipientKeys = await generateKeyPair('ML-KEM-1024');
      const message = 'Hello, quantum-resistant world!';

      const encrypted = await encrypt(message, recipientKeys.publicKey);

      expect(encrypted).to.be.a('string');
      expect(encrypted.length).to.be.greaterThan(0);

      // Should be valid JSON
      const parsed = JSON.parse(encrypted);
      expect(parsed).to.have.property('v');
      expect(parsed).to.have.property('alg');
      expect(parsed).to.have.property('kem');
      expect(parsed).to.have.property('s');
      expect(parsed).to.have.property('n');
      expect(parsed).to.have.property('c');
      expect(parsed.alg).to.equal('ML-KEM-1024');
    });

    it('should encrypt a message with ML-KEM-768', async () => {
      const recipientKeys = await generateKeyPair('ML-KEM-768');
      const message = 'Test message';

      const encrypted = await encrypt(
        message,
        recipientKeys.publicKey,
        'ML-KEM-768'
      );

      const parsed = JSON.parse(encrypted);
      expect(parsed.alg).to.equal('ML-KEM-768');
    });

    it('should produce different ciphertexts for same message', async () => {
      const recipientKeys = await generateKeyPair();
      const message = 'Same message';

      const encrypted1 = await encrypt(message, recipientKeys.publicKey);
      const encrypted2 = await encrypt(message, recipientKeys.publicKey);

      expect(encrypted1).to.not.equal(encrypted2);
    });

    it('should handle empty message', async () => {
      const recipientKeys = await generateKeyPair();
      const message = '';

      const encrypted = await encrypt(message, recipientKeys.publicKey);
      expect(encrypted).to.be.a('string');

      const parsed = JSON.parse(encrypted);
      expect(parsed).to.have.property('c');
    });

    it('should handle long messages', async () => {
      const recipientKeys = await generateKeyPair();
      const message = 'A'.repeat(10000);

      const encrypted = await encrypt(message, recipientKeys.publicKey);
      expect(encrypted).to.be.a('string');
    });

    it('should handle unicode characters', async () => {
      const recipientKeys = await generateKeyPair();
      const message = '你好世界 🌍 مرحبا';

      const encrypted = await encrypt(message, recipientKeys.publicKey);
      expect(encrypted).to.be.a('string');
    });

    it('should throw error for invalid public key', async () => {
      const message = 'Test';

      try {
        await encrypt(message, 'invalid-key');
        expect.fail('Should have thrown an error');
      } catch (error) {
        expect(error).to.exist;
      }
    });

    it('should throw error for null public key', async () => {
      const message = 'Test';

      try {
        await encrypt(message, null);
        expect.fail('Should have thrown an error');
      } catch (error) {
        expect(error).to.exist;
      }
    });
  });

  describe('decrypt', () => {
    it('should decrypt ML-KEM-1024 encrypted message', async () => {
      const recipientKeys = await generateKeyPair('ML-KEM-1024');
      const message = 'Secret message';

      const encrypted = await encrypt(message, recipientKeys.publicKey);
      const decrypted = await decrypt(encrypted, recipientKeys.privateKey);

      expect(decrypted).to.equal(message);
    });

    it('should decrypt ML-KEM-768 encrypted message', async () => {
      const recipientKeys = await generateKeyPair('ML-KEM-768');
      const message = 'Another secret';

      const encrypted = await encrypt(
        message,
        recipientKeys.publicKey,
        'ML-KEM-768'
      );
      const decrypted = await decrypt(
        encrypted,
        recipientKeys.privateKey,
        'ML-KEM-768'
      );

      expect(decrypted).to.equal(message);
    });

    it('should decrypt empty message', async () => {
      const recipientKeys = await generateKeyPair();
      const message = '';

      const encrypted = await encrypt(message, recipientKeys.publicKey);
      const decrypted = await decrypt(encrypted, recipientKeys.privateKey);

      expect(decrypted).to.equal(message);
    });

    it('should decrypt long messages', async () => {
      const recipientKeys = await generateKeyPair();
      const message = 'Long message '.repeat(1000);

      const encrypted = await encrypt(message, recipientKeys.publicKey);
      const decrypted = await decrypt(encrypted, recipientKeys.privateKey);

      expect(decrypted).to.equal(message);
    });

    it('should decrypt unicode messages', async () => {
      const recipientKeys = await generateKeyPair();
      const message = '你好世界 🌍 مرحبا العالم';

      const encrypted = await encrypt(message, recipientKeys.publicKey);
      const decrypted = await decrypt(encrypted, recipientKeys.privateKey);

      expect(decrypted).to.equal(message);
    });

    it('should fail with wrong private key', async () => {
      const recipientKeys1 = await generateKeyPair();
      const recipientKeys2 = await generateKeyPair();
      const message = 'Secret';

      const encrypted = await encrypt(message, recipientKeys1.publicKey);

      try {
        await decrypt(encrypted, recipientKeys2.privateKey);
        expect.fail('Should have thrown an error');
      } catch (error) {
        expect(error).to.exist;
      }
    });

    it('should fail with invalid encrypted data', async () => {
      const recipientKeys = await generateKeyPair();

      try {
        await decrypt('invalid-data', recipientKeys.privateKey);
        expect.fail('Should have thrown an error');
      } catch (error) {
        expect(error).to.exist;
      }
    });

    it('should fail with tampered ciphertext', async () => {
      const recipientKeys = await generateKeyPair();
      const message = 'Secret';

      const encrypted = await encrypt(message, recipientKeys.publicKey);
      const parsed = JSON.parse(encrypted);

      // Tamper with ciphertext
      parsed.c = parsed.c.slice(0, -5) + 'XXXXX';
      const tampered = JSON.stringify(parsed);

      try {
        await decrypt(tampered, recipientKeys.privateKey);
        expect.fail('Should have thrown an error');
      } catch (error) {
        expect(error).to.exist;
      }
    });
  });

  describe('end-to-end encryption', () => {
    it('should work for multiple messages with same keys', async () => {
      const recipientKeys = await generateKeyPair();
      const messages = ['Message 1', 'Message 2', 'Message 3'];

      for (const message of messages) {
        const encrypted = await encrypt(message, recipientKeys.publicKey);
        const decrypted = await decrypt(encrypted, recipientKeys.privateKey);
        expect(decrypted).to.equal(message);
      }
    });

    it('should work with both ML-KEM-1024 and ML-KEM-768', async () => {
      const keys1024 = await generateKeyPair('ML-KEM-1024');
      const keys768 = await generateKeyPair('ML-KEM-768');
      const message = 'Cross-algorithm test';

      const encrypted1024 = await encrypt(message, keys1024.publicKey);
      const decrypted1024 = await decrypt(encrypted1024, keys1024.privateKey);
      expect(decrypted1024).to.equal(message);

      const encrypted768 = await encrypt(
        message,
        keys768.publicKey,
        'ML-KEM-768'
      );
      const decrypted768 = await decrypt(
        encrypted768,
        keys768.privateKey,
        'ML-KEM-768'
      );
      expect(decrypted768).to.equal(message);
    });
  });
});
