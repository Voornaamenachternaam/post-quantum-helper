# @profullstack/post-quantum-helper

A Node.js module and CLI tool for post-quantum encryption using ML-KEM (Kyber) + ChaCha20-Poly1305. This provides quantum-resistant encryption that's easy to use both programmatically and from the command line.

**Author:** Profullstack, Inc. https://profullstack.com

## Features

- 🔐 **Post-Quantum Secure**: Uses ML-KEM (CRYSTALS-Kyber) for key encapsulation
- 🚀 **Easy to Use**: Simple API for both module and CLI usage
- 🎯 **Multiple Algorithms**: Supports ML-KEM-1024 (NIST Level 5) and ML-KEM-768 (NIST Level 3)
- 🔒 **Authenticated Encryption**: ChaCha20-Poly1305 for message encryption
- 📦 **Zero Browser Dependencies**: Pure Node.js implementation
- ✅ **Well Tested**: Comprehensive test suite with Mocha + Chai

## Installation

```bash
# Using pnpm (recommended)
pnpm install @profullstack/post-quantum-helper

# Using npm
npm install @profullstack/post-quantum-helper

# Using yarn
yarn add @profullstack/post-quantum-helper
```

## Quick Start

### As a Module

```javascript
import { generateKeyPair, encrypt, decrypt } from '@profullstack/post-quantum-helper';

// Generate a key pair
const keyPair = await generateKeyPair('ML-KEM-1024');
console.log('Public Key:', keyPair.publicKey);
console.log('Private Key:', keyPair.privateKey);

// Encrypt a message
const message = 'Hello, quantum-resistant world!';
const encrypted = await encrypt(message, keyPair.publicKey);
console.log('Encrypted:', encrypted);

// Decrypt the message
const decrypted = await decrypt(encrypted, keyPair.privateKey);
console.log('Decrypted:', decrypted); // "Hello, quantum-resistant world!"
```

### As a CLI Tool

```bash
# Generate a key pair
quantum generate --output keys.json

# Encrypt a message
quantum encrypt --message "Secret message" --key keys.json --output encrypted.txt

# Decrypt a message
quantum decrypt --input encrypted.txt --key keys.json
```

## API Reference

### Key Management

#### `generateKeyPair(algorithm?)`

Generate a new post-quantum key pair.

```javascript
const keyPair = await generateKeyPair('ML-KEM-1024');
// Returns: { publicKey: string, privateKey: string, algorithm: string }
```

**Parameters:**
- `algorithm` (optional): `'ML-KEM-1024'` (default) or `'ML-KEM-768'`

**Returns:** Promise resolving to key pair object

#### `exportKeyPair(keyPair)`

Export a key pair with metadata for storage.

```javascript
const exported = exportKeyPair(keyPair);
// Returns: { publicKey, privateKey, algorithm, timestamp, version }
```

#### `importKeyPair(data)`

Import a key pair from exported data.

```javascript
const keyPair = importKeyPair(exportedData);
```

#### `validatePublicKey(publicKey, algorithm?)`

Validate a public key format and size.

```javascript
const isValid = validatePublicKey(publicKey, 'ML-KEM-1024');
// Returns: boolean
```

### Encryption & Decryption

#### `encrypt(message, recipientPublicKey, algorithm?)`

Encrypt a message for a recipient.

```javascript
const encrypted = await encrypt(
  'Secret message',
  recipientPublicKey,
  'ML-KEM-1024'
);
```

**Parameters:**
- `message`: String message to encrypt
- `recipientPublicKey`: Recipient's public key (Base64)
- `algorithm` (optional): Algorithm to use

**Returns:** Promise resolving to encrypted message (JSON string)

#### `decrypt(encryptedContent, privateKey, algorithm?)`

Decrypt a message using private key.

```javascript
const decrypted = await decrypt(encrypted, privateKey);
```

**Parameters:**
- `encryptedContent`: Encrypted message (JSON string)
- `privateKey`: Private key (Base64)
- `algorithm` (optional): Algorithm (auto-detected if not provided)

**Returns:** Promise resolving to decrypted message string

### Crypto Utilities

#### `Base64`

Base64 encoding/decoding utilities.

```javascript
import { Base64 } from '@profullstack/post-quantum-helper';

const encoded = Base64.encode(new Uint8Array([1, 2, 3]));
const decoded = Base64.decode(encoded);
```

#### `SecureRandom`

Cryptographically secure random number generation.

```javascript
import { SecureRandom } from '@profullstack/post-quantum-helper';

const randomBytes = SecureRandom.getRandomBytes(32);
const salt = SecureRandom.generateSalt();
const nonce = SecureRandom.generateNonce();
```

## CLI Usage

### Generate Keys

```bash
# Generate ML-KEM-1024 key pair (default)
quantum generate --output keys.json

# Generate ML-KEM-768 key pair
quantum generate --algorithm ML-KEM-768 --output keys768.json

# Output to stdout
quantum generate
```

### Encrypt Messages

```bash
# Encrypt a message
quantum encrypt --message "Hello, World!" --key keys.json --output encrypted.txt

# Encrypt from stdin (output to stdout)
echo "Secret" | quantum encrypt --key keys.json
```

### Decrypt Messages

```bash
# Decrypt a message
quantum decrypt --input encrypted.txt --key keys.json

# Decrypt to file
quantum decrypt --input encrypted.txt --key keys.json --output decrypted.txt
```

### Other Commands

```bash
# Show help
quantum help

# Show version
quantum version
```

## Algorithms

### ML-KEM-1024 (Default)

- **Security Level**: NIST Level 5 (highest)
- **Public Key Size**: 1568 bytes
- **Private Key Size**: 3168 bytes
- **Recommended for**: Maximum security applications

### ML-KEM-768

- **Security Level**: NIST Level 3
- **Public Key Size**: 1184 bytes
- **Private Key Size**: 2400 bytes
- **Recommended for**: Balanced security and performance

## Security Considerations

1. **Key Storage**: Store private keys securely. Never commit them to version control.
2. **Key Rotation**: Regularly rotate encryption keys in production systems.
3. **Algorithm Choice**: Use ML-KEM-1024 for maximum security, ML-KEM-768 for better performance.
4. **Nonce Uniqueness**: The library automatically generates unique nonces for each encryption.

## Development

### Running Tests

```bash
# Run all tests
pnpm test

# Run tests in watch mode
pnpm test:watch

# Run linter
pnpm lint

# Format code
pnpm format
```

### Project Structure

```
post-quantum-helper/
├── src/
│   ├── index.js           # Main module exports
│   ├── crypto-utils.js    # Crypto utilities
│   ├── key-manager.js     # Key management
│   └── encryptor.js       # Encryption/decryption
├── bin/
│   └── cli.js             # CLI tool
├── tests/
│   ├── crypto-utils.test.js
│   ├── key-manager.test.js
│   └── encryption.test.js
├── package.json
└── README.md
```

## Examples

### End-to-End Encryption

```javascript
import { generateKeyPair, encrypt, decrypt } from '@profullstack/post-quantum-helper';

// Alice generates her key pair
const aliceKeys = await generateKeyPair();

// Bob generates his key pair
const bobKeys = await generateKeyPair();

// Alice encrypts a message for Bob
const message = 'Hello Bob!';
const encrypted = await encrypt(message, bobKeys.publicKey);

// Bob decrypts Alice's message
const decrypted = await decrypt(encrypted, bobKeys.privateKey);
console.log(decrypted); // "Hello Bob!"
```

### Key Export/Import

```javascript
import { generateKeyPair, exportKeyPair, importKeyPair } from '@profullstack/post-quantum-helper';
import { writeFileSync, readFileSync } from 'fs';

// Generate and export keys
const keyPair = await generateKeyPair();
const exported = exportKeyPair(keyPair);

// Save to file
writeFileSync('keys.json', JSON.stringify(exported, null, 2));

// Load from file
const loaded = JSON.parse(readFileSync('keys.json', 'utf8'));
const imported = importKeyPair(loaded);
```

### Multiple Messages

```javascript
import { generateKeyPair, encrypt, decrypt } from '@profullstack/post-quantum-helper';

const keyPair = await generateKeyPair();
const messages = ['Message 1', 'Message 2', 'Message 3'];

// Encrypt multiple messages
const encrypted = await Promise.all(
  messages.map(msg => encrypt(msg, keyPair.publicKey))
);

// Decrypt all messages
const decrypted = await Promise.all(
  encrypted.map(enc => decrypt(enc, keyPair.privateKey))
);

console.log(decrypted); // ['Message 1', 'Message 2', 'Message 3']
```

## License

MIT

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Acknowledgments

- Built with [mlkem](https://www.npmjs.com/package/mlkem) for ML-KEM implementation
- Uses [@noble/ciphers](https://www.npmjs.com/package/@noble/ciphers) for ChaCha20-Poly1305
- Follows NIST post-quantum cryptography standards