# Post-Quantum Helper Module - Development Plan

## Overview
Create a Node.js module and CLI tool for post-quantum encryption using ML-KEM (Kyber) + ChaCha20-Poly1305.

## Requirements

### Core Features
1. **Key Generation**
   - Generate ML-KEM-1024 key pairs (primary, NIST Level 5)
   - Generate ML-KEM-768 key pairs (backward compatibility, NIST Level 3)
   - Export keys in Base64 format
   - Import keys from Base64 format

2. **Encryption**
   - Encrypt messages using recipient's public key
   - Support both ML-KEM-1024 and ML-KEM-768
   - Use ChaCha20-Poly1305 for symmetric encryption
   - HKDF for key derivation
   - Return encrypted message as JSON string

3. **Decryption**
   - Decrypt messages using private key
   - Auto-detect algorithm (ML-KEM-1024 or ML-KEM-768)
   - Handle both key formats transparently

4. **Module API**
   - Simple, clean public API
   - ESM module format
   - No browser dependencies (Node.js only)
   - Proper error handling

5. **CLI Interface**
   - Interactive menu using inquirer
   - Commands:
     - Generate key pair
     - Encrypt message
     - Decrypt message
     - Export keys
     - Import keys
   - File-based key storage
   - User-friendly prompts

## Technical Stack
- **Node.js**: v20+
- **Module System**: ESM
- **Crypto Library**: mlkem (ML-KEM implementation)
- **CLI Framework**: inquirer
- **Testing**: Mocha + Chai
- **Linting**: ESLint
- **Formatting**: Prettier

## Dependencies
- `mlkem` - Post-quantum KEM implementation
- `inquirer` - CLI prompts (optional, only for CLI)
- `mocha` - Testing framework (dev)
- `chai` - Assertion library (dev)
- `eslint` - Linting (dev)
- `prettier` - Code formatting (dev)

## Project Structure
```
post-quantum-helper/
├── src/
│   ├── index.js           # Main module exports
│   ├── crypto-utils.js    # Base64, HKDF, ChaCha20, etc.
│   ├── key-manager.js     # Key generation and management
│   ├── encryptor.js       # Encryption functions
│   └── decryptor.js       # Decryption functions
├── bin/
│   └── cli.js             # CLI entry point
├── tests/
│   ├── crypto-utils.test.js
│   ├── key-manager.test.js
│   ├── encryptor.test.js
│   └── decryptor.test.js
├── package.json
├── .eslintrc.json
├── .prettierrc
├── README.md
└── TODO.md
```

## Development Tasks

### Phase 1: Setup
- [x] Analyze existing code
- [x] Create TODO.md
- [ ] Create project structure
- [ ] Initialize package.json
- [ ] Add ESLint and Prettier configs

### Phase 2: Core Crypto Utilities
- [ ] Write tests for Base64 encoding/decoding
- [ ] Write tests for HKDF key derivation
- [ ] Write tests for ChaCha20-Poly1305
- [ ] Implement crypto-utils.js

### Phase 3: Key Management
- [ ] Write tests for ML-KEM-1024 key generation
- [ ] Write tests for ML-KEM-768 key generation
- [ ] Write tests for key import/export
- [ ] Implement key-manager.js

### Phase 4: Encryption/Decryption
- [ ] Write tests for encryption with ML-KEM-1024
- [ ] Write tests for encryption with ML-KEM-768
- [ ] Write tests for decryption
- [ ] Write tests for algorithm auto-detection
- [ ] Implement encryptor.js
- [ ] Implement decryptor.js

### Phase 5: Module Integration
- [ ] Create main index.js with public API
- [ ] Test complete module workflow
- [ ] Add comprehensive error handling

### Phase 6: CLI
- [ ] Design CLI menu structure
- [ ] Implement key generation command
- [ ] Implement encryption command
- [ ] Implement decryption command
- [ ] Implement key import/export commands
- [ ] Add file-based key storage
- [ ] Test CLI workflows

### Phase 7: Documentation & Polish
- [ ] Write comprehensive README
- [ ] Add usage examples
- [ ] Add API documentation
- [ ] Final testing
- [ ] Code review and cleanup

## API Design

### Module API
```javascript
import { generateKeyPair, encrypt, decrypt } from 'post-quantum-helper';

// Generate keys
const { publicKey, privateKey } = await generateKeyPair('ML-KEM-1024');

// Encrypt
const encrypted = await encrypt(message, recipientPublicKey);

// Decrypt
const decrypted = await decrypt(encrypted, privateKey);
```

### CLI Usage
```bash
# Interactive mode
pqh

# Direct commands
pqh generate --algorithm ML-KEM-1024
pqh encrypt --message "Hello" --key public.key
pqh decrypt --file encrypted.txt --key private.key
```

## Success Criteria
- [ ] All tests pass
- [ ] No ESLint warnings
- [ ] Code formatted with Prettier
- [ ] README with clear examples
- [ ] CLI works interactively
- [ ] Module can be imported and used programmatically
- [ ] Proper error messages for all failure cases