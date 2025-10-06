#!/usr/bin/env node

/**
 * @fileoverview CLI for post-quantum encryption helper
 * Command: quantum
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import {
  generateKeyPair,
  encrypt,
  decrypt,
  exportKeyPair,
} from '../src/index.js';

const COMMANDS = {
  GENERATE: 'generate',
  ENCRYPT: 'encrypt',
  DECRYPT: 'decrypt',
  HELP: 'help',
  VERSION: 'version',
};

/**
 * Display help information
 */
function showHelp() {
  console.log(`
Post-Quantum Encryption Helper (quantum)

Usage:
  quantum generate [--algorithm <alg>] [--output <file>]
    Generate a new key pair
    Options:
      --algorithm, -a   Algorithm to use (ML-KEM-1024 or ML-KEM-768, default: ML-KEM-1024)
      --output, -o      Output file for key pair (default: stdout)

  quantum encrypt --message <msg> --key <file>
    Encrypt a message
    Options:
      --message, -m     Message to encrypt (required)
      --key, -k         Public key file (required)
      --output, -o      Output file (default: stdout)

  quantum decrypt --input <file> --key <file>
    Decrypt a message
    Options:
      --input, -i       Encrypted message file (required)
      --key, -k         Private key file (required)
      --output, -o      Output file (default: stdout)

  quantum help
    Show this help message

  quantum version
    Show version information

Examples:
  # Generate a key pair
  quantum generate --output keys.json

  # Encrypt a message
  quantum encrypt --message "Hello, World!" --key public.key --output encrypted.txt

  # Decrypt a message
  quantum decrypt --input encrypted.txt --key private.key
`);
}

/**
 * Parse command line arguments
 */
function parseArgs(args) {
  const parsed = {
    command: args[0],
    options: {},
  };

  for (let i = 1; i < args.length; i++) {
    const arg = args[i];
    if (arg.startsWith('--') || arg.startsWith('-')) {
      const key = arg.replace(/^-+/, '');
      const value = args[i + 1];
      parsed.options[key] = value;
      i++; // Skip next arg as it's the value
    }
  }

  return parsed;
}

/**
 * Generate key pair command
 */
async function cmdGenerate(options) {
  try {
    const algorithm = options.algorithm || options.a || 'ML-KEM-1024';
    console.error(`Generating ${algorithm} key pair...`);

    const keyPair = await generateKeyPair(algorithm);
    const exported = exportKeyPair(keyPair);

    const output = JSON.stringify(exported, null, 2);

    if (options.output || options.o) {
      const outputPath = resolve(options.output || options.o);
      writeFileSync(outputPath, output, 'utf8');
      console.error(`Key pair saved to: ${outputPath}`);
    } else {
      console.log(output);
    }

    console.error('✓ Key pair generated successfully');
  } catch (error) {
    console.error(`Error: ${error.message}`);
    process.exit(1);
  }
}

/**
 * Encrypt command
 */
async function cmdEncrypt(options) {
  try {
    const message = options.message || options.m;
    const keyFile = options.key || options.k;

    if (!message) {
      throw new Error('Message is required (--message or -m)');
    }

    if (!keyFile) {
      throw new Error('Public key file is required (--key or -k)');
    }

    // Read public key
    const keyPath = resolve(keyFile);
    const keyData = JSON.parse(readFileSync(keyPath, 'utf8'));
    const publicKey = keyData.publicKey;

    console.error('Encrypting message...');
    const encrypted = await encrypt(message, publicKey);

    if (options.output || options.o) {
      const outputPath = resolve(options.output || options.o);
      writeFileSync(outputPath, encrypted, 'utf8');
      console.error(`Encrypted message saved to: ${outputPath}`);
    } else {
      console.log(encrypted);
    }

    console.error('✓ Message encrypted successfully');
  } catch (error) {
    console.error(`Error: ${error.message}`);
    process.exit(1);
  }
}

/**
 * Decrypt command
 */
async function cmdDecrypt(options) {
  try {
    const inputFile = options.input || options.i;
    const keyFile = options.key || options.k;

    if (!inputFile) {
      throw new Error('Input file is required (--input or -i)');
    }

    if (!keyFile) {
      throw new Error('Private key file is required (--key or -k)');
    }

    // Read encrypted message
    const inputPath = resolve(inputFile);
    const encrypted = readFileSync(inputPath, 'utf8');

    // Read private key
    const keyPath = resolve(keyFile);
    const keyData = JSON.parse(readFileSync(keyPath, 'utf8'));
    const privateKey = keyData.privateKey;

    console.error('Decrypting message...');
    const decrypted = await decrypt(encrypted, privateKey);

    if (options.output || options.o) {
      const outputPath = resolve(options.output || options.o);
      writeFileSync(outputPath, decrypted, 'utf8');
      console.error(`Decrypted message saved to: ${outputPath}`);
    } else {
      console.log(decrypted);
    }

    console.error('✓ Message decrypted successfully');
  } catch (error) {
    console.error(`Error: ${error.message}`);
    process.exit(1);
  }
}

/**
 * Main CLI entry point
 */
async function main() {
  const args = process.argv.slice(2);

  if (args.length === 0) {
    showHelp();
    process.exit(0);
  }

  const { command, options } = parseArgs(args);

  switch (command) {
    case COMMANDS.GENERATE:
      await cmdGenerate(options);
      break;

    case COMMANDS.ENCRYPT:
      await cmdEncrypt(options);
      break;

    case COMMANDS.DECRYPT:
      await cmdDecrypt(options);
      break;

    case COMMANDS.VERSION:
      console.log('post-quantum-helper v1.0.0');
      break;

    case COMMANDS.HELP:
    default:
      showHelp();
      break;
  }
}

// Run CLI
main().catch((error) => {
  console.error(`Fatal error: ${error.message}`);
  process.exit(1);
});
