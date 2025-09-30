# Cryptography Examples

This directory contains practical examples of cryptographic implementations.

## Examples

### 1. AES Encryption (`aes_example.py`)
Demonstrates AES-256-GCM authenticated encryption using Python's cryptography library.

**Usage:**
```bash
python3 aes_example.py
```

### 2. RSA Encryption (`rsa_example.py`)
Shows RSA key generation, encryption, and digital signatures.

**Usage:**
```bash
python3 rsa_example.py
```

### 3. Hash Functions (`hash_example.py`)
Examples of SHA-256, SHA-512, and BLAKE2 hashing.

**Usage:**
```bash
python3 hash_example.py
```

### 4. Simple XOR Cipher (`xor_cipher.c`)
Educational example of a simple XOR encryption (NOT secure for real use).

**Compilation & Usage:**
```bash
gcc xor_cipher.c -o xor_cipher
./xor_cipher "Hello World" "secret"
```

## Requirements

```bash
pip install cryptography
```

## ⚠️ Important Notes

- These are educational examples
- Do NOT use the XOR cipher for real security
- Always use well-tested cryptographic libraries
- Never implement your own crypto for production use

## Resources

- [Python Cryptography Documentation](https://cryptography.io/)
- [NIST Cryptographic Standards](https://csrc.nist.gov/)
