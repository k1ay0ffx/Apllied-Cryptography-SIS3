# Applied Cryptography — SIS3: RSA Cryptosystem

Implementation of RSA public key cryptosystem from scratch in Java.  
No cryptographic libraries used — everything is built by hand.

---

## Team

| Name | Task |
|------|------|
| Myngbay Ramazan 24B031909| Key Generation, Encryption/Decryption, CRT Optimization |
| Atamuratov Nursultan 24B030987| Digital Signatures, PSS Padding |
| Aliaskarov Nursultan | Prime Generation, Miller-Rabin, Modular Arithmetic |

---

## Project Structure

```
├── Utils/              # Modular arithmetic, prime generation (Aliaskarov)
├── RSA_Core/           # RSA key generation, encryption/decryption (Myngbay)
├── RamazanPart/src/    # Key generation & CRT optimization (Myngbay)
├── DS/                 # Digital signatures (Atamuratov)
├── PSS/                # PSS signature padding (Atamuratov)
├── app_console/        # Console application entry point
└── RSA_Tech_Report     # Technical report
```

---

## What's Implemented

**Prime Generation** (Aliaskarov)
- Random prime generation for 512, 1024, 2048-bit primes
- Miller-Rabin primality test with 40–64 iterations
- Modular exponentiation, Extended Euclidean Algorithm, GCD

**Key Generation & Encryption** (Myngbay)
- RSA key generation for 1024, 2048, and 4096-bit keys
- PKCS#1 v1.5 encryption padding
- OAEP padding with SHA-256 and MGF1
- CRT optimization for decryption (~4x speedup)

**Digital Signatures** (Atamuratov)
- SHA-256 hash implementation from scratch
- RSA signature generation and verification
- PSS signature padding


---

## Key Sizes Supported

| Key Size | Prime Size | Security Level |
|----------|-----------|----------------|
| 1024-bit | 512-bit primes | Testing only |
| 2048-bit | 1024-bit primes | Standard |
| 4096-bit | 2048-bit primes | Bonus |

---

## Important Note

This implementation is for **educational purposes only**.  
Do not use in production — vulnerable to timing attacks and other side-channel attacks.

