# `vsslib.keys`

The `vsslib.keys` module provides a comprehensive set of cryptographic operations for key management, signatures, encryption, and signcryption.

## Key Generation

Initialize the cryptographic backend and generate key pairs:

```js
import { initBackend } from "vsslib";

// Initialize the backend with the desired curve
const ctx = initBackend("ed25519");
```

```js
import { generateKey } from "vsslib";

// Generate a new key pair
const { privateKey, publicKey } = await generateKey(ctx);
```

```js
// Derive the public key from a private key
const publicKey = await privateKey.getPublicKey();
```

## Schnorr Identification

Schnorr identification is a zero-knowledge proof system for proving knowledge of a secret key:

```js
// Generate a proof of secret key ownership
const proof = await privateKey.proveSecret({ algorithm: "sha256" });
```

```js
// Verify the proof against a public key
await publicKey.verifySecret(proof, { algorithm: "sha256" });
```

## Signatures

Create and verify digital signatures using the Schnorr signature scheme:

```js
const message = Uint8Array.from(Buffer.from("destroy earth"));

// Sign a message
const signature = await privateKey.signMessage(message, { scheme: "schnorr", algorithm: "sha256" });

// Verify a signature
await publicKey.verifySignature(message, signature, { scheme: "schnorr", algorithm: "sha256" });
```

## ElGamal Encryption

The library supports various ElGamal-based encryption schemes:

### DHIES-Encryption (Integrated Encryption Scheme)

```js
const message = Uint8Array.from(Buffer.from("destroy earth"));

// Encrypt a message using DHIES
const { ciphertext, randomness, decryptor } = await publicKey.encrypt(message, { scheme: "dhies", algorithm: "sha256", mode: "aes-256-cbc" });
```

### Hybrid Encryption (Key Encapsulation Mechanism)

```js
const message = Uint8Array.from(Buffer.from("destroy earth"));

// Encrypt a message using hybrid encryption
const { ciphertext, randomness, decryptor } = await publicKey.encrypt(message, { scheme: "hybrid", mode: "aes-256-cbc" });
```

### Plain ElGamal Encryption

```js
const message = await ctx.randomPublic();

// Encrypt a message using plain ElGamal
const { ciphertext, randomness, decryptor } = await publicKey.encrypt(message, { scheme: "plain" });
```

### Decryption

Decrypt messages encrypted with any of the above schemes:

```js
const plaintext = privateKey.decrypt(ciphertext, {
  scheme: ..., // Specify the encryption scheme used
  // Additional options
});
```

### Decryptors

Generate and verify decryptors for threshold decryption:

```js
// Compute a decryptor with a proof
const { decryptor, proof } = await privateKey.computeDecryptor(ciphertext, { algorithm: "sha256" });

// Verify a decryptor
await publicKey.verifyDecryptor(ciphertext, decryptor, proof, { algorithm: "sha256" });
```

### Encrypt-then-Prove

Prove the correctness of encryption without revealing the plaintext:

```js
// Generate a proof of correct encryption
const proof = await publicKey.proveEncryption(ciphertext, randomness, { algorithm: "sha256" });

// Verify the encryption proof
await privateKey.verifyEncryption(ciphertext, proof, { algorithm: "sha256" });
```

## Signcryption

Signcryption combines digital signatures and encryption in a single operation:

```js
const message = Uint8Array.from(Buffer.from("destroy earth"));

// Sign and encrypt a message
const { ciphertext, signature } = await senderPrivate.signEncrypt(message, receiverPublic, { encScheme: "hybrid", sigScheme: "schnorr" });

// Verify and decrypt a signcrypted message
const { plaintext } = await receiverPrivate.verifyDecrypt(ciphertext, signature, senderPublic, { encScheme: "hybrid", sigScheme: "schnorr" });
```

This signcryption process ensures both confidentiality and authenticity of the message in a single step.
