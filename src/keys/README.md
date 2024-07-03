# `vsslib.keys`
  

## Key generation

```js
import { initBackend } from "vsslib";

const ctx = initBackend("ed25519");
```

```js
import { generateKey } from "vsslib";

const { privateKey, publicKey } = await generateKey(ctx);
```

```js
const publicKey = await privateKey.getPublicKey();
```

## Schnorr identification (Proof-of-Secret)

```js
const proof = await privateKey.proveSecret({ algorithm: "sha256" });
```

```js
await publicKey.verifySecret(proof, { algorithm: "sha256" });
```

## Elgamal encryption

### DHIES-Encryption (Integrated Encryption Scheme)

```js
const message = Uint8Array.from(Buffer.from("destroy earth"));
```

```js
const { ciphertext, randomness, decryptor } = await publicKey.encrypt(message, { scheme: "dhies", algorithm: "sha256", mode: "aes-256-cbc" });
```


### Hybrid encryption (Key Encapsulation Mechanism)

```js
const message = Uint8Array.from(Buffer.from("destroy earth"));
```

```js
const { ciphertext, randomness, decryptor } = await publicKey.encrypt(message, { scheme: "hybrid", mode: "aes-256-cbc" });
```

### Plain Elgamal encryption

```js
const message = await ctx.randomPublic();
```

```js
const { ciphertext, randomness, decryptor } = await publicKey.encrypt(message, { scheme: "plain" });
```

### Decryption

```js
const plaintext = privateKey.decrypt(ciphertext, {
  scheme: ...,
  ...
});
```

## Verifiable decryptors

```js
const { decryptor, proof } = await privateKey.computeDecryptor(ciphertext, { algorithm: "sha256" });
```

```js
await publicKey.verifyDecryptor(ciphertext, decryptor, proof, { algorithm: "sha256" });
```

### Standalone proof-of-decryptor

```js
const proof = await privateKey.proveDecryptor(ciphertext, decryptor, { algorithm: "sha256" })
```

## Verifiable encryption (Encrypt-then-Prove)

```js
const { ciphertext, proof } = await publicKey.encryptProve(message, { scheme: "dhies" })
```

```js
const { plaintext } = await privateKey.verifyDecrypt(ciphertext, proof, { scheme: "dhies" })
```

### Standalone proof-of-randomness

```js
const proof = await publicKey.proveEncryption(ciphertext, randomness, { algorithm: "sha256" });
```

```js
await privateKey.verifyEncryption(ciphertext, proof, { algorithm: "sha256" });
```

## Signatures

```js
const message = Uint8Array.from(Buffer.from("destroy earth"));
```

```js
const signature = await privateKey.signMessage(message, { scheme: "schnorr", algorithm: "sha256" });
```

```js
await publicKey.verifySignature(message, signature, { scheme: "schnorr", algorithm: "sha256" });
```

## Signcryption

```js
const message = Uint8Array.from(Buffer.from("destroy earth"));
```

```js
const { ciphertext, signature } = await senderPrivate.sigEncrypt(message, recipientPublic, { encScheme: "hybrid", sigScheme: "schnorr" });
```

```js
const { plaintext } = await recipientPrivate.sigDecrypt(ciphertext, signature, senderPublic, { encScheme: "hybrid", sigScheme: "schnorr" });
```
