# `vsslib.keys`

## Key generation

```js
import { initBackend, generateKey } from "vsslib";

const ctx = initBackend("ed25519");

const { privateKey, publicKey } = await generateKey(ctx);
```

```js
const publicKey = await privateKey.publicKey();
```

## Schnorr identification

```js
const proof = await privateKey.proveSecret({ algorithm: "sha256" });
```

```js
await publicKey.verifySecret(proof);
```

## Encryption

### ElGamal schemes

#### DHIES-Encryption (Integrated Encryption Scheme)

```js
const message = Uint8Array.from(Buffer.from("destroy earth"));
```

```js
const { ciphertext, randomness, decryptor } = await publicKey.encrypt(message, { scheme: "dhies", algorithm: "sha256", mode: "aes-256-cbc" });
```


#### HYBRID-Encryption (Key Encapsulation Mechanism)

```js
const message = Uint8Array.from(Buffer.from("destroy earth"));
```

```js
const { ciphertext, randomness, decryptor } = await publicKey.encrypt(message, { scheme: "hybrid", mode: "aes-256-cbc" });
```

#### Plain Encryption

```js
const message = (await ctx.randomPoint()).toBytes();
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

#### Decryption with decryptor

#### Decryption with randomness

### Verifiable encryption

```js
const proof = await publicKey.proveEncryption(ciphertext, randomness, { algorithm: "sha256" });
```

```js
await privateKey.verifyEncryption(ciphertext, proof, { algorithm: "sha256" });
```

### Decryptors

#### Verification

```js
const proof = await privateKey.proveDecryptor(ciphertext, decryptor, { algorithm: "sha256" });
```

```js
await publicKey.verifyDecryptor(ciphertext, decryptor, proof, { algorithm: "sha256" });
```

#### Generation

```js
const { decryptor, proof } = await privateKey.computeDecryptor(ciphertext, { algorithm: "sha256" });
```

```js
await publicKey.verifyDecryptor(ciphertext, decryptor, proof, { algorithm: "sha256" });
```

## Signatures

```js
const message = Uint8Array.from(Buffer.from("destroy earth"));
```

```js
const signature = await privateKey.sigmMessage(message, { scheme: "schnorr", algorithm: "sha256" });
```

```js
await publicKey.verifySignature(message, signature, { scheme: "schnorr", algorithm: "sha256" });
```

## Signcryption

```js
const { privateKey: senderPrivate, publicKey: senderPublic } = await generateKey("ed25519");
```

```js
const { privateKey: receiverPrivate, publicKey: receiverPublic } = await generateKey("ed25519");
```

```js
const message = Uint8Array.from(Buffer.from("destroy earth"));
```

```js
const { ciphertext, signature } = await senderPrivate.signEncrypt(message, receiverPublic, { encScheme: "hybrid", sigScheme: "schnorr" });
```

```js
const { plaintext } = await receiverPrivate.verifyDecrypt(ciphertext, signature, senderPublic, { encScheme: "hybrid", sigScheme: "schnorr" });
```
