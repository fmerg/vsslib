# `vsslib.keys`

**High-level interface for discrete-log based asymmetric cryptography**

## Table of contents

* [Key interface](#key-interface)
  * [Generation](#generation)
  * [Schnorr identification](#schnorr-identification)
  * [Elgamal encryption](#elgamal-encryption)
    * [DHIES-encryption (Integrated Encryption Scheme)](#dhies-encryption)
    * [Hybrid encryption (Key Encapsulation Mechanism)](#hybrid-encryption)
    * [Plain encryption](#plain-encryption)
    * [Decryption](#decryption)
  * [Verifiable decryptors](#verifiable-decryptors)
    * [Standalone proof-of-decryptor](#standalone-proof-of-decryptor)
  * [Verifiable encryption (encrypt-then-prove)](#verifiable-encryption)
  * [Signatures](#signatures)
    * [Signcryption](#signcryption)
* [Share interface](#share-interface)
  * [Sharing and extraction](#sharing-and-extraction)
  * [Verifiable partial decryptors](#verifiable-partial-decryptors)
    * [Verifiable decryptor recovery](#verifiable-decryptor-recovery)
    * [Raw combination of partial decryptors](#raw-combination-of-partial-decryptors)

# Key interface

## Generation

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

## <a name="schnorr-identification"></a>Schnorr identification (ZK proof-of-secret)

```js
const proof = await privateKey.proveSecret({ algorithm: "sha256" });
```

```js
await publicKey.verifySecret(proof, { algorithm: "sha256" });
```

## Elgamal encryption

### <a name="dhies-encryption"></a>DHIES-Encryption (Integrated Encryption Scheme)

```js
const message = Uint8Array.from(Buffer.from("destroy earth"));
```

```js
const { ciphertext, randomness, decryptor } = await publicKey.encrypt(message, { scheme: "dhies", algorithm: "sha256", mode: "aes-256-cbc" });
```


### <a name="hybrid-encryption"></a>Hybrid encryption (Key Encapsulation Mechanism)

```js
const message = Uint8Array.from(Buffer.from("destroy earth"));
```

```js
const { ciphertext, randomness, decryptor } = await publicKey.encrypt(message, { scheme: "hybrid", mode: "aes-256-cbc" });
```

### <a name="plain-encryption"></a>Plain encryption

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

### <a name="standalone-proof-of-decryptor"></a>Standalone proof-of-decryptor


```js
const proof = await privateKey.proveDecryptor(ciphertext, decryptor, { algorithm: "sha256" })
```

### <a name="verifiable-encryption"></a>Verifiable encryption (encrypt-then-prove)

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

### Signcryption

```js
const message = Uint8Array.from(Buffer.from("destroy earth"));
```

```js
const { ciphertext, signature } = await senderPrivate.sigEncrypt(message, recipientPublic, { encScheme: "hybrid", sigScheme: "schnorr" });
```

```js
const { plaintext } = await recipientPrivate.sigDecrypt(ciphertext, signature, senderPublic, { encScheme: "hybrid", sigScheme: "schnorr" });
```

# Share interface

## Sharing and extraction

## Verifiable partial decryptors

### Verifiable decryptors recovery

#### Recovery with accurate blaming

### Raw combination of partial decryptors
