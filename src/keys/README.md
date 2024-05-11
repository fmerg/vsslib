# `vsslib.key`

## Key generation

```js
import { generateKey } from 'vsslib';
```

```js
const { privateKey, publicKey, ctx } = await generateKey('ed25519');
```

```js
const publicKey = await privateKey.publicKey();
```

## Schnorr identification

```js
const proof = await privateKey.proveSecret({
  algorithm: Algorithms.SHA256,
});
```

```js
await publicKey.verifyIdentity(proof);
```

## Encryption

### ElGamal schemes

#### IES-Encryption (Integrated Encryption Scheme)

```js
const message = Uint8Array.from(Buffer.from('destroy earth'));
```

```js
const { ciphertext, randomness, decryptor } = await publicKey.encrypt(message, {
  scheme: ElgamalSchemes.IES,
  algorithm: Algorithms.SHA256,
  mode: AesModes.AES_256_CBC,
});
```


#### KEM-Encryption (Key Encapsulation Mechanism)

```js
const message = Uint8Array.from(Buffer.from('destroy earth'));
```

```js
const { ciphertext, randomness, decryptor } = await publicKey.encrypt(message, {
  scheme: ElgamalSchemes.KEM,
  mode: AesModes.AES_256_CBC,
});
```

#### Plain Encryption

```js
const message = (await ctx.randomPoint()).toBytes();
```

```js
const { ciphertext, randomness, decryptor } = await publicKey.encrypt(message, {
  scheme: ElgamalSchemes.PLAIN,
});
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
const proof = await publicKey.proveEncryption(ciphertext, randomness, {
  algorithm: Algorithms.SHA256,
});
```

```js
await privateKey.verifyEncryption(ciphertext, proof, {
  algorithm: Algorithms.SHA256,
});
```

### Decryptors

#### Verification

```js
const proof = await privateKey.proveDecryptor(ciphertext, decryptor, {
  algorithm: Algorithms.SHA256,
});
```

```js
await publicKey.verifyDecryptor(ciphertext, decryptor, proof, {
  algorithm: Algorithms.SHA256,
});
```

#### Generation

```js
const { decryptor, proof } = await privateKey.generateDecryptor(ciphertext, {
  algorithm: Algorithms.SHA256,
});
```

```js
await publicKey.verifyDecryptor(ciphertext, decryptor, proof, {
  algorithm: Algorithms.SHA256,
});
```

## Signatures

```js
const message = Uint8Array.from(Buffer.from('destroy earth'));
```

```js
const signature = await privateKey.sign(message, {
  scheme: SignatureSchemes.SCHNORR,
  algorithm: Algorithms.SHA256,
});
```

```js
await publicKey.verifySignature(message, signature, {
  scheme: SignatureSchemes.SCHNORR,
  algorithm: Algorithms.SHA256,
});
```

## Signcryption

```js
const { privateKey: senderPrivate, publicKey: senderPublic } = await generateKey('ed25519');
```

```js
const { privateKey: receiverPrivate, publicKey: receiverPublic } = await generateKey('ed25519');
```

```js
const message = Uint8Array.from(Buffer.from('destroy earth'));
```

```js
const { ciphertext, signature } = await senderPrivate.signEncrypt(
  message, receiverPublic, {
    encScheme: ElgamalSchemes.IES,
    sigScheme: SignatureSchemes.SCHNORR,
  }
);
```

```js
const { plaintext } = await receiverPrivate.verifyDecrypt(
  ciphertext, signature, senderPublic, {
    encScheme: ElgamalSchemes.IES,
    sigScheme: SignatureSchemes.SCHNORR,
  }
);
```
