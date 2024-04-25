# `vsslib.key`

```js
const { key, PrivateKey, PublicKey } = require('vsslib/key');
```

## Generalities

### Key generation

```js
const { privateKey, publicKey, ctx } = await keys.generate('ed25519');
```

```js
const { ctx, bytes, scalar } = privateKey;
```

```js
const { ctx, bytes, point } = publicKey;
```


### Public key extraction

```js
const publicKey = await privateKey.publicKey();
```

### Serialization

```js
const serialized = privateKey.serialize();

const privBack = await PrivateKey.deserialize(serialized);
```

```js
const serialized = publicKey.serialize();

const pubBack = await PublicKey.deserialize(serialized);
```

## ElGamal encryption schemes

### Plain Elgamal encryption

```js
const message = (await ctx.randomPoint()).toBytes();

const { ciphertext, randomness, decryptor } = await publicKey.encrypt(message, {
  scheme: 'plain'
});
```

```js
const plaintext = await privateKey.decrypt(ciphertext);
```

### (DH)KEM-Encryption (Key Encapsulation Mechanism)

```js
const message = Uint8Array.from(Buffer.from('destroy earth'));

const { ciphertext, randomness, decryptor } = await publicKey.encrypt(message, {
  scheme: 'kem',
  mode: 'aes-256-cbc'
});
```

```js
const plaintext = await privateKey.decrypt(ciphertext);
```

### (DH/EC)IES-Encryption (Integrated Encryption Scheme)

```js
const message = Uint8Array.from(Buffer.from('destroy earth'));

const { ciphertext, randomness, decryptor } = await publicKey.encrypt(message, {
  scheme: 'ies',
  mode: 'aes-256-cbc'
  algorithm: 'sha256'
});
```

```js
const plaintext = await privateKey.decrypt(ciphertext);
```

### Verifiable encryption (Schnorr scheme)

```js
const proof = await publicKey.proveEncryption(ciphertext, randomness, { algorithm: 'sh256' });
```

```js
await privateKey.verifyEncryption(ciphertext, proof);
```

### Decryptor proof and verification (Chaum-Pedersen scheme)

```js
const proof = await privateKey.proveDecryptor(ciphertext, decryptor, { algorithm: 'sha256' });
```

```js
await publicKey.verifyDecryptor(ciphertext, decryptor, proof);
```

#### Standalone decryptor generation

```js
const { decryptor, proof } = await privateKey.generateDecryptor(ciphertext, { algorithm: 'sha256' });
```

```js
await publicKey.verifyDecryptor(ciphertext, decryptor, proof);
```

```js
const { decryptor } = await privateKey.generateDecryptor(ciphertext, { noProof: true });
```

## Schnorr signature

```js
const message = Uint8Array.from(Buffer.from('destroy earth'));

const signature = await privateKey.sign(message, { algorithm: 'sha256' });
```

```js
await publicKey.verifySignature(message, signature);
```

## Verifiable identity (Schnorr identification scheme)

```js
const proof = await privateKey.proveIdentity({ algorithm: 'sha256'});
```

```js
await publicKey.verifyIdentity(proof);
```

## Verifiable key sharing (Shamir scheme)

```js
const sharing = vss.distributeKey(5, 3, privateKey);

const { nrShares, threshold, polynomial } = sharing;
```

```js
const privateShares = await sharing.getSecretShares();
```

```js
const publicShares = await sharing.getPublicShares();
```

### Feldmann verification scheme

```js
const { commitments } = await sharing.proveFeldmann();
```

```js
await privateShare.verifyFeldmann(commitments);
```

### Pedersen verification scheme

```js
const hPub = await ctx.randomPoint();
```

```js
const { bindings, commitments } = await sharing.provePedersen(hPub);
```

```js
const { bindings, commitments } = await sharing.provePedersen(hPub);
const binding = bindings[share.index];
```

```js
const verified = await share.verifyPedersen(binding, hPub, commitments);
```

### Verifiable partial decryptors

```js
const partialDecryptor = await privateShare.generatePartialDecryptor(ciphertext);
```

```js
await publicShare.verifyPartialDecryptor(ciphertext, partialDecryptor);

