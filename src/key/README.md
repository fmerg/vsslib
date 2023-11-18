# `vsslib.key`

```js
const { key, PrivateKey, PublicKey } = require('vsslib/key');
```

## Generalities

### Key generation

```js
const { privateKey, publicKey } = await key.generate('ed25519');
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

## Asymmetric encryption

### Plain ElGamal Encryption

```js
const message = await ctx.randomPoint();

const { ciphertext, randomness, decryptor } = await publicKey.elgamalEncrypt(message);
```

```js
const plaintext = await privateKey.elgamalDecrypt(ciphertext);
```

### (DH)KEM-Encryption (Key Encapsulation Mechanism)

```js
const message = Uint8Array.from(Buffer.from('destroy earth'));

const { ciphertext, randomness, decryptor } = await publicKey.kemEncrypt(message, { mode: 'aes-256-cbc' });
```

```js
const plaintext = await privateKey.kemDecrypt(ciphertext);
```

### (DH/EC)IES-Encryption (Integrated Encryption Scheme)

```js
const message = Uint8Array.from(Buffer.from('destroy earth'));

const { ciphertext, randomness, decryptor } = await publicKey.iesEncrypt(message, { mode, algorithm });
```

```js
const plaintext = await privateKey.iesDecrypt(ciphertext);
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

## Verifiable identity (Schnorr identification scheme)

```js
const proof = await privateKey.proveIdentity({ algorithm: 'sha256'});
```

```js
await publicKey.verifyIdentity(proof);
```

## Verifiable key distribution (Shamir scheme)

```js
const distribution = privateKey.distribute(5, 3);

const { nrShares, threshold, polynomial } = distribution;
```

```js
const privateShares = await distribution.getSecretShares();
```

```js
const publicShares = await distribution.getPublicShares();
```

### Feldmann verification scheme

```js
const { commitments } = await distribution.getFeldmannCommitments();
```

```js
await privateShare.verify(commitments);
```

### Pedersen verification scheme

```js
const hPub = await ctx.randomPoint();
```

```js
const { bindings, commitments } = await distribution.getPedersenCommitments(hPub);
```

```js
const { bindings, commitments } = await distribution.getPedersenCommitments(hPub);
const binding = bindings[share.index];
```

```js
const verified = await share.verify(commitments, { binding, hpub });
```

### Key reconstruction

```js
const qualifiedShares = privateShares.slice(0, 3);

const reconstructed = await PrivateKey.fromShares(qualifiedShares);
```

```js
const qualifiedShares = privateShares.slice(0, 3);

const reconstructed = await PublicKey.fromShares(qualifiedShares);
```

### Verifiable partial decryptors

```js
const partialDecryptor = await privateShare.generatePartialDecryptor(ciphertext);
```

```js
await publicShare.verifyPartialDecryptor(ciphertext, partialDecryptor);

