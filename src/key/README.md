# `vsslib.key`

```js
const { key, PrivateKey, PublicKey } = require('vsslib/key');
```

## Generation

```js
const { privateKey, publicKey } = await key.generate('ed25519');
```

### Key attributes

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

```js
const publicPoint = await privateKey.publicPoint();
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


## Verifiable identity (Schnorr scheme)

```js
const proof = await privateKey.proveIdentity({ algorithm: 'sha256'});

await publicKey.verifyIdentity(proof);
```


## Elgamal encryption

```js
const { ciphertext, randomness, decryptor } = await publicKey.encrypt(message);

const plaintext = await privateKey.decrypt(ciphertext);
```

### Verifiable encryption (Schnorr scheme)

```js
const proof = await publicKey.proveEncryption(ciphertext, randomness, { algorithm: 'sh256' });

await privateKey.verifyEncryption(ciphertext, proof);
```

### Decryptor verification (Chaum-Pedersen scheme)

```js
const proof = await privateKey.proveDecryptor(ciphertext, decryptor, { algorithm: 'sha256' });

await publicKey.verifyDecryptor(ciphertext, decryptor, proof);
```

### Decryptor generation

```js
const { decryptor, proof } = await privateKey.generateDecryptor(ciphertext, { algorithm: 'sha256' });

await publicKey.verifyDecryptor(ciphertext, decryptor, proof);
```

```js
const { decryptor } = await privateKey.generateDecryptor(ciphertext, { noProof: true });
```
