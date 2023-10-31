# `vsslib.key`

```js
import { key } from 'vsslib';
```

## Generation

```js
const priv = await key.generate('ed25519');
const pub = await priv.publicKey();
```

## Serialization

```js
const serialized = priv.serialize();
const privBack = key.deserialize(serialized);
```

```js
const serialized = pub.serialize();
const pubBack = key.deserialize(serialized);
```

## Identity proof (Schnorr identification)

```js
const proof = await priv.proveIdentity({ algorithm: 'sha256'});

await pub.verifyIdentity(proof);
```


## Encryption

```js
const { ciphertext, randomness, decryptor } = await pub.encrypt(message);
const plaintext = await priv.decrypt(ciphertext);
```

### Proof of encryption

```js
const proof = await pub.proveEncryption(ciphertext, randomness, { algorithm: 'sh256' });

await priv.verifyEncryption(ciphertext, proof);
```

### Proof of decryptor

```js
const proof = await priv.proveDecryptor(ciphertext, decryptor, { algorithm: 'sha256' });

await pub.verifyDecryptor(ciphertext, decryptor, proof);
```
