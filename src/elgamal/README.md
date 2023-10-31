## `vsslib.elgamal`

```js
const { elgamal, backend } = require('vsslib');

const ctx = backend.initGroup('ed25519');
```

## Encryption and decryption

```js
const { ciphertext, randomness, decryptor } = await elgamal.encrypt(ctx, message, pub);
```

### Decryption with secret key

```js
const plaintext = await elgamal.decrypt(ctx, ciphertext, { secret });
```

### Decryption with decryptor

```js
const plaintext = await elgamal.decrypt(ctx, ciphertext, { decryptor });
```

### Decryption with randomness

```js
const plaintext = await elgamal.decrypt(ctx, ciphertext, { pub, randomness });
```

## Proof of encryption

```js
const proof = await elgamal.proveEncryption(ctx, ciphertext, randomness, { algorithm: 'sha256' });

const valid = await elgamal.verifyEncryption(ctx, ciphertext, proof);
```

## Proof of decryptor

```js
const proof = await elgamal.proveDecryptor(ctx, ciphertext, secret, decryptor, { algorithm: 'sha256' });

const valid = await elgamal.verifyDecryptor(ctx, ciphertext, pub, decryptor, proof);
```

