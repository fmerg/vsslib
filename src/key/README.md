# `vsslib.key`

```js
import { key } from 'vsslib';
```

## Generation

```js
const priv = await key.generate('ed25519');
const pub = await priv.extractPublic();
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
