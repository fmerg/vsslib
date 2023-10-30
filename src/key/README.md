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
