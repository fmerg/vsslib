# `vsslib.key`

```js
import { key } from 'vsslib';
```

## Generation

```js
const priv = await key.generate('ed25519');
const pub = await priv.extractPublic();
```
