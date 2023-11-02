# `vsslib.backend`

```js
const { backend } = require('vsslib');

const ctx = backend.initGroup('ed25519');
```

```js
const { modulus, order, generator, neutral } = ctx;
```

## Interface


### Generalities

```js
const p = await ctx.randomPoint();
```

```js
await ctx.validatePoint(p);
```

```js
const s = await ctx.randomScalar();
```

```js
await ctx.validateScalar(s);
```

```js
const b = await ctx.randomBytes();
```

```js
await ctx.validateBytes(b);
```

### Group operations

```js
const u = await ctx.combine(p, q);
```

```js
const v = await ctx.invert(p);
```

```js
const w = await ctx.operate(s, p);
```


### Point serialization

```js
const pBytes = p.toBytes();
```

```js
const pBack = ctx.unpack(pBytes);
```

```js
const pHex = p.toHex();
```

```js
const pBack = ctx.unhexify(pHex);
```

