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
const s = await ctx.randomScalar();
```

```js
const p = await ctx.randomPoint();
```

```js
const isValid = await ctx.assertValid(p);
```

```js
const areEqual = await ctx.assertEqual(p, q);
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

