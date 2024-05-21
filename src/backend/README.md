# `vsslib.backend`

```js
import { initGroup }  from 'vsslib/backend';

const ctx = initGroup('ed25519');
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
const b = await ctx.randomScalarBuff();
```


### Secret generation

```js
const { secret, publicPoint, publicBytes } = await ctx.generateSecret();
```


### Group operations

```js
const u = await ctx.operate(p, q);
```

```js
const v = await ctx.invert(p);
```

```js
const w = await ctx.exp(s, p);
```


### Point serialization

```js
const pBytes = p.toBytes();
```

```js
const pBack = ctx.unpack(pBytes);
```

```js
const pBack = ctx.unpackValid(pBytes);
```
