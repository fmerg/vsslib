# `vsslib.backend`

```js
const backend = require('vsslib/backend');

const group = backend.initGroup('ed25519');
```

```js
const { modulus, order, generator, neutral } = group;
```

## Interface


### Generalities

```js
const s = await group.randomScalar();
```

```js
const p = await group.randomPoint();
```

```js
const p = await group.generatePoint(s);
```

```js
const isValid = await group.assertValid(p);
```

```js
const areEqual = await group.assertEqual(p, q);
```


### Group operations

```js
const u = await group.combine(p, q);
```

```js
const v = await group.invert(p);
```

```js
const w = await group.operate(s, p);
```


### Point serialization

```js
const pBytes = p.toBytes();
```

```js
const pBack = group.unpack(pBytes);
```

```js
const pHex = p.toHex();
```

```js
const pBack = group.unhexify(pHex);
```

