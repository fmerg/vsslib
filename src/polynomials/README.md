# `vsslib.polynomials`

## Construction

```js
import { Polynomial } from 'vsslib/polynomials';
import { backend } from 'vsslib';

const ctx = backend.initGroup('ed25519');
const coeffs = [1, 2, 3, 4, 5].map((num) => BigInt(num));
const polynomial = new Polynomial(ctx, coeffs);
```

### Random generation

```js
const polynomial = await Polynomial.random(ctx, degree=5);
```

### Lagrange interpolation

```js
import { Lagrange } from 'vsslib/polynomials';

const polynomial = await Lagrange.interpolate(ctx, [[0, 1], [2, 3], [4, 5]]);
```

### Basic operations

```js
const y = polynomial.evaluate(x);
```

```js
const q = p.multScalar(BigInt(666));
```

```js
const r = p.add(q);
```

```js
const r = p.mult(q);
```

```js
const areEqual = p.equals(q);
```


## Feldmann commitments

```js
const { commitments } = await polynomial.getFeldmann();
```

```js
const secret = await polynomial.evaluate(index);
```

```js
import { verifyFeldmann } from 'vsslib/polynomials';

const verified = await verifyFeldmann(ctx, secret, index, commitments);
```


## Pedersen commitments

```js
const hPub = await ctx.randomPoint();
const nr = 7;

const { commitments, bindings } = await polynomial.getPedersen(nr, hPub);
```

```js
const secret = await polynomial.evaluate(index);

const binding = bindings[index];
```

```js
import { verifyPedersen } from 'vsslib/polynomials';

const verified = await verifyPedersen(ctx, secret, binding, index, hPub, commitments);
```
