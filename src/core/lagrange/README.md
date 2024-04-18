# `vsslib.lagrange`

## Construction

```js
import { Polynomial } from 'vsslib/lagrange';
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
import { lagrange } from 'vsslib';

const polynomial = await lagrange.interpolate(ctx, [[0, 1], [2, 3], [4, 5]]);
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
