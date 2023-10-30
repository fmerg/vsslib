## `vsslib.lagrange`

```js
const { lagrange } = require('vsslib');
```

### Interpolation

```js
const polynomial = lagrange.interpolate([[0, 1], [2, 3], [4, 5]], { order: 7 });
```

### Polynomial interface
