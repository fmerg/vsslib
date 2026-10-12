import { describe, it, test, mock } from 'node:test';
import assert from 'node:assert/strict';
import { each } from './utils';
import { leBytesToInt, intToLeBytes, mod, gcd, modInv, modInvBatch } from 'vsslib/arith';

const __0n = BigInt(0);
const __1n = BigInt(1);


describe('errors', () => {
  test('mod - Modulus <= 2', async () => {
    assert.throws(() => mod(__1n, __0n), /Modulus must be > 2/);
    assert.throws(() => mod(__1n, __1n), /Modulus must be > 2/);
  });
  test('gcd - Non-positive inputs', async () => {
    assert.throws(() => gcd(__0n, __1n), /Non-positive inputs/);
    assert.throws(() => gcd(__1n, __0n), /Non-positive inputs/);
    assert.throws(() => gcd(__0n, __0n), /Non-positive inputs/);
  });
});


describe('mod', () => {
  const fixtures = [
    [+0, 2, 0],
    [+1, 2, 1],
    [+2, 2, 0],
    [+3, 2, 1],
    [+4, 2, 0],
    [-1, 2, 1],
    [-2, 2, 0],
    [-3, 2, 1],
    [-4, 2, 0],
    [+0, 3, 0],
    [+1, 3, 1],
    [+2, 3, 2],
    [+3, 3, 0],
    [+4, 3, 1],
    [+5, 3, 2],
    [+6, 3, 0],
    [-1, 3, 2],
    [-2, 3, 1],
    [-3, 3, 0],
    [-4, 3, 2],
    [-5, 3, 1],
    [-6, 3, 0],
  ];
  each(fixtures)('%s, %s, %s', async (x, q, r) => {
    assert.equal(mod(BigInt(x), BigInt(q)), BigInt(r));
  })
});


describe('greatest common divisor', () => {
  const fixtures = [
    [1, 1, 1, 0, 1],
    [1, 2, 1, 0, 1],
    [2, 1, 0, 1, 1],
    [1, 3, 1, 0, 1],
    [3, 1, 0, 1, 1],
    [2, 2, 1, 0, 2],
    [2, 3, -1, 1, 1],
    [3, 2, 1, -1, 1],
    [2, 4, 1, 0, 2],
    [4, 2, 0, 1, 2],
    [3, 4, -1, 1, 1],
    [4, 3, 1, -1, 1],
    [6, 9, -1, 1, 3],
    [9, 6, 1, -1, 3],
    [8, 12, -1, 1, 4],
    [12, 8, 1, -1, 4],
    [56, 32, -1, 2, 8],
    [32, 56, 2, -1, 8],
  ];
  each(fixtures)('%s, %s, %s, %s, %s', async (a, b, x, y, g) => {
    assert.deepEqual(gcd(BigInt(a), BigInt(b)), {
      x: BigInt(x),
      y: BigInt(y),
      g: BigInt(g),
    });
  })
});


describe('mod inverse', () => {
  const fixtures = [
    [+1, 2, 1],
    [+3, 2, 1],
    [-1, 2, 1],
    [-3, 2, 1],
    [+1, 3, 1],
    [+2, 3, 2],
    [+4, 3, 1],
    [+5, 3, 2],
    [-1, 3, 2],
    [-2, 3, 1],
    [-4, 3, 2],
    [-5, 3, 1],
    [+1, 4, 1],
    [+3, 4, 3],
    [-1, 4, 3],
    [-3, 4, 1],
    [+1, 5, 1],
    [+2, 5, 3],
    [+3, 5, 2],
    [+4, 5, 4],
    [-1, 5, 4],
    [-2, 5, 2],
    [-3, 5, 3],
    [-4, 5, 1],
    [+1, 6, 1],
    [+5, 6, 5],
    [-1, 6, 5],
    [-5, 6, 1],
    [+1, 7, 1],
    [+2, 7, 4],
    [+3, 7, 5],
    [+4, 7, 2],
    [+5, 7, 3],
    [+6, 7, 6],
    [-1, 7, 6],
    [-2, 7, 3],
    [-3, 7, 2],
    [-4, 7, 5],
    [-5, 7, 4],
    [-6, 7, 1],
  ];
  each(fixtures)('%s, %s, %s', async (x, q, r) => {
    assert.equal(modInv(BigInt(x), BigInt(q)), BigInt(r));
  })
});


describe('Inverse not exists', () => {
  const fixtures = [
    [+0, 2],
    [+2, 2],
    [+4, 2],
    [-2, 2],
    [-4, 2],
    [+0, 3],
    [+3, 3],
    [+6, 3],
    [-3, 3],
    [-6, 3],
    [+0, 4],
    [+2, 4],
    [+4, 4],
    [-2, 4],
    [-4, 4],
    [+0, 5],
    [+5, 5],
    [-5, 5],
    [+0, 6],
    [+2, 6],
    [+3, 6],
    [+4, 6],
    [+6, 6],
    [-2, 6],
    [-3, 6],
    [-4, 6],
    [-6, 6],
    [+0, 7],
    [+7, 7],
    [-7, 7],
  ];
  each(fixtures)('%s, %s', async (x, q) => {
    assert.throws(() => modInv(BigInt(x), BigInt(q)), /No inverse exists for provided modulo/);
  })
})

describe('modInvBatch', () => {
  const order = BigInt(2) ** BigInt(252) + BigInt('27742317777372353535851937790883648493');
  each([
    [[1, 2, 3, 4, 5, 6], 7],
    [[-1, -6, 8, 13, 20], 7],
    [[1, 5, 7, 11, -1], 12],
    [[3], 11],
  ])('%s mod %s matches modInv', async (xs, q) => {
    const values = xs.map(x => BigInt(x));
    assert.deepEqual(modInvBatch(values, BigInt(q)), values.map(v => modInv(v, BigInt(q))));
  });
  test('large prime modulus', async () => {
    const values = Array.from({ length: 50 }, (_, i) =>
      BigInt(i + 1) ** BigInt(60) - BigInt(i * 1000003)
    );
    const inverses = modInvBatch(values, order);
    assert.deepEqual(inverses, values.map(v => modInv(v, order)));
    inverses.forEach((w, i) => assert.equal(mod(w * values[i], order), __1n));
  });
  test('empty input', async () => {
    assert.deepEqual(modInvBatch([], BigInt(7)), []);
  });
  each([
    [[1, 2, 0], 7],
    [[7, 1], 7],
    [[1, -14, 3], 7],
    [[1, 2, 5], 6],
    [[5, 9], 12],
  ])('%s mod %s has no inverse', async (xs, q) => {
    assert.throws(() => modInvBatch(xs.map(x => BigInt(x)), BigInt(q)), /No inverse exists for provided modulo/);
  });
});


describe('little-endian roundtrip', () => {
  each([
    [[0], 0],
    [[1], 1],
    [[1, 2], 513],
    [[1, 2, 3], 197121],
    [[1, 2, 3, 255], 4278387201],
  ])('%s, %s', (arr, num) => {
    const buffer = Uint8Array.from(arr);
    const number = leBytesToInt(buffer);
    assert.equal(number, BigInt(num));
    const buffBack = intToLeBytes(number);
    assert.deepEqual(buffBack, buffer);
  });
});


describe('little-endian fixed-length encoding', () => {
  each([
    [0, 1, [0]],
    [1, 4, [1, 0, 0, 0]],
    [513, 3, [1, 2, 0]],
    [4278387201, 4, [1, 2, 3, 255]],
  ])('%s, %s', (num, byteLength, arr) => {
    assert.deepEqual(intToLeBytes(BigInt(num), byteLength), Uint8Array.from(arr));
  });
  it('rejects too short length', () => {
    assert.throws(() => intToLeBytes(BigInt(513), 1), /Integer does not fit in 1 bytes/);
  });
  it('accepts exactly the integers below 256 ^ length', () => {
    assert.deepEqual(intToLeBytes((1n << 256n) - 1n, 32), new Uint8Array(32).fill(255));
    assert.throws(() => intToLeBytes(1n << 256n, 32), /Integer does not fit in 32 bytes/);
    assert.throws(() => intToLeBytes(-1n, 32), /Integer does not fit in 32 bytes/);
  });
  it('does not convert the integer to string', () => {
    // String conversion runs in variable time and copies secrets to the heap
    const spy = mock.method(BigInt.prototype, 'toString');
    try {
      intToLeBytes((1n << 255n) + 12345n, 32);
      assert.equal(spy.mock.callCount(), 0);
    } finally {
      spy.mock.restore();
    }
  });
});
