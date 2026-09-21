import { leBytesToInt, intToLeBytes, mod, gcd, modInv } from 'vsslib/arith';

const __0n = BigInt(0);
const __1n = BigInt(1);


describe('errors', () => {
  test('mod - Modulus <= 2', async () => {
    expect(() => mod(__1n, __0n)).toThrow('Modulus must be > 2');
    expect(() => mod(__1n, __1n)).toThrow('Modulus must be > 2');
  });
  test('gcd - Non-positive inputs', async () => {
    expect(() => gcd(__0n, __1n)).toThrow('Non-positive inputs');
    expect(() => gcd(__1n, __0n)).toThrow('Non-positive inputs');
    expect(() => gcd(__0n, __0n)).toThrow('Non-positive inputs');
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
  it.each(fixtures)('%s, %s, %s', async (x, q, r) => {
    expect(mod(BigInt(x), BigInt(q))).toBe(BigInt(r));
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
  it.each(fixtures)('%s, %s, %s, %s, %s', async (a, b, x, y, g) => {
    expect(gcd(BigInt(a), BigInt(b))).toEqual({
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
  it.each(fixtures)('%s, %s, %s', async (x, q, r) => {
    expect(modInv(BigInt(x), BigInt(q))).toBe(BigInt(r));
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
  it.each(fixtures)('%s, %s', async (x, q) => {
    expect(() => modInv(BigInt(x), BigInt(q))).toThrow(
      'No inverse exists for provided modulo'
    );
  })
})

describe('little-endian roundtrip', () => {
  it.each([
    [[0], 0],
    [[1], 1],
    [[1, 2], 513],
    [[1, 2, 3], 197121],
    [[1, 2, 3, 255], 4278387201],
  ])('%s, %s', (arr, num) => {
    const buffer = Uint8Array.from(arr);
    const number = leBytesToInt(buffer);
    expect(number).toBe(BigInt(num));
    const buffBack = intToLeBytes(number);
    expect(buffBack).toEqual(buffer);
  });
});


describe('little-endian fixed-length encoding', () => {
  it.each([
    [0, 1, [0]],
    [1, 4, [1, 0, 0, 0]],
    [513, 3, [1, 2, 0]],
    [4278387201, 4, [1, 2, 3, 255]],
  ])('%s, %s', (num, byteLength, arr) => {
    expect(intToLeBytes(BigInt(num), byteLength)).toEqual(Uint8Array.from(arr));
  });
  it('rejects too short length', () => {
    expect(() => intToLeBytes(BigInt(513), 1)).toThrow('Integer does not fit in 1 bytes');
  });
  it('accepts exactly the integers below 256 ^ length', () => {
    expect(intToLeBytes((1n << 256n) - 1n, 32)).toEqual(new Uint8Array(32).fill(255));
    expect(() => intToLeBytes(1n << 256n, 32)).toThrow('Integer does not fit in 32 bytes');
    expect(() => intToLeBytes(-1n, 32)).toThrow('Integer does not fit in 32 bytes');
  });
  it('does not convert the integer to string', () => {
    // String conversion runs in variable time and copies secrets to the heap
    const spy = jest.spyOn(BigInt.prototype, 'toString');
    try {
      intToLeBytes((1n << 255n) + 12345n, 32);
      expect(spy).not.toHaveBeenCalled();
    } finally {
      spy.mockRestore();
    }
  });
});
