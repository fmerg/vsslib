const utils = require('../src/utils');


describe('bits & bytes length', () => {
  it.each([
    [0, 1, 0],
    [1, 1, 1],
    [513, 2, 10],
    [197121, 3, 18],
    [4278387201, 4, 32],
  ])('%s, bytes: %s, bits: %s', (num, nrBytes, nrBits) => {
    expect(utils.byteLen(num)).toBe(nrBytes);
    expect(utils.bitLen(num)).toBe(nrBits);
  });
});


describe('little-endian roundtrip', () => {
  it.each([
    [[0], 0],
    [[1], 1],
    [[1, 2], 513],
    [[1, 2, 3], 197121],
    [[1, 2, 3, 255], 4278387201],
  ])('%s, %s', (arr, num) => {
    const buffer = new Uint8Array(arr);
    const number = utils.leBuff2Int(buffer);
    expect(number).toBe(BigInt(num));
    const buffBack = utils.leInt2Buff(number);
    expect(buffBack).toEqual(buffer);
  });
});
