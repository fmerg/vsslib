import { randomNonce, InvalidInput } from 'vsslib';


describe('randomNonce', () => {
  test('default size', () => {
    expect(randomNonce()).toHaveLength(16);
  });
  test.each([1, 32, 65536])('size %s', (nrBytes) => {
    const nonce = randomNonce(nrBytes);
    expect(nonce).toBeInstanceOf(Uint8Array);
    expect(nonce).toHaveLength(nrBytes);
  });
  test('distinct nonces', () => {
    expect(randomNonce(32)).not.toEqual(randomNonce(32));
  });
  test.each([0, -1, 1.5, 65537, NaN, Infinity])('size %s is rejected', (nrBytes) => {
    expect(() => randomNonce(nrBytes)).toThrow(InvalidInput);
  });
});
