import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { each } from './utils';
import { randomNonce, InvalidInput } from 'vsslib';


describe('randomNonce', () => {
  test('default size', () => {
    assert.equal(randomNonce().length, 16);
  });
  each([1, 32, 65536])('size %s', (nrBytes) => {
    const nonce = randomNonce(nrBytes);
    assert.ok(nonce instanceof Uint8Array);
    assert.equal(nonce.length, nrBytes);
  });
  test('distinct nonces', () => {
    assert.notDeepEqual(randomNonce(32), randomNonce(32));
  });
  each([0, -1, 1.5, 65537, NaN, Infinity])('size %s is rejected', (nrBytes) => {
    assert.throws(() => randomNonce(nrBytes), InvalidInput);
  });
});
