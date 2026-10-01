import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { isEqualBytes } from 'vsslib/bytes';


describe('isEqualBytes', () => {
  test('equal arrays', () => {
    assert.equal(isEqualBytes(new Uint8Array(), new Uint8Array()), true);
    assert.equal(isEqualBytes(Uint8Array.of(1, 2, 3), Uint8Array.of(1, 2, 3)), true);
  });
  test('arrays differing at a single position', () => {
    const a = Uint8Array.of(0, 0, 0, 0);
    for (let i = 0; i < a.length; i++) {
      for (const bit of [0x01, 0x80]) {
        const b = Uint8Array.from(a);
        b[i] ^= bit;
        assert.equal(isEqualBytes(a, b), false);
        assert.equal(isEqualBytes(b, a), false);
      }
    }
  });
  test('arrays of different lengths', () => {
    assert.equal(isEqualBytes(Uint8Array.of(1, 2), Uint8Array.of(1, 2, 0)), false);
    assert.equal(isEqualBytes(new Uint8Array(), Uint8Array.of(0)), false);
  });
});
