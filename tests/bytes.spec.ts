import { isEqualBytes } from 'vsslib/bytes';


describe('isEqualBytes', () => {
  test('equal arrays', () => {
    expect(isEqualBytes(new Uint8Array(), new Uint8Array())).toBe(true);
    expect(isEqualBytes(Uint8Array.of(1, 2, 3), Uint8Array.of(1, 2, 3))).toBe(true);
  });
  test('arrays differing at a single position', () => {
    const a = Uint8Array.of(0, 0, 0, 0);
    for (let i = 0; i < a.length; i++) {
      for (const bit of [0x01, 0x80]) {
        const b = Uint8Array.from(a);
        b[i] ^= bit;
        expect(isEqualBytes(a, b)).toBe(false);
        expect(isEqualBytes(b, a)).toBe(false);
      }
    }
  });
  test('arrays of different lengths', () => {
    expect(isEqualBytes(Uint8Array.of(1, 2), Uint8Array.of(1, 2, 0))).toBe(false);
    expect(isEqualBytes(new Uint8Array(), Uint8Array.of(0))).toBe(false);
  });
});
