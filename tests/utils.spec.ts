import { createHash } from 'node:crypto';
import { Algorithms, Encodings } from '../src/enums';

const utils = require('../src/utils');


describe('hash digest', () => {
  const algorithms = [...Object.values(Algorithms), undefined];
  const encodings = [...Object.values(Encodings), undefined];
  const combinations : any[] = [];
  for (const algorithm of algorithms) {
    for (const encoding of encodings) {
      combinations.push([algorithm, encoding]);
    }
  }

  const buffer = Buffer.from('sample-text');
  it.each(combinations)('%s, %s', async (algorithm, encoding) => {
    const digest = await utils.hash(buffer, { algorithm, encoding });
    const hasher = createHash(algorithm || Algorithms.DEFAULT).update(buffer);
    const expected = encoding ?
      hasher.digest(encoding == Encodings.HEX ? Encodings.HEX : Encodings.BASE64) :
      new Uint8Array(hasher.digest());
    expect(digest).toEqual(expected);
  });
});


describe('hash failure', () => {
  test('unsupported algorithm', async () => {
    const algorithm = 'unsupported'
    await expect(utils.hash(Buffer.from('whatever'), { algorithm })).rejects.toThrow(
      `Unsupported algorithm: ${algorithm}`
    );
  });
  test('unsupported encoding', async () => {
    const encoding = 'unsupported'
    await expect(utils.hash(Buffer.from('whatever'), { encoding })).rejects.toThrow(
      `Unsupported encoding: ${encoding}`
    );
  });
});


describe('bits & bytes', () => {
  test('little-endian roundtrip', () => {
    const buffer = new Uint8Array([1, 2, 3, 255]);
    const number = utils.leBuff2Int(buffer);
    const buffBack = utils.leInt2Buff(number);
    expect(buffBack).toEqual(buffer);
  });
});

