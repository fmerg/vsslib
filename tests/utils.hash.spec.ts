import { utils } from '../src';
import { createHash } from 'node:crypto';
import { Algorithms, Encodings } from '../src/enums';
import { Algorithm, Encoding } from '../src/types';
import { cartesian } from './helpers';

const __algorithms  = [...Object.values(Algorithms), undefined];
const __encodings   = [...Object.values(Encodings), undefined];


describe('hash digest', () => {
  const buffer = Buffer.from('sample-text');
  it.each(cartesian([__algorithms, __encodings]))('%s, %s', async (algorithm, encoding) => {
    const digest = await utils.hash(buffer, { algorithm, encoding });
    const hasher = createHash(algorithm || Algorithms.DEFAULT).update(buffer);
    const expected = encoding ?
      hasher.digest(encoding == Encodings.HEX ? Encodings.HEX : Encodings.BASE64) :
      Uint8Array.from(hasher.digest());
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
