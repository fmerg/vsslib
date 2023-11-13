import { AesModes } from '../enums';
import { AesMode } from '../types';


const crypto = require('crypto');

export function encrypt(
  key: Uint8Array,
  message: Uint8Array,
  opts?: { mode?: AesMode, iv?: Uint8Array }
): { ciphered: Uint8Array, iv: Uint8Array, tag?: Uint8Array } {
  if (key.length !== 32) throw new Error('Invalid key length');
  const mode = opts ? (opts.mode || AesModes.DEFAULT) : AesModes.DEFAULT;
  const ivLength = (mode == AesModes.AES_256_GCM) ? 12 : 16;
  const iv = Uint8Array.from(
    opts ? (opts.iv || crypto.randomBytes(ivLength)) : crypto.randomBytes(ivLength)
  );
  if (iv.length !== ivLength) throw new Error('Invalid IV length');
  const cipher = crypto.createCipheriv(mode, key, iv);
  const ciphered = Uint8Array.from(
    Buffer.from(cipher.update(message, 'binary', 'binary') + cipher.final('binary'))
  );
  const tag = (mode == AesModes.AES_256_GCM) ?
    Uint8Array.from(cipher.getAuthTag()) :
    undefined;
  return { ciphered, iv, tag };
}


export function decrypt(
  key: Uint8Array,
  ciphered: Uint8Array,
  iv: Uint8Array,
  opts?: { mode?: AesMode, tag?: Uint8Array },
): Uint8Array {
  if (key.length !== 32) throw new Error('Invalid key length');
  const mode = opts ? (opts.mode || AesModes.DEFAULT) : AesModes.DEFAULT;
  if (iv.length !== (mode == AesModes.AES_256_GCM ? 12 : 16))
    throw new Error('Invalid IV length');
  const decipher = crypto.createDecipheriv(mode, key, iv);
  if (mode == AesModes.AES_256_GCM) {
    const tag = opts ? (opts.tag || undefined) : undefined;
    if (tag === undefined) throw new Error('No authentication tag provided');
    decipher.setAuthTag(tag);
  }
  let deciphered;
  deciphered = decipher.update(Buffer.from(ciphered).toString(), 'binary', 'binary');
  try {
    deciphered += decipher.final('binary');
  } catch (err) {
    throw new Error('AES decryption failure');
  }
  return Uint8Array.from(Buffer.from(deciphered));
}
