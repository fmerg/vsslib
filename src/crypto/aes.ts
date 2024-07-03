// TODO: browser
const { createCipheriv, createDecipheriv } = require('node:crypto');

import { BlockMode } from 'vsslib/types';
import { BlockModes } from 'vsslib/enums';
import { randomBytes } from './random';
import { AesError } from 'vsslib/errors';

class AesCipher {
  mode: BlockMode;

  constructor(mode: BlockMode) {
    this.mode = mode;
  }

  encrypt = (key: Uint8Array, message: Uint8Array, iv?: Uint8Array): {
    ciphered: Uint8Array,
    iv: Uint8Array,
    tag: Uint8Array
  } => {
    if (key.length !== 32)
      throw new AesError(`Invalid key length: ${key.length}`);
    const ivLength = (this.mode == BlockModes.AES_256_GCM) ? 12 : 16;
    iv = !iv ? randomBytes(ivLength) : iv;
    if (iv.length !== ivLength)
      throw new AesError(`Invalid IV length: ${iv.length} != ${ivLength}`);
    const cipher = createCipheriv(this.mode, key, iv);
    const ciphered = Uint8Array.from(
      Buffer.from(cipher.update(message, 'binary', 'binary') + cipher.final('binary'))
    );
    const tag = Uint8Array.from(
      this.mode == BlockModes.AES_256_GCM ? cipher.getAuthTag() : []
    );
    return { ciphered, iv, tag };
  }

  decrypt = (
    key: Uint8Array, ciphered: Uint8Array, iv: Uint8Array, tag?: Uint8Array
  ): Uint8Array => {
    if (key.length !== 32)
      throw new AesError(`Invalid key length: ${key.length}`);
    const expectedIvLength = (this.mode === BlockModes.AES_256_GCM) ? 12 : 16;
    if (iv.length !== expectedIvLength)
      throw new AesError(`Invalid IV length: ${iv.length} != ${expectedIvLength}`);
    const decipher = createDecipheriv(this.mode, key, iv);
    if (this.mode == BlockModes.AES_256_GCM) {
      if (tag === undefined || tag.length == 0)
        throw new AesError('Missing authentication tag');
      decipher.setAuthTag(tag);
    }
    let deciphered;
    deciphered = decipher.update(Buffer.from(ciphered).toString(), 'binary', 'binary');
    try {
      deciphered += decipher.final('binary');
    } catch (err: any) {
      throw new AesError(`AES decryption failure: ${err.message}`);
    }
    return Uint8Array.from(Buffer.from(deciphered));
  }
}

export default function(mode: BlockMode) {
  return new AesCipher(mode);
}
