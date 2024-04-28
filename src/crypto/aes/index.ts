// TODO: browser
const { createCipheriv, createDecipheriv } = require('node:crypto');

import { AesMode } from '../../types';
import { AesModes } from '../../enums';
import { ErrorMessages } from '../../errors';
import { randomBytes } from '../random';

class AesCipher {
  mode: AesMode;

  constructor(mode: AesMode) {
    this.mode = mode;
  }

  encrypt = (
    key: Uint8Array,
    message: Uint8Array,
    iv?: Uint8Array,
  ): { ciphered: Uint8Array, iv: Uint8Array, tag?: Uint8Array } => {
    if (key.length !== 32) throw new Error(ErrorMessages.INVALID_KEY_LENGTH);
    const ivLength = (this.mode == AesModes.AES_256_GCM) ? 12 : 16;
    iv = !iv ? randomBytes(ivLength) : iv;
    if (iv.length !== ivLength) throw new Error(ErrorMessages.INVALID_IV_LENGTH);
    const cipher = createCipheriv(this.mode, key, iv);
    const ciphered = Uint8Array.from(
      Buffer.from(cipher.update(message, 'binary', 'binary') + cipher.final('binary'))
    );
    const tag = (this.mode == AesModes.AES_256_GCM) ?
      Uint8Array.from(cipher.getAuthTag()) :
      undefined;
    return { ciphered, iv, tag };
  }

  decrypt = (
    key: Uint8Array,
    ciphered: Uint8Array,
    iv: Uint8Array,
    tag?: Uint8Array
  ): Uint8Array => {
    if (key.length !== 32) throw new Error(ErrorMessages.INVALID_KEY_LENGTH);
    if (iv.length !== (this.mode == AesModes.AES_256_GCM ? 12 : 16))
      throw new Error(ErrorMessages.INVALID_IV_LENGTH);
    const decipher = createDecipheriv(this.mode, key, iv);
    if (this.mode == AesModes.AES_256_GCM) {
      if (tag === undefined) throw new Error(ErrorMessages.MISSING_AUTHENTICATION_TAG);
      decipher.setAuthTag(tag);
    }
    let deciphered;
    deciphered = decipher.update(Buffer.from(ciphered).toString(), 'binary', 'binary');
    try {
      deciphered += decipher.final('binary');
    } catch (err) {
      throw new Error(ErrorMessages.AES_DECRYPTION_FAILURE);
    }
    return Uint8Array.from(Buffer.from(deciphered));
  }
}

export default function(mode: AesMode) {
  return new AesCipher(mode);
}
