// TODO: browser
const crypto = require('node:crypto');
import { AesModes, AesMode } from '../../schemes';

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
    if (key.length !== 32) throw new Error('Invalid key length');
    const ivLength = (this.mode == AesModes.AES_256_GCM) ? 12 : 16;
    const _iv = iv == undefined ? crypto.randomBytes(ivLength) : iv;
    if (_iv.length !== ivLength) throw new Error('Invalid IV length');
    const cipher = crypto.createCipheriv(this.mode, key, _iv);
    const ciphered = Uint8Array.from(
      Buffer.from(cipher.update(message, 'binary', 'binary') + cipher.final('binary'))
    );
    const tag = (this.mode == AesModes.AES_256_GCM) ?
      Uint8Array.from(cipher.getAuthTag()) :
      undefined;
    return { ciphered, iv: _iv, tag };
  }

  decrypt = (
    key: Uint8Array,
    ciphered: Uint8Array,
    iv: Uint8Array,
    tag?: Uint8Array
  ): Uint8Array => {
    if (key.length !== 32) throw new Error('Invalid key length');
    if (iv.length !== (this.mode == AesModes.AES_256_GCM ? 12 : 16))
      throw new Error('Invalid IV length');
    const decipher = crypto.createDecipheriv(this.mode, key, iv);
    if (this.mode == AesModes.AES_256_GCM) {
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
}

export default function(mode: AesMode) {
  return new AesCipher(mode);
}
