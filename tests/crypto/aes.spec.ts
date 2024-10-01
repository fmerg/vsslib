import { BlockModes } from 'vsslib/enums';
import { aes, randomBytes } from 'vsslib/crypto';

import { resolveTestConfig } from '../environ';

const { modes }  = resolveTestConfig();


describe('AES - end to end', () => {
  it.each(modes)('success - over %s', async (mode) => {
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const key = randomBytes(32);
    const { ciphered, iv, tag } = aes(mode).encrypt(key, message);
    const deciphered = aes(mode).decrypt(key, ciphered, iv, tag);
    expect(deciphered).toEqual(message);
  });
  it.each(modes)('failure - forged key - over %s', async (mode) => {
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const key = randomBytes(32);
    const { ciphered, iv, tag } = aes(mode).encrypt(key, message);
    const forgedKey = randomBytes(32);
    if (!mode || [BlockModes.AES_256_CBC, BlockModes.AES_256_GCM].includes(mode)) {
      expect(
        () => aes(mode).decrypt(forgedKey, ciphered, iv, tag)
      ).toThrow('AES decryption failure');
    } else {
      const deciphered = aes(mode).decrypt(forgedKey, ciphered, iv, tag);
      expect(deciphered).not.toEqual(message);
    }
  });
  it.each(modes)('failure - forged IV - over %s', async (mode) => {
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const key = randomBytes(32);
    const { ciphered, iv, tag } = aes(mode).encrypt(key, message);
    const forgedIv = randomBytes(mode == BlockModes.AES_256_GCM ? 12 : 16);
    if (!mode || [BlockModes.AES_256_CBC, BlockModes.AES_256_GCM].includes(mode)) {
      expect(
        () => aes(mode).decrypt(key, ciphered, forgedIv, tag)
      ).toThrow('AES decryption failure');
    } else {
      const deciphered = aes(mode).decrypt(key, ciphered, forgedIv, tag);
      expect(deciphered).not.toEqual(message);
    }
  });
});

describe('AES - invalid key length', () => {
  const message = Uint8Array.from(Buffer.from('destroy earth'));
  const key = randomBytes(31);
  it.each(modes)('encryption error - over %s', async (mode) => {
    const iv = randomBytes(mode == BlockModes.AES_256_GCM ? 16 : 12);
    expect(() => aes(mode).encrypt(key, message, iv)).toThrow('Invalid key length');
  });
  it.each(modes)('decryption error - over %s', async (mode) => {
    const ciphered = Uint8Array.from(Buffer.from('random bits'));
    const iv = randomBytes(mode == BlockModes.AES_256_GCM ? 16 : 12);
    expect(() => aes(mode).encrypt(key, message, iv)).toThrow('Invalid key length');
  });
});

describe('AES - invalid IV length error', () => {
  const message = Uint8Array.from(Buffer.from('destroy earth'));
  const key = randomBytes(32);
  it.each(modes)('encryption error - over %s', async (mode) => {
    const iv = randomBytes(mode == BlockModes.AES_256_GCM ? 16 : 12);
    expect(() => aes(mode).encrypt(key, message, iv)).toThrow('Invalid IV length');
  });
  it.each(modes)('decryption error - over %s', async (mode) => {
    const { ciphered } = aes(mode).encrypt(key, message);
    const iv = randomBytes(mode == BlockModes.AES_256_GCM ? 16 : 12);
    expect(() => aes(mode).decrypt(key, ciphered, iv)).toThrow('Invalid IV length');
  });
});
