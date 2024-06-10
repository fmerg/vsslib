import { BlockModes } from '../../src/enums';
import { aes, randomBytes } from '../../src/crypto';

import { resolveTestConfig } from '../environ';

const { modes }  = resolveTestConfig();


describe('Encryption and decryption - success', () => {
  it.each(modes)('over %s', async (mode) => {
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const key = randomBytes(32);
    const { ciphered, iv, tag } = aes(mode).encrypt(key, message);
    const deciphered = aes(mode).decrypt(key, ciphered, iv, tag);
    expect(deciphered).toEqual(message);
  });
});


describe('Encryption and decryption - failure if forged key', () => {
  it.each(modes)('over %s', async (mode) => {
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
});


describe('Encryption and decryption - failure if forged IV', () => {
  it.each(modes)('over %s', async (mode) => {
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


describe('Invalid input errors', () => {
  describe('Invalid key length', () => {
    test('Encryption', () => {
      const message = Uint8Array.from(Buffer.from('destroy earth'));
      const key = randomBytes(31);
      expect(() => aes(BlockModes.DEFAULT).encrypt(key, message)).toThrow('Invalid key length');
    });
    test('Decryption', () => {
      const key = randomBytes(31);
      const ciphered = Uint8Array.from(Buffer.from('random bits'));
      const iv = randomBytes(16)
      expect(() => aes(BlockModes.DEFAULT).decrypt(key, ciphered, iv)).toThrow('Invalid key length');
    });
  });

  describe('Invalid IV length', () => {
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const key = randomBytes(32);
    describe('Encryption', () => {
      it.each(modes)('over %s', async (mode) => {
        const iv = randomBytes(mode == BlockModes.AES_256_GCM ? 16 : 12);
        expect(() => aes(mode).encrypt(key, message, iv)).toThrow('Invalid IV length');
      });
    });
    describe('Decryption', () => {
      it.each(modes)('over %s', async (mode) => {
        const { ciphered } = aes(mode).encrypt(key, message);
        const iv = randomBytes(mode == BlockModes.AES_256_GCM ? 16 : 12);
        expect(() => aes(mode).decrypt(key, ciphered, iv)).toThrow('Invalid IV length');
      });
    });
  });
});
