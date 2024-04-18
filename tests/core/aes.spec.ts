import { aes } from '../../src/core';
import { AesModes } from '../../src/enums';
import { AesMode } from '../../src/types';


const crypto = require('crypto');
const __aesModes  = [...Object.values(AesModes), undefined];


describe('Encryption and decryption - success', () => {
  it.each(__aesModes)('over %s', async (mode) => {
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const key = crypto.randomBytes(32);
    const { ciphered, iv, tag } = aes.encrypt(key, message, { mode });
    const deciphered = aes.decrypt(key, ciphered, iv, { mode, tag });
    expect(deciphered).toEqual(message);
  });
});


describe('Encryption and decryption - failure if forged key', () => {
  it.each(__aesModes)('over %s', async (mode) => {
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const key = crypto.randomBytes(32);
    const { ciphered, iv, tag } = aes.encrypt(key, message, { mode });
    const forgedKey = crypto.randomBytes(32);
    if (!mode || [AesModes.AES_256_CBC, AesModes.AES_256_GCM].includes(mode)) {
      expect(
        () => aes.decrypt(forgedKey, ciphered, iv, { mode, tag })
      ).toThrow('AES decryption failure');
    } else {
      const deciphered = aes.decrypt(forgedKey, ciphered, iv, { mode, tag });
      expect(deciphered).not.toEqual(message);
    }
  });
});


describe('Encryption and decryption - failure if forged IV', () => {
  it.each(__aesModes)('over %s', async (mode) => {
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const key = crypto.randomBytes(32);
    const { ciphered, iv, tag } = aes.encrypt(key, message, { mode });
    const forgedIv = crypto.randomBytes(mode == AesModes.AES_256_GCM ? 12 : 16);
    if (!mode || [AesModes.AES_256_CBC, AesModes.AES_256_GCM].includes(mode)) {
      expect(
        () => aes.decrypt(key, ciphered, forgedIv, { mode, tag })
      ).toThrow('AES decryption failure');
    } else {
      const deciphered = aes.decrypt(key, ciphered, forgedIv, { mode, tag });
      expect(deciphered).not.toEqual(message);
    }
  });
});


describe('Invalid input errors', () => {
  describe('Invalid key length', () => {
    test('Encryption', () => {
      const message = Uint8Array.from(Buffer.from('destroy earth'));
      const key = crypto.randomBytes(31);
      expect(() => aes.encrypt(key, message)).toThrow('Invalid key length');
    });
    test('Decryption', () => {
      const key = crypto.randomBytes(31);
      const ciphered = Uint8Array.from(Buffer.from('random bits'));
      const iv = crypto.randomBytes(16)
      expect(() => aes.decrypt(key, ciphered, iv)).toThrow('Invalid key length');
    });
  });

  describe('Invalid IV length', () => {
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const key = crypto.randomBytes(32);
    describe('Encryption', () => {
      it.each(__aesModes)('over %s', async (mode) => {
        const iv = crypto.randomBytes(mode == AesModes.AES_256_GCM ? 16 : 12);
        expect(() => aes.encrypt(key, message, { mode, iv })).toThrow('Invalid IV length');
      });
    });
    describe('Decryption', () => {
      it.each(__aesModes)('over %s', async (mode) => {
        const { ciphered } = aes.encrypt(key, message, { mode });
        const iv = crypto.randomBytes(mode == AesModes.AES_256_GCM ? 16 : 12);
        expect(() => aes.decrypt(key, ciphered, iv, { mode })).toThrow('Invalid IV length');
      });
    });
  });
});
