const crypto = require('crypto');

import { AesModes } from '../../src/schemes';
import aes from '../../src/core/aes';

import { resolveAesModes } from '../environ';

const __aesModes  = resolveAesModes();


describe('Encryption and decryption - success', () => {
  it.each(__aesModes)('over %s', async (mode) => {
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const key = crypto.randomBytes(32);
    const { ciphered, iv, tag } = aes(mode).encrypt(key, message);
    const deciphered = aes(mode).decrypt(key, ciphered, iv, tag);
    expect(deciphered).toEqual(message);
  });
});


describe('Encryption and decryption - failure if forged key', () => {
  it.each(__aesModes)('over %s', async (mode) => {
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const key = crypto.randomBytes(32);
    const { ciphered, iv, tag } = aes(mode).encrypt(key, message);
    const forgedKey = crypto.randomBytes(32);
    if (!mode || [AesModes.AES_256_CBC, AesModes.AES_256_GCM].includes(mode)) {
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
  it.each(__aesModes)('over %s', async (mode) => {
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const key = crypto.randomBytes(32);
    const { ciphered, iv, tag } = aes(mode).encrypt(key, message);
    const forgedIv = crypto.randomBytes(mode == AesModes.AES_256_GCM ? 12 : 16);
    if (!mode || [AesModes.AES_256_CBC, AesModes.AES_256_GCM].includes(mode)) {
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
      const key = crypto.randomBytes(31);
      expect(() => aes(AesModes.DEFAULT).encrypt(key, message)).toThrow('Invalid key length');
    });
    test('Decryption', () => {
      const key = crypto.randomBytes(31);
      const ciphered = Uint8Array.from(Buffer.from('random bits'));
      const iv = crypto.randomBytes(16)
      expect(() => aes(AesModes.DEFAULT).decrypt(key, ciphered, iv)).toThrow('Invalid key length');
    });
  });

  describe('Invalid IV length', () => {
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const key = crypto.randomBytes(32);
    describe('Encryption', () => {
      it.each(__aesModes)('over %s', async (mode) => {
        const iv = crypto.randomBytes(mode == AesModes.AES_256_GCM ? 16 : 12);
        expect(() => aes(mode).encrypt(key, message, iv)).toThrow('Invalid IV length');
      });
    });
    describe('Decryption', () => {
      it.each(__aesModes)('over %s', async (mode) => {
        const { ciphered } = aes(mode).encrypt(key, message);
        const iv = crypto.randomBytes(mode == AesModes.AES_256_GCM ? 16 : 12);
        expect(() => aes(mode).decrypt(key, ciphered, iv)).toThrow('Invalid IV length');
      });
    });
  });
});
