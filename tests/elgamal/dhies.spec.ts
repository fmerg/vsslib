import { Algorithms, BlockModes } from 'vsslib/enums';
import { randomBytes } from 'vsslib/crypto';
import { leInt2Buff } from 'vsslib/arith';
import { initBackend } from 'vsslib/backend';
import { randomSecret, randomPublic } from 'vsslib/secrets';
import { ElgamalSchemes } from 'vsslib/enums';
import { DhiesCiphertext } from 'vsslib/elgamal/driver';

import elgamal from 'vsslib/elgamal';

import { cartesian } from '../utils';
import { buildMessage } from '../helpers';
import { resolveTestConfig } from '../environ';

const { systems, modes, algorithms } = resolveTestConfig();

const DHIES = ElgamalSchemes.DHIES;


describe('DHIES encryption and decryption (Integrated Encryption Scheme)', () => {
  it.each(cartesian([systems, modes, algorithms]))(
    'success - over %s/%s/%s', async (system, mode, algorithm,) => {
    const ctx = initBackend(system);
    const { secret, publicBytes } = await randomSecret(ctx);
    const message = await buildMessage(ctx, DHIES);
    const { ciphertext } = await elgamal(ctx, DHIES, algorithm, mode).encrypt(message, publicBytes);
    const plaintext = await elgamal(ctx, DHIES, algorithm, mode).decrypt(ciphertext, secret);
    expect(plaintext).toEqual(message);
  });
  it.each(cartesian([systems, modes, algorithms]))(
    'failure - forged secret - over %s/%s/%s', async (system, mode, algorithm,) => {
    const ctx = initBackend(system);
    const { secret, publicBytes } = await randomSecret(ctx);
    const message = await buildMessage(ctx, DHIES);
    const { ciphertext } = await elgamal(ctx, DHIES, algorithm, mode).encrypt(message, publicBytes);
    const { secret: forgedSecret } = await randomSecret(ctx);
    await expect(elgamal(ctx, DHIES, algorithm, mode).decrypt(ciphertext, forgedSecret)).rejects.toThrow(
      'Could not decrypt: Invalid MAC'
    );
  });
  it.each(cartesian([systems, modes, algorithms]))(
    'failure - forged IV - over %s/%s/%s', async (system, mode, algorithm) => {
    const ctx = initBackend(system);
    const { secret, publicBytes } = await randomSecret(ctx);
    const message = await buildMessage(ctx, DHIES);
    const { ciphertext } = await elgamal(ctx, DHIES, algorithm, mode).encrypt(message, publicBytes);
    (ciphertext as DhiesCiphertext).alpha.iv = await randomBytes(mode == BlockModes.AES_256_GCM ? 12 : 16);
    if (!mode || [BlockModes.AES_256_CBC, BlockModes.AES_256_GCM].includes(mode)) {
      await expect(elgamal(ctx, DHIES, algorithm, mode).decrypt(ciphertext, secret)).rejects.toThrow(
        'Could not decrypt: AES decryption failure'
      );
    } else {
      const plaintext = await elgamal(ctx, DHIES, algorithm, mode).decrypt(ciphertext, secret);
      expect(plaintext).not.toEqual(message);
    }
  });
  it.each(cartesian([systems, modes]))(
    'decrypt with decryptor - success - over %s/%s', async (system, mode) => {
    const ctx = initBackend(system);
    const { secret, publicBytes } = await randomSecret(ctx);
    const message = await buildMessage(ctx, DHIES);
    const { ciphertext, decryptor } = await elgamal(ctx, DHIES, Algorithms.SHA256, mode).encrypt(
      message, publicBytes
    );
    const plaintext = await elgamal(ctx, DHIES, Algorithms.SHA256, mode).decryptWithDecryptor(
      ciphertext, decryptor
    )
    expect(plaintext).toEqual(message);
  });
  it.each(cartesian([systems, modes]))(
    'decrypt with decryptor - failure - forged decryptor - over %s/%s', async (system, mode) => {
    const ctx = initBackend(system);
    const { secret, publicBytes } = await randomSecret(ctx);
    const message = await buildMessage(ctx, DHIES);
    const { ciphertext, decryptor } = await elgamal(ctx, DHIES, Algorithms.SHA256, mode).encrypt(
      message, publicBytes
    );
    const forgedDecryptor = await randomPublic(ctx);
    await expect(
      elgamal(ctx, DHIES, Algorithms.SHA256, mode).decryptWithDecryptor(ciphertext, forgedDecryptor)
    ).rejects.toThrow(
      'Could not decrypt: Invalid MAC'
    );
  });
  it.each(cartesian([systems, modes]))(
    'decrypt with randomness - success - over %s/%s', async (system, mode) => {
    const ctx = initBackend(system);
    const { secret, publicBytes } = await randomSecret(ctx);
    const message = await buildMessage(ctx, DHIES);
    const { ciphertext, randomness } = await elgamal(ctx, DHIES, Algorithms.SHA256, mode).encrypt(
      message, publicBytes
    );
    const plaintext = await elgamal(ctx, DHIES, Algorithms.SHA256, mode).decryptWithRandomness(
      ciphertext, publicBytes, randomness
    );
    expect(plaintext).toEqual(message);
  });
  it.each(cartesian([systems, modes]))(
    'decrypt with randomness - failure - forged randomness - over %s/%s', async (system, mode) => {
    const ctx = initBackend(system);
    const { secret, publicBytes } = await randomSecret(ctx);
    const message = await buildMessage(ctx, DHIES);
    const { ciphertext, randomness } = await elgamal(ctx, DHIES, Algorithms.SHA256, mode).encrypt(
      message, publicBytes
    );
    const forgedRandomness = leInt2Buff(await ctx.randomScalar());
    await expect(
      elgamal(ctx, DHIES, Algorithms.SHA256, mode).decryptWithRandomness(
        ciphertext, publicBytes, forgedRandomness
      )
    ).rejects.toThrow(
      'Could not decrypt: Invalid MAC'
    );
  });
});
