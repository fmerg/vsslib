import { ElgamalSchemes } from 'vsslib/enums';
import { initBackend, generateKey } from 'vsslib';
import { cartesian } from '../utils';
import { buildMessage } from '../helpers';
import { resolveTestConfig } from '../environ';

const { systems, elgamalSchemes: schemes, modes, algorithms } = resolveTestConfig();


describe('Elgamal encryption', () => {
  it.each(cartesian([systems, schemes, modes, algorithms]))('over %s/%s/%s/%s', async (
    system, scheme, mode, algorithm
  ) => {
    const ctx = initBackend(system);
    const { privateKey, publicKey } = await generateKey(ctx);
    const message = await buildMessage(ctx, scheme);
    const opts = { scheme, mode, algorithm };
    const { ciphertext } = await publicKey.encrypt(message, opts);
    const plaintext = await privateKey.decrypt(ciphertext, opts);
    expect(plaintext).toEqual(message);
  });
});


describe('Elgamal plain encryption - invalid point encoding', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initBackend(system);
    const { privateKey, publicKey } = await generateKey(ctx);
    const message = new Uint8Array([0, 1, 666, 999]);
    expect(publicKey.encrypt(message, { scheme: ElgamalSchemes.PLAIN })).rejects.toThrow(
      'bad encoding:'
    );
  });
});
