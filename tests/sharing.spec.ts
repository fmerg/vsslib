import { Point, Group } from '../src/backend/abstract'
import {
  generateKey,
  distributeKey,
  reconstructKey,
  reconstructPublic,
} from '../src/core';
import { PrivateKey, PublicKey } from '../src/keys';
import {
  PrivateShare,
  PublicShare,
  KeySharing,
  PartialDecryptor,
} from '../src/sharing';
import { ErrorMessages } from '../src/errors';
import { FieldPolynomial } from '../src/lagrange';
import { PlainCiphertext } from '../src/crypto/elgamal/plain';
import { ElgamalSchemes } from '../src/enums';
import { partialPermutations } from './helpers';
import { resolveTestConfig } from './environ';


export function selectShare<P extends Point>(index: number, shares: PublicShare<P>[]): PublicShare<P> {
  const selected = shares.filter(share => share.index == index)[0];
  if (!selected) throw new Error(`No share found for index ${index}`);
  return selected;
}

const { system, nrShares, threshold } = resolveTestConfig();


describe(`Key sharing over ${system}`, () => {
  let ctx: Group<Point>;
  let sharing: KeySharing<Point>;
  let polynomial: FieldPolynomial<Point>
  let privateKey: PrivateKey<Point>;
  let publicKey: PublicKey<Point>;
  let privateShares: PrivateShare<Point>[];
  let publicShares: PublicShare<Point>[];
  let ciphertext: PlainCiphertext<Point>;
  let partialDecryptors: PartialDecryptor<Point>[];

  beforeAll(async () => {
    const keypair = await generateKey(system);
    privateKey = keypair.privateKey;
    publicKey = keypair.publicKey;
    ctx = keypair.ctx;
    sharing = await distributeKey(ctx, nrShares, threshold, privateKey);
    polynomial = sharing.polynomial;
    privateShares = await sharing.getSecretShares();
    publicShares = await sharing.getPublicShares();
    const message = (await ctx.randomPoint()).toBytes();
    const encryptionOutput = await publicKey.encrypt(message, {
      scheme: ElgamalSchemes.PLAIN
    });
    ciphertext = encryptionOutput.ciphertext as PlainCiphertext<Point>;
    partialDecryptors = [];
    for (const privateShare of privateShares) {
      const share = await privateShare.generatePartialDecryptor(ciphertext);
      partialDecryptors.push(share);
    }
  });

  test('Setup parameters', async () => {
    expect(privateShares.length).toEqual(nrShares);
    expect(publicShares.length).toEqual(nrShares);
    expect(polynomial.degree).toEqual(threshold - 1);
    expect(polynomial.evaluate(0)).toEqual(privateKey.secret);
  });

  test('Feldmann scheme - success', async () => {
    const { commitments } = await sharing.proveFeldmann();
    privateShares.forEach(async (share: PrivateShare<Point>) => {
      const verified = await share.verifyFeldmann(commitments);
      expect(verified).toBe(true);
    });
  });

  test('Feldmann scheme - failure', async () => {
    const { commitments } = await sharing.proveFeldmann();
    const forgedCommitmnets = [...commitments.slice(0, commitments.length - 1), await ctx.randomPoint()];
    privateShares.forEach(async (share: PrivateShare<Point>) => {
      await expect(share.verifyFeldmann(forgedCommitmnets)).rejects.toThrow('Invalid share');
    });
  });

  test('Pedersen scheme - success', async () => {
    const hPub = await ctx.randomPoint();
    const { bindings, commitments } = await sharing.provePedersen(hPub);
    privateShares.forEach(async (share: PrivateShare<Point>) => {
      const binding = bindings[share.index];
      const verified = await share.verifyPedersen(binding, hPub, commitments);
      expect(verified).toBe(true);
    });
  });

  test('Pedersen scheme - failure', async () => {
    const hPub = await ctx.randomPoint();
    const { bindings, commitments } = await sharing.provePedersen(hPub);
    privateShares.forEach(async (share: PrivateShare<Point>) => {
      const forgedBinding = await ctx.randomScalar();
      await expect(share.verifyPedersen(forgedBinding, hPub, commitments)).rejects.toThrow('Invalid share');
    });
  });

  test('Private key reconstruction', async () => {
    partialPermutations(privateShares, 1).forEach(async (qualifiedShares) => {
      const reconstructed = await reconstructKey(ctx, qualifiedShares);
      expect(await reconstructed.equals(privateKey)).toBe(qualifiedShares.length >= threshold);
    });
  });

  test('Public key reconstruction', async () => {
    partialPermutations(publicShares, 1).forEach(async (qualifiedShares) => {
      const reconstructed = await reconstructPublic(ctx, qualifiedShares);
      expect(await reconstructed.equals(publicKey)).toBe(qualifiedShares.length >= threshold);
    });
  });

  test('Partial decryptor verification - success', async () => {
    for (const share of partialDecryptors) {
      const publicShare = selectShare(share.index, publicShares);
      const verified = await publicShare.verifyPartialDecryptor(ciphertext, share);
      expect(verified).toBe(true);
    }
  });

  test('Partial decryptor verification - failure', async () => {
    const forgedCiphertext = { alpha: ciphertext.alpha, beta: await ctx.randomPoint() };
    for (const share of partialDecryptors) {
      const publicShare = selectShare(share.index, publicShares);
      await expect(publicShare.verifyPartialDecryptor(forgedCiphertext, share)).rejects.toThrow(
        ErrorMessages.INVALID_PARTIAL_DECRYPTOR
      );
    }
  });
});
