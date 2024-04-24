import { Point } from '../../src/backend/abstract'
import { key, backend } from '../../src';
import {
  PrivateKey,
  PublicKey,
  PrivateShare,
  PublicShare,
  KeySharing,
} from '../../src/key';
import { Polynomial } from '../../src/lagrange';
import { Messages } from '../../src/key/enums';
import { PartialDecryptor } from '../../src/tds';
import { PlainCiphertext } from '../../src/core/elgamal/plain';
import { ElgamalSchemes } from '../../src/schemes';
import { partialPermutations } from '../helpers';
import { resolveBackend } from '../environ';


export function selectShare<P extends Point>(index: number, shares: PublicShare<P>[]): PublicShare<P> {
  const selected = shares.filter(share => share.index == index)[0];
  if (!selected) throw new Error(`No share found for index ${index}`);
  return selected;
}

const __label = resolveBackend();


describe(`Key sharing over ${__label}`, () => {
  const ctx = backend.initGroup(__label);
  const nrShares = 5;
  const threshold = 3;

  let sharing: KeySharing<Point>;
  let polynomial: Polynomial<Point>
  let privateKey: PrivateKey<Point>;
  let publicKey: PublicKey<Point>;
  let privateShares: PrivateShare<Point>[];
  let publicShares: PublicShare<Point>[];
  let ciphertext: PlainCiphertext<Point>;
  let partialDecryptors: PartialDecryptor<Point>[];

  beforeAll(async () => {
    const keypair = await key.generate(__label);
    privateKey = keypair.privateKey;
    publicKey = keypair.publicKey;
    sharing = await privateKey.distribute(nrShares, threshold);
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
    expect(polynomial.evaluate(0)).toEqual(privateKey.scalar);
  });

  test('Feldmann VSS scheme - success', async () => {
    const { commitments } = await sharing.proveFeldmann();
    privateShares.forEach(async (share: PrivateShare<Point>) => {
      const verified = await share.verifyFeldmann(commitments);
      expect(verified).toBe(true);
    });
  });

  test('Feldmann VSS scheme - failure', async () => {
    const { commitments } = await sharing.proveFeldmann();
    const forgedCommitmnets = [...commitments.slice(0, commitments.length - 1), await ctx.randomPoint()];
    privateShares.forEach(async (share: PrivateShare<Point>) => {
      await expect(share.verifyFeldmann(forgedCommitmnets)).rejects.toThrow('Invalid share');
    });
  });

  test('Pedersen VSS scheme - success', async () => {
    const hPub = await ctx.randomPoint();
    const { bindings, commitments } = await sharing.provePedersen(hPub);
    privateShares.forEach(async (share: PrivateShare<Point>) => {
      const binding = bindings[share.index];
      const verified = await share.verifyPedersen(binding, hPub, commitments);
      expect(verified).toBe(true);
    });
  });

  test('Pedersen VSS scheme - failure', async () => {
    const hPub = await ctx.randomPoint();
    const { bindings, commitments } = await sharing.provePedersen(hPub);
    privateShares.forEach(async (share: PrivateShare<Point>) => {
      const forgedBinding = await ctx.randomScalar();
      await expect(share.verifyPedersen(forgedBinding, hPub, commitments)).rejects.toThrow('Invalid share');
    });
  });

  test('Reconstruction errors', async () => {
    await expect(PrivateKey.fromShares([])).rejects.toThrow(Messages.AT_LEAST_ONE_SHARE_NEEDED);
    await expect(PublicKey.fromShares([])).rejects.toThrow(Messages.AT_LEAST_ONE_SHARE_NEEDED);
  })

  test('Private key reconstruction', async () => {
    partialPermutations(privateShares, 1).forEach(async (qualifiedSet) => {
      const reconstructed = await PrivateKey.fromShares(qualifiedSet);
      expect(await reconstructed.equals(privateKey)).toBe(qualifiedSet.length >= threshold);
    });
  });

  test('Public key reconstruction', async () => {
    partialPermutations(publicShares, 1).forEach(async (qualifiedSet) => {
      const reconstructed = await PublicKey.fromShares(qualifiedSet);
      expect(await reconstructed.equals(publicKey)).toBe(qualifiedSet.length >= threshold);
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
        Messages.INVALID_PARTIAL_DECRYPTOR
      );
    }
  });
});
