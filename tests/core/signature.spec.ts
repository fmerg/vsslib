import { Point } from '../../src/backend/abstract'
import { key, backend } from '../../src';
import { PrivateKey, PublicKey, PrivateShare, PublicShare } from '../../src/key';
import { PartialDecryptor } from '../../src/common';
import { KeyDistribution } from '../../src/key';
import { Combiner } from '../../src/core';
import { Label } from '../../src/types';
import { partialPermutations } from '../helpers';
import { shamir } from '../../src';
import { schnorr } from '../../src';
import { fiatShamir } from '../../src/sigma';
import { mod } from '../../src/utils';

const core = require('../../src/core');


const runSetup = async (opts: { label: Label, nrShares: number, threshold: number }) => {
  const { label, nrShares, threshold } = opts;
  const { privateKey, publicKey } = await key.generate(label);
  const distribution = await privateKey.distribute(nrShares, threshold);
  const privateShares = await distribution.getSecretShares();
  const publicShares = await distribution.getPublicShares();
  const message = Uint8Array.from(Buffer.from('destroy earth'));
  const combiner = core.initCombiner({ label, threshold });
  return {
    privateKey,
    publicKey,
    privateShares,
    publicShares,
    message,
  }
}


function selectShare(index: number, shares: any[]): any {
  const selected = shares.filter(share => share.index == index)[0];
  if (!selected) throw new Error(`No share with index ${index}`);
  return selected;
}


describe('One-round schnorr threshold signature verification', () => {
  const nrShares = 5;
  const threshold = 3;
  const label = 'ed25519' as Label;
  let setup: any;

  beforeAll(async () => {
    setup = await runSetup({ label, nrShares, threshold });
  });

  test('Success', async () => {

    const { privateKey, publicKey, privateShares, publicShares, message } = setup;
    const partialSignatures: any[] = [];
    for (const privateShare of privateShares) {
      partialSignatures.push({
        value: await privateShare.sign(message),
        index: privateShare.index,
      })
    }


    const ctx = privateKey.ctx;
    const { generator: g, neutral, order, operate, combine } = ctx;
    console.log(partialSignatures[0]);
    partialPermutations(partialSignatures).forEach(async (qualifiedSet) => {

      const challengeShares = [];
      for (const { value: { commitments, algorithm }, index } of qualifiedSet) {
        const commitment = commitments[0];
        const { point: pub } = selectShare(index, publicShares);
        const challengeValue = await fiatShamir(ctx).computeChallenge(
          [
            g,
            pub,
            commitment,
          ],
          [],
          [message],
          undefined,
          algorithm,
        );
        challengeShares.push({
          value: challengeValue,
          index,
        });
      }

      let globalChallenge = BigInt(1);
      for (const { value: ci } of challengeShares) {
        globalChallenge = mod(globalChallenge * ci, order);
      }

      let s = BigInt(0);
      let rhs = await operate(globalChallenge, publicKey.point);
      const indexes = qualifiedSet.map((share: any) => share.index);
      for (const { value: { commitments, response }, index: i } of qualifiedSet) {
        // ---------------- lambda reduced
        let localChallenge = BigInt(1);
        for (const { index: k, value: ck } of challengeShares) {
          if (k !== i) localChallenge *= ck;
        }
        const li = mod(shamir.computeLambda(i, indexes, order) * localChallenge, order);
        // ----------------
        const si = response[0];
        s = mod(s + si * li, order);
        const ui = commitments[0];
        rhs = await combine(await operate(li, ui), rhs);
        // ------------------------------------------
        const ci = selectShare(i, challengeShares).value;
        const yi = selectShare(i, publicShares).point;
        expect(
          await (await operate(si, g)).equals(await combine(ui, await operate(ci, yi)))
        ).toBe(true);
        // ------------------------------------------
      }
      const lhs = await operate(s, g);
      expect(await lhs.equals(rhs)).toBe(qualifiedSet.length >= threshold);
    });
  });
});
