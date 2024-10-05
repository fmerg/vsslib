import { Group, Point } from 'vsslib/backend';
import { System, Algorithm } from 'vsslib/types';
import {
  initBackend,
  randomSecret,
  randomPublic,
  shareSecret,
  createSchnorrPacket,
} from 'vsslib';
import { IndexedNonce }  from 'vsslib/combiner';
import { randomNonce } from 'vsslib/crypto';
import { SecretShare, PublicShare } from 'vsslib/dealer';
import { SchnorrPacket } from 'vsslib/shareholder';
import { leInt2Buff } from 'vsslib/arith';
import { randomIndex } from './utils';


export const createRawSharing = async (system: System, nrShares: number, threshold: number) => {
  const ctx = initBackend(system);
  const { secret, publicBytes } = await randomSecret(ctx);
  const { sharing } = await shareSecret(ctx, nrShares, threshold, secret);
  const secretShares = await sharing.getSecretShares();
  const publicShares = await sharing.getPublicShares();
  return { ctx, secret, publicBytes, sharing, secretShares, publicShares };
}

export const mockPublicRecoverySetup = async <P extends Point>(opts: {
  ctx: Group<P>,
  shares: SecretShare[],
  algorithm?: Algorithm,
  withNonce?: boolean,
  nrInvalid?: number,
}) => {
  let { ctx, shares, algorithm, nrInvalid, withNonce } = opts;
  withNonce = withNonce || false;
  const packets = [];
  const nonces: IndexedNonce[] = [];
  for (const share of shares) {
    const nonce = withNonce ? await randomNonce() : undefined;
    const packet = await createSchnorrPacket(ctx, share, { algorithm, nonce });
    packets.push(packet);
    if (nonce) {
      nonces.push({ nonce, index: share.index });
    }
  }
  let blame: number[] = [];
  nrInvalid = nrInvalid || 0;
  while (blame.length < nrInvalid) {
    const index = randomIndex(1, shares.length);
    if (blame.includes(index)) continue;
    blame.push(index);
  }
  for (const index of blame) {
    if (withNonce) {
      nonces.filter((n: IndexedNonce) => n.index == index)[0].nonce = await randomNonce();
    } else {
      packets.filter((p: SchnorrPacket) => p.index == index)[0].value = await randomPublic(ctx);
    } 
  }
  return { packets, blame, nonces };
}
