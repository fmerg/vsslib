import { mock } from 'node:test';
import { Group, Point } from 'vsslib/backend';
import type { EcGroup, EcPoint } from 'vsslib/backend';
import { System, Algorithm } from 'vsslib/types';
import {
  initBackend,
  randomSecret,
  randomPublic,
  shareSecret,
  createSchnorrPacket,
} from 'vsslib';
import { Nonces }  from 'vsslib/operations/recovery';
import { randomNonce } from 'vsslib/random';
import { SecretShare, SchnorrPacket } from 'vsslib/types';
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
  const { ctx, shares, algorithm } = opts;
  let { nrInvalid, withNonce } = opts;
  withNonce = withNonce || false;
  const packets = [];
  const nonces: Nonces = {};
  for (const share of shares) {
    const nonce = withNonce ? await randomNonce() : undefined;
    const packet = await createSchnorrPacket(ctx, share, { algorithm, nonce });
    packets.push(packet);
    if (nonce) {
      nonces[share.index] = nonce;
    }
  }
  const blame: number[] = [];
  nrInvalid = nrInvalid || 0;
  while (blame.length < nrInvalid) {
    const index = randomIndex(1, shares.length);
    if (blame.includes(index)) continue;
    blame.push(index);
  }
  for (const index of blame) {
    if (withNonce) {
      nonces[index] = await randomNonce();
    } else {
      packets.filter((p: SchnorrPacket) => p.index == index)[0].value = await randomPublic(ctx);
    } 
  }
  return { packets, blame, nonces };
}


/** Group over the operations of an elliptic backend, with the defaults of
 * Group for everything else, as a custom backend inherits them, e.g. under
 * the name of a built-in system */
export const inheriting = (ctx: EcGroup): Group<EcPoint> => {
  class Inheriting extends Group<EcPoint> {
    randomScalar = ctx.randomScalar;
    randomPoint = ctx.randomPoint;
    validateScalar = ctx.validateScalar;
    validatePoint = ctx.validatePoint;
    exp = ctx.exp;
    operate = ctx.operate;
    invert = ctx.invert;
    bytesToPoint = ctx.bytesToPoint;
    hashToPoint = ctx.hashToPoint;
  }
  return new Inheriting(ctx.system, ctx.modulus, ctx.order, ctx.generator, ctx.neutral);
}


/** Make call `onCall` (counted from 0) of ctx.randomScalar return 0, e.g. to
 * make a polynomial coefficient vanish; restore with `.mock.restore()` */
export const zeroRandomScalarAt = <P extends Point>(ctx: Group<P>, onCall: number) => {
  const random = mock.method(ctx, 'randomScalar');
  random.mock.mockImplementationOnce(async () => 0n, onCall);
  return random;
}
