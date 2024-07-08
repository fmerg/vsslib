import { Group, Point } from 'vsslib/backend';
import {
  initBackend,
  generateSecret,
  distributeSecret,
  generateKey,
  createPublicPacket,
} from 'vsslib';
import { IndexedNonce }  from 'vsslib/combiner';
import { randomNonce } from 'vsslib/crypto';
import { SecretShare, PublicShare } from 'vsslib/dealer';
import { PartialKey, PartialPublic } from 'vsslib/keys';
import { ElgamalSchemes } from 'vsslib/enums';
import { ElgamalScheme, System, Algorithm } from 'vsslib/types';
import { leInt2Buff } from 'vsslib/arith';
import { randomIndex } from './utils';

export const buildMessage = async <P extends Point>(ctx: Group<P>, scheme: ElgamalScheme) =>
  scheme == ElgamalSchemes.PLAIN ?
    await ctx.randomPublic() :
    Uint8Array.from(Buffer.from('destroy earth'));

export const selectPartialKey = <P extends Point>(index: number, shares: PartialKey<P>[]) =>
  shares.filter(share => share.index == index)[0];

export const selectPartialPublic = <P extends Point>(index: number, shares: PartialPublic<P>[]) =>
  shares.filter(share => share.index == index)[0];


export const createSharingSetup = async (opts: {
  system: System,
  nrShares: number,
  threshold: number,
}) => {
  const { system, nrShares, threshold } = opts;
  const ctx = initBackend(system);
  const { secret, publicBytes } = await generateSecret(ctx);
  const { sharing } = await distributeSecret(ctx, nrShares, threshold, secret);
  const secretShares = await sharing.getSecretShares();
  const publicShares = await sharing.getPublicShares();
  return { ctx, secret, publicBytes, sharing, secretShares, publicShares };
}


// TODO: createPublicRecoverySetup
export const createPublicPackets = async <P extends Point>(opts: {
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
    const packet = await createPublicPacket(ctx, share, { algorithm, nonce });
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
  const invalidPackets = [];
  if (blame) {
    for (const packet of packets) {
      if(!blame.includes(packet.index)) {
        invalidPackets.push(packet);
      } else {
        if (withNonce) {
          invalidPackets.push(packet);
          nonces.filter(
            (n: IndexedNonce) => n.index == packet.index
          )[0].nonce = await randomNonce();
        } else {
          invalidPackets.push({
            value: await ctx.randomPublic(),
            index: packet.index,
            proof: packet.proof,
          });
        }
      }
    }
  }
  return { packets, invalidPackets, blame, nonces };
}


export const createKeySharingSetup = async (opts: {
  system: System,
  nrShares: number,
  threshold: number,
}) => {
  const { system, nrShares, threshold } = opts;
  const ctx = initBackend(system)
  const { privateKey, publicKey } = await generateKey(ctx);
  const sharing = await privateKey.generateSharing(nrShares, threshold);
  const polynomial = sharing.polynomial;
  const secretShares = await sharing.getSecretShares();
  const privateShares = secretShares.map(({ value, index }: SecretShare) => {
    return new PartialKey(ctx, value, index);
  });
  const publicShares = []
  for (const share of privateShares) {
    publicShares.push(await share.getPublicShare());
  }
  return {
    ctx,
    privateKey,
    publicKey,
    sharing,
    polynomial,
    privateShares,
    publicShares,
  };
}


export const createThresholdDecryptionSetup = async (opts: {
  system: System,
  scheme: ElgamalScheme,
  nrShares: number,
  threshold: number,
  withNonce?: boolean,
  nrInvalid?: number,
}) => {
  let { scheme, system, nrShares, threshold, withNonce, nrInvalid } = opts;
  withNonce = withNonce || false;
  const {
    privateKey,
    publicKey,
    privateShares,
    publicShares,
    ctx,
  } = await createKeySharingSetup({ system, nrShares, threshold, });
  const message = await buildMessage(ctx, scheme);
  const { ciphertext, decryptor } = await publicKey.encrypt(message, { scheme });
  const partialDecryptors = [];
  const nonces: IndexedNonce[] = [];
  for (const privateShare of privateShares) {
    const nonce = withNonce ? await randomNonce() : undefined;
    const share = await privateShare.computePartialDecryptor(ciphertext, { nonce });
    partialDecryptors.push(share);
    if (nonce) {
      nonces.push({ nonce, index: share.index });
    }
  }
  let blame: number[] = [];
  nrInvalid = nrInvalid || 0;
  while (blame.length < nrInvalid) {
    const index = randomIndex(1, nrShares);
    if (blame.includes(index)) continue;
    blame.push(index);
  }
  const invalidDecryptors = [];
  if (blame) {
    for (const share of partialDecryptors) {
      if(!blame.includes(share.index)) {
        invalidDecryptors.push(share);
      } else {
        if (withNonce) {
          invalidDecryptors.push(share);
          nonces.filter(
            (n: IndexedNonce) => n.index == share.index
          )[0].nonce = await randomNonce();
        } else {
          invalidDecryptors.push({
            value: await ctx.randomPublic(),
            index: share.index,
            proof: share.proof,
          });
        }
      }
    }
  }
  return {
    ctx,
    privateKey,
    publicKey,
    privateShares,
    publicShares,
    message,
    ciphertext,
    decryptor,
    partialDecryptors,
    invalidDecryptors,
    blame,
    nonces,
  }
}
