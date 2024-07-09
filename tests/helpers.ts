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
import { SecretShare, PublicShare, PublicPacket } from 'vsslib/dealer';
import { PartialKey, PartialPublic, PartialDecryptor } from 'vsslib/keys';
import { ElgamalSchemes } from 'vsslib/enums';
import { ElgamalScheme, System, Algorithm } from 'vsslib/types';
import { leInt2Buff } from 'vsslib/arith';
import { randomIndex } from './utils';

export const buildMessage = async <P extends Point>(ctx: Group<P>, scheme: ElgamalScheme) => {
  if (scheme == ElgamalSchemes.PLAIN) {
    return await ctx.randomPublic();
  } else {
    return Uint8Array.from(Buffer.from('destroy earth'));
  }
}

export const selectPartialKey = <P extends Point>(index: number, shares: PartialKey<P>[]) =>
  shares.filter(share => share.index == index)[0];

export const selectPartialPublic = <P extends Point>(index: number, shares: PartialPublic<P>[]) =>
  shares.filter(share => share.index == index)[0];


export const createRawSharing = async (system: System, nrShares: number, threshold: number) => {
  const ctx = initBackend(system);
  const { secret, publicBytes } = await generateSecret(ctx);
  const { sharing } = await distributeSecret(ctx, nrShares, threshold, secret);
  const secretShares = await sharing.getSecretShares();
  const publicShares = await sharing.getPublicShares();
  return { ctx, secret, publicBytes, sharing, secretShares, publicShares };
}


export const createKeySharingSetup = async (system: System, nrShares: number, threshold: number) => {
  const ctx = initBackend(system)
  const { privateKey, publicKey } = await generateKey(ctx);
  const sharing = await privateKey.generateSharing(nrShares, threshold);
  const polynomial = sharing.polynomial;
  const secretShares = await sharing.getSecretShares();
  const partialKeys = secretShares.map(({ value, index }: SecretShare) => {
    return new PartialKey(ctx, value, index);
  });
  const partialPublicKeys = []
  for (const key of partialKeys) {
    partialPublicKeys.push(await key.getPublicShare());
  }
  return {
    ctx,
    privateKey,
    publicKey,
    sharing,
    polynomial,
    partialKeys,
    partialPublicKeys,
  };
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
  for (const index of blame) {
    if (withNonce) {
      nonces.filter((n: IndexedNonce) => n.index == index)[0].nonce = await randomNonce();
    } else {
      packets.filter((p: PublicPacket) => p.index == index)[0].value = await ctx.randomPublic();
    } 
  }
  return { packets, blame, nonces };
}


export const mockThresholdDecryptionSetup = async (opts: {
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
    partialKeys,
    partialPublicKeys,
    ctx,
  } = await createKeySharingSetup(system, nrShares, threshold);
  const message = await buildMessage(ctx, scheme);
  const { ciphertext, decryptor } = await publicKey.encrypt(message, { scheme });
  const partialDecryptors = [];
  const nonces: IndexedNonce[] = [];
  for (const key of partialKeys) {
    const nonce = withNonce ? await randomNonce() : undefined;
    const share = await key.computePartialDecryptor(ciphertext, { nonce });
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
  for (const index of blame) {
    if (withNonce) {
      nonces.filter((n: IndexedNonce) => n.index == index)[0].nonce = await randomNonce();
    } else {
      partialDecryptors.filter((d: PartialDecryptor) => d.index == index)[0].value = await ctx.randomPublic();
    } 
  }
  return {
    ctx,
    privateKey,
    publicKey,
    partialKeys,
    partialPublicKeys,
    message,
    ciphertext,
    decryptor,
    partialDecryptors,
    blame,
    nonces,
  }
}
