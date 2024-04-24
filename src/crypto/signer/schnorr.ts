// TODO: Consider consulting https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
import { Algorithms, Algorithm} from '../../schemes';
import { Point, Group } from '../../backend/abstract';
import { DlogProtocol } from '../../crypto/sigma/dlog';
import { SigmaProof } from '../../crypto/sigma/base';
import { Signature, Signer } from './base';


export class SchnorrSignature<P extends Point> implements Signature<P> {
  commitment: P;
  response: bigint;

  constructor(commitment: P, response: bigint) {
    this.commitment = commitment;
    this.response = response;
  }
}

export class SchnorrSigner<P extends Point> extends Signer<P, SchnorrSignature<P>> {
  protocol: DlogProtocol<P>;

  constructor(ctx: Group<P>, algorithm: Algorithm) {
    super(ctx, algorithm);
    this.protocol = new DlogProtocol(ctx, algorithm);
  }

  signBytes = async (secret: bigint, message: Uint8Array, nonce?: Uint8Array): Promise<SchnorrSignature<P>> => {
    const { generator: g, operate } = this.ctx;
    const pub = await operate(secret, g);
    const { commitments, response } = await this.protocol.proveLinearDlog(
      [secret], { us: [[g]], vs: [pub] }, [message], nonce
    );
    return { commitment: commitments[0], response: response[0] };
  }

  verifyBytes = async (pub: P, message: Uint8Array, signature: SchnorrSignature<P>, nonce?: Uint8Array): Promise<boolean> => {
    const { generator: g } = this.ctx;
    const { commitment, response } = signature;
    const proof = {
      commitments: [commitment],
      response: [response],
      algorithm: this.algorithm,
    }
    return this.protocol.verifyLinearDlog({ us: [[g]], vs: [pub] }, proof, [message], nonce);
  }
}
