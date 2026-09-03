import { System } from '../types';
import { mod, leBytesToInt, intToLeBytes } from '../arith';
import { BadScalarError, BadPointError, InvalidInput } from '../errors';

export interface Point {
  toBytes: () => Uint8Array;
  equals: (other: Point) => Promise<boolean>;
}

export abstract class Group<P extends Point> {
  system: System;
  modulus: bigint;
  order: bigint;
  generator: P;
  neutral: P;
  scalarBytes: number;

  constructor(system: System, modulus: bigint, order: bigint, generator: P, neutral: P) {
    this.system = system;
    this.modulus = modulus;
    this.order = order;
    this.generator = generator;;
    this.neutral = neutral;
    this.scalarBytes = Math.ceil(order.toString(2).length / 8);
  }

  /** Fixed-length little-endian encoding of a scalar reduced modulo the group order */
  scalarToBytes = (scalar: bigint): Uint8Array => intToLeBytes(mod(scalar, this.order), this.scalarBytes);

  generateSecret = async (): Promise<Uint8Array> => this.scalarToBytes(await this.randomScalar());

  /** Decode and validate a scalar, rejecting non-canonical encodings; throws
   * InvalidInput on invalid bytes */
  parseScalar = async (bytes: Uint8Array): Promise<bigint> => {
    if (bytes.length !== this.scalarBytes) throw new InvalidInput(
      `Invalid scalar provided: expected ${this.scalarBytes} bytes, got ${bytes.length}`
    );
    const scalar = leBytesToInt(bytes);
    try {
      await this.validateScalar(scalar);
    } catch (err: unknown) {
      if (err instanceof BadScalarError) throw new InvalidInput(
        'Invalid scalar provided: ' + err.message
      );
      throw err;
    }
    return scalar;
  }

  /** Decode and validate a group element; throws InvalidInput on invalid bytes */
  parsePoint = async (bytes: Uint8Array): Promise<P> => {
    let point;
    try {
      point = this.bytesToPoint(bytes);
      await this.validatePoint(point);
    } catch (err: unknown) {
      if (err instanceof BadPointError) throw new InvalidInput(
        'Invalid point provided: ' + err.message
      );
      throw err;
    }
    return point;
  }

  abstract randomScalar: () => Promise<bigint>;
  abstract randomPoint: () => Promise<P>;
  abstract validateScalar: (scalar: bigint) => Promise<boolean>;
  abstract validatePoint: (point: P) => Promise<boolean>;
  abstract exp: (point: P, scalar: bigint) => Promise<P>;
  abstract operate: (lhs: P, rhs: P) => Promise<P>;
  abstract invert: (point: P) => Promise<P>;
  abstract bytesToPoint: (bytes: Uint8Array) => P;
  /** Hash to a point of the prime-order subgroup whose discrete log is unknown */
  abstract hashToPoint: (msg: Uint8Array, dst: Uint8Array) => Promise<P>;
}

