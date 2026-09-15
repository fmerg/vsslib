import { InvalidInput } from './errors';
import { intToLeBytes } from './arith';


/** Ensure that `index` is a positive safe integer; throws InvalidInput otherwise */
export function validateIndex(index: number): void {
  if (!(Number.isSafeInteger(index) && index > 0)) throw new InvalidInput(
    `Index must be a positive integer: ${index}`
  );
}


/** Ensure that `indexes` are distinct positive safe integers; throws InvalidInput otherwise */
export function validateIndexes(indexes: number[]): void {
  indexes.forEach(validateIndex);
  if (new Set(indexes).size !== indexes.length) throw new InvalidInput(
    `Indexes must be distinct: ${indexes}`
  );
}


/** Ensure that `threshold` is a positive safe integer; throws InvalidInput otherwise */
export function validateThreshold(threshold: number): void {
  if (!(Number.isSafeInteger(threshold) && threshold > 0)) throw new InvalidInput(
    `Threshold must be a positive integer: ${threshold}`
  );
}


/** Ensure that `threshold` is valid and that there are at least `threshold` shares;
 * throws InvalidInput otherwise */
export function validateShareCount(count: number, threshold: number): void {
  validateThreshold(threshold);
  if (count < threshold) throw new InvalidInput(
    `Insufficient number of shares: ${count} < ${threshold}`
  );
}


/** Fixed-length encoding of an index, used to bind it to NIZK proofs */
export function indexToBytes(index: number): Uint8Array {
  return intToLeBytes(BigInt(index), 8);
}
