import { Permutation, PowerSet } from "js-combinatorics";


/** Powerset of the provided collection **/
export const powerSet = (array: any[]): any[] => [...PowerSet.of(array)];


/** Permutations of the provided collection **/
export const permutations = (array: any[]): any[] => [...Permutation.of(array)];


/** Union of sets of permutations of each member of the powerset of
* the provided collection */
export const partialPermutations = (
  array: any[], minSize = 0, maxSize = array.length): any[] => {
  const out = powerSet(array).reduce(
    (acc: any[], comb: any[]) => acc = acc.concat(permutations(comb)), []
  );
  return out.filter(
    (perm: any[]) => perm.length >= minSize && perm.length <= maxSize
  );
}


/** Cartesian product of the provided arrays */
export const cartesian = (arrays: any[]): any[] => {
  const xs = arrays[0];
  const ys = arrays.length > 2 ? cartesian(arrays.slice(1)) :
    arrays[1].map((a: any[]) => [a]);
  let out = new Array(xs.length * ys.length);
  for (const [i, x] of xs.entries()) {
    for (const [j, y] of ys.entries()) {
      out[i * ys.length + j] = [x, ...y];
    }
  }
  return out;
}


/** Trim trailing zeroes from number array */
export const trimZeroes = (arr: number[]): number[] => {
  let len = arr.length;
  if (len > 0) while (arr[len - 1] == 0) len--;
  return arr.slice(0, len);
}


/** Remove item from and return array */
export const removeItem = (array: any[], item: any) => {
  const index = array.indexOf(item);
  if (index !== -1) array.splice(index, 1);
  return array;
}


/** Random index in range inclusive ends */
export const randomIndex = (min: number, max: number) => {
  min = Math.ceil(min);
  max = Math.floor(max);
  return Math.floor(Math.random() * (max - min + 1)) + min;
}


/** Checks equality of byte arrays */
export const isEqualBuffer = (a: Uint8Array, b: Uint8Array) => {
  if (a.length != b.length) return false;
  for (let i = 0; i < a.length; i++)
    if (a[i] != b[i]) return false;
  return true;
}


