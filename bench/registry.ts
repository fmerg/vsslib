import { Suite } from './types';
import secrets from './suites/secrets';
import shamir from './suites/shamir';
import feldman from './suites/feldman';
import pedersen from './suites/pedersen';
import recovery from './suites/recovery';
import protocols from './suites/protocols';


export const SUITES: Suite[] = [
  secrets,
  shamir,
  feldman,
  pedersen,
  recovery,
  protocols,
];

export const MODULES = SUITES.map(suite => suite.module);
