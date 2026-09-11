import { Suite } from './types';
import secrets from './suites/secrets';
import dealer from './suites/dealer';
import shareholder from './suites/shareholder';
import combiner from './suites/combiner';
import protocols from './suites/protocols';


export const SUITES: Suite[] = [
  secrets,
  dealer,
  shareholder,
  combiner,
  protocols,
];

export const MODULES = SUITES.map(suite => suite.module);
