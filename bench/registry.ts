import { Suite } from './types';
import secrets from './suites/secrets';
import dealer from './suites/dealer';
import shareholder from './suites/shareholder';
import combiner from './suites/combiner';


export const SUITES: Suite[] = [
  secrets,
  dealer,
  shareholder,
  combiner,
];

export const MODULES = SUITES.map(suite => suite.module);
