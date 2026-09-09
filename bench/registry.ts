import { Suite } from './types';
import secrets from './suites/secrets';


export const SUITES: Suite[] = [
  secrets,
];

export const MODULES = SUITES.map(suite => suite.module);
