import { Modular } from '../enums';
import { System } from '../types';
import { initModular } from './modular';
import { initElliptic } from './elliptic';

const sanitize  = (system: System | string) => system as System;
const isModular = (system: System | string) => Object.values(Modular).includes(sanitize(system));
const initBackend = (system: System | string) => isModular(system) ?
    initModular(sanitize(system)) :
    initElliptic(sanitize(system));

export { initBackend };
