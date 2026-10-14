/** Operations of the library, one module per scheme, each holding both
 * directions of the scheme (e.g., packet creation and parsing).
 *
 * Dependency rule: operations import from the core modules (backend, nizk,
 * lagrange, polynomials, indexes, ...), which never import from operations.
 * Among operations, feldman and pedersen may import from shamir and from
 * the internal commitments module; nothing else imports a sibling. */

export * from './secrets';
export * from './shamir';
export * from './feldman';
export * from './pedersen';
export * from './recovery';
