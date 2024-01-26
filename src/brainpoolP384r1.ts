/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import { createCurve } from './_shortw_utils.js';
import { sha384 } from '@noble/hashes/sha512';
import { Field } from './abstract/modular.js';
import { mapToCurveSimpleSWU } from './abstract/weierstrass.js';
import { createHasher } from './abstract/hash-to-curve.js';

// brainpoolP384r1 (1.3.36.3.3.2.8.1.1.11)
// https://www.rfc-editor.org/rfc/rfc5639.html https://neuromancer.sk/std/brainpool/brainpoolP384r1

// Field over which we'll do calculations.
// prettier-ignore
const P = BigInt('0x8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53');
const Fp = Field(P);
// prettier-ignore
const CURVE_A = BigInt('0x7bc382c63d8c150c3c72080ace05afa0c2bea28e4fb22787139165efba91f90f8aa5814a503ad4eb04a8c7dd22ce2826');
// prettier-ignore
const CURVE_B = BigInt('0x4a8c7dd22ce28268b39b55416f0447c2fb77de107dcd2a62e880ea53eeb62d57cb4390295dbc9943ab78696fa504c11');

// prettier-ignore
export const brainpoolP384r1 = createCurve({
  a: CURVE_A, // Equation params: a, b
  b: CURVE_B,
  Fp, // Field: 
  // Curve order, total count of valid points in the field.
  n: BigInt('0x8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565'),
  // Base (generator) point (x, y)
  Gx: BigInt('0x1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1e'),
  Gy: BigInt('0x8abe1d7520f9c2a45cb1eb8e95cfd55262b70b29feec5864e19c054ff99129280e4646217791811142820341263c5315'),
  h: BigInt(1),
  lowS: false,
} as const, sha384);

const mapSWU = /* @__PURE__ */ (() =>
  mapToCurveSimpleSWU(Fp, {
    A: CURVE_A,
    B: CURVE_B,
    Z: Fp.create(BigInt('-5')),
  }))();

const htf = /* @__PURE__ */ (() =>
  createHasher(brainpoolP384r1.ProjectivePoint, (scalars: bigint[]) => mapSWU(scalars[0]), {
    DST: 'brainpoolP384r1_XMD:SHA-384_SSWU_RO_',
    encodeDST: 'brainpoolP384r1_XMD:SHA-384_SSWU_NU_',
    p: Fp.ORDER,
    m: 1,
    k: 192,
    expand: 'xmd',
    hash: sha384,
  }))();
export const hashToCurve = /* @__PURE__ */ (() => htf.hashToCurve)();
export const encodeToCurve = /* @__PURE__ */ (() => htf.encodeToCurve)();
