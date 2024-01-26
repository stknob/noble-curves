/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import { createCurve } from './_shortw_utils.js';
import { sha256 } from '@noble/hashes/sha256';
import { Field } from './abstract/modular.js';
import { mapToCurveSimpleSWU } from './abstract/weierstrass.js';
import { createHasher } from './abstract/hash-to-curve.js';

// brainpoolP256r1 (1.3.36.3.3.2.8.1.1.7)
// https://www.rfc-editor.org/rfc/rfc5639.html https://neuromancer.sk/std/brainpool/brainpoolP256r1

const Fp = Field(BigInt('0xa9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377'));
const CURVE_A = BigInt('0x7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9');
const CURVE_B = BigInt('0x26dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b6');

// prettier-ignore
export const brainpoolP256r1 = createCurve({
  a: CURVE_A, // Equation params: a, b
  b: CURVE_B,
  Fp, // Field: 
  // Curve order, total count of valid points in the field
  n: BigInt('0xa9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7'),
  // Base (generator) point (x, y)
  Gx: BigInt('0x8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262'),
  Gy: BigInt('0x547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997'),
  h: BigInt(1),
  lowS: false,
} as const, sha256);

const mapSWU = /* @__PURE__ */ (() =>
  mapToCurveSimpleSWU(Fp, {
    A: CURVE_A,
    B: CURVE_B,
    Z: Fp.create(BigInt('-2')),
  }))();

const htf = /* @__PURE__ */ (() =>
  createHasher(brainpoolP256r1.ProjectivePoint, (scalars: bigint[]) => mapSWU(scalars[0]), {
    DST: 'brainpoolP256r1_XMD:SHA-256_SSWU_RO_',
    encodeDST: 'brainpoolP256r1_XMD:SHA-256_SSWU_NU_',
    p: Fp.ORDER,
    m: 1,
    k: 128,
    expand: 'xmd',
    hash: sha256,
  }))();
export const hashToCurve = /* @__PURE__ */ (() => htf.hashToCurve)();
export const encodeToCurve = /* @__PURE__ */ (() => htf.encodeToCurve)();
