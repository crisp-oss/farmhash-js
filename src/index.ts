/**
 * farmhashjs - Pure JavaScript implementation of Google's FarmHash
 *
 * Copyright (c) 2025 Crisp IM SAS
 * Licensed under the Apache-2.0 License
 *
 * This module provides both legacy-compatible and modern stable hash functions:
 *
 * Legacy (v3.x compatible):
 *   - legacyHash64(): Compatible with farmhash v3.3.1 hash64()
 *   - legacyHash32(): Compatible with farmhash v3.3.1 hash32()
 *
 * Modern (stable fingerprints):
 *   - fingerprint64(): Stable 64-bit hash (same as farmhash fingerprint64)
 *   - fingerprint32(): Stable 32-bit hash (same as farmhash fingerprint32)
 *
 * The difference is that legacy functions apply a "DebugTweak" transformation
 * that was present in farmhash v3.x (compiled with FARMHASH_DEBUG=1).
 * Modern fingerprint functions are guaranteed stable across all platforms.
 */

/**************************************************************************
 * 64-BIT CONSTANTS
 ***************************************************************************/

const k0 = 0xc3a5c85c97cb3127n;
const k1 = 0xb492b66fbe98f273n;
const k2 = 0x9ae16a3b2f90404fn;

/**************************************************************************
 * 32-BIT CONSTANTS
 ***************************************************************************/

const c1_32 = 0xcc9e2d51;
const c2_32 = 0x1b873593;

/**************************************************************************
 * 64-BIT HELPER FUNCTIONS
 ***************************************************************************/

function fetch64(buf: Buffer, offset: number): bigint {
  return buf.readBigUInt64LE(offset);
}

function fetch32(buf: Buffer, offset: number): bigint {
  return BigInt(buf.readUInt32LE(offset));
}

function fetch32AsNumber(buf: Buffer, offset: number): number {
  return buf.readUInt32LE(offset);
}

function rotate64(val: bigint, shift: number): bigint {
  shift = shift & 63;
  return ((val >> BigInt(shift)) | (val << BigInt(64 - shift))) & 0xFFFFFFFFFFFFFFFFn;
}

function rotate32(val: number, shift: number): number {
  shift = shift & 31;
  return ((val >>> shift) | (val << (32 - shift))) >>> 0;
}

function bswap64(x: bigint): bigint {
  const b0 = (x >> 0n) & 0xFFn;
  const b1 = (x >> 8n) & 0xFFn;
  const b2 = (x >> 16n) & 0xFFn;
  const b3 = (x >> 24n) & 0xFFn;
  const b4 = (x >> 32n) & 0xFFn;
  const b5 = (x >> 40n) & 0xFFn;
  const b6 = (x >> 48n) & 0xFFn;
  const b7 = (x >> 56n) & 0xFFn;
  return (b0 << 56n) | (b1 << 48n) | (b2 << 40n) | (b3 << 32n) |
         (b4 << 24n) | (b5 << 16n) | (b6 << 8n) | b7;
}

function bswap32(x: number): number {
  return (((x & 0xFF) << 24) |
          ((x & 0xFF00) << 8) |
          ((x >> 8) & 0xFF00) |
          ((x >> 24) & 0xFF)) >>> 0;
}

function shiftMix(val: bigint): bigint {
  return (val ^ (val >> 47n)) & 0xFFFFFFFFFFFFFFFFn;
}

function hashLen16Mul(u: bigint, v: bigint, mul: bigint): bigint {
  let a = ((u ^ v) * mul) & 0xFFFFFFFFFFFFFFFFn;
  a = (a ^ (a >> 47n)) & 0xFFFFFFFFFFFFFFFFn;
  let b = ((v ^ a) * mul) & 0xFFFFFFFFFFFFFFFFn;
  b = (b ^ (b >> 47n)) & 0xFFFFFFFFFFFFFFFFn;
  b = (b * mul) & 0xFFFFFFFFFFFFFFFFn;
  return b;
}

/**************************************************************************
 * 32-BIT HELPER FUNCTIONS
 ***************************************************************************/

function fmix(h: number): number {
  h = (h ^ (h >>> 16)) >>> 0;
  h = Math.imul(h, 0x85ebca6b) >>> 0;
  h = (h ^ (h >>> 13)) >>> 0;
  h = Math.imul(h, 0xc2b2ae35) >>> 0;
  h = (h ^ (h >>> 16)) >>> 0;
  return h;
}

function mur(a: number, h: number): number {
  a = Math.imul(a, c1_32) >>> 0;
  a = rotate32(a, 17);
  a = Math.imul(a, c2_32) >>> 0;
  h = (h ^ a) >>> 0;
  h = rotate32(h, 19);
  return (Math.imul(h, 5) + 0xe6546b64) >>> 0;
}

/**************************************************************************
 * 64-BIT HASH LENGTH FUNCTIONS
 ***************************************************************************/

function hashLen0to16(buf: Buffer, len: number): bigint {
  if (len >= 8) {
    const mul = k2 + BigInt(len) * 2n;
    const a = (fetch64(buf, 0) + k2) & 0xFFFFFFFFFFFFFFFFn;
    const b = fetch64(buf, len - 8);
    const c = (rotate64(b, 37) * mul + a) & 0xFFFFFFFFFFFFFFFFn;
    const d = ((rotate64(a, 25) + b) * mul) & 0xFFFFFFFFFFFFFFFFn;
    return hashLen16Mul(c, d, mul);
  }
  if (len >= 4) {
    const mul = k2 + BigInt(len) * 2n;
    const a = fetch32(buf, 0);
    return hashLen16Mul(BigInt(len) + (a << 3n), fetch32(buf, len - 4), mul);
  }
  if (len > 0) {
    const a = buf[0];
    const b = buf[len >> 1];
    const c = buf[len - 1];
    const y = BigInt(a) + (BigInt(b) << 8n);
    const z = BigInt(len) + (BigInt(c) << 2n);
    return (shiftMix(((y * k2) ^ (z * k0)) & 0xFFFFFFFFFFFFFFFFn) * k2) & 0xFFFFFFFFFFFFFFFFn;
  }
  return k2;
}

function hashLen17to32(buf: Buffer, len: number): bigint {
  const mul = k2 + BigInt(len) * 2n;
  const a = (fetch64(buf, 0) * k1) & 0xFFFFFFFFFFFFFFFFn;
  const b = fetch64(buf, 8);
  const c = (fetch64(buf, len - 8) * mul) & 0xFFFFFFFFFFFFFFFFn;
  const d = (fetch64(buf, len - 16) * k2) & 0xFFFFFFFFFFFFFFFFn;
  return hashLen16Mul(
    (rotate64((a + b) & 0xFFFFFFFFFFFFFFFFn, 43) + rotate64(c, 30) + d) & 0xFFFFFFFFFFFFFFFFn,
    (a + rotate64((b + k2) & 0xFFFFFFFFFFFFFFFFn, 18) + c) & 0xFFFFFFFFFFFFFFFFn,
    mul
  );
}

function xoH32(buf: Buffer, offset: number, mul: bigint, seed0: bigint = 0n, seed1: bigint = 0n): bigint {
  const a = (fetch64(buf, offset) * k1) & 0xFFFFFFFFFFFFFFFFn;
  const b = fetch64(buf, offset + 8);
  const c = (fetch64(buf, offset + 24) * mul) & 0xFFFFFFFFFFFFFFFFn;
  const d = (fetch64(buf, offset + 16) * k2) & 0xFFFFFFFFFFFFFFFFn;
  const u = (rotate64((a + b) & 0xFFFFFFFFFFFFFFFFn, 43) + rotate64(c, 30) + d + seed0) & 0xFFFFFFFFFFFFFFFFn;
  const v = (a + rotate64((b + k2) & 0xFFFFFFFFFFFFFFFFn, 18) + c + seed1) & 0xFFFFFFFFFFFFFFFFn;
  const a2 = shiftMix(((u ^ v) * mul) & 0xFFFFFFFFFFFFFFFFn);
  const b2 = shiftMix(((v ^ a2) * mul) & 0xFFFFFFFFFFFFFFFFn);
  return b2;
}

function hashLen33to64(buf: Buffer, len: number): bigint {
  const mul0 = k2 - 30n;
  const mul1 = k2 - 30n + 2n * BigInt(len);
  const h0 = xoH32(buf, 0, mul0);
  const h1 = xoH32(buf, len - 32, mul1);
  return ((((h1 * mul1) & 0xFFFFFFFFFFFFFFFFn) + h0) * mul1) & 0xFFFFFFFFFFFFFFFFn;
}

function hashLen65to96(buf: Buffer, len: number): bigint {
  const mul0 = k2 - 114n;
  const mul1 = k2 - 114n + 2n * BigInt(len);
  const h0 = xoH32(buf, 0, mul0);
  const h1 = xoH32(buf, 32, mul1);
  const h2 = xoH32(buf, len - 32, mul1, h0, h1);
  return (((h2 * 9n) + (h0 >> 17n) + (h1 >> 21n)) * mul1) & 0xFFFFFFFFFFFFFFFFn;
}

function weakHashLen32WithSeeds(buf: Buffer, offset: number, a: bigint, b: bigint): [bigint, bigint] {
  const w = fetch64(buf, offset);
  const x = fetch64(buf, offset + 8);
  const y = fetch64(buf, offset + 16);
  const z = fetch64(buf, offset + 24);
  a = (a + w) & 0xFFFFFFFFFFFFFFFFn;
  b = rotate64((b + a + z) & 0xFFFFFFFFFFFFFFFFn, 21);
  const c = a;
  a = (a + x) & 0xFFFFFFFFFFFFFFFFn;
  a = (a + y) & 0xFFFFFFFFFFFFFFFFn;
  b = (b + rotate64(a, 44)) & 0xFFFFFFFFFFFFFFFFn;
  return [(a + z) & 0xFFFFFFFFFFFFFFFFn, (b + c) & 0xFFFFFFFFFFFFFFFFn];
}

/**************************************************************************
 * FARMHASH NA (64+ bytes, used by fingerprint64)
 ***************************************************************************/

function naHash64(buf: Buffer, len: number): bigint {
  const seed = 81n;

  let x = seed;
  let y = (seed * k1 + 113n) & 0xFFFFFFFFFFFFFFFFn;
  let z = (shiftMix((y * k2 + 113n) & 0xFFFFFFFFFFFFFFFFn) * k2) & 0xFFFFFFFFFFFFFFFFn;
  let v: [bigint, bigint] = [0n, 0n];
  let w: [bigint, bigint] = [0n, 0n];
  x = (x * k2 + fetch64(buf, 0)) & 0xFFFFFFFFFFFFFFFFn;

  const endIdx = Math.floor((len - 1) / 64) * 64;
  const last64 = endIdx + ((len - 1) & 63) - 63;

  let idx = 0;
  do {
    x = (rotate64((x + y + v[0] + fetch64(buf, idx + 8)) & 0xFFFFFFFFFFFFFFFFn, 37) * k1) & 0xFFFFFFFFFFFFFFFFn;
    y = (rotate64((y + v[1] + fetch64(buf, idx + 48)) & 0xFFFFFFFFFFFFFFFFn, 42) * k1) & 0xFFFFFFFFFFFFFFFFn;
    x = (x ^ w[1]) & 0xFFFFFFFFFFFFFFFFn;
    y = (y + v[0] + fetch64(buf, idx + 40)) & 0xFFFFFFFFFFFFFFFFn;
    z = (rotate64((z + w[0]) & 0xFFFFFFFFFFFFFFFFn, 33) * k1) & 0xFFFFFFFFFFFFFFFFn;
    v = weakHashLen32WithSeeds(buf, idx, (v[1] * k1) & 0xFFFFFFFFFFFFFFFFn, (x + w[0]) & 0xFFFFFFFFFFFFFFFFn);
    w = weakHashLen32WithSeeds(buf, idx + 32, (z + w[1]) & 0xFFFFFFFFFFFFFFFFn, (y + fetch64(buf, idx + 16)) & 0xFFFFFFFFFFFFFFFFn);
    [z, x] = [x, z];
    idx += 64;
  } while (idx !== endIdx);

  const mul = k1 + ((z & 0xFFn) << 1n);
  idx = last64;
  w[0] = (w[0] + (BigInt(len - 1) & 63n)) & 0xFFFFFFFFFFFFFFFFn;
  v[0] = (v[0] + w[0]) & 0xFFFFFFFFFFFFFFFFn;
  w[0] = (w[0] + v[0]) & 0xFFFFFFFFFFFFFFFFn;

  x = (rotate64((x + y + v[0] + fetch64(buf, idx + 8)) & 0xFFFFFFFFFFFFFFFFn, 37) * mul) & 0xFFFFFFFFFFFFFFFFn;
  y = (rotate64((y + v[1] + fetch64(buf, idx + 48)) & 0xFFFFFFFFFFFFFFFFn, 42) * mul) & 0xFFFFFFFFFFFFFFFFn;
  x = (x ^ (w[1] * 9n)) & 0xFFFFFFFFFFFFFFFFn;
  y = (y + (v[0] * 9n) + fetch64(buf, idx + 40)) & 0xFFFFFFFFFFFFFFFFn;
  z = (rotate64((z + w[0]) & 0xFFFFFFFFFFFFFFFFn, 33) * mul) & 0xFFFFFFFFFFFFFFFFn;
  v = weakHashLen32WithSeeds(buf, idx, (v[1] * mul) & 0xFFFFFFFFFFFFFFFFn, (x + w[0]) & 0xFFFFFFFFFFFFFFFFn);
  w = weakHashLen32WithSeeds(buf, idx + 32, (z + w[1]) & 0xFFFFFFFFFFFFFFFFn, (y + fetch64(buf, idx + 16)) & 0xFFFFFFFFFFFFFFFFn);
  [z, x] = [x, z];

  return hashLen16Mul(
    (hashLen16Mul(v[0], w[0], mul) + (shiftMix(y) * k0) + z) & 0xFFFFFFFFFFFFFFFFn,
    (hashLen16Mul(v[1], w[1], mul) + x) & 0xFFFFFFFFFFFFFFFFn,
    mul
  );
}

/**************************************************************************
 * FARMHASH UO (>256 bytes, used by legacy hash64)
 ***************************************************************************/

function uoH(x: bigint, y: bigint, mul: bigint, r: number): bigint {
  let a = ((x ^ y) * mul) & 0xFFFFFFFFFFFFFFFFn;
  a = (a ^ (a >> 47n)) & 0xFFFFFFFFFFFFFFFFn;
  const b = ((y ^ a) * mul) & 0xFFFFFFFFFFFFFFFFn;
  return (rotate64(b, r) * mul) & 0xFFFFFFFFFFFFFFFFn;
}

function uoHash64WithSeeds(buf: Buffer, len: number, seed0: bigint, seed1: bigint): bigint {
  let x = seed0;
  let y = (seed1 * k2 + 113n) & 0xFFFFFFFFFFFFFFFFn;
  let z = (shiftMix((y * k2) & 0xFFFFFFFFFFFFFFFFn) * k2) & 0xFFFFFFFFFFFFFFFFn;
  let v: [bigint, bigint] = [seed0, seed1];
  let w: [bigint, bigint] = [0n, 0n];
  let u = (x - z) & 0xFFFFFFFFFFFFFFFFn;
  x = (x * k2) & 0xFFFFFFFFFFFFFFFFn;
  const mul = (k2 + (u & 0x82n)) & 0xFFFFFFFFFFFFFFFFn;

  const endIdx = Math.floor((len - 1) / 64) * 64;
  const last64 = endIdx + ((len - 1) & 63) - 63;

  let idx = 0;
  do {
    const a0 = fetch64(buf, idx);
    const a1 = fetch64(buf, idx + 8);
    const a2 = fetch64(buf, idx + 16);
    const a3 = fetch64(buf, idx + 24);
    const a4 = fetch64(buf, idx + 32);
    const a5 = fetch64(buf, idx + 40);
    const a6 = fetch64(buf, idx + 48);
    const a7 = fetch64(buf, idx + 56);

    x = (x + a0 + a1) & 0xFFFFFFFFFFFFFFFFn;
    y = (y + a2) & 0xFFFFFFFFFFFFFFFFn;
    z = (z + a3) & 0xFFFFFFFFFFFFFFFFn;
    v[0] = (v[0] + a4) & 0xFFFFFFFFFFFFFFFFn;
    v[1] = (v[1] + a5 + a1) & 0xFFFFFFFFFFFFFFFFn;
    w[0] = (w[0] + a6) & 0xFFFFFFFFFFFFFFFFn;
    w[1] = (w[1] + a7) & 0xFFFFFFFFFFFFFFFFn;

    x = rotate64(x, 26);
    x = (x * 9n) & 0xFFFFFFFFFFFFFFFFn;
    y = rotate64(y, 29);
    z = (z * mul) & 0xFFFFFFFFFFFFFFFFn;
    v[0] = rotate64(v[0], 33);
    v[1] = rotate64(v[1], 30);
    w[0] = (w[0] ^ x) & 0xFFFFFFFFFFFFFFFFn;
    w[0] = (w[0] * 9n) & 0xFFFFFFFFFFFFFFFFn;
    z = rotate64(z, 32);
    z = (z + w[1]) & 0xFFFFFFFFFFFFFFFFn;
    w[1] = (w[1] + z) & 0xFFFFFFFFFFFFFFFFn;
    z = (z * 9n) & 0xFFFFFFFFFFFFFFFFn;
    [u, y] = [y, u];

    z = (z + a0 + a6) & 0xFFFFFFFFFFFFFFFFn;
    v[0] = (v[0] + a2) & 0xFFFFFFFFFFFFFFFFn;
    v[1] = (v[1] + a3) & 0xFFFFFFFFFFFFFFFFn;
    w[0] = (w[0] + a4) & 0xFFFFFFFFFFFFFFFFn;
    w[1] = (w[1] + a5 + a6) & 0xFFFFFFFFFFFFFFFFn;
    x = (x + a1) & 0xFFFFFFFFFFFFFFFFn;
    y = (y + a7) & 0xFFFFFFFFFFFFFFFFn;

    y = (y + v[0]) & 0xFFFFFFFFFFFFFFFFn;
    v[0] = (v[0] + (x - y)) & 0xFFFFFFFFFFFFFFFFn;
    v[1] = (v[1] + w[0]) & 0xFFFFFFFFFFFFFFFFn;
    w[0] = (w[0] + v[1]) & 0xFFFFFFFFFFFFFFFFn;
    w[1] = (w[1] + (x - y)) & 0xFFFFFFFFFFFFFFFFn;
    x = (x + w[1]) & 0xFFFFFFFFFFFFFFFFn;
    w[1] = rotate64(w[1], 34);
    [u, z] = [z, u];
    idx += 64;
  } while (idx !== endIdx);

  idx = last64;
  u = (u * 9n) & 0xFFFFFFFFFFFFFFFFn;
  v[1] = rotate64(v[1], 28);
  v[0] = rotate64(v[0], 20);
  w[0] = (w[0] + (BigInt(len - 1) & 63n)) & 0xFFFFFFFFFFFFFFFFn;
  u = (u + y) & 0xFFFFFFFFFFFFFFFFn;
  y = (y + u) & 0xFFFFFFFFFFFFFFFFn;

  x = (rotate64((y - x + v[0] + fetch64(buf, idx + 8)) & 0xFFFFFFFFFFFFFFFFn, 37) * mul) & 0xFFFFFFFFFFFFFFFFn;
  y = (rotate64((y ^ v[1] ^ fetch64(buf, idx + 48)) & 0xFFFFFFFFFFFFFFFFn, 42) * mul) & 0xFFFFFFFFFFFFFFFFn;
  x = (x ^ (w[1] * 9n)) & 0xFFFFFFFFFFFFFFFFn;
  y = (y + v[0] + fetch64(buf, idx + 40)) & 0xFFFFFFFFFFFFFFFFn;
  z = (rotate64((z + w[0]) & 0xFFFFFFFFFFFFFFFFn, 33) * mul) & 0xFFFFFFFFFFFFFFFFn;

  v = weakHashLen32WithSeeds(buf, idx, (v[1] * mul) & 0xFFFFFFFFFFFFFFFFn, (x + w[0]) & 0xFFFFFFFFFFFFFFFFn);
  w = weakHashLen32WithSeeds(buf, idx + 32, (z + w[1]) & 0xFFFFFFFFFFFFFFFFn, (y + fetch64(buf, idx + 16)) & 0xFFFFFFFFFFFFFFFFn);

  return uoH(
    (hashLen16Mul(v[0] + x, w[0] ^ y, mul) + z - u) & 0xFFFFFFFFFFFFFFFFn,
    uoH((v[1] + y) & 0xFFFFFFFFFFFFFFFFn, (w[1] + z) & 0xFFFFFFFFFFFFFFFFn, k2, 30) ^ x,
    k2,
    31
  );
}

function uoHash64(buf: Buffer, len: number): bigint {
  return uoHash64WithSeeds(buf, len, 81n, 0n);
}

/**************************************************************************
 * FARMHASH XO (legacy hash64 router)
 ***************************************************************************/

function xoHash64(buf: Buffer, len: number): bigint {
  if (len <= 16) return hashLen0to16(buf, len);
  if (len <= 32) return hashLen17to32(buf, len);
  if (len <= 64) return hashLen33to64(buf, len);
  if (len <= 96) return hashLen65to96(buf, len);
  if (len <= 256) return naHash64(buf, len);
  return uoHash64(buf, len);
}

/**************************************************************************
 * FARMHASH TE (x86_64 SIMD simulation for strings ≥512 bytes)
 * 
 * This simulates the SSE4.1 SIMD operations used in farmhashte::Hash64Long
 * using pairs of 64-bit bigints to represent 128-bit values.
 ***************************************************************************/

type M128i = [bigint, bigint];

function m128iFromSeed(seed: bigint): M128i {
  return [seed & 0xFFFFFFFFFFFFFFFFn, 0n];
}

function m128iSet1Epi32(val: bigint): M128i {
  const v32 = val & 0xFFFFFFFFn;
  const packed = (v32 << 32n) | v32;
  return [packed, packed];
}

function fetch128(buf: Buffer, offset: number): M128i {
  return [
    buf.readBigUInt64LE(offset),
    buf.readBigUInt64LE(offset + 8)
  ];
}

function add128(x: M128i, y: M128i): M128i {
  return [
    (x[0] + y[0]) & 0xFFFFFFFFFFFFFFFFn,
    (x[1] + y[1]) & 0xFFFFFFFFFFFFFFFFn
  ];
}

function xor128(x: M128i, y: M128i): M128i {
  return [x[0] ^ y[0], x[1] ^ y[1]];
}

function mul128(x: M128i, y: M128i): M128i {
  const x0 = x[0] & 0xFFFFFFFFn;
  const x1 = (x[0] >> 32n) & 0xFFFFFFFFn;
  const x2 = x[1] & 0xFFFFFFFFn;
  const x3 = (x[1] >> 32n) & 0xFFFFFFFFn;
  const y0 = y[0] & 0xFFFFFFFFn;
  const y1 = (y[0] >> 32n) & 0xFFFFFFFFn;
  const y2 = y[1] & 0xFFFFFFFFn;
  const y3 = (y[1] >> 32n) & 0xFFFFFFFFn;
  const r0 = (x0 * y0) & 0xFFFFFFFFn;
  const r1 = (x1 * y1) & 0xFFFFFFFFn;
  const r2 = (x2 * y2) & 0xFFFFFFFFn;
  const r3 = (x3 * y3) & 0xFFFFFFFFn;
  return [
    (r1 << 32n) | r0,
    (r3 << 32n) | r2
  ];
}

function shuf128(mask: M128i, data: M128i): M128i {
  const bytes: number[] = [];
  bytes.push(Number(data[0] & 0xFFn));
  bytes.push(Number((data[0] >> 8n) & 0xFFn));
  bytes.push(Number((data[0] >> 16n) & 0xFFn));
  bytes.push(Number((data[0] >> 24n) & 0xFFn));
  bytes.push(Number((data[0] >> 32n) & 0xFFn));
  bytes.push(Number((data[0] >> 40n) & 0xFFn));
  bytes.push(Number((data[0] >> 48n) & 0xFFn));
  bytes.push(Number((data[0] >> 56n) & 0xFFn));
  bytes.push(Number(data[1] & 0xFFn));
  bytes.push(Number((data[1] >> 8n) & 0xFFn));
  bytes.push(Number((data[1] >> 16n) & 0xFFn));
  bytes.push(Number((data[1] >> 24n) & 0xFFn));
  bytes.push(Number((data[1] >> 32n) & 0xFFn));
  bytes.push(Number((data[1] >> 40n) & 0xFFn));
  bytes.push(Number((data[1] >> 48n) & 0xFFn));
  bytes.push(Number((data[1] >> 56n) & 0xFFn));

  const maskBytes: number[] = [];
  maskBytes.push(Number(mask[0] & 0xFFn));
  maskBytes.push(Number((mask[0] >> 8n) & 0xFFn));
  maskBytes.push(Number((mask[0] >> 16n) & 0xFFn));
  maskBytes.push(Number((mask[0] >> 24n) & 0xFFn));
  maskBytes.push(Number((mask[0] >> 32n) & 0xFFn));
  maskBytes.push(Number((mask[0] >> 40n) & 0xFFn));
  maskBytes.push(Number((mask[0] >> 48n) & 0xFFn));
  maskBytes.push(Number((mask[0] >> 56n) & 0xFFn));
  maskBytes.push(Number(mask[1] & 0xFFn));
  maskBytes.push(Number((mask[1] >> 8n) & 0xFFn));
  maskBytes.push(Number((mask[1] >> 16n) & 0xFFn));
  maskBytes.push(Number((mask[1] >> 24n) & 0xFFn));
  maskBytes.push(Number((mask[1] >> 32n) & 0xFFn));
  maskBytes.push(Number((mask[1] >> 40n) & 0xFFn));
  maskBytes.push(Number((mask[1] >> 48n) & 0xFFn));
  maskBytes.push(Number((mask[1] >> 56n) & 0xFFn));

  const result: number[] = [];
  for (let i = 0; i < 16; i++) {
    const idx = maskBytes[i] & 0x0F;
    result.push(bytes[idx]);
  }

  let lo = 0n;
  let hi = 0n;
  for (let i = 0; i < 8; i++) {
    lo |= BigInt(result[i]) << BigInt(i * 8);
    hi |= BigInt(result[i + 8]) << BigInt(i * 8);
  }
  return [lo, hi];
}

function shuffle32(x: M128i, imm8: number): M128i {
  const dwords: bigint[] = [
    x[0] & 0xFFFFFFFFn,
    (x[0] >> 32n) & 0xFFFFFFFFn,
    x[1] & 0xFFFFFFFFn,
    (x[1] >> 32n) & 0xFFFFFFFFn
  ];
  const r0 = dwords[imm8 & 3];
  const r1 = dwords[(imm8 >> 2) & 3];
  const r2 = dwords[(imm8 >> 4) & 3];
  const r3 = dwords[(imm8 >> 6) & 3];
  return [
    (r1 << 32n) | r0,
    (r3 << 32n) | r2
  ];
}

function m128iToBuffer(vals: M128i[]): Buffer {
  const buf = Buffer.alloc(vals.length * 16);
  for (let i = 0; i < vals.length; i++) {
    buf.writeBigUInt64LE(vals[i][0], i * 16);
    buf.writeBigUInt64LE(vals[i][1], i * 16 + 8);
  }
  return buf;
}

function teHash64Long(buf: Buffer, len: number, seed0: bigint, seed1: bigint): bigint {
  const kShuf: M128i = [0x0c020e0d00070301n, 0x040b0a05080f0609n];
  const kMult: M128i = [0x343e33edcc9e2d51n, 0xbdd633394554fa03n];

  const seed2 = ((seed0 + 113n) * (seed1 + 9n)) & 0xFFFFFFFFFFFFFFFFn;
  const seed3 = ((rotate64(seed0, 23) + 27n) * (rotate64(seed1, 30) + 111n)) & 0xFFFFFFFFFFFFFFFFn;

  let d0 = m128iFromSeed(seed0);
  let d1 = m128iFromSeed(seed1);
  let d2 = shuf128(kShuf, d0);
  let d3 = shuf128(kShuf, d1);
  let d4 = xor128(d0, d1);
  let d5 = xor128(d1, d2);
  let d6 = xor128(d2, d4);
  let d7 = m128iSet1Epi32(seed2 >> 32n);
  let d8 = mul128(kMult, d2);
  let d9 = m128iSet1Epi32(seed3 >> 32n);
  let d10 = m128iSet1Epi32(seed3 & 0xFFFFFFFFn);
  let d11 = add128(d2, m128iSet1Epi32(seed2 & 0xFFFFFFFFn));

  const endOffset = len & ~255;
  let offset = 0;

  while (offset < endOffset) {
    let z: M128i;

    z = fetch128(buf, offset);
    d0 = add128(d0, z);
    d1 = shuf128(kShuf, d1);
    d2 = xor128(d2, d0);
    d4 = xor128(d4, z);
    d4 = xor128(d4, d1);
    [d0, d6] = [d6, d0];

    z = fetch128(buf, offset + 16);
    d5 = add128(d5, z);
    d6 = shuf128(kShuf, d6);
    d8 = shuf128(kShuf, d8);
    d7 = xor128(d7, d5);
    d0 = xor128(d0, z);
    d0 = xor128(d0, d6);
    [d5, d11] = [d11, d5];

    z = fetch128(buf, offset + 32);
    d1 = add128(d1, z);
    d2 = shuf128(kShuf, d2);
    d4 = shuf128(kShuf, d4);
    d5 = xor128(d5, z);
    d5 = xor128(d5, d2);
    [d10, d4] = [d4, d10];

    z = fetch128(buf, offset + 48);
    d6 = add128(d6, z);
    d7 = shuf128(kShuf, d7);
    d0 = shuf128(kShuf, d0);
    d8 = xor128(d8, d6);
    d1 = xor128(d1, z);
    d1 = add128(d1, d7);

    z = fetch128(buf, offset + 64);
    d2 = add128(d2, z);
    d5 = shuf128(kShuf, d5);
    d4 = add128(d4, d2);
    d6 = xor128(d6, z);
    d6 = xor128(d6, d11);
    [d8, d2] = [d2, d8];

    z = fetch128(buf, offset + 80);
    d7 = xor128(d7, z);
    d8 = shuf128(kShuf, d8);
    d1 = shuf128(kShuf, d1);
    d0 = add128(d0, d7);
    d2 = add128(d2, z);
    d2 = add128(d2, d8);
    [d1, d7] = [d7, d1];

    z = fetch128(buf, offset + 96);
    d4 = shuf128(kShuf, d4);
    d6 = shuf128(kShuf, d6);
    d8 = mul128(kMult, d8);
    d5 = xor128(d5, d11);
    d7 = xor128(d7, z);
    d7 = add128(d7, d4);
    [d6, d0] = [d0, d6];

    z = fetch128(buf, offset + 112);
    d8 = add128(d8, z);
    d0 = shuf128(kShuf, d0);
    d2 = shuf128(kShuf, d2);
    d1 = xor128(d1, d8);
    d10 = xor128(d10, z);
    d10 = xor128(d10, d0);
    [d11, d5] = [d5, d11];

    z = fetch128(buf, offset + 128);
    d4 = add128(d4, z);
    d5 = shuf128(kShuf, d5);
    d7 = shuf128(kShuf, d7);
    d6 = add128(d6, d4);
    d8 = xor128(d8, z);
    d8 = xor128(d8, d5);
    [d4, d10] = [d10, d4];

    z = fetch128(buf, offset + 144);
    d0 = add128(d0, z);
    d1 = shuf128(kShuf, d1);
    d2 = add128(d2, d0);
    d4 = xor128(d4, z);
    d4 = xor128(d4, d1);

    z = fetch128(buf, offset + 160);
    d5 = add128(d5, z);
    d6 = shuf128(kShuf, d6);
    d8 = shuf128(kShuf, d8);
    d7 = xor128(d7, d5);
    d0 = xor128(d0, z);
    d0 = xor128(d0, d6);
    [d2, d8] = [d8, d2];

    z = fetch128(buf, offset + 176);
    d1 = add128(d1, z);
    d2 = shuf128(kShuf, d2);
    d4 = shuf128(kShuf, d4);
    d5 = mul128(kMult, d5);
    d5 = xor128(d5, z);
    d5 = xor128(d5, d2);
    [d7, d1] = [d1, d7];

    z = fetch128(buf, offset + 192);
    d6 = add128(d6, z);
    d7 = shuf128(kShuf, d7);
    d0 = shuf128(kShuf, d0);
    d8 = add128(d8, d6);
    d1 = xor128(d1, z);
    d1 = xor128(d1, d7);
    [d0, d6] = [d6, d0];

    z = fetch128(buf, offset + 208);
    d2 = add128(d2, z);
    d5 = shuf128(kShuf, d5);
    d4 = xor128(d4, d2);
    d6 = xor128(d6, z);
    d6 = xor128(d6, d9);
    [d5, d11] = [d11, d5];

    z = fetch128(buf, offset + 224);
    d7 = add128(d7, z);
    d8 = shuf128(kShuf, d8);
    d1 = shuf128(kShuf, d1);
    d0 = xor128(d0, d7);
    d2 = xor128(d2, z);
    d2 = xor128(d2, d8);
    [d10, d4] = [d4, d10];

    z = fetch128(buf, offset + 240);
    d3 = add128(d3, z);
    d4 = shuf128(kShuf, d4);
    d6 = shuf128(kShuf, d6);
    d7 = mul128(kMult, d7);
    d5 = add128(d5, d3);
    d7 = xor128(d7, z);
    d7 = xor128(d7, d4);
    [d3, d9] = [d9, d3];

    offset += 256;
  }

  d6 = add128(mul128(kMult, d6), m128iFromSeed(BigInt(len)));

  if (len % 256 !== 0) {
    const imm8 = (0 << 6) + (3 << 4) + (2 << 2) + (1 << 0);
    d7 = add128(shuffle32(d8, imm8), d7);
    d8 = add128(mul128(kMult, d8), m128iFromSeed(xoHash64(buf.subarray(offset), len % 256)));
  }

  d0 = mul128(kMult, shuf128(kShuf, mul128(kMult, d0)));
  d3 = mul128(kMult, shuf128(kShuf, mul128(kMult, d3)));
  d9 = mul128(kMult, shuf128(kShuf, mul128(kMult, d9)));
  d1 = mul128(kMult, shuf128(kShuf, mul128(kMult, d1)));
  d0 = add128(d11, d0);
  d3 = xor128(d7, d3);
  d9 = add128(d8, d9);
  d1 = add128(d10, d1);
  d4 = add128(d3, d4);
  d5 = add128(d9, d5);
  d6 = xor128(d1, d6);
  d2 = add128(d0, d2);

  const t: M128i[] = [d0, d3, d9, d1, d4, d5, d6, d2];
  const tBuf = m128iToBuffer(t);
  return xoHash64(tBuf, 128);
}

function teHash64(buf: Buffer, len: number): bigint {
  if (len >= 512) {
    return teHash64Long(buf, len, k2, k1);
  }
  return xoHash64(buf, len);
}

/**************************************************************************
 * FARMHASH NA - HashLen33to64 (used by fingerprint64)
 ***************************************************************************/

function naHashLen33to64(buf: Buffer, len: number): bigint {
  const mul = k2 + BigInt(len) * 2n;
  const a = (fetch64(buf, 0) * k2) & 0xFFFFFFFFFFFFFFFFn;
  const b = fetch64(buf, 8);
  const c = (fetch64(buf, len - 8) * mul) & 0xFFFFFFFFFFFFFFFFn;
  const d = (fetch64(buf, len - 16) * k2) & 0xFFFFFFFFFFFFFFFFn;
  const y = (rotate64((a + b) & 0xFFFFFFFFFFFFFFFFn, 43) + rotate64(c, 30) + d) & 0xFFFFFFFFFFFFFFFFn;
  const z = hashLen16Mul(y, (a + rotate64((b + k2) & 0xFFFFFFFFFFFFFFFFn, 18) + c) & 0xFFFFFFFFFFFFFFFFn, mul);
  const e = (fetch64(buf, 16) * mul) & 0xFFFFFFFFFFFFFFFFn;
  const f = fetch64(buf, 24);
  const g = ((y + fetch64(buf, len - 32)) * mul) & 0xFFFFFFFFFFFFFFFFn;
  const h = ((z + fetch64(buf, len - 24)) * mul) & 0xFFFFFFFFFFFFFFFFn;
  return hashLen16Mul(
    (rotate64((e + f) & 0xFFFFFFFFFFFFFFFFn, 43) + rotate64(g, 30) + h) & 0xFFFFFFFFFFFFFFFFn,
    (e + rotate64((f + a) & 0xFFFFFFFFFFFFFFFFn, 18) + g) & 0xFFFFFFFFFFFFFFFFn,
    mul
  );
}

/**************************************************************************
 * FINGERPRINT64 (farmhashna::Hash64 - stable across all platforms)
 ***************************************************************************/

function fingerprint64Internal(buf: Buffer, len: number): bigint {
  if (len <= 16) return hashLen0to16(buf, len);
  if (len <= 32) return hashLen17to32(buf, len);
  if (len <= 64) return naHashLen33to64(buf, len);
  return naHash64(buf, len);
}

/**************************************************************************
 * FARMHASH MK (32-bit)
 ***************************************************************************/

function mkHash32Len0to4(buf: Buffer, len: number, seed: number = 0): number {
  let b = seed;
  let c = 9;
  for (let i = 0; i < len; i++) {
    const v = buf.readInt8(i);
    b = (Math.imul(b, c1_32) + v) >>> 0;
    c = (c ^ b) >>> 0;
  }
  return fmix(mur(b, mur(len, c)));
}

function mkHash32Len5to12(buf: Buffer, len: number, seed: number = 0): number {
  let a = len;
  let b = len * 5;
  let c = 9;
  let d = (b + seed) >>> 0;
  a = (a + fetch32AsNumber(buf, 0)) >>> 0;
  b = (b + fetch32AsNumber(buf, len - 4)) >>> 0;
  c = (c + fetch32AsNumber(buf, (len >> 1) & 4)) >>> 0;
  return fmix((seed ^ mur(c, mur(b, mur(a, d)))) >>> 0);
}

function mkHash32Len13to24(buf: Buffer, len: number, seed: number = 0): number {
  const a = fetch32AsNumber(buf, (len >> 1) - 4);
  const b = fetch32AsNumber(buf, 4);
  const c = fetch32AsNumber(buf, len - 8);
  const d = fetch32AsNumber(buf, len >> 1);
  const e = fetch32AsNumber(buf, 0);
  const f = fetch32AsNumber(buf, len - 4);
  let h = (Math.imul(d, c1_32) + len + seed) >>> 0;
  let a2 = (rotate32(a, 12) + f) >>> 0;
  h = (mur(c, h) + a2) >>> 0;
  a2 = (rotate32(a2, 3) + c) >>> 0;
  h = (mur(e, h) + a2) >>> 0;
  a2 = (rotate32(a2 + f, 12) + d) >>> 0;
  h = (mur((b ^ seed) >>> 0, h) + a2) >>> 0;
  return fmix(h);
}

function mkHash32(buf: Buffer, len: number): number {
  if (len <= 4) return mkHash32Len0to4(buf, len);
  if (len <= 12) return mkHash32Len5to12(buf, len);
  if (len <= 24) return mkHash32Len13to24(buf, len);

  let h = len;
  let g = Math.imul(c1_32, len) >>> 0;
  let f = g;
  let a0 = (Math.imul(rotate32(Math.imul(fetch32AsNumber(buf, len - 4), c1_32) >>> 0, 17), c2_32)) >>> 0;
  let a1 = (Math.imul(rotate32(Math.imul(fetch32AsNumber(buf, len - 8), c1_32) >>> 0, 17), c2_32)) >>> 0;
  let a2 = (Math.imul(rotate32(Math.imul(fetch32AsNumber(buf, len - 16), c1_32) >>> 0, 17), c2_32)) >>> 0;
  let a3 = (Math.imul(rotate32(Math.imul(fetch32AsNumber(buf, len - 12), c1_32) >>> 0, 17), c2_32)) >>> 0;
  let a4 = (Math.imul(rotate32(Math.imul(fetch32AsNumber(buf, len - 20), c1_32) >>> 0, 17), c2_32)) >>> 0;

  h = (h ^ a0) >>> 0;
  h = rotate32(h, 19);
  h = (Math.imul(h, 5) + 0xe6546b64) >>> 0;
  h = (h ^ a2) >>> 0;
  h = rotate32(h, 19);
  h = (Math.imul(h, 5) + 0xe6546b64) >>> 0;
  g = (g ^ a1) >>> 0;
  g = rotate32(g, 19);
  g = (Math.imul(g, 5) + 0xe6546b64) >>> 0;
  g = (g ^ a3) >>> 0;
  g = rotate32(g, 19);
  g = (Math.imul(g, 5) + 0xe6546b64) >>> 0;
  f = (f + a4) >>> 0;
  f = (rotate32(f, 19) + 113) >>> 0;

  let iters = Math.floor((len - 1) / 20);
  let offset = 0;

  do {
    const a = fetch32AsNumber(buf, offset);
    const b = fetch32AsNumber(buf, offset + 4);
    const c = fetch32AsNumber(buf, offset + 8);
    const d = fetch32AsNumber(buf, offset + 12);
    const e = fetch32AsNumber(buf, offset + 16);
    h = (h + a) >>> 0;
    g = (g + b) >>> 0;
    f = (f + c) >>> 0;
    h = (mur(d, h) + e) >>> 0;
    g = (mur(c, g) + a) >>> 0;
    f = (mur((b + Math.imul(e, c1_32)) >>> 0, f) + d) >>> 0;
    f = (f + g) >>> 0;
    g = (g + f) >>> 0;
    offset += 20;
  } while (--iters !== 0);

  g = (Math.imul(rotate32(g, 11), c1_32)) >>> 0;
  g = (Math.imul(rotate32(g, 17), c1_32)) >>> 0;
  f = (Math.imul(rotate32(f, 11), c1_32)) >>> 0;
  f = (Math.imul(rotate32(f, 17), c1_32)) >>> 0;
  h = rotate32((h + g) >>> 0, 19);
  h = (Math.imul(h, 5) + 0xe6546b64) >>> 0;
  h = (Math.imul(rotate32(h, 17), c1_32)) >>> 0;
  h = rotate32((h + f) >>> 0, 19);
  h = (Math.imul(h, 5) + 0xe6546b64) >>> 0;
  h = (Math.imul(rotate32(h, 17), c1_32)) >>> 0;
  return h;
}

/**************************************************************************
 * DEBUG TWEAK (applied in farmhash v3.x with FARMHASH_DEBUG=1)
 ***************************************************************************/

function debugTweak64(x: bigint): bigint {
  const multiplied = (x * k1) & 0xFFFFFFFFFFFFFFFFn;
  const swapped = bswap64(multiplied);
  return (~swapped) & 0xFFFFFFFFFFFFFFFFn;
}

function debugTweak32(x: number): number {
  const multiplied = Math.imul(x, c1_32) >>> 0;
  const swapped = bswap32(multiplied);
  return (~swapped) >>> 0;
}

/**************************************************************************
 * PUBLIC API - LEGACY (with DebugTweak, compatible with farmhash v3.3.1)
 * 
 * Note: farmhash v3.3.1 produces different results on ARM64 vs x86_64 for:
 * - hash64: Different for strings ≥512 bytes
 * - hash32: Different for ALL strings (different algorithms)
 ***************************************************************************/

/**
 * Compute a 64-bit hash compatible with farmhash v3.3.1 hash64() on ARM64
 * Also matches x86_64 for strings <512 bytes
 * @param input - The string to hash
 * @returns The hash as a decimal string
 */
export function legacyHash64_arm(input: string): string {
  const buf = Buffer.from(input);
  const rawHash = xoHash64(buf, buf.length);
  return debugTweak64(rawHash).toString();
}

/**
 * Compute a 64-bit hash compatible with farmhash v3.3.1 hash64() on x86_64
 * Uses farmhashte algorithm (SIMD simulation for ≥512 bytes)
 * @param input - The string to hash
 * @returns The hash as a decimal string
 */
export function legacyHash64_x86(input: string): string {
  const buf = Buffer.from(input);
  const rawHash = teHash64(buf, buf.length);
  return debugTweak64(rawHash).toString();
}

/**
 * Compute a 64-bit hash compatible with farmhash v3.3.1 hash64() on ARM64
 * Also matches x86_64 for strings <512 bytes
 * @param input - The string to hash
 * @returns The hash as a BigInt
 */
export function legacyHash64BigInt_arm(input: string): bigint {
  const buf = Buffer.from(input);
  const rawHash = xoHash64(buf, buf.length);
  return debugTweak64(rawHash);
}

/**
 * Compute a 64-bit hash compatible with farmhash v3.3.1 hash64() on x86_64
 * Uses farmhashte algorithm (SIMD simulation for ≥512 bytes)
 * @param input - The string to hash
 * @returns The hash as a BigInt
 */
export function legacyHash64BigInt_x86(input: string): bigint {
  const buf = Buffer.from(input);
  const rawHash = teHash64(buf, buf.length);
  return debugTweak64(rawHash);
}

/**
 * Compute a 32-bit hash compatible with farmhash v3.3.1 hash32() on ARM64
 * Uses farmhashmk algorithm
 * @param input - The string to hash
 * @returns The hash as a number
 */
export function legacyHash32_arm(input: string): number {
  const buf = Buffer.from(input);
  const rawHash = mkHash32(buf, buf.length);
  return debugTweak32(rawHash);
}

/**
 * Compute a 32-bit hash compatible with farmhash v3.3.1 hash32() on x86_64
 * Uses lower32(farmhashte::Hash64) algorithm (SIMD simulation for ≥512 bytes)
 * @param input - The string to hash
 * @returns The hash as a number
 */
export function legacyHash32_x86(input: string): number {
  const buf = Buffer.from(input);
  const rawHash64 = teHash64(buf, buf.length);
  const lower32 = Number(rawHash64 & 0xFFFFFFFFn);
  return debugTweak32(lower32);
}

/**************************************************************************
 * PUBLIC API - MODERN (stable fingerprints, same as farmhash v5)
 ***************************************************************************/

/**
 * Compute a stable 64-bit fingerprint hash
 * This is guaranteed stable across all platforms and versions.
 * @param input - The string to hash
 * @returns The hash as a decimal string
 */
export function fingerprint64(input: string): string {
  const buf = Buffer.from(input);
  return fingerprint64Internal(buf, buf.length).toString();
}

/**
 * Compute a stable 64-bit fingerprint hash
 * This is guaranteed stable across all platforms and versions.
 * @param input - The string to hash
 * @returns The hash as a BigInt
 */
export function fingerprint64BigInt(input: string): bigint {
  const buf = Buffer.from(input);
  return fingerprint64Internal(buf, buf.length);
}

/**
 * Compute a stable 32-bit fingerprint hash
 * This is guaranteed stable across all platforms and versions.
 * @param input - The string to hash
 * @returns The hash as a number
 */
export function fingerprint32(input: string): number {
  const buf = Buffer.from(input);
  return mkHash32(buf, buf.length);
}

/**************************************************************************
 * ALIASES
 ***************************************************************************/

/** Alias for fingerprint64 */
export const hash64 = fingerprint64;

/** Alias for fingerprint64BigInt */
export const hash64BigInt = fingerprint64BigInt;

/** Alias for fingerprint32 */
export const hash32 = fingerprint32;

/**************************************************************************
 * DEFAULT EXPORT
 ***************************************************************************/

export default {
  // Legacy (farmhash v3.3.1 compatible) - explicit architecture
  legacyHash64_arm,
  legacyHash64_x86,
  legacyHash64BigInt_arm,
  legacyHash64BigInt_x86,
  legacyHash32_arm,
  legacyHash32_x86,
  // Modern stable fingerprints
  fingerprint64,
  fingerprint64BigInt,
  fingerprint32,
  // Aliases
  hash64,
  hash64BigInt,
  hash32
};
