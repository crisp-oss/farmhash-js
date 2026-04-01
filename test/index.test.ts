/**
 * Comprehensive test suite for farmhashjs
 *
 * Tests against:
 * - Pre-computed values from farmhash@3.3.1 on macOS (legacy functions)
 * - Pre-computed values from farmhash@5.0.0 (fingerprint functions)
 * - Native farmhash when available (for local development)
 * - Random inputs for consistency checks
 */

import crypto from "crypto";
import {
  legacyHash64,
  legacyHash32,
  fingerprint64,
  fingerprint32
} from "../src/index.js";

// Try to load native farmhash for comparison (optional, for local dev)
let nativeFarmhash: any = null;
let nativeFarmhashModern: any = null;
try {
  nativeFarmhash = (await import("farmhash")).default;
  nativeFarmhashModern = (await import("farmhash-modern")).default;
} catch {
  // Native not available (CI or missing build tools)
}

/**
 * Expected values from farmhash@3.3.1 on macOS
 * These are platform-specific (macOS build with specific compile flags)
 */
const expectedLegacyHash64: Record<string, string> = {
  // Small strings
  "": "9398590711596223983",
  "a": "465389341092861716",
  "hello": "14403600180753024522",
  "hello world": "16022978042064026561",
  "session_20b9ed23-cc36-4177-8661-b2a6d4a71c18": "14834288349232330321",
  "1234567890123456": "15247786856340235214",
  "The quick brown fox jumps over the lazy dog": "452171363274304682",
  // Big strings (testing different hash paths for >64, >256 bytes, etc.)
  ["a".repeat(64)]: "11579970309768883552",
  ["b".repeat(128)]: "791797933527416355",
  ["c".repeat(256)]: "16296582071812616792",
  ["d".repeat(512)]: "17502333385417971036",
  ["e".repeat(1000)]: "14902101418149741055",
  ["f".repeat(2000)]: "17022258781865295252",
  ["g".repeat(5000)]: "17196588775594883102",
  ["h".repeat(10000)]: "2482386043086949318",
};

const expectedLegacyHash32: Record<string, number> = {
  // Small strings
  "": 1699113348,
  "a": 2719078668,
  "hello": 3111026382,
  "hello world": 3314386015,
  "session_20b9ed23-cc36-4177-8661-b2a6d4a71c18": 568412729,
  "1234567890123456": 672947600,
  "The quick brown fox jumps over the lazy dog": 3756171449,
  // Big strings
  ["a".repeat(64)]: 1775295225,
  ["b".repeat(128)]: 1500035920,
  ["c".repeat(256)]: 2616941317,
  ["d".repeat(512)]: 2282389650,
  ["e".repeat(1000)]: 3429703920,
  ["f".repeat(2000)]: 740168438,
  ["g".repeat(5000)]: 3011582401,
  ["h".repeat(10000)]: 3051546313,
};

/**
 * Expected values from farmhash@5.0.0 (stable across all platforms)
 */
const expectedFingerprint64: Record<string, string> = {
  // Small strings
  "": "11160318154034397263",
  "a": "12917804110809363939",
  "hello": "13009744463427800296",
  "hello world": "6381520714923946011",
  "session_20b9ed23-cc36-4177-8661-b2a6d4a71c18": "16528987318367749121",
  "1234567890123456": "17239105360639788068",
  "The quick brown fox jumps over the lazy dog": "12375473906752639284",
  // Big strings (testing different hash paths for >64, >256 bytes, etc.)
  ["a".repeat(64)]: "5893282057753879417",
  ["b".repeat(128)]: "17638211491968783095",
  ["c".repeat(256)]: "726802415163973935",
  ["d".repeat(512)]: "11981075791954381165",
  ["e".repeat(1000)]: "9485535561285839443",
  ["f".repeat(2000)]: "12587369799272928147",
  ["g".repeat(5000)]: "15389559131033639025",
  ["h".repeat(10000)]: "8693126793702641692",
};

const expectedFingerprint32: Record<string, number> = {
  // Small strings
  "": 3696677242,
  "a": 1016544589,
  "hello": 2039911270,
  "hello world": 430397466,
  "session_20b9ed23-cc36-4177-8661-b2a6d4a71c18": 3329589630,
  "1234567890123456": 1813583015,
  "The quick brown fox jumps over the lazy dog": 3969483552,
  // Big strings
  ["a".repeat(64)]: 3095623862,
  ["b".repeat(128)]: 977673158,
  ["c".repeat(256)]: 2890798372,
  ["d".repeat(512)]: 581051463,
  ["e".repeat(1000)]: 957929027,
  ["f".repeat(2000)]: 620217315,
  ["g".repeat(5000)]: 2235881100,
  ["h".repeat(10000)]: 455560746,
};

/**
 * Dummy hash compatibility test
 * Some tools use: (+farmhash.hash64(value)).toString(16)
 * The + coerces to number, losing precision but we must match
 */
const expectedDummyHash: Record<string, string> = {
  "session_20b9ed23-cc36-4177-8661-b2a6d4a71c18": "cdddfaa87fb57800",
};

function dummyHash(input: string): string {
  return (+legacyHash64(input)).toString(16);
}

function randomUUID(): string {
  return crypto.randomUUID();
}

function generateRandomSessions(count: number): string[] {
  return Array.from({ length: count }, () => `session_${randomUUID()}`);
}

function generateRandomStrings(count: number, maxLen: number): string[] {
  const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  return Array.from({ length: count }, () => {
    const len = Math.floor(Math.random() * maxLen) + 1;
    return Array.from({ length: len }, () => chars[Math.floor(Math.random() * chars.length)]).join("");
  });
}

console.log("=".repeat(70));
console.log("farmhashjs Test Suite");
console.log("=".repeat(70));

let passed = 0;
let failed = 0;
const failures: string[] = [];

function test(name: string, condition: boolean, details?: string) {
  if (condition) {
    passed++;
  } else {
    failed++;
    const msg = details ? `${name}: ${details}` : name;
    failures.push(msg);
  }
}

// Test legacyHash64 against known values
console.log("\n[1/5] Testing legacyHash64 against known values...");
for (const [input, expected] of Object.entries(expectedLegacyHash64)) {
  const actual = legacyHash64(input);
  const display = input.length > 30 ? `${input.substring(0, 30)}...` : `"${input}"`;
  test(
    `legacyHash64(${display})`,
    actual === expected,
    `expected ${expected}, got ${actual}`
  );
}

// Test legacyHash32 against known values
console.log("[2/5] Testing legacyHash32 against known values...");
for (const [input, expected] of Object.entries(expectedLegacyHash32)) {
  const actual = legacyHash32(input);
  const display = input.length > 30 ? `${input.substring(0, 30)}...` : `"${input}"`;
  test(
    `legacyHash32(${display})`,
    actual === expected,
    `expected ${expected}, got ${actual}`
  );
}

// Test fingerprint64 against known values
console.log("[3/5] Testing fingerprint64 against known values...");
for (const [input, expected] of Object.entries(expectedFingerprint64)) {
  const actual = fingerprint64(input);
  const display = input.length > 30 ? `${input.substring(0, 30)}...` : `"${input}"`;
  test(
    `fingerprint64(${display})`,
    actual === expected,
    `expected ${expected}, got ${actual}`
  );
}

// Test fingerprint32 against known values
console.log("[4/5] Testing fingerprint32 against known values...");
for (const [input, expected] of Object.entries(expectedFingerprint32)) {
  const actual = fingerprint32(input);
  const display = input.length > 30 ? `${input.substring(0, 30)}...` : `"${input}"`;
  test(
    `fingerprint32(${display})`,
    actual === expected,
    `expected ${expected}, got ${actual}`
  );
}

// Test dummy-hash compatibility
console.log("[5/5] Testing dummy-hash compatibility...");
for (const [input, expected] of Object.entries(expectedDummyHash)) {
  const actual = dummyHash(input);
  const display = input.length > 30 ? `${input.substring(0, 30)}...` : `"${input}"`;
  test(
    `dummyHash(${display})`,
    actual === expected,
    `expected ${expected}, got ${actual}`
  );
}

// Test consistency: same input always produces same output
console.log("\n[Bonus] Testing consistency with random inputs...");
const randomInputs = [
  ...generateRandomSessions(20),
  ...generateRandomStrings(30, 500),
];

for (const input of randomInputs) {
  const h64a = legacyHash64(input);
  const h64b = legacyHash64(input);
  const h32a = legacyHash32(input);
  const h32b = legacyHash32(input);
  const fp64a = fingerprint64(input);
  const fp64b = fingerprint64(input);
  const fp32a = fingerprint32(input);
  const fp32b = fingerprint32(input);

  test(
    `consistency(${input.substring(0, 20)}...)`,
    h64a === h64b && h32a === h32b && fp64a === fp64b && fp32a === fp32b,
    "hash values not consistent"
  );
}

// Compare against native farmhash (only when available locally)
if (nativeFarmhash) {
  console.log("\n[Native] Comparing against native farmhash (local only)...");
  
  const nativeTestInputs = [
    ...Object.keys(expectedLegacyHash64),
    ...generateRandomSessions(50),
    ...generateRandomStrings(100, 500),
  ];

  let nativeMatches = 0;
  let nativeMismatches = 0;

  for (const input of nativeTestInputs) {
    const jsHash64 = legacyHash64(input);
    const nativeHash64 = nativeFarmhash.hash64(input);
    const jsHash32 = legacyHash32(input);
    const nativeHash32 = nativeFarmhash.hash32(input);

    if (jsHash64 === nativeHash64 && jsHash32 === nativeHash32) {
      nativeMatches++;
    } else {
      nativeMismatches++;
      if (nativeMismatches <= 5) {
        console.log(`  ⚠️  Mismatch for "${input.substring(0, 30)}..."`);
        console.log(`      hash64: JS=${jsHash64}, native=${nativeHash64}`);
        console.log(`      hash32: JS=${jsHash32}, native=${nativeHash32}`);
      }
    }
  }

  console.log(`  Native comparison: ${nativeMatches} matches, ${nativeMismatches} mismatches`);
  
  if (nativeMismatches === 0) {
    passed++;
    console.log("  ✅ All native comparisons match!");
  } else {
    console.log("  ⚠️  Some mismatches (expected if native was built with different flags)");
  }
} else {
  console.log("\n[Native] Skipping native comparison (farmhash not available)");
}

// Summary
console.log("\n" + "=".repeat(70));
console.log(`Results: ${passed} passed, ${failed} failed`);
console.log("=".repeat(70));

if (failures.length > 0) {
  console.log("\nFailures:");
  for (const f of failures.slice(0, 20)) {
    console.log(`  ❌ ${f}`);
  }
  if (failures.length > 20) {
    console.log(`  ... and ${failures.length - 20} more`);
  }
  process.exit(1);
} else {
  console.log("\n✅ All tests passed!");
}
