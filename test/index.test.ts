/**
 * Comprehensive test suite for farmhashjs
 *
 * Tests against:
 * - Pre-computed values (hardcoded, always run)
 * - Native farmhash when available (architecture-aware comparison)
 * - Random inputs for consistency checks
 */

import crypto from "crypto";
import os from "os";
import {
  legacyHash64_arm,
  legacyHash64_x86,
  legacyHash32_arm,
  legacyHash32_x86,
  fingerprint64,
  fingerprint32
} from "../src/index.js";

// Detect architecture
const arch = os.arch();
const isArm = arch === "arm64" || arch === "arm";
const isX86 = arch === "x64" || arch === "x86" || arch === "ia32";

// Try to load native farmhash for comparison
let nativeFarmhash: any = null;
let nativeFarmhashModern: any = null;
try {
  nativeFarmhash = (await import("farmhash")).default;
  nativeFarmhashModern = (await import("farmhash-modern")).default;
} catch {
  // Native not available
}

/**
 * Expected values from farmhash@3.3.1 on ARM64
 */
const expectedLegacyHash64_arm: Record<string, string> = {
  "": "9398590711596223983",
  "a": "465389341092861716",
  "hello": "14403600180753024522",
  "hello world": "16022978042064026561",
  "session_20b9ed23-cc36-4177-8661-b2a6d4a71c18": "14834288349232330321",
  "1234567890123456": "15247786856340235214",
  "The quick brown fox jumps over the lazy dog": "452171363274304682",
  ["a".repeat(64)]: "11579970309768883552",
  ["b".repeat(128)]: "791797933527416355",
  ["c".repeat(256)]: "16296582071812616792",
  ["d".repeat(512)]: "17502333385417971036",
  ["e".repeat(1000)]: "14902101418149741055",
  ["f".repeat(2000)]: "17022258781865295252",
  ["g".repeat(5000)]: "17196588775594883102",
};

const expectedLegacyHash32_arm: Record<string, number> = {
  "": 1699113348,
  "a": 2719078668,
  "hello": 3111026382,
  "hello world": 3314386015,
  "session_20b9ed23-cc36-4177-8661-b2a6d4a71c18": 568412729,
  "1234567890123456": 672947600,
  "The quick brown fox jumps over the lazy dog": 3756171449,
  ["a".repeat(64)]: 1775295225,
  ["b".repeat(128)]: 1500035920,
  ["c".repeat(256)]: 2616941317,
  ["d".repeat(512)]: 2282389650,
  ["e".repeat(1000)]: 3429703920,
  ["f".repeat(2000)]: 740168438,
  ["g".repeat(5000)]: 3011582401,
};

/**
 * Expected values from farmhash@3.3.1 on x86_64
 */
const expectedLegacyHash64_x86: Record<string, string> = {
  "": "9398590711596223983",
  "a": "465389341092861716",
  "hello": "14403600180753024522",
  "hello world": "16022978042064026561",
  "session_20b9ed23-cc36-4177-8661-b2a6d4a71c18": "14834288349232330321",
  "1234567890123456": "15247786856340235214",
  "The quick brown fox jumps over the lazy dog": "452171363274304682",
  ["a".repeat(64)]: "11579970309768883552",
  ["b".repeat(128)]: "791797933527416355",
  ["c".repeat(256)]: "16296582071812616792",
  // ≥512 bytes: different from ARM64 (SIMD path)
  ["d".repeat(512)]: "17293859482641448156",
  ["e".repeat(1000)]: "1542213450519704787",
  ["f".repeat(2000)]: "9736066212118144737",
  ["g".repeat(5000)]: "6349839083275802131",
};

const expectedLegacyHash32_x86: Record<string, number> = {
  "": 12864499,
  "a": 751597621,
  "hello": 2535641019,
  "hello world": 1955099599,
  "session_20b9ed23-cc36-4177-8661-b2a6d4a71c18": 2575909061,
  "1234567890123456": 2614934743,
  "The quick brown fox jumps over the lazy dog": 753375869,
  ["a".repeat(64)]: 177445479,
  ["b".repeat(128)]: 3633594136,
  ["c".repeat(256)]: 549279713,
  ["d".repeat(400)]: 208779977,
  ["d".repeat(512)]: 2049238837,
  ["e".repeat(1000)]: 2977449388,
  ["f".repeat(2000)]: 3621095630,
  ["g".repeat(5000)]: 4070543414,
};

/**
 * Expected values from farmhash@5.0.0 (stable across all platforms)
 */
const expectedFingerprint64: Record<string, string> = {
  "": "11160318154034397263",
  "a": "12917804110809363939",
  "hello": "13009744463427800296",
  "hello world": "6381520714923946011",
  "session_20b9ed23-cc36-4177-8661-b2a6d4a71c18": "16528987318367749121",
  "1234567890123456": "17239105360639788068",
  "The quick brown fox jumps over the lazy dog": "12375473906752639284",
  ["a".repeat(64)]: "5893282057753879417",
  ["b".repeat(128)]: "17638211491968783095",
  ["c".repeat(256)]: "726802415163973935",
  ["d".repeat(512)]: "11981075791954381165",
  ["e".repeat(1000)]: "9485535561285839443",
  ["f".repeat(2000)]: "12587369799272928147",
  ["g".repeat(5000)]: "15389559131033639025",
};

const expectedFingerprint32: Record<string, number> = {
  "": 3696677242,
  "a": 1016544589,
  "hello": 2039911270,
  "hello world": 430397466,
  "session_20b9ed23-cc36-4177-8661-b2a6d4a71c18": 3329589630,
  "1234567890123456": 1813583015,
  "The quick brown fox jumps over the lazy dog": 3969483552,
  ["a".repeat(64)]: 3095623862,
  ["b".repeat(128)]: 977673158,
  ["c".repeat(256)]: 2890798372,
  ["d".repeat(512)]: 581051463,
  ["e".repeat(1000)]: 957929027,
  ["f".repeat(2000)]: 620217315,
  ["g".repeat(5000)]: 2235881100,
};

/**
 * Dummy hash compatibility (crisp-hash on x86_64)
 */
const expectedDummyHash: Record<string, string> = {
  "session_20b9ed23-cc36-4177-8661-b2a6d4a71c18": "cdddfaa87fb57800",
};

function dummyHash(input: string): string {
  return (+legacyHash64_x86(input)).toString(16);
}

function generateRandomSessions(count: number): string[] {
  return Array.from({ length: count }, () => `session_${crypto.randomUUID()}`);
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
console.log(`Architecture: ${arch} (${isArm ? "ARM" : isX86 ? "x86" : "unknown"})`);
console.log(`Native farmhash: ${nativeFarmhash ? "available" : "not available"}`);
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

// ============================================================================
// HARDCODED VALUE TESTS (always run, no native dependency)
// ============================================================================

console.log("\n[1/7] Testing legacyHash64_arm against hardcoded values...");
for (const [input, expected] of Object.entries(expectedLegacyHash64_arm)) {
  const actual = legacyHash64_arm(input);
  const display = input.length > 30 ? `${input.substring(0, 30)}... (${input.length}b)` : `"${input}"`;
  test(`legacyHash64_arm(${display})`, actual === expected, `expected ${expected}, got ${actual}`);
}

console.log("[2/7] Testing legacyHash32_arm against hardcoded values...");
for (const [input, expected] of Object.entries(expectedLegacyHash32_arm)) {
  const actual = legacyHash32_arm(input);
  const display = input.length > 30 ? `${input.substring(0, 30)}... (${input.length}b)` : `"${input}"`;
  test(`legacyHash32_arm(${display})`, actual === expected, `expected ${expected}, got ${actual}`);
}

console.log("[3/7] Testing legacyHash64_x86 against hardcoded values...");
for (const [input, expected] of Object.entries(expectedLegacyHash64_x86)) {
  const actual = legacyHash64_x86(input);
  const display = input.length > 30 ? `${input.substring(0, 30)}... (${input.length}b)` : `"${input}"`;
  test(`legacyHash64_x86(${display})`, actual === expected, `expected ${expected}, got ${actual}`);
}

console.log("[4/7] Testing legacyHash32_x86 against hardcoded values...");
for (const [input, expected] of Object.entries(expectedLegacyHash32_x86)) {
  const actual = legacyHash32_x86(input);
  const display = input.length > 30 ? `${input.substring(0, 30)}... (${input.length}b)` : `"${input}"`;
  test(`legacyHash32_x86(${display})`, actual === expected, `expected ${expected}, got ${actual}`);
}

console.log("[5/7] Testing fingerprint64 against hardcoded values...");
for (const [input, expected] of Object.entries(expectedFingerprint64)) {
  const actual = fingerprint64(input);
  const display = input.length > 30 ? `${input.substring(0, 30)}... (${input.length}b)` : `"${input}"`;
  test(`fingerprint64(${display})`, actual === expected, `expected ${expected}, got ${actual}`);
}

console.log("[6/7] Testing fingerprint32 against hardcoded values...");
for (const [input, expected] of Object.entries(expectedFingerprint32)) {
  const actual = fingerprint32(input);
  const display = input.length > 30 ? `${input.substring(0, 30)}... (${input.length}b)` : `"${input}"`;
  test(`fingerprint32(${display})`, actual === expected, `expected ${expected}, got ${actual}`);
}

console.log("[7/7] Testing dummy-hash compatibility...");
for (const [input, expected] of Object.entries(expectedDummyHash)) {
  const actual = dummyHash(input);
  const display = input.length > 30 ? `${input.substring(0, 30)}...` : `"${input}"`;
  test(`dummyHash(${display})`, actual === expected, `expected ${expected}, got ${actual}`);
}

// ============================================================================
// CONSISTENCY TESTS (random inputs, verify same input = same output)
// ============================================================================

console.log("\n[Consistency] Testing with random inputs...");
const randomInputs = [
  ...generateRandomSessions(20),
  ...generateRandomStrings(30, 500),
  ...generateRandomStrings(10, 2000), // Some long strings for SIMD path
];

for (const input of randomInputs) {
  const h64arm_a = legacyHash64_arm(input);
  const h64arm_b = legacyHash64_arm(input);
  const h32arm_a = legacyHash32_arm(input);
  const h32arm_b = legacyHash32_arm(input);
  const h64x86_a = legacyHash64_x86(input);
  const h64x86_b = legacyHash64_x86(input);
  const h32x86_a = legacyHash32_x86(input);
  const h32x86_b = legacyHash32_x86(input);
  const fp64_a = fingerprint64(input);
  const fp64_b = fingerprint64(input);
  const fp32_a = fingerprint32(input);
  const fp32_b = fingerprint32(input);

  const allConsistent = 
    h64arm_a === h64arm_b && 
    h32arm_a === h32arm_b && 
    h64x86_a === h64x86_b && 
    h32x86_a === h32x86_b && 
    fp64_a === fp64_b && 
    fp32_a === fp32_b;

  test(`consistency(${input.substring(0, 20)}... ${input.length}b)`, allConsistent, "hash not consistent");
}

// ============================================================================
// NATIVE COMPARISON (architecture-aware, random inputs)
// ============================================================================

if (nativeFarmhash) {
  console.log(`\n[Native] Comparing against native farmhash on ${arch}...`);
  
  // Generate random test inputs of various sizes
  const nativeTestInputs = [
    ...generateRandomSessions(50),
    ...generateRandomStrings(50, 100),   // Small
    ...generateRandomStrings(30, 500),   // Medium
    ...generateRandomStrings(20, 2000),  // Large (triggers SIMD on x86)
  ];

  let nativeMatches = 0;
  let nativeMismatches = 0;

  // Select the correct JS function based on architecture
  const jsHash64 = isArm ? legacyHash64_arm : legacyHash64_x86;
  const jsHash32 = isArm ? legacyHash32_arm : legacyHash32_x86;
  const archLabel = isArm ? "ARM" : "x86";

  for (const input of nativeTestInputs) {
    const jsH64 = jsHash64(input);
    const nativeH64 = nativeFarmhash.hash64(input);
    const jsH32 = jsHash32(input);
    const nativeH32 = nativeFarmhash.hash32(input);

    if (jsH64 === nativeH64 && jsH32 === nativeH32) {
      nativeMatches++;
    } else {
      nativeMismatches++;
      if (nativeMismatches <= 5) {
        console.log(`  ⚠️  Mismatch for "${input.substring(0, 30)}..." (${input.length}b)`);
        console.log(`      hash64: JS=${jsH64}, native=${nativeH64}`);
        console.log(`      hash32: JS=${jsH32}, native=${nativeH32}`);
      }
    }
  }

  console.log(`  ${archLabel} native comparison: ${nativeMatches} matches, ${nativeMismatches} mismatches`);
  
  if (nativeMismatches === 0) {
    passed++;
    console.log(`  ✅ All ${archLabel} native comparisons match!`);
  } else {
    failed++;
    failures.push(`Native ${archLabel} comparison had ${nativeMismatches} mismatches`);
    console.log(`  ❌ ${nativeMismatches} mismatches found`);
  }

  // Also test fingerprint functions against modern farmhash
  if (nativeFarmhashModern) {
    console.log(`\n[Native] Comparing fingerprint functions against farmhash@5.0.0...`);
    
    let fpMatches = 0;
    let fpMismatches = 0;

    for (const input of nativeTestInputs) {
      const jsFp64 = fingerprint64(input);
      const nativeFp64 = nativeFarmhashModern.fingerprint64(input).toString();
      const jsFp32 = fingerprint32(input);
      const nativeFp32 = Number(nativeFarmhashModern.fingerprint32(input));

      if (jsFp64 === nativeFp64 && jsFp32 === nativeFp32) {
        fpMatches++;
      } else {
        fpMismatches++;
        if (fpMismatches <= 5) {
          console.log(`  ⚠️  Mismatch for "${input.substring(0, 30)}..." (${input.length}b)`);
          console.log(`      fp64: JS=${jsFp64}, native=${nativeFp64}`);
          console.log(`      fp32: JS=${jsFp32}, native=${nativeFp32}`);
        }
      }
    }

    console.log(`  Fingerprint comparison: ${fpMatches} matches, ${fpMismatches} mismatches`);
    
    if (fpMismatches === 0) {
      passed++;
      console.log("  ✅ All fingerprint comparisons match!");
    } else {
      failed++;
      failures.push(`Fingerprint comparison had ${fpMismatches} mismatches`);
      console.log(`  ❌ ${fpMismatches} mismatches found`);
    }
  }
} else {
  console.log("\n[Native] Skipping native comparison (farmhash not available)");
}

// ============================================================================
// SUMMARY
// ============================================================================

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
