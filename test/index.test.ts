/**
 * Comprehensive test suite for farmhashjs
 *
 * Compares our pure JS implementation against:
 * - farmhash@3.3.1 (legacy, with DebugTweak)
 * - farmhash@5.0.0 (modern, stable fingerprints)
 */

import crypto from "crypto";
import {
  legacyHash64,
  legacyHash32,
  fingerprint64,
  fingerprint32
} from "../src/index.js";

// @ts-ignore - aliased package
import legacyFarmhash from "farmhash";
// @ts-ignore - aliased package
import modernFarmhash from "farmhash-modern";

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

const testStrings: string[] = [
  // Empty and single char
  "",
  "a",
  "b",
  "ab",
  "abc",

  // Common strings
  "hello",
  "hello world",
  "Hello World",
  "test",
  "testing",
  "The quick brown fox jumps over the lazy dog",

  // Numeric strings
  "0",
  "123",
  "1234567890",
  "1234567890123456",

  // Special characters
  "!@#$%^&*()",
  "hello\nworld",
  "hello\tworld",
  "hello\0world",
  "path/to/file.txt",
  "https://example.com/path?query=value&foo=bar",

  // Unicode - various scripts
  "你好",
  "你好世界",
  "こんにちは",
  "안녕하세요",
  "مرحبا",
  "שלום",
  "Привет",
  "Γειά σου",

  // Emojis
  "🚀",
  "Hello 🌍 World",
  "🎉🎊🎁",
  "👨‍👩‍👧‍👦",

  // Mixed content
  "user@example.com",
  "scenarioId__blockId",
  "2024-01-15T10:30:00Z",

  // Edge cases around length boundaries
  // 0-16 bytes boundary
  "1234567",         // 7 bytes
  "12345678",        // 8 bytes (boundary)
  "123456789",       // 9 bytes
  "123456789012345", // 15 bytes
  "1234567890123456", // 16 bytes (boundary)
  "12345678901234567", // 17 bytes

  // 17-32 bytes boundary
  "12345678901234567890123456789012", // 32 bytes (boundary)
  "123456789012345678901234567890123", // 33 bytes

  // 33-64 bytes boundary
  "a".repeat(33),
  "a".repeat(50),
  "a".repeat(63),
  "a".repeat(64),  // boundary
  "a".repeat(65),

  // 65-96 bytes boundary
  "b".repeat(80),
  "b".repeat(95),
  "b".repeat(96),  // boundary
  "b".repeat(97),

  // 97-256 bytes boundary (na hash)
  "c".repeat(100),
  "c".repeat(128),
  "c".repeat(200),
  "c".repeat(255),
  "c".repeat(256), // boundary
  "c".repeat(257),

  // >256 bytes (uo hash for legacy)
  "d".repeat(300),
  "d".repeat(500),
  "d".repeat(1000),
  "d".repeat(2000),
  "d".repeat(5000),

  // Patterns
  "ababababababababababababababababababababababababab",
  "aaaaaaaabbbbbbbbccccccccdddddddd",
  "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",

  // Random session IDs (50 random UUIDs)
  ...generateRandomSessions(50),

  // Random strings of various lengths (100 random strings up to 500 chars)
  ...generateRandomStrings(100, 500),
];

console.log("=".repeat(70));
console.log("farmhashjs Comprehensive Test Suite");
console.log("Comparing against native farmhash@3.3.1 and farmhash@5.0.0");
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

// Test legacy hash64 against farmhash@3.3.1
console.log("\n[1/4] Testing legacyHash64 against farmhash@3.3.1 hash64...");
for (const input of testStrings) {
  const expected = legacyFarmhash.hash64(input);
  const actual = legacyHash64(input);
  const display = input.length > 30 ? `${input.substring(0, 30)}... (${Buffer.from(input).length}b)` : `"${input}"`;
  test(
    `legacyHash64(${display})`,
    actual === expected,
    `expected ${expected}, got ${actual}`
  );
}

// Test legacy hash32 against farmhash@3.3.1
console.log("[2/4] Testing legacyHash32 against farmhash@3.3.1 hash32...");
for (const input of testStrings) {
  const expected = legacyFarmhash.hash32(input);
  const actual = legacyHash32(input);
  const display = input.length > 30 ? `${input.substring(0, 30)}... (${Buffer.from(input).length}b)` : `"${input}"`;
  test(
    `legacyHash32(${display})`,
    actual === expected,
    `expected ${expected}, got ${actual}`
  );
}

// Test fingerprint64 against farmhash@5.0.0
// Note: farmhash@5 returns bigint, we return string
console.log("[3/4] Testing fingerprint64 against farmhash@5.0.0 fingerprint64...");
for (const input of testStrings) {
  const expected = modernFarmhash.fingerprint64(input).toString();
  const actual = fingerprint64(input);
  const display = input.length > 30 ? `${input.substring(0, 30)}... (${Buffer.from(input).length}b)` : `"${input}"`;
  test(
    `fingerprint64(${display})`,
    actual === expected,
    `expected ${expected}, got ${actual}`
  );
}

// Test fingerprint32 against farmhash@5.0.0
console.log("[4/4] Testing fingerprint32 against farmhash@5.0.0 fingerprint32...");
for (const input of testStrings) {
  const expected = Number(modernFarmhash.fingerprint32(input));
  const actual = fingerprint32(input);
  const display = input.length > 30 ? `${input.substring(0, 30)}... (${Buffer.from(input).length}b)` : `"${input}"`;
  test(
    `fingerprint32(${display})`,
    actual === expected,
    `expected ${expected}, got ${actual}`
  );
}

// Summary
console.log("\n" + "=".repeat(70));
console.log(`Results: ${passed} passed, ${failed} failed`);
console.log(`Test inputs: ${testStrings.length} strings × 4 functions = ${testStrings.length * 4} tests`);
console.log("=".repeat(70));

if (failures.length > 0) {
  console.log("\nFailures:");
  for (const f of failures) {
    console.log(`  ❌ ${f}`);
  }
  process.exit(1);
} else {
  console.log("\n✅ All tests passed!");
}
