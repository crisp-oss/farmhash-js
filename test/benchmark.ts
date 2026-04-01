/**
 * Performance benchmark for farmhashjs vs native farmhash
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

const ITERATIONS = 100_000;

function generateTestData(): { small: string[]; medium: string[]; large: string[] } {
  const small: string[] = [];   // ~10-50 bytes
  const medium: string[] = [];  // ~100-500 bytes
  const large: string[] = [];   // ~1000-5000 bytes

  for (let i = 0; i < 1000; i++) {
    small.push(`session_${crypto.randomUUID()}`);
    medium.push(crypto.randomBytes(250).toString("hex"));
    large.push(crypto.randomBytes(2500).toString("hex"));
  }

  return { small, medium, large };
}

interface BenchResult {
  opsPerSec: number;
  nsPerOp: number;
}

function benchmark(name: string, fn: () => void, iterations: number): BenchResult {
  // Warmup
  for (let i = 0; i < 1000; i++) fn();

  const start = performance.now();
  for (let i = 0; i < iterations; i++) {
    fn();
  }
  const elapsed = performance.now() - start;
  const opsPerSec = Math.round(iterations / (elapsed / 1000));
  const nsPerOp = (elapsed * 1_000_000) / iterations;

  return { opsPerSec, nsPerOp };
}

function formatOps(ops: number): string {
  if (ops >= 1_000_000) return `${(ops / 1_000_000).toFixed(2)}M`;
  if (ops >= 1_000) return `${(ops / 1_000).toFixed(1)}K`;
  return ops.toString();
}

function formatNs(ns: number): string {
  if (ns >= 1_000_000) return `${(ns / 1_000_000).toFixed(2)}ms`;
  if (ns >= 1_000) return `${(ns / 1_000).toFixed(2)}µs`;
  return `${ns.toFixed(0)}ns`;
}

function runBenchmarks(label: string, data: string[], iterations: number) {
  console.log(`\n${label} (~${data[0].length} bytes, ${iterations.toLocaleString()} iterations)`);
  console.log("-".repeat(80));
  console.log("  Function         │ JS (pure)          │ Native (C++)       │ JS % of Native");
  console.log("-".repeat(80));

  let idx = 0;
  const nextInput = () => data[idx++ % data.length];

  // Hash64
  idx = 0;
  const jsLegacy64 = benchmark("JS legacyHash64", () => legacyHash64(nextInput()), iterations);
  idx = 0;
  const nativeLegacy64 = benchmark("Native hash64 (v3)", () => legacyFarmhash.hash64(nextInput()), iterations);
  const ratio64legacy = (jsLegacy64.opsPerSec / nativeLegacy64.opsPerSec * 100).toFixed(1);
  console.log(`  legacyHash64     │ ${formatNs(jsLegacy64.nsPerOp).padStart(8)}/op       │ ${formatNs(nativeLegacy64.nsPerOp).padStart(8)}/op       │ ${ratio64legacy.padStart(5)}%`);

  // Hash32
  idx = 0;
  const jsLegacy32 = benchmark("JS legacyHash32", () => legacyHash32(nextInput()), iterations);
  idx = 0;
  const nativeLegacy32 = benchmark("Native hash32 (v3)", () => legacyFarmhash.hash32(nextInput()), iterations);
  const ratio32legacy = (jsLegacy32.opsPerSec / nativeLegacy32.opsPerSec * 100).toFixed(1);
  console.log(`  legacyHash32     │ ${formatNs(jsLegacy32.nsPerOp).padStart(8)}/op       │ ${formatNs(nativeLegacy32.nsPerOp).padStart(8)}/op       │ ${ratio32legacy.padStart(5)}%`);

  // Fingerprint64
  idx = 0;
  const jsFp64 = benchmark("JS fingerprint64", () => fingerprint64(nextInput()), iterations);
  idx = 0;
  const nativeFp64 = benchmark("Native fp64 (v5)", () => modernFarmhash.fingerprint64(nextInput()), iterations);
  const ratioFp64 = (jsFp64.opsPerSec / nativeFp64.opsPerSec * 100).toFixed(1);
  console.log(`  fingerprint64    │ ${formatNs(jsFp64.nsPerOp).padStart(8)}/op       │ ${formatNs(nativeFp64.nsPerOp).padStart(8)}/op       │ ${ratioFp64.padStart(5)}%`);

  // Fingerprint32
  idx = 0;
  const jsFp32 = benchmark("JS fingerprint32", () => fingerprint32(nextInput()), iterations);
  idx = 0;
  const nativeFp32 = benchmark("Native fp32 (v5)", () => modernFarmhash.fingerprint32(nextInput()), iterations);
  const ratioFp32 = (jsFp32.opsPerSec / nativeFp32.opsPerSec * 100).toFixed(1);
  console.log(`  fingerprint32    │ ${formatNs(jsFp32.nsPerOp).padStart(8)}/op       │ ${formatNs(nativeFp32.nsPerOp).padStart(8)}/op       │ ${ratioFp32.padStart(5)}%`);
}

console.log("=".repeat(70));
console.log("farmhashjs Performance Benchmark");
console.log("Pure JS vs Native (C++ via N-API)");
console.log("=".repeat(70));

console.log("\nGenerating test data...");
const { small, medium, large } = generateTestData();

runBenchmarks("Small strings", small, ITERATIONS);
runBenchmarks("Medium strings", medium, ITERATIONS);
runBenchmarks("Large strings", large, Math.floor(ITERATIONS / 10));

console.log("\n" + "=".repeat(70));
console.log("Note: Percentage shows JS performance relative to native (higher = better)");
console.log("=".repeat(70));
