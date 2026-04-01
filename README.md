# farmhashjs

Pure JavaScript implementation of Google's [FarmHash](https://github.com/google/farmhash) algorithm. No native dependencies, works in Node.js and browsers.

## Why?

The native `farmhash` npm package requires C++ compilation, which can be problematic:
- Fails on some platforms (Windows, Alpine Linux, etc.)
- Requires node-gyp and build tools
- Doesn't work in browsers or edge runtimes

`farmhashjs` provides the same hash outputs with zero native dependencies.

## Installation

```bash
npm install farmhashjs
```

## Usage

```javascript
import { fingerprint64, fingerprint32, legacyHash64, legacyHash32 } from 'farmhashjs';

// Modern stable fingerprints (recommended)
fingerprint64('hello world');  // "6381520714923946011"
fingerprint32('hello world');  // 430397466

// Legacy hashes (compatible with farmhash@3.3.1)
legacyHash64('hello world');   // "16022978042064026561"
legacyHash32('hello world');   // 3602808830
```

## API

### Modern Functions (Stable Fingerprints)

These produce stable hashes guaranteed to be consistent across all platforms and versions.

| Function | Returns | Description |
|----------|---------|-------------|
| `fingerprint64(input)` | `string` | 64-bit hash as decimal string |
| `fingerprint64BigInt(input)` | `bigint` | 64-bit hash as BigInt |
| `fingerprint32(input)` | `number` | 32-bit hash as number |

### Legacy Functions (farmhash v3.x Compatible)

These are compatible with `farmhash@3.3.1` which was compiled with `FARMHASH_DEBUG=1`.

| Function | Returns | Description |
|----------|---------|-------------|
| `legacyHash64(input)` | `string` | 64-bit hash as decimal string |
| `legacyHash64BigInt(input)` | `bigint` | 64-bit hash as BigInt |
| `legacyHash32(input)` | `number` | 32-bit hash as number |

### Aliases

```javascript
import { hash64, hash32 } from 'farmhashjs';

// hash64 = fingerprint64
// hash32 = fingerprint32
```

## Compatibility

Tested against native implementations:

| Function | Compared Against |
|----------|------------------|
| `fingerprint64` | `farmhash@5.0.0` fingerprint64 |
| `fingerprint32` | `farmhash@5.0.0` fingerprint32 |
| `legacyHash64` | `farmhash@3.3.1` hash64 |
| `legacyHash32` | `farmhash@3.3.1` hash32 |

## Performance

Benchmarked on Apple M1:

| Function | 44 bytes | 500 bytes | 5 KB |
|----------|----------|-----------|------|
| `fingerprint32` | 251 ns/op | 903 ns/op | 9 µs/op |
| `fingerprint64` | 843 ns/op | 7 µs/op | 65 µs/op |
| `legacyHash32` | 302 ns/op | 974 ns/op | 9 µs/op |
| `legacyHash64` | 1.1 µs/op | 6.8 µs/op | 58 µs/op |

32-bit functions are faster because they use native `number` operations. 64-bit functions use `BigInt` which has more overhead.

For comparison, native C++ (`farmhash@5.0.0`) is ~2-10x faster depending on input size.

## When to Use

**Use `farmhashjs` when:**
- You need cross-platform compatibility
- You're running in browsers, Cloudflare Workers, or edge runtimes
- You can't compile native modules
- You're hashing moderate volumes (< 100K hashes/second)

**Use native `farmhash` when:**
- Maximum performance is critical
- You're in a Node.js environment that supports native modules
- You're hashing millions of strings per second

## License

Apache-2.0

This is a port of Google's FarmHash. Original FarmHash is Copyright 2014 Google Inc.
