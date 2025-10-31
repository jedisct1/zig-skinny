# zig-skinny

A Zig implementation of the SKINNY-128 tweakable block cipher family.

## What is SKINNY?

SKINNY is a lightweight tweakable block cipher designed for constrained environments. It's one of those ciphers that came out of the research community looking for alternatives to AES when you need something lighter or when you want built-in tweak support.

This library implements the SKINNY-128 variants (128-bit block size) with different key and tweak sizes.

Note: SKINNY is optimized for hardware implementations and excels in resource-constrained hardware environments.

However, on modern CPUs with AES-NI acceleration, AES-XTX, Deoxys-BC and KIASU-BC will be significantly faster in software. Consider using SKINNY when implementing on hardware, or are working in environments without AES acceleration.

## Usage

### Basic encryption (key-only variants)

```zig
const std = @import("std");
const skinny = @import("skinny");

// SKINNY-128-128 (128-bit key, 40 rounds)
const key: [16]u8 = @splat(0x00);
const plaintext: [16]u8 = @splat(0x00);

const enc_ctx = skinny.Skinny128_128.initEnc(key);
var ciphertext: [16]u8 = undefined;
enc_ctx.encrypt(&ciphertext, &plaintext);

const dec_ctx = skinny.Skinny128_128.initDec(key);
var recovered: [16]u8 = undefined;
dec_ctx.decrypt(&recovered, &ciphertext);
```

### Tweakable variants (key + tweak)

```zig
// SKINNY-128T-128-128 (128-bit key + 128-bit tweak, 48 rounds)
const key: [16]u8 = @splat(0x00);
const tweak: [16]u8 = @splat(0x00);

const enc_ctx = skinny.Skinny128T_128_128.initEnc(key, tweak);
var ciphertext: [16]u8 = undefined;
enc_ctx.encrypt(&ciphertext, &plaintext);
```

### Available variants

Key-only:

- `Skinny128_128` - 128-bit key (40 rounds)
- `Skinny128_256` - 256-bit key (48 rounds)
- `Skinny128_384` - 384-bit key (56 rounds)

Tweakable:

- `Skinny128T_128_128` - 128-bit key + 128-bit tweak (48 rounds)
- `Skinny128T_128_256` - 128-bit key + 256-bit tweak (56 rounds)
- `Skinny128T_256_128` - 256-bit key + 128-bit tweak (56 rounds)
