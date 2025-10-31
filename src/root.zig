const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

/// SKINNY-128-128: 128-bit block cipher with 128-bit key (40 rounds)
pub const Skinny128_128 = Skinny128(128, 0);

/// SKINNY-128-256: 128-bit block cipher with 256-bit key (48 rounds)
pub const Skinny128_256 = Skinny128(256, 0);

/// SKINNY-128-384: 128-bit block cipher with 384-bit key (56 rounds)
pub const Skinny128_384 = Skinny128(384, 0);

/// SKINNY-128-256 with 128-bit key + 128-bit tweak (48 rounds)
pub const Skinny128T_128_128 = Skinny128(128, 128);

/// SKINNY-128-384 with 128-bit key + 256-bit tweak (56 rounds)
pub const Skinny128T_128_256 = Skinny128(128, 256);

/// SKINNY-128-384 with 256-bit key + 128-bit tweak (56 rounds)
pub const Skinny128T_256_128 = Skinny128(256, 128);

const Config = struct {
    key_bits: u16,
    tweak_bits: u16 = 0,
};

fn GenericImpl(comptime cfg: Config) type {
    comptime assert(cfg.key_bits % 8 == 0);
    comptime assert(cfg.tweak_bits % 8 == 0);

    const total_bits: u16 = cfg.key_bits + cfg.tweak_bits;
    const rounds = switch (total_bits) {
        128 => 40,
        256 => 48,
        384 => 56,
        else => @compileError("Unsupported total tweakey size for SKINNY-128"),
    };

    const key_bytes: usize = cfg.key_bits / 8;
    const tweak_bytes: usize = cfg.tweak_bits / 8;
    const total_bytes: usize = key_bytes + tweak_bytes;

    return struct {
        pub const BlockSize = 16;
        pub const KeySize = key_bytes;
        pub const TweakSize = tweak_bytes;
        pub const TweakeySize = total_bytes;

        const Vec8u8 = @Vector(8, u8);
        const Vec16u8 = @Vector(16, u8);

        const sbox8: [256]u8 = [_]u8{
            0x65, 0x4c, 0x6a, 0x42, 0x4b, 0x63, 0x43, 0x6b, 0x55, 0x75, 0x5a, 0x7a, 0x53, 0x73, 0x5b, 0x7b,
            0x35, 0x8c, 0x3a, 0x81, 0x89, 0x33, 0x80, 0x3b, 0x95, 0x25, 0x98, 0x2a, 0x90, 0x23, 0x99, 0x2b,
            0xe5, 0xcc, 0xe8, 0xc1, 0xc9, 0xe0, 0xc0, 0xe9, 0xd5, 0xf5, 0xd8, 0xf8, 0xd0, 0xf0, 0xd9, 0xf9,
            0xa5, 0x1c, 0xa8, 0x12, 0x1b, 0xa0, 0x13, 0xa9, 0x05, 0xb5, 0x0a, 0xb8, 0x03, 0xb0, 0x0b, 0xb9,
            0x32, 0x88, 0x3c, 0x85, 0x8d, 0x34, 0x84, 0x3d, 0x91, 0x22, 0x9c, 0x2c, 0x94, 0x24, 0x9d, 0x2d,
            0x62, 0x4a, 0x6c, 0x45, 0x4d, 0x64, 0x44, 0x6d, 0x52, 0x72, 0x5c, 0x7c, 0x54, 0x74, 0x5d, 0x7d,
            0xa1, 0x1a, 0xac, 0x15, 0x1d, 0xa4, 0x14, 0xad, 0x02, 0xb1, 0x0c, 0xbc, 0x04, 0xb4, 0x0d, 0xbd,
            0xe1, 0xc8, 0xec, 0xc5, 0xcd, 0xe4, 0xc4, 0xed, 0xd1, 0xf1, 0xdc, 0xfc, 0xd4, 0xf4, 0xdd, 0xfd,
            0x36, 0x8e, 0x38, 0x82, 0x8b, 0x30, 0x83, 0x39, 0x96, 0x26, 0x9a, 0x28, 0x93, 0x20, 0x9b, 0x29,
            0x66, 0x4e, 0x68, 0x41, 0x49, 0x60, 0x40, 0x69, 0x56, 0x76, 0x58, 0x78, 0x50, 0x70, 0x59, 0x79,
            0xa6, 0x1e, 0xaa, 0x11, 0x19, 0xa3, 0x10, 0xab, 0x06, 0xb6, 0x08, 0xba, 0x00, 0xb3, 0x09, 0xbb,
            0xe6, 0xce, 0xea, 0xc2, 0xcb, 0xe3, 0xc3, 0xeb, 0xd6, 0xf6, 0xda, 0xfa, 0xd3, 0xf3, 0xdb, 0xfb,
            0x31, 0x8a, 0x3e, 0x86, 0x8f, 0x37, 0x87, 0x3f, 0x92, 0x21, 0x9e, 0x2e, 0x97, 0x27, 0x9f, 0x2f,
            0x61, 0x48, 0x6e, 0x46, 0x4f, 0x67, 0x47, 0x6f, 0x51, 0x71, 0x5e, 0x7e, 0x57, 0x77, 0x5f, 0x7f,
            0xa2, 0x18, 0xae, 0x16, 0x1f, 0xa7, 0x17, 0xaf, 0x01, 0xb2, 0x0e, 0xbe, 0x07, 0xb7, 0x0f, 0xbf,
            0xe2, 0xca, 0xee, 0xc6, 0xcf, 0xe7, 0xc7, 0xef, 0xd2, 0xf2, 0xde, 0xfe, 0xd7, 0xf7, 0xdf, 0xff,
        };

        const sbox8_inv: [256]u8 = [_]u8{
            0xac, 0xe8, 0x68, 0x3c, 0x6c, 0x38, 0xa8, 0xec, 0xaa, 0xae, 0x3a, 0x3e,
            0x6a, 0x6e, 0xea, 0xee, 0xa6, 0xa3, 0x33, 0x36, 0x66, 0x63, 0xe3, 0xe6,
            0xe1, 0xa4, 0x61, 0x34, 0x31, 0x64, 0xa1, 0xe4, 0x8d, 0xc9, 0x49, 0x1d,
            0x4d, 0x19, 0x89, 0xcd, 0x8b, 0x8f, 0x1b, 0x1f, 0x4b, 0x4f, 0xcb, 0xcf,
            0x85, 0xc0, 0x40, 0x15, 0x45, 0x10, 0x80, 0xc5, 0x82, 0x87, 0x12, 0x17,
            0x42, 0x47, 0xc2, 0xc7, 0x96, 0x93, 0x03, 0x06, 0x56, 0x53, 0xd3, 0xd6,
            0xd1, 0x94, 0x51, 0x04, 0x01, 0x54, 0x91, 0xd4, 0x9c, 0xd8, 0x58, 0x0c,
            0x5c, 0x08, 0x98, 0xdc, 0x9a, 0x9e, 0x0a, 0x0e, 0x5a, 0x5e, 0xda, 0xde,
            0x95, 0xd0, 0x50, 0x05, 0x55, 0x00, 0x90, 0xd5, 0x92, 0x97, 0x02, 0x07,
            0x52, 0x57, 0xd2, 0xd7, 0x9d, 0xd9, 0x59, 0x0d, 0x5d, 0x09, 0x99, 0xdd,
            0x9b, 0x9f, 0x0b, 0x0f, 0x5b, 0x5f, 0xdb, 0xdf, 0x16, 0x13, 0x83, 0x86,
            0x46, 0x43, 0xc3, 0xc6, 0x41, 0x14, 0xc1, 0x84, 0x11, 0x44, 0x81, 0xc4,
            0x1c, 0x48, 0xc8, 0x8c, 0x4c, 0x18, 0x88, 0xcc, 0x1a, 0x1e, 0x8a, 0x8e,
            0x4a, 0x4e, 0xca, 0xce, 0x35, 0x60, 0xe0, 0xa5, 0x65, 0x30, 0xa0, 0xe5,
            0x32, 0x37, 0xa2, 0xa7, 0x62, 0x67, 0xe2, 0xe7, 0x3d, 0x69, 0xe9, 0xad,
            0x6d, 0x39, 0xa9, 0xed, 0x3b, 0x3f, 0xab, 0xaf, 0x6b, 0x6f, 0xeb, 0xef,
            0x26, 0x23, 0xb3, 0xb6, 0x76, 0x73, 0xf3, 0xf6, 0x71, 0x24, 0xf1, 0xb4,
            0x21, 0x74, 0xb1, 0xf4, 0x2c, 0x78, 0xf8, 0xbc, 0x7c, 0x28, 0xb8, 0xfc,
            0x2a, 0x2e, 0xba, 0xbe, 0x7a, 0x7e, 0xfa, 0xfe, 0x25, 0x70, 0xf0, 0xb5,
            0x75, 0x20, 0xb0, 0xf5, 0x22, 0x27, 0xb2, 0xb7, 0x72, 0x77, 0xf2, 0xf7,
            0x2d, 0x79, 0xf9, 0xbd, 0x7d, 0x29, 0xb9, 0xfd, 0x2b, 0x2f, 0xbb, 0xbf,
            0x7b, 0x7f, 0xfb, 0xff,
        };

        const rcs: [64]u8 = [_]u8{
            0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3E, 0x3D, 0x3B,
            0x37, 0x2F, 0x1E, 0x3C, 0x39, 0x33, 0x27, 0x0E,
            0x1D, 0x3A, 0x35, 0x2B, 0x16, 0x2C, 0x18, 0x30,
            0x21, 0x02, 0x05, 0x0B, 0x17, 0x2E, 0x1C, 0x38,
            0x31, 0x23, 0x06, 0x0D, 0x1B, 0x36, 0x2D, 0x1A,
            0x34, 0x29, 0x12, 0x24, 0x08, 0x11, 0x22, 0x04,
            0x09, 0x13, 0x26, 0x0C, 0x19, 0x32, 0x25, 0x0A,
            0x15, 0x2A, 0x14, 0x28, 0x10, 0x20, 0x40, 0x80,
        };

        tweakey_states: [3][16]u8,
        precomputed_tk1: [rounds][16]u8,

        const num_tweakey_words: u32 = total_bytes / 16;

        const Self = @This();

        /// Initialize SKINNY cipher with key and optional tweak
        pub fn init(key: *const [key_bytes]u8, tweak: *const [tweak_bytes]u8) Self {
            var cipher = Self{
                .tweakey_states = @splat(@splat(0)),
                .precomputed_tk1 = @splat(@splat(0)),
            };

            cipher.initializeTweakeyStates(key, tweak);
            cipher.precomputeTK1RoundKeys();

            return cipher;
        }

        /// Precompute TK1 round keys (only PT permutation for key material)
        fn precomputeTK1RoundKeys(self: *Self) void {
            var current_tk1 = self.tweakey_states[0];
            self.precomputed_tk1[0] = current_tk1;

            for (1..rounds) |round| {
                applyPTPermutation(&current_tk1);
                self.precomputed_tk1[round] = current_tk1;
            }
        }

        /// Initialize the tweakey states TK1, TK2, TK3 based on key and tweak
        fn initializeTweakeyStates(self: *Self, key: *const [key_bytes]u8, tweak: *const [tweak_bytes]u8) void {
            self.tweakey_states = @splat(@splat(0));

            var concat: [total_bytes]u8 = undefined;
            @memcpy(concat[0..key_bytes], key);
            if (tweak_bytes > 0) {
                @memcpy(concat[key_bytes..][0..tweak_bytes], tweak);
            }

            const tk_words = total_bytes / 16;
            inline for (0..tk_words) |i| {
                @memcpy(&self.tweakey_states[i], concat[i * 16 ..][0..16]);
            }
        }

        /// Apply PT permutation to a tweakey state using @shuffle for optimal performance
        inline fn applyPTPermutation(state: *[16]u8) void {
            const pt_shuffle = [16]i32{ 9, 15, 8, 13, 10, 14, 12, 11, 0, 1, 2, 3, 4, 5, 6, 7 };
            const state_vec: Vec16u8 = @as(Vec16u8, state.*);
            const result_vec = @shuffle(u8, state_vec, undefined, pt_shuffle);
            state.* = @as([16]u8, result_vec);
        }

        /// Apply LFSR to the first two rows of a tweakey state (8-bit cells)
        /// SKINNY-128 uses 8-bit cells, so we need 8-bit LFSRs
        inline fn applyLFSR8bit(state: *[16]u8, tk_index: u32) void {
            const state_vec: Vec8u8 = state[0..8].*;

            const result_vec = if (tk_index == 1) blk: {
                const shifted_left = state_vec << @as(Vec8u8, @splat(1));
                const bit7 = state_vec >> @as(Vec8u8, @splat(7));
                const bit5 = (state_vec >> @as(Vec8u8, @splat(5))) & @as(Vec8u8, @splat(1));
                const feedback = bit7 ^ bit5;
                break :blk shifted_left ^ feedback;
            } else blk: {
                const shifted_right = state_vec >> @as(Vec8u8, @splat(1));
                const shifted_left7 = state_vec << @as(Vec8u8, @splat(7));
                const shifted_left1_masked = (state_vec << @as(Vec8u8, @splat(1))) & @as(Vec8u8, @splat(0x80));
                const feedback = shifted_left7 ^ shifted_left1_masked;
                break :blk shifted_right ^ feedback;
            };

            state[0..8].* = result_vec;
        }

        /// SubCells operation - apply 8-bit S-box to all bytes
        inline fn subCells(state: *[16]u8) void {
            for (state) |*byte| {
                byte.* = sbox8[byte.*];
            }
        }

        /// Inverse SubCells operation - apply inverse 8-bit S-box to all bytes
        inline fn subCellsInv(state: *[16]u8) void {
            for (state) |*byte| {
                byte.* = sbox8_inv[byte.*];
            }
        }

        /// AddConstants operation
        inline fn addConstants(state: *[16]u8, round: u32) void {
            const c0 = rcs[round] & 0x0F;
            const c1 = (rcs[round] >> 4) & 0x03;
            const c2 = 0x02;

            state[0] ^= c0;
            state[4] ^= c1;
            state[8] ^= c2;
        }

        inline fn shiftRows(state: *[16]u8) void {
            const shuffle_pattern = [16]i32{ 0, 1, 2, 3, 7, 4, 5, 6, 10, 11, 8, 9, 13, 14, 15, 12 };
            const state_vec: Vec16u8 = @as(Vec16u8, state.*);
            const result_vec = @shuffle(u8, state_vec, undefined, shuffle_pattern);
            state.* = @as([16]u8, result_vec);
        }

        inline fn shiftRowsInv(state: *[16]u8) void {
            const shuffle_pattern_inv = [16]i32{ 0, 1, 2, 3, 5, 6, 7, 4, 10, 11, 8, 9, 15, 12, 13, 14 };
            const state_vec: Vec16u8 = @as(Vec16u8, state.*);
            const result_vec = @shuffle(u8, state_vec, undefined, shuffle_pattern_inv);
            state.* = @as([16]u8, result_vec);
        }

        /// MixColumns operation - vectorized for 4-byte columns
        fn mixColumns(state: *[16]u8) void {
            inline for (0..4) |col| {
                const row0 = state[0 + col];
                const row1 = state[4 + col];
                const row2 = state[8 + col];
                const row3 = state[12 + col];

                const mix_1 = row1 ^ row2;
                const mix_2 = row0 ^ row2;
                const mix_3 = row3 ^ mix_2;

                state[0 + col] = mix_3;
                state[4 + col] = row0;
                state[8 + col] = mix_1;
                state[12 + col] = mix_2;
            }
        }

        /// Inverse MixColumns operation
        fn mixColumnsInv(state: *[16]u8) void {
            inline for (0..4) |col| {
                const row0 = state[0 + col];
                const row1 = state[4 + col];
                const row2 = state[8 + col];
                const row3 = state[12 + col];

                const orig_row0 = row1;
                const orig_row2 = orig_row0 ^ row3;
                const orig_row1 = row2 ^ orig_row2;
                const orig_row3 = row0 ^ row3;

                state[0 + col] = orig_row0;
                state[4 + col] = orig_row1;
                state[8 + col] = orig_row2;
                state[12 + col] = orig_row3;
            }
        }

        /// Incremental tweakey schedule with precomputed TK1
        const TweakeySchedule = struct {
            tk2_state: [16]u8,
            tk3_state: [16]u8,
            current_round: u32,

            fn init(tweakey_states: [3][16]u8) TweakeySchedule {
                return .{
                    .tk2_state = tweakey_states[1],
                    .tk3_state = tweakey_states[2],
                    .current_round = 0,
                };
            }

            fn updateToRound(self: *TweakeySchedule, target_round: u32) void {
                while (self.current_round < target_round) {
                    if (num_tweakey_words > 1) {
                        applyPTPermutation(&self.tk2_state);
                        applyLFSR8bit(&self.tk2_state, 1);
                    }

                    if (num_tweakey_words > 2) {
                        applyPTPermutation(&self.tk3_state);
                        applyLFSR8bit(&self.tk3_state, 2);
                    }

                    self.current_round += 1;
                }
            }
        };

        /// Generate round tweakey using precomputed TK1 and incremental updates
        fn generateRoundTweakey(self: *const Self, round: u32, round_tweakey: *[16]u8, schedule: *TweakeySchedule) void {
            @memset(round_tweakey, 0);
            schedule.updateToRound(round);

            var tweakey_vec: Vec8u8 = self.precomputed_tk1[round][0..8].*;
            if (num_tweakey_words > 1) {
                tweakey_vec ^= schedule.tk2_state[0..8].*;
            }
            if (num_tweakey_words > 2) {
                tweakey_vec ^= schedule.tk3_state[0..8].*;
            }
            round_tweakey[0..8].* = tweakey_vec;
        }

        /// AddRoundTweakey operation - XORs rows 0 and 1 with tweakey
        inline fn addRoundTweakey(state: *[16]u8, round_tweakey: *const [16]u8) void {
            const state_vec: Vec8u8 = state[0..8].*;
            const tweakey_vec: Vec8u8 = round_tweakey[0..8].*;
            state[0..8].* = state_vec ^ tweakey_vec;
        }

        /// Encrypt a 128-bit block
        pub fn encrypt(self: *const Self, plaintext: *const [16]u8, ciphertext: *[16]u8) void {
            @memcpy(ciphertext, plaintext);
            var round_tweakey: [16]u8 = undefined;
            var schedule = TweakeySchedule.init(self.tweakey_states);

            var round: u32 = 0;
            while (round < rounds) : (round += 1) {
                subCells(ciphertext);
                addConstants(ciphertext, round);

                self.generateRoundTweakey(round, &round_tweakey, &schedule);
                addRoundTweakey(ciphertext, &round_tweakey);

                shiftRows(ciphertext);
                mixColumns(ciphertext);
            }
        }

        /// Decrypt a 128-bit block
        pub fn decrypt(self: *const Self, ciphertext: *const [16]u8, plaintext: *[16]u8) void {
            @memcpy(plaintext, ciphertext);

            var all_round_keys: [rounds][16]u8 = undefined;
            var schedule = TweakeySchedule.init(self.tweakey_states);

            for (0..rounds) |round| {
                self.generateRoundTweakey(@intCast(round), &all_round_keys[round], &schedule);
            }

            var round: usize = rounds;
            while (round > 0) {
                round -= 1;

                mixColumnsInv(plaintext);
                shiftRowsInv(plaintext);
                addRoundTweakey(plaintext, &all_round_keys[round]);
                addConstants(plaintext, @intCast(round));
                subCellsInv(plaintext);
            }
        }
    };
}

/// Create SKINNY-128 cipher type with specified key and tweak sizes
fn Skinny128(comptime key_bits_param: u16, comptime tweak_bits_param: u16) type {
    const cfg = Config{ .key_bits = key_bits_param, .tweak_bits = tweak_bits_param };
    const key_bytes = key_bits_param / 8;
    const tweak_bytes = tweak_bits_param / 8;
    const total_bits = key_bits_param + tweak_bits_param;
    const num_rounds = switch (total_bits) {
        128 => 40,
        256 => 48,
        384 => 56,
        else => @compileError("Invalid tweakey size"),
    };

    return if (tweak_bits_param == 0) struct {
        // Key-only variant
        pub const block_length: usize = 16;
        pub const key_bits: usize = key_bits_param;
        pub const rounds = num_rounds;

        pub fn initEnc(key: [key_bytes]u8) Ctx(cfg, true) {
            return Ctx(cfg, true).init(key);
        }

        pub fn initDec(key: [key_bytes]u8) Ctx(cfg, false) {
            return Ctx(cfg, false).init(key);
        }
    } else struct {
        // Tweakable variant (key + tweak)
        pub const block_length: usize = 16;
        pub const key_bits: usize = key_bits_param;
        pub const tweak_bits: usize = tweak_bits_param;
        pub const rounds = num_rounds;

        pub fn initEnc(key: [key_bytes]u8, tweak: [tweak_bytes]u8) Ctx(cfg, true) {
            return Ctx(cfg, true).initWithTweak(key, tweak);
        }

        pub fn initDec(key: [key_bytes]u8, tweak: [tweak_bytes]u8) Ctx(cfg, false) {
            return Ctx(cfg, false).initWithTweak(key, tweak);
        }
    };
}

/// Context for SKINNY-128 (encryption or decryption)
fn Ctx(comptime cfg: Config, comptime is_encrypt: bool) type {
    const Impl = GenericImpl(cfg);
    return struct {
        pub const block_length = 16;
        impl: Impl,

        /// Initialize with key only (tweak will be zero)
        pub fn init(key: [cfg.key_bits / 8]u8) @This() {
            const empty_tweak: [cfg.tweak_bits / 8]u8 = .{};
            return .{ .impl = Impl.init(&key, &empty_tweak) };
        }

        /// Initialize with both key and tweak
        pub fn initWithTweak(key: [cfg.key_bits / 8]u8, tweak: [cfg.tweak_bits / 8]u8) @This() {
            return .{ .impl = Impl.init(&key, &tweak) };
        }

        pub fn encrypt(ctx: @This(), dst: *[16]u8, src: *const [16]u8) void {
            comptime if (!is_encrypt) @compileError("Cannot encrypt with decryption context");
            ctx.impl.encrypt(src, dst);
        }

        pub fn decrypt(ctx: @This(), dst: *[16]u8, src: *const [16]u8) void {
            comptime if (is_encrypt) @compileError("Cannot decrypt with encryption context");
            ctx.impl.decrypt(src, dst);
        }
    };
}

test "SKINNY-128-256 roundtrip" {
    var tk1: [16]u8 = undefined;
    var tk2: [16]u8 = undefined;
    var plaintext: [16]u8 = undefined;
    var expected: [16]u8 = undefined;

    _ = try std.fmt.hexToBytes(&tk1, "c683dc9e0ad25edf7d6300367d4b8665");
    _ = try std.fmt.hexToBytes(&tk2, "7926f29ea97cf5d67a08d6446cb7ce32");
    _ = try std.fmt.hexToBytes(&plaintext, "e82da08d25828a562dfd13ffca64e18a");
    _ = try std.fmt.hexToBytes(&expected, "8a7fa5c2f46472123f28c639cfa00824");

    var key: [32]u8 = undefined;
    @memcpy(key[0..16], &tk1);
    @memcpy(key[16..32], &tk2);

    const enc_ctx = Skinny128_256.initEnc(key);
    const dec_ctx = Skinny128_256.initDec(key);

    var ciphertext: [16]u8 = undefined;
    var decrypted: [16]u8 = undefined;

    enc_ctx.encrypt(&ciphertext, &plaintext);
    dec_ctx.decrypt(&decrypted, &ciphertext);

    try testing.expectEqualSlices(u8, &expected, &ciphertext);
    try testing.expectEqualSlices(u8, &plaintext, &decrypted);
}

test "SKINNY-128-384 roundtrip" {
    var tk1: [16]u8 = undefined;
    var tk2: [16]u8 = undefined;
    var tk3: [16]u8 = undefined;
    var plaintext: [16]u8 = undefined;
    var expected: [16]u8 = undefined;

    _ = try std.fmt.hexToBytes(&tk1, "b372cdd48ca7d309d10f2fb2e6f5fe2a");
    _ = try std.fmt.hexToBytes(&tk2, "365b015aac7bfd8f4b06b919864c3839");
    _ = try std.fmt.hexToBytes(&tk3, "be050e4bade1547ef08330d6792e01af");
    _ = try std.fmt.hexToBytes(&plaintext, "44405dd624507aa3e3d0092ace7f931f");
    _ = try std.fmt.hexToBytes(&expected, "4b25c67cf6f5d9dca8d718120fe3903c");

    var key: [48]u8 = undefined;
    @memcpy(key[0..16], &tk1);
    @memcpy(key[16..32], &tk2);
    @memcpy(key[32..48], &tk3);

    const enc_ctx = Skinny128_384.initEnc(key);
    const dec_ctx = Skinny128_384.initDec(key);

    var ciphertext: [16]u8 = undefined;
    var decrypted: [16]u8 = undefined;

    enc_ctx.encrypt(&ciphertext, &plaintext);
    dec_ctx.decrypt(&decrypted, &ciphertext);

    try testing.expectEqualSlices(u8, &expected, &ciphertext);
    try testing.expectEqualSlices(u8, &plaintext, &decrypted);
}

test "SKINNY-128-128 roundtrip" {
    const key: [16]u8 = @splat(0x01);
    const plaintext: [16]u8 = @splat(0xAB);

    const enc_ctx = Skinny128_128.initEnc(key);
    const dec_ctx = Skinny128_128.initDec(key);

    var ciphertext: [16]u8 = undefined;
    var decrypted: [16]u8 = undefined;

    enc_ctx.encrypt(&ciphertext, &plaintext);
    dec_ctx.decrypt(&decrypted, &ciphertext);

    try testing.expectEqualSlices(u8, &plaintext, &decrypted);
}

test "SKINNY-128T-128-128 (tweakable) roundtrip" {
    const key: [16]u8 = @splat(0x01);
    const tweak: [16]u8 = @splat(0x02);
    const plaintext: [16]u8 = @splat(0xAB);

    const enc_ctx = Skinny128T_128_128.initEnc(key, tweak);
    const dec_ctx = Skinny128T_128_128.initDec(key, tweak);

    var ciphertext: [16]u8 = undefined;
    var decrypted: [16]u8 = undefined;

    enc_ctx.encrypt(&ciphertext, &plaintext);
    dec_ctx.decrypt(&decrypted, &ciphertext);

    try testing.expectEqualSlices(u8, &plaintext, &decrypted);
}

test "SKINNY-128T-128-256 (tweakable) roundtrip" {
    const key: [16]u8 = @splat(0x01);
    const tweak: [32]u8 = @splat(0x02);
    const plaintext: [16]u8 = @splat(0xAB);

    const enc_ctx = Skinny128T_128_256.initEnc(key, tweak);
    const dec_ctx = Skinny128T_128_256.initDec(key, tweak);

    var ciphertext: [16]u8 = undefined;
    var decrypted: [16]u8 = undefined;

    enc_ctx.encrypt(&ciphertext, &plaintext);
    dec_ctx.decrypt(&decrypted, &ciphertext);

    try testing.expectEqualSlices(u8, &plaintext, &decrypted);
}

test "SKINNY-128T-256-128 (tweakable) roundtrip" {
    const key: [32]u8 = @splat(0x01);
    const tweak: [16]u8 = @splat(0x02);
    const plaintext: [16]u8 = @splat(0xAB);

    const enc_ctx = Skinny128T_256_128.initEnc(key, tweak);
    const dec_ctx = Skinny128T_256_128.initDec(key, tweak);

    var ciphertext: [16]u8 = undefined;
    var decrypted: [16]u8 = undefined;

    enc_ctx.encrypt(&ciphertext, &plaintext);
    dec_ctx.decrypt(&decrypted, &ciphertext);

    try testing.expectEqualSlices(u8, &plaintext, &decrypted);
}

test "SKINNY-128T-128-128 tweak changes ciphertext" {
    const key: [16]u8 = @splat(0x01);
    const tweak1: [16]u8 = @splat(0x02);
    const tweak2: [16]u8 = @splat(0x03);
    const plaintext: [16]u8 = @splat(0xAB);

    const enc_ctx1 = Skinny128T_128_128.initEnc(key, tweak1);
    const enc_ctx2 = Skinny128T_128_128.initEnc(key, tweak2);

    var ciphertext1: [16]u8 = undefined;
    var ciphertext2: [16]u8 = undefined;

    enc_ctx1.encrypt(&ciphertext1, &plaintext);
    enc_ctx2.encrypt(&ciphertext2, &plaintext);

    // Different tweaks should produce different ciphertexts
    var different = false;
    for (ciphertext1, ciphertext2) |c1, c2| {
        if (c1 != c2) {
            different = true;
            break;
        }
    }
    try testing.expect(different);
}

test "SKINNY-128 official test vectors" {
    // SKINNY-128-256 (48 rounds)
    {
        var tk1: [16]u8 = undefined;
        var tk2: [16]u8 = undefined;
        var plaintext: [16]u8 = undefined;
        var expected_ciphertext: [16]u8 = undefined;

        _ = try std.fmt.hexToBytes(&tk1, "c683dc9e0ad25edf7d6300367d4b8665");
        _ = try std.fmt.hexToBytes(&tk2, "7926f29ea97cf5d67a08d6446cb7ce32");
        _ = try std.fmt.hexToBytes(&plaintext, "e82da08d25828a562dfd13ffca64e18a");
        _ = try std.fmt.hexToBytes(&expected_ciphertext, "8a7fa5c2f46472123f28c639cfa00824");

        var key: [32]u8 = undefined;
        @memcpy(key[0..16], &tk1);
        @memcpy(key[16..32], &tk2);

        const enc_ctx = Skinny128_256.initEnc(key);
        const dec_ctx = Skinny128_256.initDec(key);

        var ciphertext: [16]u8 = undefined;
        var decrypted: [16]u8 = undefined;

        enc_ctx.encrypt(&ciphertext, &plaintext);
        dec_ctx.decrypt(&decrypted, &ciphertext);

        try testing.expectEqualSlices(u8, &expected_ciphertext, &ciphertext);
        try testing.expectEqualSlices(u8, &plaintext, &decrypted);
    }

    // SKINNY-128-384 (56 rounds)
    {
        var tk1: [16]u8 = undefined;
        var tk2: [16]u8 = undefined;
        var tk3: [16]u8 = undefined;
        var plaintext: [16]u8 = undefined;
        var expected_ciphertext: [16]u8 = undefined;

        _ = try std.fmt.hexToBytes(&tk1, "b372cdd48ca7d309d10f2fb2e6f5fe2a");
        _ = try std.fmt.hexToBytes(&tk2, "365b015aac7bfd8f4b06b919864c3839");
        _ = try std.fmt.hexToBytes(&tk3, "be050e4bade1547ef08330d6792e01af");
        _ = try std.fmt.hexToBytes(&plaintext, "44405dd624507aa3e3d0092ace7f931f");
        _ = try std.fmt.hexToBytes(&expected_ciphertext, "4b25c67cf6f5d9dca8d718120fe3903c");

        var key: [48]u8 = undefined;
        @memcpy(key[0..16], &tk1);
        @memcpy(key[16..32], &tk2);
        @memcpy(key[32..48], &tk3);

        const enc_ctx = Skinny128_384.initEnc(key);
        const dec_ctx = Skinny128_384.initDec(key);

        var ciphertext: [16]u8 = undefined;
        var decrypted: [16]u8 = undefined;

        enc_ctx.encrypt(&ciphertext, &plaintext);
        dec_ctx.decrypt(&decrypted, &ciphertext);

        try testing.expectEqualSlices(u8, &expected_ciphertext, &ciphertext);
        try testing.expectEqualSlices(u8, &plaintext, &decrypted);
    }
}
