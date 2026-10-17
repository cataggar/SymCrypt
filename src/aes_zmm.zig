// Copyright (c) Microsoft Corporation. Licensed under the MIT license.

const types = @import("types.zig");
const aes_xmm = @import("aes_xmm.zig");

const SYMCRYPT_AES_BLOCK_SIZE = types.SYMCRYPT_AES_BLOCK_SIZE;
const SYMCRYPT_AES_EXPANDED_KEY = types.SYMCRYPT_AES_EXPANDED_KEY;
const SYMCRYPT_GF128_FIELD_ELEMENT = types.SYMCRYPT_GF128_ELEMENT;

const V16u8 = @Vector(16, u8);
const V4u32 = @Vector(4, u32);
const V2u64 = @Vector(2, u64);

inline fn load128(ptr: [*]const u8) V16u8 {
    return @as(*align(1) const V16u8, @ptrCast(ptr)).*;
}

inline fn store128(ptr: [*]u8, v: V16u8) void {
    @as(*align(1) V16u8, @ptrCast(ptr)).* = v;
}

inline fn loadGF128(fe: *const SYMCRYPT_GF128_FIELD_ELEMENT) V16u8 {
    return @bitCast(fe.ull);
}

inline fn storeGF128(fe: *SYMCRYPT_GF128_FIELD_ELEMENT, v: V16u8) void {
    fe.ull = @bitCast(v);
}

inline fn zeroupper() void {
    asm volatile ("vzeroupper");
}

inline fn xtsMulAlpha(in_v: V16u8) V16u8 {
    const alpha_mask: V4u32 = .{ 0x87, 1, 1, 1 };
    const zero: V4u32 = @splat(0);
    const in_i32: @Vector(4, i32) = @bitCast(in_v);
    const zero_i32: @Vector(4, i32) = @splat(0);
    const cmp: V4u32 = @select(u32, zero_i32 > in_i32, @as(V4u32, @splat(0xffffffff)), @as(V4u32, @splat(0)));
    const t1: V2u64 = @as(V2u64, @bitCast(in_v)) << @splat(1);
    const t2: V16u8 = @shuffle(u8, @as(V16u8, @bitCast(cmp)), @as(V16u8, @bitCast(zero)), [16]i32{
        12, 13, 14, 15,
        0,  1,  2,  3,
        4,  5,  6,  7,
        8,  9,  10, 11,
    });
    const t2_masked: V4u32 = @as(V4u32, @bitCast(t2)) & alpha_mask;
    return @as(V16u8, @bitCast(t1)) ^ @as(V16u8, @bitCast(t2_masked));
}

inline fn xtsMulAlpha4(in_v: V16u8) V16u8 {
    const zero: V16u8 = @splat(0);
    const in_u64: V2u64 = @bitCast(in_v);
    const t1: V16u8 = @bitCast(in_u64 << @splat(4));
    const t2_shifted: V16u8 = @bitCast(in_u64 >> @splat(60));
    const t1_carry: V16u8 = @shuffle(u8, t2_shifted, zero, [16]i32{
        -1, -1, -1, -1, -1, -1, -1, -1,
        0,  1,  2,  3,  4,  5,  6,  7,
    });
    const t1_combined = t1 ^ t1_carry;
    const t2_hi: V16u8 = @shuffle(u8, t2_shifted, zero, [16]i32{
        8,  9,  10, 11, 12, 13, 14, 15,
        -1, -1, -1, -1, -1, -1, -1, -1,
    });
    const t2_u32: V4u32 = @bitCast(t2_hi);
    const poly: V4u32 = (t2_u32 << @splat(7)) ^ (t2_u32 << @splat(2)) ^ (t2_u32 << @splat(1)) ^ t2_u32;
    return t1_combined ^ @as(V16u8, @bitCast(poly));
}

inline fn xtsMulAlpha8(in_v: V16u8) V16u8 {
    const zero: V16u8 = @splat(0);
    const t1: V16u8 = @shuffle(u8, in_v, zero, [16]i32{
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
    });
    const t2: V16u8 = @shuffle(u8, in_v, zero, [16]i32{
        15, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    });
    const t2_u32: V4u32 = @bitCast(t2);
    const poly: V4u32 = (t2_u32 << @splat(7)) ^ (t2_u32 << @splat(2)) ^ (t2_u32 << @splat(1)) ^ t2_u32;
    return t1 ^ @as(V16u8, @bitCast(poly));
}

inline fn xtsMulAlpha16(in_v: V16u8) V16u8 {
    const zero: V16u8 = @splat(0);
    const in_u32: V4u32 = @bitCast(in_v);
    const t1: V16u8 = @bitCast(in_u32 << @splat(16));
    const t2: V16u8 = @bitCast(in_u32 >> @splat(16));
    const t1_carry: V16u8 = @shuffle(u8, t2, zero, [16]i32{
        -1, -1, -1, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
    });
    const t2_hi: V16u8 = @shuffle(u8, t2, zero, [16]i32{
        12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    });
    const t2_u32: V4u32 = @bitCast(t2_hi);
    const poly: V4u32 = (t2_u32 << @splat(7)) ^ (t2_u32 << @splat(2)) ^ (t2_u32 << @splat(1)) ^ t2_u32;
    return t1 ^ t1_carry ^ @as(V16u8, @bitCast(poly));
}

inline fn aesEncryptZmm2048(
    pExpandedKey: *const SYMCRYPT_AES_EXPANDED_KEY,
    buf: *[256]u8,
) void {
    var keyPtr: [*]const [4][4]u8 = @ptrCast(&pExpandedKey.RoundKey[0]);
    const keyLimit: [*]const [4][4]u8 = pExpandedKey.lastEncRoundKey;
    const bPtr: [*]u8 = buf;
    asm volatile (
        \\vmovdqu64 0(%[b]), %%zmm0
        \\vmovdqu64 64(%[b]), %%zmm1
        \\vmovdqu64 128(%[b]), %%zmm2
        \\vmovdqu64 192(%[b]), %%zmm3
        \\vbroadcasti32x4 (%[kp]), %%zmm4
        \\add $16, %[kp]
        \\vpxorq %%zmm4, %%zmm0, %%zmm0
        \\vpxorq %%zmm4, %%zmm1, %%zmm1
        \\vpxorq %%zmm4, %%zmm2, %%zmm2
        \\vpxorq %%zmm4, %%zmm3, %%zmm3
        \\1:
        \\vbroadcasti32x4 (%[kp]), %%zmm4
        \\add $16, %[kp]
        \\vaesenc %%zmm4, %%zmm0, %%zmm0
        \\vaesenc %%zmm4, %%zmm1, %%zmm1
        \\vaesenc %%zmm4, %%zmm2, %%zmm2
        \\vaesenc %%zmm4, %%zmm3, %%zmm3
        \\cmp %[kl], %[kp]
        \\jb 1b
        \\vbroadcasti32x4 (%[kp]), %%zmm4
        \\vaesenclast %%zmm4, %%zmm0, %%zmm0
        \\vaesenclast %%zmm4, %%zmm1, %%zmm1
        \\vaesenclast %%zmm4, %%zmm2, %%zmm2
        \\vaesenclast %%zmm4, %%zmm3, %%zmm3
        \\vmovdqu64 %%zmm0, 0(%[b])
        \\vmovdqu64 %%zmm1, 64(%[b])
        \\vmovdqu64 %%zmm2, 128(%[b])
        \\vmovdqu64 %%zmm3, 192(%[b])
        : [kp] "+r" (keyPtr),
        : [kl] "r" (keyLimit),
          [b] "r" (bPtr),
        : .{
          .xmm0 = true,
          .xmm1 = true,
          .xmm2 = true,
          .xmm3 = true,
          .xmm4 = true,
          .cc = true,
          .memory = true,
        });
}

inline fn aesDecryptZmm2048(
    pExpandedKey: *const SYMCRYPT_AES_EXPANDED_KEY,
    buf: *[256]u8,
) void {
    var keyPtr: [*]const [4][4]u8 = pExpandedKey.lastEncRoundKey;
    const keyLimit: [*]const [4][4]u8 = pExpandedKey.lastDecRoundKey;
    const bPtr: [*]u8 = buf;
    asm volatile (
        \\vmovdqu64 0(%[b]), %%zmm0
        \\vmovdqu64 64(%[b]), %%zmm1
        \\vmovdqu64 128(%[b]), %%zmm2
        \\vmovdqu64 192(%[b]), %%zmm3
        \\vbroadcasti32x4 (%[kp]), %%zmm4
        \\add $16, %[kp]
        \\vpxorq %%zmm4, %%zmm0, %%zmm0
        \\vpxorq %%zmm4, %%zmm1, %%zmm1
        \\vpxorq %%zmm4, %%zmm2, %%zmm2
        \\vpxorq %%zmm4, %%zmm3, %%zmm3
        \\1:
        \\vbroadcasti32x4 (%[kp]), %%zmm4
        \\add $16, %[kp]
        \\vaesdec %%zmm4, %%zmm0, %%zmm0
        \\vaesdec %%zmm4, %%zmm1, %%zmm1
        \\vaesdec %%zmm4, %%zmm2, %%zmm2
        \\vaesdec %%zmm4, %%zmm3, %%zmm3
        \\cmp %[kl], %[kp]
        \\jb 1b
        \\vbroadcasti32x4 (%[kp]), %%zmm4
        \\vaesdeclast %%zmm4, %%zmm0, %%zmm0
        \\vaesdeclast %%zmm4, %%zmm1, %%zmm1
        \\vaesdeclast %%zmm4, %%zmm2, %%zmm2
        \\vaesdeclast %%zmm4, %%zmm3, %%zmm3
        \\vmovdqu64 %%zmm0, 0(%[b])
        \\vmovdqu64 %%zmm1, 64(%[b])
        \\vmovdqu64 %%zmm2, 128(%[b])
        \\vmovdqu64 %%zmm3, 192(%[b])
        : [kp] "+r" (keyPtr),
        : [kl] "r" (keyLimit),
          [b] "r" (bPtr),
        : .{
          .xmm0 = true,
          .xmm1 = true,
          .xmm2 = true,
          .xmm3 = true,
          .xmm4 = true,
          .cc = true,
          .memory = true,
        });
}

inline fn aesEncryptZmm4096(
    pExpandedKey: *const SYMCRYPT_AES_EXPANDED_KEY,
    buf: *[512]u8,
) void {
    var keyPtr: [*]const [4][4]u8 = @ptrCast(&pExpandedKey.RoundKey[0]);
    const keyLimit: [*]const [4][4]u8 = pExpandedKey.lastEncRoundKey;
    const bPtr: [*]u8 = buf;
    asm volatile (
        \\vmovdqu64 0(%[b]), %%zmm0
        \\vmovdqu64 64(%[b]), %%zmm1
        \\vmovdqu64 128(%[b]), %%zmm2
        \\vmovdqu64 192(%[b]), %%zmm3
        \\vmovdqu64 256(%[b]), %%zmm4
        \\vmovdqu64 320(%[b]), %%zmm5
        \\vmovdqu64 384(%[b]), %%zmm6
        \\vmovdqu64 448(%[b]), %%zmm7
        \\vbroadcasti32x4 (%[kp]), %%zmm8
        \\add $16, %[kp]
        \\vpxorq %%zmm8, %%zmm0, %%zmm0
        \\vpxorq %%zmm8, %%zmm1, %%zmm1
        \\vpxorq %%zmm8, %%zmm2, %%zmm2
        \\vpxorq %%zmm8, %%zmm3, %%zmm3
        \\vpxorq %%zmm8, %%zmm4, %%zmm4
        \\vpxorq %%zmm8, %%zmm5, %%zmm5
        \\vpxorq %%zmm8, %%zmm6, %%zmm6
        \\vpxorq %%zmm8, %%zmm7, %%zmm7
        \\1:
        \\vbroadcasti32x4 (%[kp]), %%zmm8
        \\add $16, %[kp]
        \\vaesenc %%zmm8, %%zmm0, %%zmm0
        \\vaesenc %%zmm8, %%zmm1, %%zmm1
        \\vaesenc %%zmm8, %%zmm2, %%zmm2
        \\vaesenc %%zmm8, %%zmm3, %%zmm3
        \\vaesenc %%zmm8, %%zmm4, %%zmm4
        \\vaesenc %%zmm8, %%zmm5, %%zmm5
        \\vaesenc %%zmm8, %%zmm6, %%zmm6
        \\vaesenc %%zmm8, %%zmm7, %%zmm7
        \\cmp %[kl], %[kp]
        \\jb 1b
        \\vbroadcasti32x4 (%[kp]), %%zmm8
        \\vaesenclast %%zmm8, %%zmm0, %%zmm0
        \\vaesenclast %%zmm8, %%zmm1, %%zmm1
        \\vaesenclast %%zmm8, %%zmm2, %%zmm2
        \\vaesenclast %%zmm8, %%zmm3, %%zmm3
        \\vaesenclast %%zmm8, %%zmm4, %%zmm4
        \\vaesenclast %%zmm8, %%zmm5, %%zmm5
        \\vaesenclast %%zmm8, %%zmm6, %%zmm6
        \\vaesenclast %%zmm8, %%zmm7, %%zmm7
        \\vmovdqu64 %%zmm0, 0(%[b])
        \\vmovdqu64 %%zmm1, 64(%[b])
        \\vmovdqu64 %%zmm2, 128(%[b])
        \\vmovdqu64 %%zmm3, 192(%[b])
        \\vmovdqu64 %%zmm4, 256(%[b])
        \\vmovdqu64 %%zmm5, 320(%[b])
        \\vmovdqu64 %%zmm6, 384(%[b])
        \\vmovdqu64 %%zmm7, 448(%[b])
        : [kp] "+r" (keyPtr),
        : [kl] "r" (keyLimit),
          [b] "r" (bPtr),
        : .{
          .xmm0 = true,
          .xmm1 = true,
          .xmm2 = true,
          .xmm3 = true,
          .xmm4 = true,
          .xmm5 = true,
          .xmm6 = true,
          .xmm7 = true,
          .xmm8 = true,
          .cc = true,
          .memory = true,
        });
}

inline fn aesEncryptZmm512(
    pExpandedKey: *const SYMCRYPT_AES_EXPANDED_KEY,
    buf: *[64]u8,
) void {
    var keyPtr: [*]const [4][4]u8 = @ptrCast(&pExpandedKey.RoundKey[0]);
    const keyLimit: [*]const [4][4]u8 = pExpandedKey.lastEncRoundKey;
    const bPtr: [*]u8 = buf;
    asm volatile (
        \\vmovdqu64 0(%[b]), %%zmm0
        \\vbroadcasti32x4 (%[kp]), %%zmm1
        \\add $16, %[kp]
        \\vpxorq %%zmm1, %%zmm0, %%zmm0
        \\1:
        \\vbroadcasti32x4 (%[kp]), %%zmm1
        \\add $16, %[kp]
        \\vaesenc %%zmm1, %%zmm0, %%zmm0
        \\cmp %[kl], %[kp]
        \\jb 1b
        \\vbroadcasti32x4 (%[kp]), %%zmm1
        \\vaesenclast %%zmm1, %%zmm0, %%zmm0
        \\vmovdqu64 %%zmm0, 0(%[b])
        : [kp] "+r" (keyPtr),
        : [kl] "r" (keyLimit),
          [b] "r" (bPtr),
        : .{
          .xmm0 = true,
          .xmm1 = true,
          .cc = true,
          .memory = true,
        });
}

inline fn clmulAcc3Zmm(
    r_quad: *[4]V16u8,
    h_quad: *[4]V16u8,
    hx_quad: *[4]V16u8,
    a0: *[4]V16u8,
    a1: *[4]V16u8,
    a2: *[4]V16u8,
) void {
    asm volatile (
        \\vmovdqu64 (%[r]), %%zmm0
        \\vmovdqu64 (%[h]), %%zmm1
        \\vmovdqu64 (%[hx]), %%zmm2
        \\vpclmulqdq $0x00, %%zmm1, %%zmm0, %%zmm3
        \\vpclmulqdq $0x11, %%zmm1, %%zmm0, %%zmm4
        \\vpsrldq $8, %%zmm0, %%zmm5
        \\vpxorq %%zmm5, %%zmm0, %%zmm5
        \\vpclmulqdq $0x00, %%zmm2, %%zmm5, %%zmm5
        \\vmovdqu64 (%[a0]), %%zmm6
        \\vpxorq %%zmm3, %%zmm6, %%zmm6
        \\vmovdqu64 %%zmm6, (%[a0])
        \\vmovdqu64 (%[a1]), %%zmm6
        \\vpxorq %%zmm5, %%zmm6, %%zmm6
        \\vmovdqu64 %%zmm6, (%[a1])
        \\vmovdqu64 (%[a2]), %%zmm6
        \\vpxorq %%zmm4, %%zmm6, %%zmm6
        \\vmovdqu64 %%zmm6, (%[a2])
        :
        : [r] "r" (@as([*]const u8, @ptrCast(r_quad))),
          [h] "r" (@as([*]const u8, @ptrCast(h_quad))),
          [hx] "r" (@as([*]const u8, @ptrCast(hx_quad))),
          [a0] "r" (@as([*]u8, @ptrCast(a0))),
          [a1] "r" (@as([*]u8, @ptrCast(a1))),
          [a2] "r" (@as([*]u8, @ptrCast(a2))),
        : .{
          .xmm0 = true,
          .xmm1 = true,
          .xmm2 = true,
          .xmm3 = true,
          .xmm4 = true,
          .xmm5 = true,
          .xmm6 = true,
          .memory = true,
        });
}

inline fn clmul3Post(a0: *V16u8, a1: *V16u8, a2: *V16u8) void {
    aes_xmm.clmul3Post(a0, a1, a2);
}

inline fn modReduce(a0: V16u8, a1: V16u8, a2: V16u8, state: *V16u8) void {
    const vMultiplicationConstant: V16u8 = @bitCast(V4u32{ 0, 0xc2000000, 0, 0 });
    aes_xmm.modReduce(vMultiplicationConstant, a0, a1, a2, state);
}

inline fn byteReverse128(v: V16u8) V16u8 {
    return @shuffle(u8, v, v, [16]i32{
        15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
    });
}

inline fn add32x4(a: V16u8, b: V16u8) V16u8 {
    return @bitCast(@as(V4u32, @bitCast(a)) +% @as(V4u32, @bitCast(b)));
}

pub fn SymCryptXtsAesEncryptDataUnitZmm_2048(
    pExpandedKey: *const SYMCRYPT_AES_EXPANDED_KEY,
    pbTweakBlock: [*]u8,
    pbScratch: [*]u8,
    pbSrc: [*]const u8,
    pbDst: [*]u8,
    cbData: usize,
) callconv(types.SYMCRYPT_CALL) void {
    var cbDataTail = cbData & ((16 * SYMCRYPT_AES_BLOCK_SIZE) - 1);
    if (cbDataTail > 0 and cbDataTail < SYMCRYPT_AES_BLOCK_SIZE) {
        cbDataTail += 16 * SYMCRYPT_AES_BLOCK_SIZE;
    }
    var cbDataMain = cbData - cbDataTail;

    if (cbDataMain == 0) {
        aes_xmm.SymCryptXtsAesEncryptDataUnitXmm(pExpandedKey, pbTweakBlock, pbScratch, pbSrc, pbDst, cbDataTail);
        return;
    }

    var tweaks: [16]V16u8 = undefined;
    tweaks[0] = load128(pbTweakBlock);
    tweaks[4] = xtsMulAlpha4(tweaks[0]);
    tweaks[1] = xtsMulAlpha(tweaks[0]);
    tweaks[5] = xtsMulAlpha(tweaks[4]);
    tweaks[2] = xtsMulAlpha(tweaks[1]);
    tweaks[6] = xtsMulAlpha(tweaks[5]);
    tweaks[3] = xtsMulAlpha(tweaks[2]);
    tweaks[7] = xtsMulAlpha(tweaks[6]);
    inline for (0..8) |i| {
        tweaks[8 + i] = xtsMulAlpha8(tweaks[i]);
    }

    var src = pbSrc;
    var dst = pbDst;
    var buf: [256]u8 = undefined;

    while (true) {
        inline for (0..16) |i| {
            store128(buf[i * 16 ..].ptr, tweaks[i] ^ load128(src + i * 16));
        }
        src += 16 * SYMCRYPT_AES_BLOCK_SIZE;

        aesEncryptZmm2048(pExpandedKey, &buf);

        inline for (0..16) |i| {
            store128(dst + i * 16, load128(buf[i * 16 ..].ptr) ^ tweaks[i]);
        }
        dst += 16 * SYMCRYPT_AES_BLOCK_SIZE;

        cbDataMain -= 16 * SYMCRYPT_AES_BLOCK_SIZE;
        if (cbDataMain < 16 * SYMCRYPT_AES_BLOCK_SIZE) {
            break;
        }

        inline for (0..16) |i| {
            tweaks[i] = xtsMulAlpha16(tweaks[i]);
        }
    }

    if (cbDataTail > 0) {
        zeroupper();
        const next_tweak = xtsMulAlpha(tweaks[15]);
        store128(pbTweakBlock, next_tweak);
        aes_xmm.SymCryptXtsAesEncryptDataUnitXmm(pExpandedKey, pbTweakBlock, pbScratch, src, dst, cbDataTail);
    } else {
        zeroupper();
    }
}

pub fn SymCryptXtsAesDecryptDataUnitZmm_2048(
    pExpandedKey: *const SYMCRYPT_AES_EXPANDED_KEY,
    pbTweakBlock: [*]u8,
    pbScratch: [*]u8,
    pbSrc: [*]const u8,
    pbDst: [*]u8,
    cbData: usize,
) callconv(types.SYMCRYPT_CALL) void {
    var cbDataTail = cbData & ((16 * SYMCRYPT_AES_BLOCK_SIZE) - 1);
    if (cbDataTail > 0 and cbDataTail < SYMCRYPT_AES_BLOCK_SIZE) {
        cbDataTail += 16 * SYMCRYPT_AES_BLOCK_SIZE;
    }
    var cbDataMain = cbData - cbDataTail;

    if (cbDataMain == 0) {
        aes_xmm.SymCryptXtsAesDecryptDataUnitXmm(pExpandedKey, pbTweakBlock, pbScratch, pbSrc, pbDst, cbDataTail);
        return;
    }

    var tweaks: [16]V16u8 = undefined;
    tweaks[0] = load128(pbTweakBlock);
    tweaks[4] = xtsMulAlpha4(tweaks[0]);
    tweaks[1] = xtsMulAlpha(tweaks[0]);
    tweaks[5] = xtsMulAlpha(tweaks[4]);
    tweaks[2] = xtsMulAlpha(tweaks[1]);
    tweaks[6] = xtsMulAlpha(tweaks[5]);
    tweaks[3] = xtsMulAlpha(tweaks[2]);
    tweaks[7] = xtsMulAlpha(tweaks[6]);
    inline for (0..8) |i| {
        tweaks[8 + i] = xtsMulAlpha8(tweaks[i]);
    }

    var src = pbSrc;
    var dst = pbDst;
    var buf: [256]u8 = undefined;

    while (true) {
        inline for (0..16) |i| {
            store128(buf[i * 16 ..].ptr, tweaks[i] ^ load128(src + i * 16));
        }
        src += 16 * SYMCRYPT_AES_BLOCK_SIZE;

        aesDecryptZmm2048(pExpandedKey, &buf);

        inline for (0..16) |i| {
            store128(dst + i * 16, load128(buf[i * 16 ..].ptr) ^ tweaks[i]);
        }
        dst += 16 * SYMCRYPT_AES_BLOCK_SIZE;

        cbDataMain -= 16 * SYMCRYPT_AES_BLOCK_SIZE;
        if (cbDataMain < 16 * SYMCRYPT_AES_BLOCK_SIZE) {
            break;
        }

        inline for (0..16) |i| {
            tweaks[i] = xtsMulAlpha16(tweaks[i]);
        }
    }

    if (cbDataTail > 0) {
        zeroupper();
        const next_tweak = xtsMulAlpha(tweaks[15]);
        store128(pbTweakBlock, next_tweak);
        aes_xmm.SymCryptXtsAesDecryptDataUnitXmm(pExpandedKey, pbTweakBlock, pbScratch, src, dst, cbDataTail);
    } else {
        zeroupper();
    }
}

pub fn SymCryptAesGcmEncryptStitchedZmm(
    pExpandedKey: *const SYMCRYPT_AES_EXPANDED_KEY,
    pbChainingValue: [*]u8,
    expandedKeyTable: [*]const SYMCRYPT_GF128_FIELD_ELEMENT,
    pStateInOut: *SYMCRYPT_GF128_FIELD_ELEMENT,
    pbSrc: [*]const u8,
    pbDst: [*]u8,
    cbData: usize,
) callconv(types.SYMCRYPT_CALL) void {
    var nBlocks = cbData / SYMCRYPT_AES_BLOCK_SIZE;
    var src = pbSrc;
    var dst = pbDst;

    var state = loadGF128(pStateInOut);
    var ctr = byteReverse128(load128(pbChainingValue));
    const one: V16u8 = @bitCast(V4u32{ 1, 0, 0, 0 });
    const two: V16u8 = @bitCast(V4u32{ 2, 0, 0, 0 });
    const three: V16u8 = @bitCast(V4u32{ 3, 0, 0, 0 });
    const four: V16u8 = @bitCast(V4u32{ 4, 0, 0, 0 });

    var ctr_quad: [4]V16u8 = .{
        ctr,
        add32x4(ctr, one),
        add32x4(ctr, two),
        add32x4(ctr, three),
    };

    if (nBlocks >= 32) {
        var h_quads: [8][4]V16u8 = undefined;
        var hx_quads: [8][4]V16u8 = undefined;
        inline for (0..8) |i| {
            inline for (0..4) |j| {
                const ind = 32 - (4 * i + j);
                h_quads[i][j] = loadGF128(&expandedKeyTable[32 - ind]);
                hx_quads[i][j] = loadGF128(&expandedKeyTable[64 - ind]);
            }
        }

        var buf: [512]u8 = undefined;
        var r_quads: [8][4]V16u8 = undefined;

        inline for (0..8) |i| {
            inline for (0..4) |j| {
                const c = ctr_quad[j];
                store128(buf[(4 * i + j) * 16 ..].ptr, byteReverse128(c));
                ctr_quad[j] = add32x4(c, four);
            }
        }

        aesEncryptZmm4096(pExpandedKey, &buf);

        inline for (0..8) |i| {
            inline for (0..4) |j| {
                const off = (4 * i + j) * 16;
                const ct = load128(buf[off..].ptr) ^ load128(src + off);
                store128(dst + off, ct);
                r_quads[i][j] = byteReverse128(ct) ^ (if (i == 0 and j == 0) state else @as(V16u8, @splat(0)));
            }
        }

        src += 32 * SYMCRYPT_AES_BLOCK_SIZE;
        dst += 32 * SYMCRYPT_AES_BLOCK_SIZE;
        nBlocks -= 32;

        while (nBlocks >= 32) {
            inline for (0..8) |i| {
                inline for (0..4) |j| {
                    const c = ctr_quad[j];
                    store128(buf[(4 * i + j) * 16 ..].ptr, byteReverse128(c));
                    ctr_quad[j] = add32x4(c, four);
                }
            }

            aesEncryptZmm4096(pExpandedKey, &buf);

            var a0: [4]V16u8 = .{ @splat(0), @splat(0), @splat(0), @splat(0) };
            var a1: [4]V16u8 = .{ @splat(0), @splat(0), @splat(0), @splat(0) };
            var a2: [4]V16u8 = .{ @splat(0), @splat(0), @splat(0), @splat(0) };
            inline for (0..8) |i| {
                clmulAcc3Zmm(&r_quads[i], &h_quads[i], &hx_quads[i], &a0, &a1, &a2);
            }

            var a0_128 = (a0[0] ^ a0[1]) ^ (a0[2] ^ a0[3]);
            var a1_128 = (a1[0] ^ a1[1]) ^ (a1[2] ^ a1[3]);
            var a2_128 = (a2[0] ^ a2[1]) ^ (a2[2] ^ a2[3]);
            clmul3Post(&a0_128, &a1_128, &a2_128);
            modReduce(a0_128, a1_128, a2_128, &state);

            inline for (0..8) |i| {
                inline for (0..4) |j| {
                    const off = (4 * i + j) * 16;
                    const ct = load128(buf[off..].ptr) ^ load128(src + off);
                    store128(dst + off, ct);
                    r_quads[i][j] = byteReverse128(ct) ^ (if (i == 0 and j == 0) state else @as(V16u8, @splat(0)));
                }
            }

            src += 32 * SYMCRYPT_AES_BLOCK_SIZE;
            dst += 32 * SYMCRYPT_AES_BLOCK_SIZE;
            nBlocks -= 32;
        }

        var a0: [4]V16u8 = .{ @splat(0), @splat(0), @splat(0), @splat(0) };
        var a1: [4]V16u8 = .{ @splat(0), @splat(0), @splat(0), @splat(0) };
        var a2: [4]V16u8 = .{ @splat(0), @splat(0), @splat(0), @splat(0) };
        inline for (0..8) |i| {
            clmulAcc3Zmm(&r_quads[i], &h_quads[i], &hx_quads[i], &a0, &a1, &a2);
        }

        var a0_128 = (a0[0] ^ a0[1]) ^ (a0[2] ^ a0[3]);
        var a1_128 = (a1[0] ^ a1[1]) ^ (a1[2] ^ a1[3]);
        var a2_128 = (a2[0] ^ a2[1]) ^ (a2[2] ^ a2[3]);
        clmul3Post(&a0_128, &a1_128, &a2_128);
        modReduce(a0_128, a1_128, a2_128, &state);
    }

    if (nBlocks > 0) {
        var a0: [4]V16u8 = .{ @splat(0), @splat(0), @splat(0), @splat(0) };
        var a1: [4]V16u8 = .{ @splat(0), @splat(0), @splat(0), @splat(0) };
        var a2: [4]V16u8 = .{ @splat(0), @splat(0), @splat(0), @splat(0) };
        var state_xored = false;
        var buf64: [64]u8 = undefined;

        while (nBlocks >= 4) {
            inline for (0..4) |j| {
                const c = ctr_quad[j];
                store128(buf64[j * 16 ..].ptr, byteReverse128(c));
                ctr_quad[j] = add32x4(c, four);
            }

            aesEncryptZmm512(pExpandedKey, &buf64);

            var r_quad: [4]V16u8 = undefined;
            var h_quad: [4]V16u8 = undefined;
            var hx_quad: [4]V16u8 = undefined;
            inline for (0..4) |j| {
                const ct = load128(buf64[j * 16 ..].ptr) ^ load128(src + j * 16);
                store128(dst + j * 16, ct);
                r_quad[j] = byteReverse128(ct) ^ (if (!state_xored and j == 0) state else @as(V16u8, @splat(0)));
                const ind = nBlocks - j;
                h_quad[j] = loadGF128(&expandedKeyTable[32 - ind]);
                hx_quad[j] = loadGF128(&expandedKeyTable[64 - ind]);
            }
            state_xored = true;
            clmulAcc3Zmm(&r_quad, &h_quad, &hx_quad, &a0, &a1, &a2);

            src += 4 * SYMCRYPT_AES_BLOCK_SIZE;
            dst += 4 * SYMCRYPT_AES_BLOCK_SIZE;
            nBlocks -= 4;
        }

        if (nBlocks > 0) {
            inline for (0..4) |j| {
                store128(buf64[j * 16 ..].ptr, byteReverse128(ctr_quad[j]));
            }
            aesEncryptZmm512(pExpandedKey, &buf64);

            var r_quad: [4]V16u8 = .{ @splat(0), @splat(0), @splat(0), @splat(0) };
            var h_quad: [4]V16u8 = .{ @splat(0), @splat(0), @splat(0), @splat(0) };
            var hx_quad: [4]V16u8 = .{ @splat(0), @splat(0), @splat(0), @splat(0) };

            for (0..nBlocks) |j| {
                const ct = load128(buf64[j * 16 ..].ptr) ^ load128(src + j * 16);
                store128(dst + j * 16, ct);
                r_quad[j] = byteReverse128(ct) ^ (if (!state_xored and j == 0) state else @as(V16u8, @splat(0)));
                const ind = nBlocks - j;
                h_quad[j] = loadGF128(&expandedKeyTable[32 - ind]);
                hx_quad[j] = loadGF128(&expandedKeyTable[64 - ind]);
            }
            clmulAcc3Zmm(&r_quad, &h_quad, &hx_quad, &a0, &a1, &a2);

            const rem_vec: V16u8 = @bitCast(V4u32{ @intCast(nBlocks), 0, 0, 0 });
            ctr_quad[0] = add32x4(ctr_quad[0], rem_vec);
        }

        var a0_128 = (a0[0] ^ a0[1]) ^ (a0[2] ^ a0[3]);
        var a1_128 = (a1[0] ^ a1[1]) ^ (a1[2] ^ a1[3]);
        var a2_128 = (a2[0] ^ a2[1]) ^ (a2[2] ^ a2[3]);
        clmul3Post(&a0_128, &a1_128, &a2_128);
        modReduce(a0_128, a1_128, a2_128, &state);
    }

    ctr = ctr_quad[0];
    zeroupper();

    store128(pbChainingValue, byteReverse128(ctr));
    storeGF128(pStateInOut, state);
}

pub fn SymCryptAesGcmDecryptStitchedZmm(
    pExpandedKey: *const SYMCRYPT_AES_EXPANDED_KEY,
    pbChainingValue: [*]u8,
    expandedKeyTable: [*]const SYMCRYPT_GF128_FIELD_ELEMENT,
    pStateInOut: *SYMCRYPT_GF128_FIELD_ELEMENT,
    pbSrc: [*]const u8,
    pbDst: [*]u8,
    cbData: usize,
) callconv(types.SYMCRYPT_CALL) void {
    var nBlocks = cbData / SYMCRYPT_AES_BLOCK_SIZE;
    var src = pbSrc;
    var dst = pbDst;

    var state = loadGF128(pStateInOut);
    var ctr = byteReverse128(load128(pbChainingValue));
    const one: V16u8 = @bitCast(V4u32{ 1, 0, 0, 0 });
    const two: V16u8 = @bitCast(V4u32{ 2, 0, 0, 0 });
    const three: V16u8 = @bitCast(V4u32{ 3, 0, 0, 0 });
    const four: V16u8 = @bitCast(V4u32{ 4, 0, 0, 0 });

    var ctr_quad: [4]V16u8 = .{
        ctr,
        add32x4(ctr, one),
        add32x4(ctr, two),
        add32x4(ctr, three),
    };

    if (nBlocks >= 32) {
        var h_quads: [8][4]V16u8 = undefined;
        var hx_quads: [8][4]V16u8 = undefined;
        inline for (0..8) |i| {
            inline for (0..4) |j| {
                const ind = 32 - (4 * i + j);
                h_quads[i][j] = loadGF128(&expandedKeyTable[32 - ind]);
                hx_quads[i][j] = loadGF128(&expandedKeyTable[64 - ind]);
            }
        }

        var buf: [512]u8 = undefined;
        var r_quads: [8][4]V16u8 = undefined;

        while (nBlocks >= 32) {
            inline for (0..8) |i| {
                inline for (0..4) |j| {
                    const c = ctr_quad[j];
                    store128(buf[(4 * i + j) * 16 ..].ptr, byteReverse128(c));
                    ctr_quad[j] = add32x4(c, four);
                }
            }

            inline for (0..8) |i| {
                inline for (0..4) |j| {
                    const off = (4 * i + j) * 16;
                    const ct = load128(src + off);
                    r_quads[i][j] = byteReverse128(ct) ^ (if (i == 0 and j == 0) state else @as(V16u8, @splat(0)));
                }
            }

            aesEncryptZmm4096(pExpandedKey, &buf);

            var a0: [4]V16u8 = .{ @splat(0), @splat(0), @splat(0), @splat(0) };
            var a1: [4]V16u8 = .{ @splat(0), @splat(0), @splat(0), @splat(0) };
            var a2: [4]V16u8 = .{ @splat(0), @splat(0), @splat(0), @splat(0) };
            inline for (0..8) |i| {
                clmulAcc3Zmm(&r_quads[i], &h_quads[i], &hx_quads[i], &a0, &a1, &a2);
            }

            var a0_128 = (a0[0] ^ a0[1]) ^ (a0[2] ^ a0[3]);
            var a1_128 = (a1[0] ^ a1[1]) ^ (a1[2] ^ a1[3]);
            var a2_128 = (a2[0] ^ a2[1]) ^ (a2[2] ^ a2[3]);
            clmul3Post(&a0_128, &a1_128, &a2_128);
            modReduce(a0_128, a1_128, a2_128, &state);

            inline for (0..8) |i| {
                inline for (0..4) |j| {
                    const off = (4 * i + j) * 16;
                    const pt = load128(buf[off..].ptr) ^ load128(src + off);
                    store128(dst + off, pt);
                }
            }

            src += 32 * SYMCRYPT_AES_BLOCK_SIZE;
            dst += 32 * SYMCRYPT_AES_BLOCK_SIZE;
            nBlocks -= 32;
        }
    }

    if (nBlocks > 0) {
        var a0: [4]V16u8 = .{ @splat(0), @splat(0), @splat(0), @splat(0) };
        var a1: [4]V16u8 = .{ @splat(0), @splat(0), @splat(0), @splat(0) };
        var a2: [4]V16u8 = .{ @splat(0), @splat(0), @splat(0), @splat(0) };
        var state_xored = false;
        var buf64: [64]u8 = undefined;

        while (nBlocks >= 4) {
            inline for (0..4) |j| {
                const c = ctr_quad[j];
                store128(buf64[j * 16 ..].ptr, byteReverse128(c));
                ctr_quad[j] = add32x4(c, four);
            }

            var r_quad: [4]V16u8 = undefined;
            var h_quad: [4]V16u8 = undefined;
            var hx_quad: [4]V16u8 = undefined;
            inline for (0..4) |j| {
                const ct = load128(src + j * 16);
                r_quad[j] = byteReverse128(ct) ^ (if (!state_xored and j == 0) state else @as(V16u8, @splat(0)));
                const ind = nBlocks - j;
                h_quad[j] = loadGF128(&expandedKeyTable[32 - ind]);
                hx_quad[j] = loadGF128(&expandedKeyTable[64 - ind]);
            }
            state_xored = true;
            clmulAcc3Zmm(&r_quad, &h_quad, &hx_quad, &a0, &a1, &a2);

            aesEncryptZmm512(pExpandedKey, &buf64);

            inline for (0..4) |j| {
                const pt = load128(buf64[j * 16 ..].ptr) ^ load128(src + j * 16);
                store128(dst + j * 16, pt);
            }

            src += 4 * SYMCRYPT_AES_BLOCK_SIZE;
            dst += 4 * SYMCRYPT_AES_BLOCK_SIZE;
            nBlocks -= 4;
        }

        if (nBlocks > 0) {
            inline for (0..4) |j| {
                store128(buf64[j * 16 ..].ptr, byteReverse128(ctr_quad[j]));
            }
            aesEncryptZmm512(pExpandedKey, &buf64);

            var r_quad: [4]V16u8 = .{ @splat(0), @splat(0), @splat(0), @splat(0) };
            var h_quad: [4]V16u8 = .{ @splat(0), @splat(0), @splat(0), @splat(0) };
            var hx_quad: [4]V16u8 = .{ @splat(0), @splat(0), @splat(0), @splat(0) };

            for (0..nBlocks) |j| {
                const ct = load128(src + j * 16);
                const pt = load128(buf64[j * 16 ..].ptr) ^ ct;
                store128(dst + j * 16, pt);
                r_quad[j] = byteReverse128(ct) ^ (if (!state_xored and j == 0) state else @as(V16u8, @splat(0)));
                const ind = nBlocks - j;
                h_quad[j] = loadGF128(&expandedKeyTable[32 - ind]);
                hx_quad[j] = loadGF128(&expandedKeyTable[64 - ind]);
            }
            clmulAcc3Zmm(&r_quad, &h_quad, &hx_quad, &a0, &a1, &a2);

            const rem_vec: V16u8 = @bitCast(V4u32{ @intCast(nBlocks), 0, 0, 0 });
            ctr_quad[0] = add32x4(ctr_quad[0], rem_vec);
        }

        var a0_128 = (a0[0] ^ a0[1]) ^ (a0[2] ^ a0[3]);
        var a1_128 = (a1[0] ^ a1[1]) ^ (a1[2] ^ a1[3]);
        var a2_128 = (a2[0] ^ a2[1]) ^ (a2[2] ^ a2[3]);
        clmul3Post(&a0_128, &a1_128, &a2_128);
        modReduce(a0_128, a1_128, a2_128, &state);
    }

    ctr = ctr_quad[0];
    zeroupper();

    store128(pbChainingValue, byteReverse128(ctr));
    storeGF128(pStateInOut, state);
}

comptime {
    if (types.CPU_AMD64 and !types.IGNORE_PLATFORM) {
        @export(&SymCryptXtsAesEncryptDataUnitZmm_2048, .{ .name = "SymCryptXtsAesEncryptDataUnitZmm_2048" });
        @export(&SymCryptXtsAesDecryptDataUnitZmm_2048, .{ .name = "SymCryptXtsAesDecryptDataUnitZmm_2048" });
        @export(&SymCryptAesGcmEncryptStitchedZmm, .{ .name = "SymCryptAesGcmEncryptStitchedZmm" });
        @export(&SymCryptAesGcmDecryptStitchedZmm, .{ .name = "SymCryptAesGcmDecryptStitchedZmm" });
    }
}
