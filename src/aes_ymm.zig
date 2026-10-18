// Copyright (c) Microsoft Corporation. Licensed under the MIT license.

const types = @import("types.zig");
const aes_xmm = @import("aes_xmm.zig");
const wipe = @import("libmain.zig");

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
    return aes_xmm.xtsMulAlpha(in_v);
}

inline fn xtsMulAlpha4(in_v: V16u8) V16u8 {
    return aes_xmm.xtsMulAlpha4(in_v);
}

inline fn xtsMulAlpha8(in_v: V16u8) V16u8 {
    return aes_xmm.xtsMulAlpha8(in_v);
}

inline fn xtsMulAlpha16(in_v: V16u8) V16u8 {
    return aes_xmm.xtsMulAlpha8(aes_xmm.xtsMulAlpha8(in_v));
}

inline fn aesEncryptYmm2048(
    pExpandedKey: *const SYMCRYPT_AES_EXPANDED_KEY,
    buf: *[256]u8,
) void {
    var keyPtr: [*]const [4][4]u8 = @ptrCast(&pExpandedKey.RoundKey[0]);
    const keyLimit: [*]const [4][4]u8 = pExpandedKey.lastEncRoundKey;
    const bPtr: [*]u8 = buf;
    asm volatile (
        \\vmovdqu 0(%[b]), %%ymm0
        \\vmovdqu 32(%[b]), %%ymm1
        \\vmovdqu 64(%[b]), %%ymm2
        \\vmovdqu 96(%[b]), %%ymm3
        \\vmovdqu 128(%[b]), %%ymm4
        \\vmovdqu 160(%[b]), %%ymm5
        \\vmovdqu 192(%[b]), %%ymm6
        \\vmovdqu 224(%[b]), %%ymm7
        \\vbroadcasti128 (%[kp]), %%ymm8
        \\add $16, %[kp]
        \\vpxor %%ymm8, %%ymm0, %%ymm0
        \\vpxor %%ymm8, %%ymm1, %%ymm1
        \\vpxor %%ymm8, %%ymm2, %%ymm2
        \\vpxor %%ymm8, %%ymm3, %%ymm3
        \\vpxor %%ymm8, %%ymm4, %%ymm4
        \\vpxor %%ymm8, %%ymm5, %%ymm5
        \\vpxor %%ymm8, %%ymm6, %%ymm6
        \\vpxor %%ymm8, %%ymm7, %%ymm7
        \\1:
        \\vbroadcasti128 (%[kp]), %%ymm8
        \\add $16, %[kp]
        \\vaesenc %%ymm8, %%ymm0, %%ymm0
        \\vaesenc %%ymm8, %%ymm1, %%ymm1
        \\vaesenc %%ymm8, %%ymm2, %%ymm2
        \\vaesenc %%ymm8, %%ymm3, %%ymm3
        \\vaesenc %%ymm8, %%ymm4, %%ymm4
        \\vaesenc %%ymm8, %%ymm5, %%ymm5
        \\vaesenc %%ymm8, %%ymm6, %%ymm6
        \\vaesenc %%ymm8, %%ymm7, %%ymm7
        \\cmp %[kl], %[kp]
        \\jb 1b
        \\vbroadcasti128 (%[kp]), %%ymm8
        \\vaesenclast %%ymm8, %%ymm0, %%ymm0
        \\vaesenclast %%ymm8, %%ymm1, %%ymm1
        \\vaesenclast %%ymm8, %%ymm2, %%ymm2
        \\vaesenclast %%ymm8, %%ymm3, %%ymm3
        \\vaesenclast %%ymm8, %%ymm4, %%ymm4
        \\vaesenclast %%ymm8, %%ymm5, %%ymm5
        \\vaesenclast %%ymm8, %%ymm6, %%ymm6
        \\vaesenclast %%ymm8, %%ymm7, %%ymm7
        \\vmovdqu %%ymm0, 0(%[b])
        \\vmovdqu %%ymm1, 32(%[b])
        \\vmovdqu %%ymm2, 64(%[b])
        \\vmovdqu %%ymm3, 96(%[b])
        \\vmovdqu %%ymm4, 128(%[b])
        \\vmovdqu %%ymm5, 160(%[b])
        \\vmovdqu %%ymm6, 192(%[b])
        \\vmovdqu %%ymm7, 224(%[b])
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

inline fn aesDecryptYmm2048(
    pExpandedKey: *const SYMCRYPT_AES_EXPANDED_KEY,
    buf: *[256]u8,
) void {
    var keyPtr: [*]const [4][4]u8 = pExpandedKey.lastEncRoundKey;
    const keyLimit: [*]const [4][4]u8 = pExpandedKey.lastDecRoundKey;
    const bPtr: [*]u8 = buf;
    asm volatile (
        \\vmovdqu 0(%[b]), %%ymm0
        \\vmovdqu 32(%[b]), %%ymm1
        \\vmovdqu 64(%[b]), %%ymm2
        \\vmovdqu 96(%[b]), %%ymm3
        \\vmovdqu 128(%[b]), %%ymm4
        \\vmovdqu 160(%[b]), %%ymm5
        \\vmovdqu 192(%[b]), %%ymm6
        \\vmovdqu 224(%[b]), %%ymm7
        \\vbroadcasti128 (%[kp]), %%ymm8
        \\add $16, %[kp]
        \\vpxor %%ymm8, %%ymm0, %%ymm0
        \\vpxor %%ymm8, %%ymm1, %%ymm1
        \\vpxor %%ymm8, %%ymm2, %%ymm2
        \\vpxor %%ymm8, %%ymm3, %%ymm3
        \\vpxor %%ymm8, %%ymm4, %%ymm4
        \\vpxor %%ymm8, %%ymm5, %%ymm5
        \\vpxor %%ymm8, %%ymm6, %%ymm6
        \\vpxor %%ymm8, %%ymm7, %%ymm7
        \\1:
        \\vbroadcasti128 (%[kp]), %%ymm8
        \\add $16, %[kp]
        \\vaesdec %%ymm8, %%ymm0, %%ymm0
        \\vaesdec %%ymm8, %%ymm1, %%ymm1
        \\vaesdec %%ymm8, %%ymm2, %%ymm2
        \\vaesdec %%ymm8, %%ymm3, %%ymm3
        \\vaesdec %%ymm8, %%ymm4, %%ymm4
        \\vaesdec %%ymm8, %%ymm5, %%ymm5
        \\vaesdec %%ymm8, %%ymm6, %%ymm6
        \\vaesdec %%ymm8, %%ymm7, %%ymm7
        \\cmp %[kl], %[kp]
        \\jb 1b
        \\vbroadcasti128 (%[kp]), %%ymm8
        \\vaesdeclast %%ymm8, %%ymm0, %%ymm0
        \\vaesdeclast %%ymm8, %%ymm1, %%ymm1
        \\vaesdeclast %%ymm8, %%ymm2, %%ymm2
        \\vaesdeclast %%ymm8, %%ymm3, %%ymm3
        \\vaesdeclast %%ymm8, %%ymm4, %%ymm4
        \\vaesdeclast %%ymm8, %%ymm5, %%ymm5
        \\vaesdeclast %%ymm8, %%ymm6, %%ymm6
        \\vaesdeclast %%ymm8, %%ymm7, %%ymm7
        \\vmovdqu %%ymm0, 0(%[b])
        \\vmovdqu %%ymm1, 32(%[b])
        \\vmovdqu %%ymm2, 64(%[b])
        \\vmovdqu %%ymm3, 96(%[b])
        \\vmovdqu %%ymm4, 128(%[b])
        \\vmovdqu %%ymm5, 160(%[b])
        \\vmovdqu %%ymm6, 192(%[b])
        \\vmovdqu %%ymm7, 224(%[b])
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

inline fn aesXtsEncryptYmm2048(
    pExpandedKey: *const SYMCRYPT_AES_EXPANDED_KEY,
    tweaks: *const [16]V16u8,
    src: [*]const u8,
    dst: [*]u8,
) void {
    var keyPtr: [*]const [4][4]u8 = @ptrCast(&pExpandedKey.RoundKey[0]);
    const keyLimit: [*]const [4][4]u8 = pExpandedKey.lastEncRoundKey;
    const twPtr: [*]const u8 = @ptrCast(tweaks);
    asm volatile (
        \\vmovdqu 0(%[src]), %%ymm0
        \\vmovdqu 32(%[src]), %%ymm1
        \\vmovdqu 64(%[src]), %%ymm2
        \\vmovdqu 96(%[src]), %%ymm3
        \\vmovdqu 128(%[src]), %%ymm4
        \\vmovdqu 160(%[src]), %%ymm5
        \\vmovdqu 192(%[src]), %%ymm6
        \\vmovdqu 224(%[src]), %%ymm7
        \\vpxor 0(%[tw]), %%ymm0, %%ymm0
        \\vpxor 32(%[tw]), %%ymm1, %%ymm1
        \\vpxor 64(%[tw]), %%ymm2, %%ymm2
        \\vpxor 96(%[tw]), %%ymm3, %%ymm3
        \\vpxor 128(%[tw]), %%ymm4, %%ymm4
        \\vpxor 160(%[tw]), %%ymm5, %%ymm5
        \\vpxor 192(%[tw]), %%ymm6, %%ymm6
        \\vpxor 224(%[tw]), %%ymm7, %%ymm7
        \\vbroadcasti128 (%[kp]), %%ymm8
        \\add $16, %[kp]
        \\vpxor %%ymm8, %%ymm0, %%ymm0
        \\vpxor %%ymm8, %%ymm1, %%ymm1
        \\vpxor %%ymm8, %%ymm2, %%ymm2
        \\vpxor %%ymm8, %%ymm3, %%ymm3
        \\vpxor %%ymm8, %%ymm4, %%ymm4
        \\vpxor %%ymm8, %%ymm5, %%ymm5
        \\vpxor %%ymm8, %%ymm6, %%ymm6
        \\vpxor %%ymm8, %%ymm7, %%ymm7
        \\1:
        \\vbroadcasti128 (%[kp]), %%ymm8
        \\add $16, %[kp]
        \\vaesenc %%ymm8, %%ymm0, %%ymm0
        \\vaesenc %%ymm8, %%ymm1, %%ymm1
        \\vaesenc %%ymm8, %%ymm2, %%ymm2
        \\vaesenc %%ymm8, %%ymm3, %%ymm3
        \\vaesenc %%ymm8, %%ymm4, %%ymm4
        \\vaesenc %%ymm8, %%ymm5, %%ymm5
        \\vaesenc %%ymm8, %%ymm6, %%ymm6
        \\vaesenc %%ymm8, %%ymm7, %%ymm7
        \\cmp %[kl], %[kp]
        \\jb 1b
        \\vbroadcasti128 (%[kp]), %%ymm8
        \\vaesenclast %%ymm8, %%ymm0, %%ymm0
        \\vaesenclast %%ymm8, %%ymm1, %%ymm1
        \\vaesenclast %%ymm8, %%ymm2, %%ymm2
        \\vaesenclast %%ymm8, %%ymm3, %%ymm3
        \\vaesenclast %%ymm8, %%ymm4, %%ymm4
        \\vaesenclast %%ymm8, %%ymm5, %%ymm5
        \\vaesenclast %%ymm8, %%ymm6, %%ymm6
        \\vaesenclast %%ymm8, %%ymm7, %%ymm7
        \\vpxor 0(%[tw]), %%ymm0, %%ymm0
        \\vpxor 32(%[tw]), %%ymm1, %%ymm1
        \\vpxor 64(%[tw]), %%ymm2, %%ymm2
        \\vpxor 96(%[tw]), %%ymm3, %%ymm3
        \\vpxor 128(%[tw]), %%ymm4, %%ymm4
        \\vpxor 160(%[tw]), %%ymm5, %%ymm5
        \\vpxor 192(%[tw]), %%ymm6, %%ymm6
        \\vpxor 224(%[tw]), %%ymm7, %%ymm7
        \\vmovdqu %%ymm0, 0(%[dst])
        \\vmovdqu %%ymm1, 32(%[dst])
        \\vmovdqu %%ymm2, 64(%[dst])
        \\vmovdqu %%ymm3, 96(%[dst])
        \\vmovdqu %%ymm4, 128(%[dst])
        \\vmovdqu %%ymm5, 160(%[dst])
        \\vmovdqu %%ymm6, 192(%[dst])
        \\vmovdqu %%ymm7, 224(%[dst])
        : [kp] "+r" (keyPtr),
        : [kl] "r" (keyLimit),
          [tw] "r" (twPtr),
          [src] "r" (src),
          [dst] "r" (dst),
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

inline fn aesXtsDecryptYmm2048(
    pExpandedKey: *const SYMCRYPT_AES_EXPANDED_KEY,
    tweaks: *const [16]V16u8,
    src: [*]const u8,
    dst: [*]u8,
) void {
    var keyPtr: [*]const [4][4]u8 = pExpandedKey.lastEncRoundKey;
    const keyLimit: [*]const [4][4]u8 = pExpandedKey.lastDecRoundKey;
    const twPtr: [*]const u8 = @ptrCast(tweaks);
    asm volatile (
        \\vmovdqu 0(%[src]), %%ymm0
        \\vmovdqu 32(%[src]), %%ymm1
        \\vmovdqu 64(%[src]), %%ymm2
        \\vmovdqu 96(%[src]), %%ymm3
        \\vmovdqu 128(%[src]), %%ymm4
        \\vmovdqu 160(%[src]), %%ymm5
        \\vmovdqu 192(%[src]), %%ymm6
        \\vmovdqu 224(%[src]), %%ymm7
        \\vpxor 0(%[tw]), %%ymm0, %%ymm0
        \\vpxor 32(%[tw]), %%ymm1, %%ymm1
        \\vpxor 64(%[tw]), %%ymm2, %%ymm2
        \\vpxor 96(%[tw]), %%ymm3, %%ymm3
        \\vpxor 128(%[tw]), %%ymm4, %%ymm4
        \\vpxor 160(%[tw]), %%ymm5, %%ymm5
        \\vpxor 192(%[tw]), %%ymm6, %%ymm6
        \\vpxor 224(%[tw]), %%ymm7, %%ymm7
        \\vbroadcasti128 (%[kp]), %%ymm8
        \\add $16, %[kp]
        \\vpxor %%ymm8, %%ymm0, %%ymm0
        \\vpxor %%ymm8, %%ymm1, %%ymm1
        \\vpxor %%ymm8, %%ymm2, %%ymm2
        \\vpxor %%ymm8, %%ymm3, %%ymm3
        \\vpxor %%ymm8, %%ymm4, %%ymm4
        \\vpxor %%ymm8, %%ymm5, %%ymm5
        \\vpxor %%ymm8, %%ymm6, %%ymm6
        \\vpxor %%ymm8, %%ymm7, %%ymm7
        \\1:
        \\vbroadcasti128 (%[kp]), %%ymm8
        \\add $16, %[kp]
        \\vaesdec %%ymm8, %%ymm0, %%ymm0
        \\vaesdec %%ymm8, %%ymm1, %%ymm1
        \\vaesdec %%ymm8, %%ymm2, %%ymm2
        \\vaesdec %%ymm8, %%ymm3, %%ymm3
        \\vaesdec %%ymm8, %%ymm4, %%ymm4
        \\vaesdec %%ymm8, %%ymm5, %%ymm5
        \\vaesdec %%ymm8, %%ymm6, %%ymm6
        \\vaesdec %%ymm8, %%ymm7, %%ymm7
        \\cmp %[kl], %[kp]
        \\jb 1b
        \\vbroadcasti128 (%[kp]), %%ymm8
        \\vaesdeclast %%ymm8, %%ymm0, %%ymm0
        \\vaesdeclast %%ymm8, %%ymm1, %%ymm1
        \\vaesdeclast %%ymm8, %%ymm2, %%ymm2
        \\vaesdeclast %%ymm8, %%ymm3, %%ymm3
        \\vaesdeclast %%ymm8, %%ymm4, %%ymm4
        \\vaesdeclast %%ymm8, %%ymm5, %%ymm5
        \\vaesdeclast %%ymm8, %%ymm6, %%ymm6
        \\vaesdeclast %%ymm8, %%ymm7, %%ymm7
        \\vpxor 0(%[tw]), %%ymm0, %%ymm0
        \\vpxor 32(%[tw]), %%ymm1, %%ymm1
        \\vpxor 64(%[tw]), %%ymm2, %%ymm2
        \\vpxor 96(%[tw]), %%ymm3, %%ymm3
        \\vpxor 128(%[tw]), %%ymm4, %%ymm4
        \\vpxor 160(%[tw]), %%ymm5, %%ymm5
        \\vpxor 192(%[tw]), %%ymm6, %%ymm6
        \\vpxor 224(%[tw]), %%ymm7, %%ymm7
        \\vmovdqu %%ymm0, 0(%[dst])
        \\vmovdqu %%ymm1, 32(%[dst])
        \\vmovdqu %%ymm2, 64(%[dst])
        \\vmovdqu %%ymm3, 96(%[dst])
        \\vmovdqu %%ymm4, 128(%[dst])
        \\vmovdqu %%ymm5, 160(%[dst])
        \\vmovdqu %%ymm6, 192(%[dst])
        \\vmovdqu %%ymm7, 224(%[dst])
        : [kp] "+r" (keyPtr),
        : [kl] "r" (keyLimit),
          [tw] "r" (twPtr),
          [src] "r" (src),
          [dst] "r" (dst),
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

inline fn clmulAcc8Ymm(
    r_pairs: *const [8][2]V16u8,
    h_pairs: *const [8][2]V16u8,
    hx_pairs: *const [8][2]V16u8,
    a0: *[2]V16u8,
    a1: *[2]V16u8,
    a2: *[2]V16u8,
) void {
    var idx: usize = 0;
    asm volatile (
        \\vpxor %%ymm5, %%ymm5, %%ymm5
        \\vpxor %%ymm6, %%ymm6, %%ymm6
        \\vpxor %%ymm7, %%ymm7, %%ymm7
        \\1:
        \\vmovdqu (%[r], %[idx]), %%ymm0
        \\vmovdqu (%[h], %[idx]), %%ymm1
        \\vmovdqu (%[hx], %[idx]), %%ymm2
        \\vpclmulqdq $0x00, %%ymm1, %%ymm0, %%ymm3
        \\vpclmulqdq $0x11, %%ymm1, %%ymm0, %%ymm4
        \\vpsrldq $8, %%ymm0, %%ymm0
        \\vpxor (%[r], %[idx]), %%ymm0, %%ymm0
        \\vpclmulqdq $0x00, %%ymm2, %%ymm0, %%ymm0
        \\vpxor %%ymm3, %%ymm5, %%ymm5
        \\vpxor %%ymm0, %%ymm6, %%ymm6
        \\vpxor %%ymm4, %%ymm7, %%ymm7
        \\add $32, %[idx]
        \\cmp $256, %[idx]
        \\jb 1b
        \\vmovdqu %%ymm5, (%[a0])
        \\vmovdqu %%ymm6, (%[a1])
        \\vmovdqu %%ymm7, (%[a2])
        : [idx] "+r" (idx),
        : [r] "r" (@as([*]const u8, @ptrCast(r_pairs))),
          [h] "r" (@as([*]const u8, @ptrCast(h_pairs))),
          [hx] "r" (@as([*]const u8, @ptrCast(hx_pairs))),
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
          .xmm7 = true,
          .cc = true,
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

pub fn SymCryptXtsAesEncryptDataUnitYmm_2048(
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

    while (true) {
        aesXtsEncryptYmm2048(pExpandedKey, &tweaks, src, dst);
        src += 16 * SYMCRYPT_AES_BLOCK_SIZE;
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

pub fn SymCryptXtsAesDecryptDataUnitYmm_2048(
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

    while (true) {
        aesXtsDecryptYmm2048(pExpandedKey, &tweaks, src, dst);
        src += 16 * SYMCRYPT_AES_BLOCK_SIZE;
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

pub fn SymCryptAesGcmEncryptStitchedYmm_2048(
    pExpandedKey: *const SYMCRYPT_AES_EXPANDED_KEY,
    pbChainingValue: [*]u8,
    expandedKeyTable: [*]const SYMCRYPT_GF128_FIELD_ELEMENT,
    pStateInOut: *SYMCRYPT_GF128_FIELD_ELEMENT,
    pbSrc: [*]const u8,
    pbDst: [*]u8,
    cbData: usize,
) callconv(types.SYMCRYPT_CALL) void {
    const cbDataTail = cbData & ((16 * SYMCRYPT_AES_BLOCK_SIZE) - 1);
    var cbDataMain = cbData - cbDataTail;

    if (cbDataMain == 0) {
        aes_xmm.SymCryptAesGcmEncryptStitchedXmm(pExpandedKey, pbChainingValue, expandedKeyTable, pStateInOut, pbSrc, pbDst, cbDataTail);
        return;
    }

    var state = loadGF128(pStateInOut);
    var ctr = byteReverse128(load128(pbChainingValue));
    const one: V16u8 = @bitCast(V4u32{ 1, 0, 0, 0 });
    const two: V16u8 = @bitCast(V4u32{ 2, 0, 0, 0 });

    var ctr_pair: [2]V16u8 = .{ ctr, add32x4(ctr, one) };

    var h_pairs: [8][2]V16u8 = undefined;
    var hx_pairs: [8][2]V16u8 = undefined;
    inline for (0..8) |i| {
        const ind0 = 16 - 2 * i;
        const ind1 = 15 - 2 * i;
        h_pairs[i] = .{
            loadGF128(&expandedKeyTable[32 - ind0]),
            loadGF128(&expandedKeyTable[32 - ind1]),
        };
        hx_pairs[i] = .{
            loadGF128(&expandedKeyTable[64 - ind0]),
            loadGF128(&expandedKeyTable[64 - ind1]),
        };
    }

    var src = pbSrc;
    var dst = pbDst;
    var buf: [256]u8 = undefined;
    defer wipe.SymCryptWipeKnownSize(&buf, @sizeOf(@TypeOf(buf)));
    var r_pairs: [8][2]V16u8 = undefined;

    inline for (0..8) |i| {
        const c0 = ctr_pair[0];
        const c1 = ctr_pair[1];
        store128(buf[i * 32 ..].ptr, byteReverse128(c0));
        store128(buf[i * 32 + 16 ..].ptr, byteReverse128(c1));
        ctr_pair[0] = add32x4(c0, two);
        ctr_pair[1] = add32x4(c1, two);
    }

    aesEncryptYmm2048(pExpandedKey, &buf);

    inline for (0..8) |i| {
        const c0 = load128(buf[i * 32 ..].ptr) ^ load128(src + i * 32);
        const c1 = load128(buf[i * 32 + 16 ..].ptr) ^ load128(src + i * 32 + 16);
        store128(dst + i * 32, c0);
        store128(dst + i * 32 + 16, c1);
        r_pairs[i] = .{
            byteReverse128(c0) ^ (if (i == 0) state else @as(V16u8, @splat(0))),
            byteReverse128(c1),
        };
    }

    src += 16 * SYMCRYPT_AES_BLOCK_SIZE;
    dst += 16 * SYMCRYPT_AES_BLOCK_SIZE;
    cbDataMain -= 16 * SYMCRYPT_AES_BLOCK_SIZE;

    while (cbDataMain > 0) {
        inline for (0..8) |i| {
            const c0 = ctr_pair[0];
            const c1 = ctr_pair[1];
            store128(buf[i * 32 ..].ptr, byteReverse128(c0));
            store128(buf[i * 32 + 16 ..].ptr, byteReverse128(c1));
            ctr_pair[0] = add32x4(c0, two);
            ctr_pair[1] = add32x4(c1, two);
        }

        aesEncryptYmm2048(pExpandedKey, &buf);

        var a0: [2]V16u8 = undefined;
        var a1: [2]V16u8 = undefined;
        var a2: [2]V16u8 = undefined;
        clmulAcc8Ymm(&r_pairs, &h_pairs, &hx_pairs, &a0, &a1, &a2);

        var a0_128 = a0[0] ^ a0[1];
        var a1_128 = a1[0] ^ a1[1];
        var a2_128 = a2[0] ^ a2[1];
        clmul3Post(&a0_128, &a1_128, &a2_128);
        modReduce(a0_128, a1_128, a2_128, &state);

        inline for (0..8) |i| {
            const c0 = load128(buf[i * 32 ..].ptr) ^ load128(src + i * 32);
            const c1 = load128(buf[i * 32 + 16 ..].ptr) ^ load128(src + i * 32 + 16);
            store128(dst + i * 32, c0);
            store128(dst + i * 32 + 16, c1);
            r_pairs[i] = .{
                byteReverse128(c0) ^ (if (i == 0) state else @as(V16u8, @splat(0))),
                byteReverse128(c1),
            };
        }

        src += 16 * SYMCRYPT_AES_BLOCK_SIZE;
        dst += 16 * SYMCRYPT_AES_BLOCK_SIZE;
        cbDataMain -= 16 * SYMCRYPT_AES_BLOCK_SIZE;
    }

    var a0: [2]V16u8 = undefined;
    var a1: [2]V16u8 = undefined;
    var a2: [2]V16u8 = undefined;
    clmulAcc8Ymm(&r_pairs, &h_pairs, &hx_pairs, &a0, &a1, &a2);

    var a0_128 = a0[0] ^ a0[1];
    var a1_128 = a1[0] ^ a1[1];
    var a2_128 = a2[0] ^ a2[1];
    clmul3Post(&a0_128, &a1_128, &a2_128);
    modReduce(a0_128, a1_128, a2_128, &state);

    ctr = ctr_pair[0];
    zeroupper();

    store128(pbChainingValue, byteReverse128(ctr));
    storeGF128(pStateInOut, state);

    if (cbDataTail > 0) {
        aes_xmm.SymCryptAesGcmEncryptStitchedXmm(pExpandedKey, pbChainingValue, expandedKeyTable, pStateInOut, src, dst, cbDataTail);
    }
}

pub fn SymCryptAesGcmDecryptStitchedYmm_2048(
    pExpandedKey: *const SYMCRYPT_AES_EXPANDED_KEY,
    pbChainingValue: [*]u8,
    expandedKeyTable: [*]const SYMCRYPT_GF128_FIELD_ELEMENT,
    pStateInOut: *SYMCRYPT_GF128_FIELD_ELEMENT,
    pbSrc: [*]const u8,
    pbDst: [*]u8,
    cbData: usize,
) callconv(types.SYMCRYPT_CALL) void {
    const cbDataTail = cbData & ((16 * SYMCRYPT_AES_BLOCK_SIZE) - 1);
    var cbDataMain = cbData - cbDataTail;

    if (cbDataMain == 0) {
        aes_xmm.SymCryptAesGcmDecryptStitchedXmm(pExpandedKey, pbChainingValue, expandedKeyTable, pStateInOut, pbSrc, pbDst, cbDataTail);
        return;
    }

    var state = loadGF128(pStateInOut);
    var ctr = byteReverse128(load128(pbChainingValue));
    const one: V16u8 = @bitCast(V4u32{ 1, 0, 0, 0 });
    const two: V16u8 = @bitCast(V4u32{ 2, 0, 0, 0 });

    var ctr_pair: [2]V16u8 = .{ ctr, add32x4(ctr, one) };

    var h_pairs: [8][2]V16u8 = undefined;
    var hx_pairs: [8][2]V16u8 = undefined;
    inline for (0..8) |i| {
        const ind0 = 16 - 2 * i;
        const ind1 = 15 - 2 * i;
        h_pairs[i] = .{
            loadGF128(&expandedKeyTable[32 - ind0]),
            loadGF128(&expandedKeyTable[32 - ind1]),
        };
        hx_pairs[i] = .{
            loadGF128(&expandedKeyTable[64 - ind0]),
            loadGF128(&expandedKeyTable[64 - ind1]),
        };
    }

    var src = pbSrc;
    var dst = pbDst;
    var buf: [256]u8 = undefined;
    defer wipe.SymCryptWipeKnownSize(&buf, @sizeOf(@TypeOf(buf)));
    var r_pairs: [8][2]V16u8 = undefined;

    while (cbDataMain > 0) {
        inline for (0..8) |i| {
            const c0 = ctr_pair[0];
            const c1 = ctr_pair[1];
            store128(buf[i * 32 ..].ptr, byteReverse128(c0));
            store128(buf[i * 32 + 16 ..].ptr, byteReverse128(c1));
            ctr_pair[0] = add32x4(c0, two);
            ctr_pair[1] = add32x4(c1, two);
        }

        inline for (0..8) |i| {
            const s0 = load128(src + i * 32);
            const s1 = load128(src + i * 32 + 16);
            r_pairs[i] = .{
                byteReverse128(s0) ^ (if (i == 0) state else @as(V16u8, @splat(0))),
                byteReverse128(s1),
            };
        }

        aesEncryptYmm2048(pExpandedKey, &buf);

        var a0: [2]V16u8 = undefined;
        var a1: [2]V16u8 = undefined;
        var a2: [2]V16u8 = undefined;
        clmulAcc8Ymm(&r_pairs, &h_pairs, &hx_pairs, &a0, &a1, &a2);

        var a0_128 = a0[0] ^ a0[1];
        var a1_128 = a1[0] ^ a1[1];
        var a2_128 = a2[0] ^ a2[1];
        clmul3Post(&a0_128, &a1_128, &a2_128);
        modReduce(a0_128, a1_128, a2_128, &state);

        inline for (0..8) |i| {
            const c0 = load128(buf[i * 32 ..].ptr) ^ load128(src + i * 32);
            const c1 = load128(buf[i * 32 + 16 ..].ptr) ^ load128(src + i * 32 + 16);
            store128(dst + i * 32, c0);
            store128(dst + i * 32 + 16, c1);
        }

        src += 16 * SYMCRYPT_AES_BLOCK_SIZE;
        dst += 16 * SYMCRYPT_AES_BLOCK_SIZE;
        cbDataMain -= 16 * SYMCRYPT_AES_BLOCK_SIZE;
    }

    ctr = ctr_pair[0];
    zeroupper();

    store128(pbChainingValue, byteReverse128(ctr));
    storeGF128(pStateInOut, state);

    if (cbDataTail > 0) {
        aes_xmm.SymCryptAesGcmDecryptStitchedXmm(pExpandedKey, pbChainingValue, expandedKeyTable, pStateInOut, src, dst, cbDataTail);
    }
}

pub fn SymCryptAesCbcDecryptYmm(
    pExpandedKey: *const SYMCRYPT_AES_EXPANDED_KEY,
    pbChainingValue: [*]u8,
    pbSrc: [*]const u8,
    pbDst: [*]u8,
    cbData: usize,
) callconv(types.SYMCRYPT_CALL) void {
    if (cbData < 16 * SYMCRYPT_AES_BLOCK_SIZE) {
        aes_xmm.SymCryptAesCbcDecryptXmm(pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData);
        return;
    }

    var chain = load128(pbChainingValue);
    var src = pbSrc;
    var dst = pbDst;
    var rem = cbData;
    var buf: [256]u8 = undefined;
    defer wipe.SymCryptWipeKnownSize(&buf, @sizeOf(@TypeOf(buf)));
    var ct: [16]V16u8 = undefined;

    while (rem >= 16 * SYMCRYPT_AES_BLOCK_SIZE) {
        inline for (0..16) |i| {
            ct[i] = load128(src + i * 16);
            store128(buf[i * 16 ..].ptr, ct[i]);
        }

        aesDecryptYmm2048(pExpandedKey, &buf);

        store128(dst, load128(buf[0..].ptr) ^ chain);
        inline for (1..16) |i| {
            store128(dst + i * 16, load128(buf[i * 16 ..].ptr) ^ ct[i - 1]);
        }
        chain = ct[15];

        src += 16 * SYMCRYPT_AES_BLOCK_SIZE;
        dst += 16 * SYMCRYPT_AES_BLOCK_SIZE;
        rem -= 16 * SYMCRYPT_AES_BLOCK_SIZE;
    }

    zeroupper();
    store128(pbChainingValue, chain);

    if (rem >= SYMCRYPT_AES_BLOCK_SIZE) {
        aes_xmm.SymCryptAesCbcDecryptXmm(pExpandedKey, pbChainingValue, src, dst, rem);
    }
}

comptime {
    if ((types.CPU_X86 or types.CPU_AMD64) and !types.IGNORE_PLATFORM) {
        @export(&SymCryptXtsAesEncryptDataUnitYmm_2048, .{ .name = "SymCryptXtsAesEncryptDataUnitYmm_2048" });
        @export(&SymCryptXtsAesDecryptDataUnitYmm_2048, .{ .name = "SymCryptXtsAesDecryptDataUnitYmm_2048" });
        @export(&SymCryptAesGcmEncryptStitchedYmm_2048, .{ .name = "SymCryptAesGcmEncryptStitchedYmm_2048" });
        @export(&SymCryptAesGcmDecryptStitchedYmm_2048, .{ .name = "SymCryptAesGcmDecryptStitchedYmm_2048" });
        @export(&SymCryptAesCbcDecryptYmm, .{ .name = "SymCryptAesCbcDecryptYmm" });
    }
}
