//
// sha256_xmm.zig
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
// XMM (SSSE3) 4-block message schedule implementation for SHA-256,
// ported from lib/sha256-xmm.c.
//

const std = @import("std");
const types = @import("types.zig");
const macros = @import("macros.zig");
const hash = @import("hash.zig");
const sha256 = @import("sha256.zig");

const PCBYTE = types.PCBYTE;
const UINT32 = types.UINT32;
const SIZE_T = types.SIZE_T;
const SYMCRYPT_CALL = types.SYMCRYPT_CALL;
const SYMCRYPT_ALIGN_VALUE = types.SYMCRYPT_ALIGN_VALUE;
const SYMCRYPT_SHA256_INPUT_BLOCK_SIZE = sha256.SYMCRYPT_SHA256_INPUT_BLOCK_SIZE;
const SYMCRYPT_SHA256_CHAINING_STATE = sha256.SYMCRYPT_SHA256_CHAINING_STATE;
const SymCryptSha256K = &sha256.SymCryptSha256K;

const V4U32 = @Vector(4, u32);
const V16U8 = @Vector(16, u8);

// Endianness transformation for 4 32-bit values in an XMM register
pub const BYTE_REVERSE_32: [4]UINT32 align(16) = .{
    0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f,
};

// Shuffle 32-bit words in an XMM register: W3 W2 W1 W0 -> 0 0 W2 W0
// Used by the SSSE3 assembly implementation
pub const XMM_PACKLOW: [4]UINT32 align(16) = .{
    0x03020100, 0x0b0a0908, 0x80808080, 0x80808080,
};

// Shuffle 32-bit words in an XMM register: W3 W2 W1 W0 -> W2 W0 0 0
// Used by the SSSE3 assembly implementation
pub const XMM_PACKHIGH: [4]UINT32 align(16) = .{
    0x80808080, 0x80808080, 0x03020100, 0x0b0a0908,
};

inline fn maj(x: UINT32, y: UINT32, z: UINT32) UINT32 {
    return (((z | y) & x) | (z & y));
}

inline fn ch(x: UINT32, y: UINT32, z: UINT32) UINT32 {
    return (((z ^ y) & x) ^ z);
}

inline fn lsigma0(x: UINT32) UINT32 {
    return macros.ROR32(x, 7) ^ macros.ROR32(x, 18) ^ (x >> 3);
}

inline fn lsigma1(x: UINT32) UINT32 {
    return macros.ROR32(x, 17) ^ macros.ROR32(x, 19) ^ (x >> 10);
}

inline fn csigma0(x: UINT32) UINT32 {
    return macros.ROR32(x, 2) ^ macros.ROR32(x, 13) ^ macros.ROR32(x, 22);
}

inline fn csigma1(x: UINT32) UINT32 {
    return macros.ROR32(x, 6) ^ macros.ROR32(x, 11) ^ macros.ROR32(x, 25);
}

inline fn lsigma0Xmm(x: V4U32) V4U32 {
    return (x << @splat(25)) ^ (x >> @splat(7)) ^
        (x << @splat(14)) ^ (x >> @splat(18)) ^
        (x >> @splat(3));
}

inline fn lsigma1Xmm(x: V4U32) V4U32 {
    return (x << @splat(15)) ^ (x >> @splat(17)) ^
        (x << @splat(13)) ^ (x >> @splat(19)) ^
        (x >> @splat(10));
}

inline fn loaduByteReverse32(ptr: PCBYTE) V4U32 {
    const raw: V16U8 = @bitCast(std.mem.readInt(u128, ptr[0..16], .little));
    const rev = @shuffle(u8, raw, undefined, [16]i32{
        3,  2,  1,  0,
        7,  6,  5,  4,
        11, 10, 9,  8,
        15, 14, 13, 12,
    });
    return @bitCast(rev);
}

const WxArray = [64]V4U32;

inline fn sha256MsgLoad4Blocks(Wx: *WxArray, pbData: PCBYTE, bl: SIZE_T) void {
    var i: SIZE_T = 0;
    while (i < bl) : (i += 1) {
        const base = i * SYMCRYPT_SHA256_INPUT_BLOCK_SIZE;
        Wx[i + 0] = loaduByteReverse32(pbData + base + 0);
        Wx[i + 4] = loaduByteReverse32(pbData + base + 16);
        Wx[i + 8] = loaduByteReverse32(pbData + base + 32);
        Wx[i + 12] = loaduByteReverse32(pbData + base + 48);
    }
}

inline fn sha256MsgTransposeQuarter4Blocks(Wx: *WxArray, comptime ind: usize) void {
    const t1 = @shuffle(u32, Wx[4 * ind + 0], Wx[4 * ind + 1], [4]i32{ 0, -1, 1, -2 });
    const t2 = @shuffle(u32, Wx[4 * ind + 2], Wx[4 * ind + 3], [4]i32{ 0, -1, 1, -2 });
    const t3 = @shuffle(u32, Wx[4 * ind + 0], Wx[4 * ind + 1], [4]i32{ 2, -3, 3, -4 });
    const t4 = @shuffle(u32, Wx[4 * ind + 2], Wx[4 * ind + 3], [4]i32{ 2, -3, 3, -4 });
    Wx[4 * ind + 0] = @shuffle(u32, t1, t2, [4]i32{ 0, 1, -1, -2 });
    Wx[4 * ind + 1] = @shuffle(u32, t1, t2, [4]i32{ 2, 3, -3, -4 });
    Wx[4 * ind + 2] = @shuffle(u32, t3, t4, [4]i32{ 0, 1, -1, -2 });
    Wx[4 * ind + 3] = @shuffle(u32, t3, t4, [4]i32{ 2, 3, -3, -4 });
}

inline fn sha256MsgTranspose4Blocks(Wx: *WxArray) void {
    sha256MsgTransposeQuarter4Blocks(Wx, 0);
    sha256MsgTransposeQuarter4Blocks(Wx, 1);
    sha256MsgTransposeQuarter4Blocks(Wx, 2);
    sha256MsgTransposeQuarter4Blocks(Wx, 3);
}

inline fn sha256MsgExpand4Blocks1Round(Wx: *WxArray, r: usize) void {
    Wx[r] = Wx[r - 16] +% Wx[r - 7] +% lsigma0Xmm(Wx[r - 15]) +% lsigma1Xmm(Wx[r - 2]);
    Wx[r - 16] +%= @splat(SymCryptSha256K[r - 16]);
}

inline fn sha256MsgExpand4Blocks4Rounds(Wx: *WxArray, r: usize) void {
    sha256MsgExpand4Blocks1Round(Wx, r + 0);
    sha256MsgExpand4Blocks1Round(Wx, r + 1);
    sha256MsgExpand4Blocks1Round(Wx, r + 2);
    sha256MsgExpand4Blocks1Round(Wx, r + 3);
}

inline fn sha256MsgExpand4Blocks16Rounds(Wx: *WxArray, r: usize) void {
    sha256MsgExpand4Blocks4Rounds(Wx, r + 0);
    sha256MsgExpand4Blocks4Rounds(Wx, r + 4);
    sha256MsgExpand4Blocks4Rounds(Wx, r + 8);
    sha256MsgExpand4Blocks4Rounds(Wx, r + 12);
}

inline fn cround4Blocks(Wx: *const WxArray, ah: *[8]UINT32, comptime r16: usize, rb: usize, b: usize) void {
    const Wt = @as([4]UINT32, Wx[rb + r16])[b];
    ah[r16 & 7] +%= csigma1(ah[(r16 + 3) & 7]) +% ch(ah[(r16 + 3) & 7], ah[(r16 + 2) & 7], ah[(r16 + 1) & 7]) +% Wt;
    ah[(r16 + 4) & 7] +%= ah[r16 & 7];
    ah[r16 & 7] +%= csigma0(ah[(r16 + 7) & 7]) +% maj(ah[(r16 + 7) & 7], ah[(r16 + 6) & 7], ah[(r16 + 5) & 7]);
}

inline fn cround(ah: *[8]UINT32, comptime r16: usize, r: usize, Wt: UINT32) void {
    ah[r16 & 7] +%= csigma1(ah[(r16 + 3) & 7]) +% ch(ah[(r16 + 3) & 7], ah[(r16 + 2) & 7], ah[(r16 + 1) & 7]) +% SymCryptSha256K[r] +% Wt;
    ah[(r16 + 4) & 7] +%= ah[r16 & 7];
    ah[r16 & 7] +%= csigma0(ah[(r16 + 7) & 7]) +% maj(ah[(r16 + 7) & 7], ah[(r16 + 6) & 7], ah[(r16 + 5) & 7]);
}

inline fn iround(Wx_ul: *[16]UINT32, ah: *[8]UINT32, pbData: PCBYTE, comptime r: usize) void {
    const Wt = macros.LOAD_MSBFIRST32(pbData + 4 * r);
    Wx_ul[r] = Wt;
    cround(ah, r, r, Wt);
}

inline fn fround(Wx_ul: *[16]UINT32, ah: *[8]UINT32, comptime r16: usize, rb: usize) void {
    const Wt = lsigma1(Wx_ul[(r16 + 16 - 2) & 15]) +% Wx_ul[(r16 + 16 - 7) & 15] +%
        lsigma0(Wx_ul[(r16 + 16 - 15) & 15]) +% Wx_ul[r16 & 15];
    Wx_ul[r16] = Wt;
    cround(ah, r16, r16 + rb, Wt);
}

pub fn SymCryptSha256AppendBlocks_xmm_4blocks(
    pChain: *SYMCRYPT_SHA256_CHAINING_STATE,
    pbData_in: PCBYTE,
    cbData_in: SIZE_T,
    pcbRemaining: *SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    @setRuntimeSafety(false);
    var pbData = pbData_in;
    var cbData = cbData_in;

    var Wx: WxArray align(SYMCRYPT_ALIGN_VALUE) = undefined;
    const Wx_ul: *[16]UINT32 = @ptrCast(&Wx);
    var ah: [8]UINT32 align(SYMCRYPT_ALIGN_VALUE) = undefined;
    const uWipeSize: SIZE_T = if (cbData >= (3 * SYMCRYPT_SHA256_INPUT_BLOCK_SIZE))
        (64 * 4 * @sizeOf(UINT32))
    else
        (16 * @sizeOf(UINT32));

    while (cbData >= (3 * SYMCRYPT_SHA256_INPUT_BLOCK_SIZE)) {
        const numBlocks: SIZE_T = if (cbData >= 4 * SYMCRYPT_SHA256_INPUT_BLOCK_SIZE)
            4
        else
            (cbData / SYMCRYPT_SHA256_INPUT_BLOCK_SIZE);

        sha256MsgLoad4Blocks(&Wx, pbData, numBlocks);
        sha256MsgTranspose4Blocks(&Wx);

        var j: usize = 16;
        while (j < 64) : (j += 16) {
            sha256MsgExpand4Blocks16Rounds(&Wx, j);
        }

        var i: usize = 48;
        while (i < 64) : (i += 1) {
            Wx[i] +%= @splat(SymCryptSha256K[i]);
        }

        var bl: SIZE_T = 0;
        while (bl < numBlocks) : (bl += 1) {
            ah[7] = pChain.H[0];
            ah[6] = pChain.H[1];
            ah[5] = pChain.H[2];
            ah[4] = pChain.H[3];
            ah[3] = pChain.H[4];
            ah[2] = pChain.H[5];
            ah[1] = pChain.H[6];
            ah[0] = pChain.H[7];

            var iterCount: usize = 0;
            while (iterCount < (64 / 8)) : (iterCount += 1) {
                const roundBase = iterCount * 8;
                cround4Blocks(&Wx, &ah, 0, roundBase, bl);
                cround4Blocks(&Wx, &ah, 1, roundBase, bl);
                cround4Blocks(&Wx, &ah, 2, roundBase, bl);
                cround4Blocks(&Wx, &ah, 3, roundBase, bl);
                cround4Blocks(&Wx, &ah, 4, roundBase, bl);
                cround4Blocks(&Wx, &ah, 5, roundBase, bl);
                cround4Blocks(&Wx, &ah, 6, roundBase, bl);
                cround4Blocks(&Wx, &ah, 7, roundBase, bl);
            }

            pChain.H[0] +%= ah[7];
            pChain.H[1] +%= ah[6];
            pChain.H[2] +%= ah[5];
            pChain.H[3] +%= ah[4];
            pChain.H[4] +%= ah[3];
            pChain.H[5] +%= ah[2];
            pChain.H[6] +%= ah[1];
            pChain.H[7] +%= ah[0];
        }

        pbData += (numBlocks * SYMCRYPT_SHA256_INPUT_BLOCK_SIZE);
        cbData -= (numBlocks * SYMCRYPT_SHA256_INPUT_BLOCK_SIZE);
    }

    while (cbData >= SYMCRYPT_SHA256_INPUT_BLOCK_SIZE) {
        ah[7] = pChain.H[0];
        ah[6] = pChain.H[1];
        ah[5] = pChain.H[2];
        ah[4] = pChain.H[3];
        ah[3] = pChain.H[4];
        ah[2] = pChain.H[5];
        ah[1] = pChain.H[6];
        ah[0] = pChain.H[7];

        iround(Wx_ul, &ah, pbData, 0);
        iround(Wx_ul, &ah, pbData, 1);
        iround(Wx_ul, &ah, pbData, 2);
        iround(Wx_ul, &ah, pbData, 3);
        iround(Wx_ul, &ah, pbData, 4);
        iround(Wx_ul, &ah, pbData, 5);
        iround(Wx_ul, &ah, pbData, 6);
        iround(Wx_ul, &ah, pbData, 7);
        iround(Wx_ul, &ah, pbData, 8);
        iround(Wx_ul, &ah, pbData, 9);
        iround(Wx_ul, &ah, pbData, 10);
        iround(Wx_ul, &ah, pbData, 11);
        iround(Wx_ul, &ah, pbData, 12);
        iround(Wx_ul, &ah, pbData, 13);
        iround(Wx_ul, &ah, pbData, 14);
        iround(Wx_ul, &ah, pbData, 15);

        var iterCount: usize = 1;
        while (iterCount < (64 / 16)) : (iterCount += 1) {
            const roundBase = iterCount * 16;
            fround(Wx_ul, &ah, 0, roundBase);
            fround(Wx_ul, &ah, 1, roundBase);
            fround(Wx_ul, &ah, 2, roundBase);
            fround(Wx_ul, &ah, 3, roundBase);
            fround(Wx_ul, &ah, 4, roundBase);
            fround(Wx_ul, &ah, 5, roundBase);
            fround(Wx_ul, &ah, 6, roundBase);
            fround(Wx_ul, &ah, 7, roundBase);
            fround(Wx_ul, &ah, 8, roundBase);
            fround(Wx_ul, &ah, 9, roundBase);
            fround(Wx_ul, &ah, 10, roundBase);
            fround(Wx_ul, &ah, 11, roundBase);
            fround(Wx_ul, &ah, 12, roundBase);
            fround(Wx_ul, &ah, 13, roundBase);
            fround(Wx_ul, &ah, 14, roundBase);
            fround(Wx_ul, &ah, 15, roundBase);
        }

        pChain.H[0] +%= ah[7];
        pChain.H[1] +%= ah[6];
        pChain.H[2] +%= ah[5];
        pChain.H[3] +%= ah[4];
        pChain.H[4] +%= ah[3];
        pChain.H[5] +%= ah[2];
        pChain.H[6] +%= ah[1];
        pChain.H[7] +%= ah[0];

        pbData += SYMCRYPT_SHA256_INPUT_BLOCK_SIZE;
        cbData -= SYMCRYPT_SHA256_INPUT_BLOCK_SIZE;
    }

    pcbRemaining.* = cbData;

    hash.SymCryptWipe(@ptrCast(&Wx), uWipeSize);
    hash.SymCryptWipeKnownSize(@ptrCast(&ah), @sizeOf(@TypeOf(ah)));
}

comptime {
    if (types.CPU_X86 or types.CPU_AMD64) {
        @export(&BYTE_REVERSE_32, .{ .name = "BYTE_REVERSE_32" });
        @export(&XMM_PACKLOW, .{ .name = "XMM_PACKLOW" });
        @export(&XMM_PACKHIGH, .{ .name = "XMM_PACKHIGH" });
        @export(&SymCryptSha256AppendBlocks_xmm_4blocks, .{ .name = "SymCryptSha256AppendBlocks_xmm_4blocks" });
    }
}
