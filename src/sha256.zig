//
// sha256.zig
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
// This module contains the routines to implement SHA-224 and SHA-256
// from FIPS 180-2.
//

const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");
const types = @import("types.zig");
const macros = @import("macros.zig");
const hash = @import("hash.zig");
const hash_pattern = @import("hash_pattern.zig");

const BYTE = types.BYTE;
const PBYTE = types.PBYTE;
const PCBYTE = types.PCBYTE;
const UINT32 = types.UINT32;
const UINT64 = types.UINT64;
const SIZE_T = types.SIZE_T;
const PVOID = types.PVOID;
const SYMCRYPT_ERROR = types.SYMCRYPT_ERROR;
const SYMCRYPT_HASH = types.SYMCRYPT_HASH;
const PCSYMCRYPT_HASH = types.PCSYMCRYPT_HASH;
const SYMCRYPT_OID = types.SYMCRYPT_OID;
const SYMCRYPT_CALL = types.SYMCRYPT_CALL;
const SYMCRYPT_ALIGN_VALUE = types.SYMCRYPT_ALIGN_VALUE;

pub const SYMCRYPT_SHA224_RESULT_SIZE: usize = 28;
pub const SYMCRYPT_SHA224_INPUT_BLOCK_SIZE: usize = 64;
pub const SYMCRYPT_SHA224_STATE_EXPORT_SIZE: usize = 132;
pub const SYMCRYPT_SHA224_OID_COUNT: usize = 2;

pub const SYMCRYPT_SHA256_RESULT_SIZE: usize = 32;
pub const SYMCRYPT_SHA256_INPUT_BLOCK_SIZE: usize = 64;
pub const SYMCRYPT_SHA256_STATE_EXPORT_SIZE: usize = 132;
pub const SYMCRYPT_SHA256_OID_COUNT: usize = 2;

pub const SYMCRYPT_SHA256_CHAINING_STATE = hash.SYMCRYPT_SHA256_CHAINING_STATE;
pub const PSYMCRYPT_SHA256_CHAINING_STATE = hash.PSYMCRYPT_SHA256_CHAINING_STATE;
pub const SYMCRYPT_SHA256_STATE = hash.SYMCRYPT_SHA256_STATE;
pub const PSYMCRYPT_SHA256_STATE = hash.PSYMCRYPT_SHA256_STATE;
pub const PCSYMCRYPT_SHA256_STATE = hash.PCSYMCRYPT_SHA256_STATE;

pub const SYMCRYPT_SHA224_STATE = hash.SYMCRYPT_SHA224_STATE;
pub const PSYMCRYPT_SHA224_STATE = *SYMCRYPT_SHA224_STATE;
pub const PCSYMCRYPT_SHA224_STATE = *const SYMCRYPT_SHA224_STATE;

pub const SYMCRYPT_SHA256_STATE_EXPORT_BLOB = extern struct {
    header: hash.SYMCRYPT_BLOB_HEADER align(1),
    chain: [32]BYTE,
    dataLength: UINT64 align(1),
    buffer: [64]BYTE,
    rfu: [8]BYTE,
    trailer: hash.SYMCRYPT_BLOB_TRAILER,
};

// ============================================================================
// CPU Feature Detection & Extended Register Save/Restore
// ============================================================================

const SYMCRYPT_CPU_FEATURES = UINT32;
extern var g_SymCryptCpuFeaturesNotPresent: SYMCRYPT_CPU_FEATURES;
extern fn SymCryptCpuFeaturesNeverPresent() callconv(SYMCRYPT_CALL) SYMCRYPT_CPU_FEATURES;

const SYMCRYPT_CPU_FEATURE_SSE2: SYMCRYPT_CPU_FEATURES = 0x0001;
const SYMCRYPT_CPU_FEATURE_SSSE3: SYMCRYPT_CPU_FEATURES = 0x0002;
const SYMCRYPT_CPU_FEATURE_SAVEXMM_NOFAIL: SYMCRYPT_CPU_FEATURES = 0x0020;
const SYMCRYPT_CPU_FEATURE_SHANI: SYMCRYPT_CPU_FEATURES = 0x0040;
const SYMCRYPT_CPU_FEATURE_BMI2: SYMCRYPT_CPU_FEATURES = 0x0080;
const SYMCRYPT_CPU_FEATURES_FOR_SHANI_CODE: SYMCRYPT_CPU_FEATURES = SYMCRYPT_CPU_FEATURE_SSSE3 | SYMCRYPT_CPU_FEATURE_SHANI;

const SYMCRYPT_CPU_FEATURE_NEON_SHA256: SYMCRYPT_CPU_FEATURES = 0x08;

inline fn cpuFeaturesPresent(features: SYMCRYPT_CPU_FEATURES) bool {
    return ((features & SymCryptCpuFeaturesNeverPresent()) == 0) and ((features & g_SymCryptCpuFeaturesNotPresent) == 0);
}

const SYMCRYPT_XSTATE_SAVE_SIZE: usize = if (builtin.cpu.arch == .x86) 32 else 56;
const SYMCRYPT_EXTENDED_SAVE_DATA = extern struct {
    data: [SYMCRYPT_XSTATE_SAVE_SIZE]BYTE align(SYMCRYPT_ALIGN_VALUE),
    magic: SIZE_T,
};

extern fn SymCryptSaveXmm(pSaveData: *SYMCRYPT_EXTENDED_SAVE_DATA) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;
extern fn SymCryptRestoreXmm(pSaveData: *SYMCRYPT_EXTENDED_SAVE_DATA) callconv(SYMCRYPT_CALL) void;

extern fn SymCryptSha256AppendBlocks_xmm_ssse3_asm(
    pChain: *SYMCRYPT_SHA256_CHAINING_STATE,
    pbData: PCBYTE,
    cbData: SIZE_T,
    pcbRemaining: *SIZE_T,
) callconv(SYMCRYPT_CALL) void;

extern fn SymCryptSha256AppendBlocks_xmm_4blocks(
    pChain: *SYMCRYPT_SHA256_CHAINING_STATE,
    pbData: PCBYTE,
    cbData: SIZE_T,
    pcbRemaining: *SIZE_T,
) callconv(SYMCRYPT_CALL) void;

// ============================================================================
// Constants & OIDs
// ============================================================================

// SymCryptSha256K must be aligned to at least a multiple of 256 so that
// an indexing mode aligned with 64-byte alignment never crosses a 256-byte boundary.
pub export const SymCryptSha256K: [64]UINT32 align(256) = .{
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

pub const SymCryptSha224OidList: [SYMCRYPT_SHA224_OID_COUNT]SYMCRYPT_OID = .{
    .{ .cbOID = 13, .pbOID = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x04\x05\x00" },
    .{ .cbOID = 11, .pbOID = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x04" },
};

pub const SymCryptSha256OidList: [SYMCRYPT_SHA256_OID_COUNT]SYMCRYPT_OID = .{
    .{ .cbOID = 13, .pbOID = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00" },
    .{ .cbOID = 11, .pbOID = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01" },
};

// Initial states from FIPS 180-2
const sha224InitialState = [8]UINT32{
    0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
    0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
};

const sha256InitialState = [8]UINT32{
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};

// ============================================================================
// Pattern Instantiation & Algorithm Descriptors
// ============================================================================

const Sha224Pattern = hash_pattern.HashPattern(
    SYMCRYPT_SHA224_STATE,
    SYMCRYPT_SHA256_CHAINING_STATE,
    &SymCryptSha224Init,
    &SymCryptSha224Append,
    &SymCryptSha224Result,
    &SymCryptSha256AppendBlocks,
);

const Sha256Pattern = hash_pattern.HashPattern(
    SYMCRYPT_SHA256_STATE,
    SYMCRYPT_SHA256_CHAINING_STATE,
    &SymCryptSha256Init,
    &SymCryptSha256Append,
    &SymCryptSha256Result,
    &SymCryptSha256AppendBlocks,
);

pub export const SymCryptSha224Algorithm_default: SYMCRYPT_HASH align(SYMCRYPT_ALIGN_VALUE) = .{
    .initFunc = &Sha224Pattern.initVoid,
    .appendFunc = &Sha224Pattern.appendVoid,
    .resultFunc = &Sha224Pattern.resultVoid,
    .appendBlockFunc = &Sha224Pattern.appendBlocksVoid,
    .stateCopyFunc = &Sha224Pattern.stateCopyVoid,
    .stateSize = @sizeOf(SYMCRYPT_SHA224_STATE),
    .resultSize = SYMCRYPT_SHA224_RESULT_SIZE,
    .inputBlockSize = SYMCRYPT_SHA224_INPUT_BLOCK_SIZE,
    .chainOffset = @offsetOf(SYMCRYPT_SHA224_STATE, "chain"),
    .chainSize = @sizeOf(SYMCRYPT_SHA256_CHAINING_STATE),
};

pub export const SymCryptSha224Algorithm: PCSYMCRYPT_HASH = &SymCryptSha224Algorithm_default;

pub export const SymCryptSha256Algorithm_default: SYMCRYPT_HASH align(SYMCRYPT_ALIGN_VALUE) = .{
    .initFunc = &Sha256Pattern.initVoid,
    .appendFunc = &Sha256Pattern.appendVoid,
    .resultFunc = &Sha256Pattern.resultVoid,
    .appendBlockFunc = &Sha256Pattern.appendBlocksVoid,
    .stateCopyFunc = &Sha256Pattern.stateCopyVoid,
    .stateSize = @sizeOf(SYMCRYPT_SHA256_STATE),
    .resultSize = SYMCRYPT_SHA256_RESULT_SIZE,
    .inputBlockSize = SYMCRYPT_SHA256_INPUT_BLOCK_SIZE,
    .chainOffset = @offsetOf(SYMCRYPT_SHA256_STATE, "chain"),
    .chainSize = @sizeOf(SYMCRYPT_SHA256_CHAINING_STATE),
};

pub export const SymCryptSha256Algorithm: PCSYMCRYPT_HASH = &SymCryptSha256Algorithm_default;

// ============================================================================
// Public API
// ============================================================================

pub export fn SymCryptSha224StateCopy(pSrc: PCSYMCRYPT_SHA224_STATE, pDst: PSYMCRYPT_SHA224_STATE) callconv(SYMCRYPT_CALL) void {
    Sha224Pattern.stateCopy(pSrc, pDst);
}

pub export fn SymCryptSha224(pbData: PCBYTE, cbData: SIZE_T, pbResult: PBYTE) callconv(SYMCRYPT_CALL) void {
    Sha224Pattern.hash(pbData, cbData, pbResult);
}

pub export fn SymCryptSha256StateCopy(pSrc: PCSYMCRYPT_SHA256_STATE, pDst: PSYMCRYPT_SHA256_STATE) callconv(SYMCRYPT_CALL) void {
    Sha256Pattern.stateCopy(pSrc, pDst);
}

pub export fn SymCryptSha256(pbData: PCBYTE, cbData: SIZE_T, pbResult: PBYTE) callconv(SYMCRYPT_CALL) void {
    Sha256Pattern.hash(pbData, cbData, pbResult);
}

pub export fn SymCryptSha224Init(pState: PSYMCRYPT_SHA224_STATE) callconv(SYMCRYPT_CALL) void {
    macros.SET_MAGIC(pState);

    pState.dataLengthL = 0;
    pState.dataLengthH = 0;
    pState.bytesInBuffer = 0;

    pState.chain.H = sha224InitialState;
}

pub export fn SymCryptSha256Init(pState: PSYMCRYPT_SHA256_STATE) callconv(SYMCRYPT_CALL) void {
    macros.SET_MAGIC(pState);

    pState.dataLengthL = 0;
    pState.dataLengthH = 0;
    pState.bytesInBuffer = 0;

    pState.chain.H = sha256InitialState;
}

pub export fn SymCryptSha224Append(pState: PSYMCRYPT_SHA224_STATE, pbData: PCBYTE, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void {
    SymCryptSha256Append(pState, pbData, cbData);
}

pub export fn SymCryptSha256Append(pState: PSYMCRYPT_SHA256_STATE, pbData: PCBYTE, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void {
    hash_pattern.hashBufferAppendWithRemaining(
        SYMCRYPT_SHA256_INPUT_BLOCK_SIZE,
        false,
        pState,
        pbData,
        cbData,
        SymCryptSha256AppendBlocks,
    );
}

pub export fn SymCryptSha224Result(pState: PSYMCRYPT_SHA224_STATE, pbResult: PBYTE) callconv(SYMCRYPT_CALL) void {
    var sha256Output: [SYMCRYPT_SHA256_RESULT_SIZE]BYTE = undefined;
    var tmp: SIZE_T = 0;
    var bytesInBuffer = pState.bytesInBuffer;

    macros.CHECK_MAGIC(pState);

    // The buffer is never completely full, so we can always put the first
    // padding byte in.
    pState.buffer[bytesInBuffer] = 0x80;
    bytesInBuffer += 1;

    if (bytesInBuffer > 64 - 8) {
        // No room for the rest of the padding. Pad with zeroes & process block
        // bytesInBuffer is at most 64, so we do not have an integer underflow
        hash.SymCryptWipe(@ptrCast(pState.buffer[bytesInBuffer..].ptr), 64 - bytesInBuffer);
        SymCryptSha256AppendBlocks(&pState.chain, &pState.buffer, 64, &tmp);
        bytesInBuffer = 0;
    }

    // Set the rest of the padding
    // We choose to wipe to the end of the buffer, as it is 16-aligned,
    // and wiping to a 16-aligned boundary is slightly faster
    hash.SymCryptWipe(@ptrCast(pState.buffer[bytesInBuffer..].ptr), 64 - bytesInBuffer);
    macros.STORE_MSBFIRST64(pState.buffer[64 - 8 ..].ptr, pState.dataLengthL *% 8);

    // Process the final block
    SymCryptSha256AppendBlocks(&pState.chain, &pState.buffer, 64, &tmp);

    // Write the output in the correct byte order
    macros.SymCryptUint32ToMsbFirst(&pState.chain.H, &sha256Output, 8);
    @memcpy(pbResult[0..SYMCRYPT_SHA224_RESULT_SIZE], sha256Output[0..SYMCRYPT_SHA224_RESULT_SIZE]);

    // Wipe & re-initialize
    // We have to wipe the whole state because the Init call
    // might be optimized by a smart compiler.
    hash.SymCryptWipeKnownSize(@ptrCast(&sha256Output), @sizeOf(@TypeOf(sha256Output)));
    hash.SymCryptWipeKnownSize(@ptrCast(pState), @sizeOf(SYMCRYPT_SHA224_STATE));
    SymCryptSha224Init(pState);
}

pub export fn SymCryptSha256Result(pState: PSYMCRYPT_SHA256_STATE, pbResult: PBYTE) callconv(SYMCRYPT_CALL) void {
    var tmp: SIZE_T = 0;
    var bytesInBuffer = pState.bytesInBuffer;

    macros.CHECK_MAGIC(pState);

    // The buffer is never completely full, so we can always put the first
    // padding byte in.
    pState.buffer[bytesInBuffer] = 0x80;
    bytesInBuffer += 1;

    if (bytesInBuffer > 64 - 8) {
        // No room for the rest of the padding. Pad with zeroes & process block
        // bytesInBuffer is at most 64, so we do not have an integer underflow
        hash.SymCryptWipe(@ptrCast(pState.buffer[bytesInBuffer..].ptr), 64 - bytesInBuffer);
        SymCryptSha256AppendBlocks(&pState.chain, &pState.buffer, 64, &tmp);
        bytesInBuffer = 0;
    }

    // Set the rest of the padding
    // We choose to wipe to the end of the buffer, as it is 16-aligned,
    // and wiping to a 16-aligned boundary is slightly faster
    hash.SymCryptWipe(@ptrCast(pState.buffer[bytesInBuffer..].ptr), 64 - bytesInBuffer);
    macros.STORE_MSBFIRST64(pState.buffer[64 - 8 ..].ptr, pState.dataLengthL *% 8);

    // Process the final block
    SymCryptSha256AppendBlocks(&pState.chain, &pState.buffer, 64, &tmp);

    // Write the output in the correct byte order
    macros.SymCryptUint32ToMsbFirst(&pState.chain.H, pbResult, 8);

    // Wipe & re-initialize
    // We have to wipe the whole state because the Init call
    // might be optimized by a smart compiler.
    hash.SymCryptWipeKnownSize(@ptrCast(pState), @sizeOf(SYMCRYPT_SHA256_STATE));
    SymCryptSha256Init(pState);
}

// ============================================================================
// Compression Function Implementations
// ============================================================================

inline fn maj(x: UINT32, y: UINT32, z: UINT32) UINT32 {
    return (((z | y) & x) | (z & y));
}

inline fn ch(x: UINT32, y: UINT32, z: UINT32) UINT32 {
    return (((z ^ y) & x) ^ z);
}

inline fn csigma0(x: UINT32) UINT32 {
    return macros.ROR32(x, 2) ^ macros.ROR32(x, 13) ^ macros.ROR32(x, 22);
}

inline fn csigma1(x: UINT32) UINT32 {
    return macros.ROR32(x, 6) ^ macros.ROR32(x, 11) ^ macros.ROR32(x, 25);
}

inline fn lsigma0(x: UINT32) UINT32 {
    return macros.ROR32(x, 7) ^ macros.ROR32(x, 18) ^ (x >> 3);
}

inline fn lsigma1(x: UINT32) UINT32 {
    return macros.ROR32(x, 17) ^ macros.ROR32(x, 19) ^ (x >> 10);
}

inline fn cround(ah: *[8]UINT32, comptime r16: usize, r: usize, Wt: UINT32) void {
    ah[r16 & 7] +%= csigma1(ah[(r16 + 3) & 7]) +% ch(ah[(r16 + 3) & 7], ah[(r16 + 2) & 7], ah[(r16 + 1) & 7]) +% SymCryptSha256K[r] +% Wt;
    ah[(r16 + 4) & 7] +%= ah[r16 & 7];
    ah[r16 & 7] +%= csigma0(ah[(r16 + 7) & 7]) +% maj(ah[(r16 + 7) & 7], ah[(r16 + 6) & 7], ah[(r16 + 5) & 7]);
}

inline fn iround(ah: *[8]UINT32, W: *[16]UINT32, pbData: PCBYTE, comptime r: usize) void {
    const Wt = macros.LOAD_MSBFIRST32(pbData + 4 * r);
    W[r] = Wt;
    cround(ah, r, r, Wt);
}

inline fn fround(ah: *[8]UINT32, W: *[16]UINT32, comptime r16: usize, rb: usize) void {
    const Wt = lsigma1(W[(r16 + 16 - 2) & 15]) +% W[(r16 + 16 - 7) & 15] +%
        lsigma0(W[(r16 + 16 - 15) & 15]) +% W[r16 & 15];
    W[r16] = Wt;
    cround(ah, r16, r16 + rb, Wt);
}

pub export fn SymCryptSha256AppendBlocks_ul1(
    pChain: *SYMCRYPT_SHA256_CHAINING_STATE,
    pbData_in: PCBYTE,
    cbData_in: SIZE_T,
    pcbRemaining: *SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    var pbData = pbData_in;
    var cbData = cbData_in;
    var W: [16]UINT32 align(SYMCRYPT_ALIGN_VALUE) = undefined;
    var ah: [8]UINT32 align(SYMCRYPT_ALIGN_VALUE) = undefined;

    while (cbData >= 64) {
        ah[7] = pChain.H[0];
        ah[6] = pChain.H[1];
        ah[5] = pChain.H[2];
        ah[4] = pChain.H[3];
        ah[3] = pChain.H[4];
        ah[2] = pChain.H[5];
        ah[1] = pChain.H[6];
        ah[0] = pChain.H[7];

        // Initial rounds 0 to 15
        iround(&ah, &W, pbData, 0);
        iround(&ah, &W, pbData, 1);
        iround(&ah, &W, pbData, 2);
        iround(&ah, &W, pbData, 3);
        iround(&ah, &W, pbData, 4);
        iround(&ah, &W, pbData, 5);
        iround(&ah, &W, pbData, 6);
        iround(&ah, &W, pbData, 7);
        iround(&ah, &W, pbData, 8);
        iround(&ah, &W, pbData, 9);
        iround(&ah, &W, pbData, 10);
        iround(&ah, &W, pbData, 11);
        iround(&ah, &W, pbData, 12);
        iround(&ah, &W, pbData, 13);
        iround(&ah, &W, pbData, 14);
        iround(&ah, &W, pbData, 15);

        // Rounds 16 to 63
        var round: usize = 16;
        while (round < 64) : (round += 16) {
            fround(&ah, &W, 0, round);
            fround(&ah, &W, 1, round);
            fround(&ah, &W, 2, round);
            fround(&ah, &W, 3, round);
            fround(&ah, &W, 4, round);
            fround(&ah, &W, 5, round);
            fround(&ah, &W, 6, round);
            fround(&ah, &W, 7, round);
            fround(&ah, &W, 8, round);
            fround(&ah, &W, 9, round);
            fround(&ah, &W, 10, round);
            fround(&ah, &W, 11, round);
            fround(&ah, &W, 12, round);
            fround(&ah, &W, 13, round);
            fround(&ah, &W, 14, round);
            fround(&ah, &W, 15, round);
        }

        pChain.H[0] +%= ah[7];
        pChain.H[1] +%= ah[6];
        pChain.H[2] +%= ah[5];
        pChain.H[3] +%= ah[4];
        pChain.H[4] +%= ah[3];
        pChain.H[5] +%= ah[2];
        pChain.H[6] +%= ah[1];
        pChain.H[7] +%= ah[0];

        pbData += 64;
        cbData -= 64;
    }

    pcbRemaining.* = cbData;

    // Wipe the variables
    hash.SymCryptWipeKnownSize(@ptrCast(&W), @sizeOf(@TypeOf(W)));
    hash.SymCryptWipeKnownSize(@ptrCast(&ah), @sizeOf(@TypeOf(ah)));
}

// ============================================================================
// x86 / AMD64 SHA-NI Implementation
// ============================================================================

const V4U32 = @Vector(4, u32);
const V4I32 = @Vector(4, i32);
const V16U8 = @Vector(16, u8);

extern fn @"llvm.x86.ssse3.pshuf.b.128"(a: V16U8, b: V16U8) V16U8;
extern fn @"llvm.x86.sha256rnds2"(a: V4I32, b: V4I32, k: V4I32) V4I32;
extern fn @"llvm.x86.sha256msg1"(a: V4I32, b: V4I32) V4I32;
extern fn @"llvm.x86.sha256msg2"(a: V4I32, b: V4I32) V4I32;

inline fn mmLoaduSi128(ptr: PCBYTE) V4U32 {
    return @bitCast(std.mem.readInt(u128, ptr[0..16], .little));
}

inline fn mmStoreuSi128(ptr: [*]u8, v: V4U32) void {
    std.mem.writeInt(u128, ptr[0..16], @bitCast(v), .little);
}

inline fn loadSha256K4(r: usize) V4U32 {
    return V4U32{
        SymCryptSha256K[r + 0],
        SymCryptSha256K[r + 1],
        SymCryptSha256K[r + 2],
        SymCryptSha256K[r + 3],
    };
}

inline fn mmShuffleEpi32(a: V4U32, comptime imm8: u8) V4U32 {
    return @shuffle(u32, a, undefined, [4]i32{
        (imm8 >> 0) & 3,
        (imm8 >> 2) & 3,
        (imm8 >> 4) & 3,
        (imm8 >> 6) & 3,
    });
}

inline fn mmUnpackloEpi64(a: V4U32, b: V4U32) V4U32 {
    return @shuffle(u32, a, b, [4]i32{ 0, 1, -1, -2 });
}

inline fn mmUnpackhiEpi64(a: V4U32, b: V4U32) V4U32 {
    return @shuffle(u32, a, b, [4]i32{ 2, 3, -3, -4 });
}

inline fn mmAlignrEpi8(a: V4U32, b: V4U32, comptime count: u8) V4U32 {
    const ab = @shuffle(u8, @as(V16U8, @bitCast(b)), @as(V16U8, @bitCast(a)), [16]i32{
        if (count + 0 < 16) @as(i32, count + 0) else -1 - @as(i32, count + 0 - 16),
        if (count + 1 < 16) @as(i32, count + 1) else -1 - @as(i32, count + 1 - 16),
        if (count + 2 < 16) @as(i32, count + 2) else -1 - @as(i32, count + 2 - 16),
        if (count + 3 < 16) @as(i32, count + 3) else -1 - @as(i32, count + 3 - 16),
        if (count + 4 < 16) @as(i32, count + 4) else -1 - @as(i32, count + 4 - 16),
        if (count + 5 < 16) @as(i32, count + 5) else -1 - @as(i32, count + 5 - 16),
        if (count + 6 < 16) @as(i32, count + 6) else -1 - @as(i32, count + 6 - 16),
        if (count + 7 < 16) @as(i32, count + 7) else -1 - @as(i32, count + 7 - 16),
        if (count + 8 < 16) @as(i32, count + 8) else -1 - @as(i32, count + 8 - 16),
        if (count + 9 < 16) @as(i32, count + 9) else -1 - @as(i32, count + 9 - 16),
        if (count + 10 < 16) @as(i32, count + 10) else -1 - @as(i32, count + 10 - 16),
        if (count + 11 < 16) @as(i32, count + 11) else -1 - @as(i32, count + 11 - 16),
        if (count + 12 < 16) @as(i32, count + 12) else -1 - @as(i32, count + 12 - 16),
        if (count + 13 < 16) @as(i32, count + 13) else -1 - @as(i32, count + 13 - 16),
        if (count + 14 < 16) @as(i32, count + 14) else -1 - @as(i32, count + 14 - 16),
        if (count + 15 < 16) @as(i32, count + 15) else -1 - @as(i32, count + 15 - 16),
    });
    return @bitCast(ab);
}

inline fn mmShuffleEpi8(a: V4U32, mask: V16U8) V4U32 {
    return @bitCast(@"llvm.x86.ssse3.pshuf.b.128"(@bitCast(a), mask));
}

inline fn mmSha256rnds2Epu32(a: V4U32, b: V4U32, k: V4U32) V4U32 {
    return @bitCast(@"llvm.x86.sha256rnds2"(@bitCast(a), @bitCast(b), @bitCast(k)));
}

inline fn mmSha256msg1Epu32(a: V4U32, b: V4U32) V4U32 {
    return @bitCast(@"llvm.x86.sha256msg1"(@bitCast(a), @bitCast(b)));
}

inline fn mmSha256msg2Epu32(a: V4U32, b: V4U32) V4U32 {
    return @bitCast(@"llvm.x86.sha256msg2"(@bitCast(a), @bitCast(b)));
}

inline fn sha256AppendBlocksShani(
    pChain: *SYMCRYPT_SHA256_CHAINING_STATE,
    pbData_in: PCBYTE,
    cbData_in: SIZE_T,
    pcbRemaining: *SIZE_T,
) void {
    @setRuntimeSafety(false);
    var pbData = pbData_in;
    var cbData = cbData_in;

    const byte_reverse_32 = V16U8{ 3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12 };

    // Load initial values:
    // DCBA = (D, C, B, A), HGFE = (H, G, F, E)
    const dcba_init = mmLoaduSi128(@ptrCast(&pChain.H[0]));
    const hgfe_init = mmLoaduSi128(@ptrCast(&pChain.H[4]));
    const cdba = mmShuffleEpi32(dcba_init, 0xb1); // (C, D, A, B)
    const ghef = mmShuffleEpi32(hgfe_init, 0xb1); // (G, H, E, F)
    var abef = mmAlignrEpi8(cdba, ghef, 8); // (A, B, E, F)
    var cdgh = mmUnpackhiEpi64(ghef, cdba); // (C, D, G, H)

    while (cbData >= 64) {
        const abef_save = abef;
        const cdgh_save = cdgh;

        var w0 = mmShuffleEpi8(mmLoaduSi128(pbData + 0), byte_reverse_32);
        var w1 = mmShuffleEpi8(mmLoaduSi128(pbData + 16), byte_reverse_32);
        var w2 = mmShuffleEpi8(mmLoaduSi128(pbData + 32), byte_reverse_32);
        var w3 = mmShuffleEpi8(mmLoaduSi128(pbData + 48), byte_reverse_32);

        // Rounds 0 - 3
        var m0 = w0 +% loadSha256K4(0);
        cdgh = mmSha256rnds2Epu32(cdgh, abef, m0);
        m0 = mmShuffleEpi32(m0, 0x0E);
        abef = mmSha256rnds2Epu32(abef, cdgh, m0);

        // Rounds 4 - 7
        m0 = w1 +% loadSha256K4(4);
        cdgh = mmSha256rnds2Epu32(cdgh, abef, m0);
        m0 = mmShuffleEpi32(m0, 0x0E);
        abef = mmSha256rnds2Epu32(abef, cdgh, m0);
        w0 = mmSha256msg1Epu32(w0, w1);

        // Rounds 8 - 11
        m0 = w2 +% loadSha256K4(8);
        cdgh = mmSha256rnds2Epu32(cdgh, abef, m0);
        m0 = mmShuffleEpi32(m0, 0x0E);
        abef = mmSha256rnds2Epu32(abef, cdgh, m0);
        w1 = mmSha256msg1Epu32(w1, w2);

        // Rounds 12 - 15
        m0 = w3 +% loadSha256K4(12);
        cdgh = mmSha256rnds2Epu32(cdgh, abef, m0);
        m0 = mmShuffleEpi32(m0, 0x0E);
        abef = mmSha256rnds2Epu32(abef, cdgh, m0);
        w0 = w0 +% mmAlignrEpi8(w3, w2, 4);
        w0 = mmSha256msg2Epu32(w0, w3);
        w2 = mmSha256msg1Epu32(w2, w3);

        var r: usize = 16;
        while (r < 48) : (r += 16) {
            // Rounds r .. r+3
            m0 = w0 +% loadSha256K4(r);
            cdgh = mmSha256rnds2Epu32(cdgh, abef, m0);
            m0 = mmShuffleEpi32(m0, 0x0E);
            abef = mmSha256rnds2Epu32(abef, cdgh, m0);
            w1 = w1 +% mmAlignrEpi8(w0, w3, 4);
            w1 = mmSha256msg2Epu32(w1, w0);
            w3 = mmSha256msg1Epu32(w3, w0);

            // Rounds r+4 .. r+7
            m0 = w1 +% loadSha256K4(r + 4);
            cdgh = mmSha256rnds2Epu32(cdgh, abef, m0);
            m0 = mmShuffleEpi32(m0, 0x0E);
            abef = mmSha256rnds2Epu32(abef, cdgh, m0);
            w2 = w2 +% mmAlignrEpi8(w1, w0, 4);
            w2 = mmSha256msg2Epu32(w2, w1);
            w0 = mmSha256msg1Epu32(w0, w1);

            // Rounds r+8 .. r+11
            m0 = w2 +% loadSha256K4(r + 8);
            cdgh = mmSha256rnds2Epu32(cdgh, abef, m0);
            m0 = mmShuffleEpi32(m0, 0x0E);
            abef = mmSha256rnds2Epu32(abef, cdgh, m0);
            w3 = w3 +% mmAlignrEpi8(w2, w1, 4);
            w3 = mmSha256msg2Epu32(w3, w2);
            w1 = mmSha256msg1Epu32(w1, w2);

            // Rounds r+12 .. r+15
            m0 = w3 +% loadSha256K4(r + 12);
            cdgh = mmSha256rnds2Epu32(cdgh, abef, m0);
            m0 = mmShuffleEpi32(m0, 0x0E);
            abef = mmSha256rnds2Epu32(abef, cdgh, m0);
            w0 = w0 +% mmAlignrEpi8(w3, w2, 4);
            w0 = mmSha256msg2Epu32(w0, w3);
            w2 = mmSha256msg1Epu32(w2, w3);
        }

        // Rounds 48 - 51
        m0 = w0 +% loadSha256K4(48);
        cdgh = mmSha256rnds2Epu32(cdgh, abef, m0);
        m0 = mmShuffleEpi32(m0, 0x0E);
        abef = mmSha256rnds2Epu32(abef, cdgh, m0);
        w1 = w1 +% mmAlignrEpi8(w0, w3, 4);
        w1 = mmSha256msg2Epu32(w1, w0);
        w3 = mmSha256msg1Epu32(w3, w0);

        // Rounds 52 - 55
        m0 = w1 +% loadSha256K4(52);
        cdgh = mmSha256rnds2Epu32(cdgh, abef, m0);
        m0 = mmShuffleEpi32(m0, 0x0E);
        abef = mmSha256rnds2Epu32(abef, cdgh, m0);
        w2 = w2 +% mmAlignrEpi8(w1, w0, 4);
        w2 = mmSha256msg2Epu32(w2, w1);

        // Rounds 56 - 59
        m0 = w2 +% loadSha256K4(56);
        cdgh = mmSha256rnds2Epu32(cdgh, abef, m0);
        m0 = mmShuffleEpi32(m0, 0x0E);
        abef = mmSha256rnds2Epu32(abef, cdgh, m0);
        w3 = w3 +% mmAlignrEpi8(w2, w1, 4);
        w3 = mmSha256msg2Epu32(w3, w2);

        // Rounds 60 - 63
        m0 = w3 +% loadSha256K4(60);
        cdgh = mmSha256rnds2Epu32(cdgh, abef, m0);
        m0 = mmShuffleEpi32(m0, 0x0E);
        abef = mmSha256rnds2Epu32(abef, cdgh, m0);

        // Add initial values
        abef = abef +% abef_save;
        cdgh = cdgh +% cdgh_save;

        pbData += 64;
        cbData -= 64;
    }

    // Unpack the state registers and store them in the state
    const feba = mmShuffleEpi32(abef, 0x1b);
    const hgdc = mmShuffleEpi32(cdgh, 0x1b);
    const dcba = mmUnpackloEpi64(feba, hgdc); // (D, C, B, A)
    const hgfe = mmUnpackhiEpi64(feba, hgdc); // (H, G, F, E)

    mmStoreuSi128(@ptrCast(&pChain.H[0]), dcba);
    mmStoreuSi128(@ptrCast(&pChain.H[4]), hgfe);

    pcbRemaining.* = cbData;
}

comptime {
    if ((builtin.cpu.arch == .x86_64 or builtin.cpu.arch == .x86) and
        std.Target.x86.featureSetHasAll(builtin.cpu.features, .{ .sha, .ssse3 }))
    {
        @export(&SymCryptSha256AppendBlocks_shani, .{ .name = "SymCryptSha256AppendBlocks_shani" });
    }
}

fn SymCryptSha256AppendBlocks_shani(
    pChain: *SYMCRYPT_SHA256_CHAINING_STATE,
    pbData_in: PCBYTE,
    cbData_in: SIZE_T,
    pcbRemaining: *SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    sha256AppendBlocksShani(pChain, pbData_in, cbData_in, pcbRemaining);
}

// ============================================================================
// ARM64 SHA256 Crypto Extension Implementation
// ============================================================================

extern fn @"llvm.aarch64.crypto.sha256h"(hash_abcd: V4U32, hash_efgh: V4U32, wk: V4U32) V4U32;
extern fn @"llvm.aarch64.crypto.sha256h2"(hash_efgh: V4U32, hash_abcd: V4U32, wk: V4U32) V4U32;
extern fn @"llvm.aarch64.crypto.sha256su0"(w0_3: V4U32, w4_7: V4U32) V4U32;
extern fn @"llvm.aarch64.crypto.sha256su1"(tw0_3: V4U32, w8_11: V4U32, w12_15: V4U32) V4U32;

inline fn arm64Rev32(v: V4U32) V4U32 {
    const bytes: V16U8 = @bitCast(v);
    const rev = @shuffle(u8, bytes, undefined, [16]i32{
        3,  2,  1,  0,
        7,  6,  5,  4,
        11, 10, 9,  8,
        15, 14, 13, 12,
    });
    return @bitCast(rev);
}

inline fn sha256AppendBlocksInstr(
    pChain: *SYMCRYPT_SHA256_CHAINING_STATE,
    pbData_in: PCBYTE,
    cbData_in: SIZE_T,
    pcbRemaining: *SIZE_T,
) void {
    @setRuntimeSafety(false);
    var pbData = pbData_in;
    var cbData = cbData_in;

    var abcd = mmLoaduSi128(@ptrCast(&pChain.H[0]));
    var efgh = mmLoaduSi128(@ptrCast(&pChain.H[4]));

    var abcd_orig = abcd;
    var efgh_orig = efgh;

    while (cbData >= 64) {
        var m0 = arm64Rev32(mmLoaduSi128(pbData + 0));
        var m1 = arm64Rev32(mmLoaduSi128(pbData + 16));
        var m2 = arm64Rev32(mmLoaduSi128(pbData + 32));
        var m3 = arm64Rev32(mmLoaduSi128(pbData + 48));

        var r: usize = 0;
        while (r < 48) : (r += 16) {
            // Rounds r .. r+3
            var wk = m0 +% loadSha256K4(r);
            m0 = @"llvm.aarch64.crypto.sha256su0"(m0, m1);
            var htmp = abcd;
            abcd = @"llvm.aarch64.crypto.sha256h"(abcd, efgh, wk);
            efgh = @"llvm.aarch64.crypto.sha256h2"(efgh, htmp, wk);
            m0 = @"llvm.aarch64.crypto.sha256su1"(m0, m2, m3);

            // Rounds r+4 .. r+7
            wk = m1 +% loadSha256K4(r + 4);
            m1 = @"llvm.aarch64.crypto.sha256su0"(m1, m2);
            htmp = abcd;
            abcd = @"llvm.aarch64.crypto.sha256h"(abcd, efgh, wk);
            efgh = @"llvm.aarch64.crypto.sha256h2"(efgh, htmp, wk);
            m1 = @"llvm.aarch64.crypto.sha256su1"(m1, m3, m0);

            // Rounds r+8 .. r+11
            wk = m2 +% loadSha256K4(r + 8);
            m2 = @"llvm.aarch64.crypto.sha256su0"(m2, m3);
            htmp = abcd;
            abcd = @"llvm.aarch64.crypto.sha256h"(abcd, efgh, wk);
            efgh = @"llvm.aarch64.crypto.sha256h2"(efgh, htmp, wk);
            m2 = @"llvm.aarch64.crypto.sha256su1"(m2, m0, m1);

            // Rounds r+12 .. r+15
            wk = m3 +% loadSha256K4(r + 12);
            m3 = @"llvm.aarch64.crypto.sha256su0"(m3, m0);
            htmp = abcd;
            abcd = @"llvm.aarch64.crypto.sha256h"(abcd, efgh, wk);
            efgh = @"llvm.aarch64.crypto.sha256h2"(efgh, htmp, wk);
            m3 = @"llvm.aarch64.crypto.sha256su1"(m3, m1, m2);
        }

        // Rounds 48 .. 51
        var wk = m0 +% loadSha256K4(48);
        var htmp = abcd;
        abcd = @"llvm.aarch64.crypto.sha256h"(abcd, efgh, wk);
        efgh = @"llvm.aarch64.crypto.sha256h2"(efgh, htmp, wk);

        // Rounds 52 .. 55
        wk = m1 +% loadSha256K4(52);
        htmp = abcd;
        abcd = @"llvm.aarch64.crypto.sha256h"(abcd, efgh, wk);
        efgh = @"llvm.aarch64.crypto.sha256h2"(efgh, htmp, wk);

        // Rounds 56 .. 59
        wk = m2 +% loadSha256K4(56);
        htmp = abcd;
        abcd = @"llvm.aarch64.crypto.sha256h"(abcd, efgh, wk);
        efgh = @"llvm.aarch64.crypto.sha256h2"(efgh, htmp, wk);

        // Rounds 60 .. 63
        wk = m3 +% loadSha256K4(60);
        htmp = abcd;
        abcd = @"llvm.aarch64.crypto.sha256h"(abcd, efgh, wk);
        efgh = @"llvm.aarch64.crypto.sha256h2"(efgh, htmp, wk);

        abcd = abcd +% abcd_orig;
        efgh = efgh +% efgh_orig;

        pbData += 64;
        cbData -= 64;

        abcd_orig = abcd;
        efgh_orig = efgh;
    }

    mmStoreuSi128(@ptrCast(&pChain.H[0]), abcd);
    mmStoreuSi128(@ptrCast(&pChain.H[4]), efgh);

    pcbRemaining.* = cbData;
}

comptime {
    if (builtin.cpu.arch == .aarch64 and
        std.Target.aarch64.featureSetHas(builtin.cpu.features, .sha2))
    {
        @export(&SymCryptSha256AppendBlocks_instr, .{ .name = "SymCryptSha256AppendBlocks_instr" });
    }
}

fn SymCryptSha256AppendBlocks_instr(
    pChain: *SYMCRYPT_SHA256_CHAINING_STATE,
    pbData_in: PCBYTE,
    cbData_in: SIZE_T,
    pcbRemaining: *SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    sha256AppendBlocksInstr(pChain, pbData_in, cbData_in, pcbRemaining);
}

// ============================================================================
// AppendBlocks Dispatch
// ============================================================================

pub export fn SymCryptSha256AppendBlocks(
    pChain: *SYMCRYPT_SHA256_CHAINING_STATE,
    pbData: PCBYTE,
    cbData: SIZE_T,
    pcbRemaining: *SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    if (comptime !build_options.use_asm) {
        SymCryptSha256AppendBlocks_ul1(pChain, pbData, cbData, pcbRemaining);
        return;
    }

    if (comptime builtin.cpu.arch == .x86_64) {
        var saveData: SYMCRYPT_EXTENDED_SAVE_DATA = undefined;
        if (comptime std.Target.x86.featureSetHasAll(builtin.cpu.features, .{ .sha, .ssse3 })) {
            if (cpuFeaturesPresent(SYMCRYPT_CPU_FEATURES_FOR_SHANI_CODE) and SymCryptSaveXmm(&saveData) == .SYMCRYPT_NO_ERROR) {
                SymCryptSha256AppendBlocks_shani(pChain, pbData, cbData, pcbRemaining);
                SymCryptRestoreXmm(&saveData);
                return;
            }
        }
        if (cpuFeaturesPresent(SYMCRYPT_CPU_FEATURE_SSSE3 | SYMCRYPT_CPU_FEATURE_BMI2) and
            SymCryptSaveXmm(&saveData) == .SYMCRYPT_NO_ERROR)
        {
            if (comptime builtin.os.tag == .linux) {
                SymCryptSha256AppendBlocks_xmm_ssse3_asm(pChain, pbData, cbData, pcbRemaining);
            } else {
                SymCryptSha256AppendBlocks_xmm_4blocks(pChain, pbData, cbData, pcbRemaining);
            }
            SymCryptRestoreXmm(&saveData);
            return;
        }
        SymCryptSha256AppendBlocks_ul1(pChain, pbData, cbData, pcbRemaining);
    } else if (comptime builtin.cpu.arch == .x86) {
        var saveData: SYMCRYPT_EXTENDED_SAVE_DATA = undefined;
        if (comptime std.Target.x86.featureSetHasAll(builtin.cpu.features, .{ .sha, .ssse3 })) {
            if (cpuFeaturesPresent(SYMCRYPT_CPU_FEATURES_FOR_SHANI_CODE | SYMCRYPT_CPU_FEATURE_SAVEXMM_NOFAIL) and
                SymCryptSaveXmm(&saveData) == .SYMCRYPT_NO_ERROR)
            {
                SymCryptSha256AppendBlocks_shani(pChain, pbData, cbData, pcbRemaining);
                SymCryptRestoreXmm(&saveData);
                return;
            }
        }
        if (cpuFeaturesPresent(SYMCRYPT_CPU_FEATURE_SSSE3 | SYMCRYPT_CPU_FEATURE_BMI2) and
            SymCryptSaveXmm(&saveData) == .SYMCRYPT_NO_ERROR)
        {
            SymCryptSha256AppendBlocks_xmm_4blocks(pChain, pbData, cbData, pcbRemaining);
            SymCryptRestoreXmm(&saveData);
            return;
        }
        SymCryptSha256AppendBlocks_ul1(pChain, pbData, cbData, pcbRemaining);
    } else if (comptime builtin.cpu.arch == .aarch64) {
        if (comptime std.Target.aarch64.featureSetHas(builtin.cpu.features, .sha2)) {
            if (cpuFeaturesPresent(SYMCRYPT_CPU_FEATURE_NEON_SHA256)) {
                SymCryptSha256AppendBlocks_instr(pChain, pbData, cbData, pcbRemaining);
                return;
            }
        }
        SymCryptSha256AppendBlocks_ul1(pChain, pbData, cbData, pcbRemaining);
    } else {
        SymCryptSha256AppendBlocks_ul1(pChain, pbData, cbData, pcbRemaining);
    }
}

// ============================================================================
// State Export / Import
// ============================================================================

fn SymCryptSha256StateExportCore(
    pState: PCSYMCRYPT_SHA256_STATE,
    pbBlob: PBYTE,
    blobType: hash.SYMCRYPT_BLOB_TYPE,
) void {
    var blob: SYMCRYPT_SHA256_STATE_EXPORT_BLOB align(SYMCRYPT_ALIGN_VALUE) = undefined;

    macros.CHECK_MAGIC(pState);

    hash.SymCryptWipeKnownSize(@ptrCast(&blob), @sizeOf(SYMCRYPT_SHA256_STATE_EXPORT_BLOB));

    blob.header.magic = hash.SYMCRYPT_BLOB_MAGIC;
    blob.header.size = SYMCRYPT_SHA256_STATE_EXPORT_SIZE;
    blob.header.type = @backingInt(blobType);

    macros.SymCryptUint32ToMsbFirst(&pState.chain.H, &blob.chain, 8);
    blob.dataLength = pState.dataLengthL;
    @memcpy(blob.buffer[0..pState.bytesInBuffer], pState.buffer[0..pState.bytesInBuffer]);

    macros.ASSERT(@as(SIZE_T, @sizeOf(SYMCRYPT_SHA256_STATE_EXPORT_BLOB)) == SYMCRYPT_SHA256_STATE_EXPORT_SIZE);
    hash.SymCryptMarvin32(
        hash.SymCryptMarvin32DefaultSeed,
        @ptrCast(&blob),
        SYMCRYPT_SHA256_STATE_EXPORT_SIZE - @sizeOf(hash.SYMCRYPT_BLOB_TRAILER),
        &blob.trailer.checksum,
    );

    @memcpy(pbBlob[0..SYMCRYPT_SHA256_STATE_EXPORT_SIZE], @as([*]const BYTE, @ptrCast(&blob))[0..SYMCRYPT_SHA256_STATE_EXPORT_SIZE]);

    hash.SymCryptWipeKnownSize(@ptrCast(&blob), @sizeOf(SYMCRYPT_SHA256_STATE_EXPORT_BLOB));
}

fn SymCryptSha256StateImportCore(
    pState: PSYMCRYPT_SHA256_STATE,
    pbBlob: PCBYTE,
    blobType: hash.SYMCRYPT_BLOB_TYPE,
) SYMCRYPT_ERROR {
    var blob: SYMCRYPT_SHA256_STATE_EXPORT_BLOB align(SYMCRYPT_ALIGN_VALUE) = undefined;
    var checksum: [8]BYTE = undefined;
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;

    macros.ASSERT(@as(SIZE_T, @sizeOf(SYMCRYPT_SHA256_STATE_EXPORT_BLOB)) == SYMCRYPT_SHA256_STATE_EXPORT_SIZE);
    @memcpy(@as([*]BYTE, @ptrCast(&blob))[0..SYMCRYPT_SHA256_STATE_EXPORT_SIZE], pbBlob[0..SYMCRYPT_SHA256_STATE_EXPORT_SIZE]);

    if (blob.header.magic != hash.SYMCRYPT_BLOB_MAGIC or
        blob.header.size != SYMCRYPT_SHA256_STATE_EXPORT_SIZE or
        blob.header.type != @backingInt(blobType))
    {
        scError = .SYMCRYPT_INVALID_BLOB;
        hash.SymCryptWipeKnownSize(@ptrCast(&blob), @sizeOf(SYMCRYPT_SHA256_STATE_EXPORT_BLOB));
        return scError;
    }

    hash.SymCryptMarvin32(
        hash.SymCryptMarvin32DefaultSeed,
        @ptrCast(&blob),
        SYMCRYPT_SHA256_STATE_EXPORT_SIZE - @sizeOf(hash.SYMCRYPT_BLOB_TRAILER),
        &checksum,
    );
    if (!std.mem.eql(u8, &checksum, &blob.trailer.checksum)) {
        scError = .SYMCRYPT_INVALID_BLOB;
        hash.SymCryptWipeKnownSize(@ptrCast(&blob), @sizeOf(SYMCRYPT_SHA256_STATE_EXPORT_BLOB));
        return scError;
    }

    macros.SymCryptMsbFirstToUint32(&blob.chain, &pState.chain.H, 8);
    pState.dataLengthL = blob.dataLength;
    pState.dataLengthH = 0;
    pState.bytesInBuffer = @intCast(blob.dataLength & 0x3f);
    @memcpy(pState.buffer[0..pState.bytesInBuffer], blob.buffer[0..pState.bytesInBuffer]);

    macros.SET_MAGIC(pState);

    hash.SymCryptWipeKnownSize(@ptrCast(&blob), @sizeOf(SYMCRYPT_SHA256_STATE_EXPORT_BLOB));
    return scError;
}

pub export fn SymCryptSha224StateExport(
    pState: PCSYMCRYPT_SHA224_STATE,
    pbBlob: PBYTE,
) callconv(SYMCRYPT_CALL) void {
    SymCryptSha256StateExportCore(pState, pbBlob, .SymCryptBlobTypeSha224State);
}

pub export fn SymCryptSha224StateImport(
    pState: PSYMCRYPT_SHA224_STATE,
    pbBlob: PCBYTE,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    return SymCryptSha256StateImportCore(pState, pbBlob, .SymCryptBlobTypeSha224State);
}

pub export fn SymCryptSha256StateExport(
    pState: PCSYMCRYPT_SHA256_STATE,
    pbBlob: PBYTE,
) callconv(SYMCRYPT_CALL) void {
    SymCryptSha256StateExportCore(pState, pbBlob, .SymCryptBlobTypeSha256State);
}

pub export fn SymCryptSha256StateImport(
    pState: PSYMCRYPT_SHA256_STATE,
    pbBlob: PCBYTE,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    return SymCryptSha256StateImportCore(pState, pbBlob, .SymCryptBlobTypeSha256State);
}

// ============================================================================
// Self-Test
// ============================================================================

pub export const SymCryptSha224KATAnswer: [28]BYTE = .{
    0x23, 0x09, 0x7d, 0x22, 0x34, 0x05, 0xd8, 0x22,
    0x86, 0x42, 0xa4, 0x77, 0xbd, 0xa2, 0x55, 0xb3,
    0x2a, 0xad, 0xbc, 0xe4, 0xbd, 0xa0, 0xb3, 0xf7,
    0xe3, 0x6c, 0x9d, 0xa7,
};

pub export const SymCryptSha256KATAnswer: [32]BYTE = .{
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
    0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
    0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
};

pub export fn SymCryptSha224Selftest() callconv(SYMCRYPT_CALL) void {
    var res: [SYMCRYPT_SHA224_RESULT_SIZE]BYTE = undefined;

    SymCryptSha224(&hash.SymCryptTestMsg3, hash.SymCryptTestMsg3.len, &res);

    hash.SymCryptInjectError(&res, res.len);

    if (!std.mem.eql(u8, &res, &SymCryptSha224KATAnswer)) {
        macros.SymCryptFatal(comptime macros.multiCharConstant("SH22"));
    }
}

pub export fn SymCryptSha256Selftest() callconv(SYMCRYPT_CALL) void {
    var res: [SYMCRYPT_SHA256_RESULT_SIZE]BYTE = undefined;

    SymCryptSha256(&hash.SymCryptTestMsg3, hash.SymCryptTestMsg3.len, &res);

    hash.SymCryptInjectError(&res, res.len);

    if (!std.mem.eql(u8, &res, &SymCryptSha256KATAnswer)) {
        macros.SymCryptFatal(comptime macros.multiCharConstant("SH25"));
    }
}
