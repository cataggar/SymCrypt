//
// sha512.zig
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
// This module contains the routines to implement SHA-384, SHA-512,
// SHA-512/224, and SHA-512/256 from FIPS 180-2 and FIPS 180-4.
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

pub const SYMCRYPT_SHA384_RESULT_SIZE: usize = 48;
pub const SYMCRYPT_SHA384_INPUT_BLOCK_SIZE: usize = 128;
pub const SYMCRYPT_SHA384_STATE_EXPORT_SIZE: usize = 236;
pub const SYMCRYPT_SHA384_OID_COUNT: usize = 2;

pub const SYMCRYPT_SHA512_RESULT_SIZE: usize = 64;
pub const SYMCRYPT_SHA512_INPUT_BLOCK_SIZE: usize = 128;
pub const SYMCRYPT_SHA512_STATE_EXPORT_SIZE: usize = 236;
pub const SYMCRYPT_SHA512_OID_COUNT: usize = 2;

pub const SYMCRYPT_SHA512_224_RESULT_SIZE: usize = 28;
pub const SYMCRYPT_SHA512_224_INPUT_BLOCK_SIZE: usize = 128;
pub const SYMCRYPT_SHA512_224_STATE_EXPORT_SIZE: usize = 236;
pub const SYMCRYPT_SHA512_224_OID_COUNT: usize = 2;

pub const SYMCRYPT_SHA512_256_RESULT_SIZE: usize = 32;
pub const SYMCRYPT_SHA512_256_INPUT_BLOCK_SIZE: usize = 128;
pub const SYMCRYPT_SHA512_256_STATE_EXPORT_SIZE: usize = 236;
pub const SYMCRYPT_SHA512_256_OID_COUNT: usize = 2;

pub const SYMCRYPT_SHA512_CHAINING_STATE = hash.SYMCRYPT_SHA512_CHAINING_STATE;
pub const PSYMCRYPT_SHA512_CHAINING_STATE = hash.PSYMCRYPT_SHA512_CHAINING_STATE;
pub const SYMCRYPT_SHA512_STATE = hash.SYMCRYPT_SHA512_STATE;
pub const PSYMCRYPT_SHA512_STATE = hash.PSYMCRYPT_SHA512_STATE;
pub const PCSYMCRYPT_SHA512_STATE = hash.PCSYMCRYPT_SHA512_STATE;

pub const SYMCRYPT_SHA384_STATE = hash.SYMCRYPT_SHA384_STATE;
pub const PSYMCRYPT_SHA384_STATE = *SYMCRYPT_SHA384_STATE;
pub const PCSYMCRYPT_SHA384_STATE = *const SYMCRYPT_SHA384_STATE;

pub const SYMCRYPT_SHA512_224_STATE = hash.SYMCRYPT_SHA512_224_STATE;
pub const PSYMCRYPT_SHA512_224_STATE = *SYMCRYPT_SHA512_224_STATE;
pub const PCSYMCRYPT_SHA512_224_STATE = *const SYMCRYPT_SHA512_224_STATE;

pub const SYMCRYPT_SHA512_256_STATE = hash.SYMCRYPT_SHA512_256_STATE;
pub const PSYMCRYPT_SHA512_256_STATE = *SYMCRYPT_SHA512_256_STATE;
pub const PCSYMCRYPT_SHA512_256_STATE = *const SYMCRYPT_SHA512_256_STATE;

pub const SYMCRYPT_SHA512_STATE_EXPORT_BLOB = extern struct {
    header: hash.SYMCRYPT_BLOB_HEADER align(1),
    chain: [64]BYTE,
    dataLengthL: UINT64 align(1),
    dataLengthH: UINT64 align(1),
    buffer: [128]BYTE,
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
const SYMCRYPT_CPU_FEATURE_NEON: SYMCRYPT_CPU_FEATURES = 0x01;

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

// ============================================================================
// Constants & OIDs
// ============================================================================

// The array length is 81, with an empty last element so that we can safely read 16 bytes
// into an XMM register on the last iteration of the compression loop in the XMM implementation.
pub export const SymCryptSha512K: [81]UINT64 align(64) = .{
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
    0,
};

pub const SymCryptSha384OidList: [SYMCRYPT_SHA384_OID_COUNT]SYMCRYPT_OID = .{
    .{ .cbOID = 13, .pbOID = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00" },
    .{ .cbOID = 11, .pbOID = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02" },
};

pub const SymCryptSha512OidList: [SYMCRYPT_SHA512_OID_COUNT]SYMCRYPT_OID = .{
    .{ .cbOID = 13, .pbOID = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00" },
    .{ .cbOID = 11, .pbOID = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03" },
};

pub const SymCryptSha512_224OidList: [SYMCRYPT_SHA512_224_OID_COUNT]SYMCRYPT_OID = .{
    .{ .cbOID = 13, .pbOID = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x05\x05\x00" },
    .{ .cbOID = 11, .pbOID = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x05" },
};

pub const SymCryptSha512_256OidList: [SYMCRYPT_SHA512_256_OID_COUNT]SYMCRYPT_OID = .{
    .{ .cbOID = 13, .pbOID = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x06\x05\x00" },
    .{ .cbOID = 11, .pbOID = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x06" },
};

// Initial states
pub export const SymCryptSha512InitialState: [8]UINT64 = .{
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
};

pub export const SymCryptSha384InitialState: [8]UINT64 = .{
    0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
    0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4,
};

pub export const SymCryptSha512_224InitialState: [8]UINT64 = .{
    0x8c3d37c819544da2, 0x73e1996689dcd4d6, 0x1dfab7ae32ff9c82, 0x679dd514582f9fcf,
    0x0f6d2b697bd44da8, 0x77e36f7304c48942, 0x3f9d85a86a1d36c8, 0x1112e6ad91d692a1,
};

pub export const SymCryptSha512_256InitialState: [8]UINT64 = .{
    0x22312194fc2bf72c, 0x9f555fa3c84c64c2, 0x2393b86b6f53b151, 0x963877195940eabd,
    0x96283ee2a88effe3, 0xbe5e1e2553863992, 0x2b0199fc2c85b8aa, 0x0eb72ddc81c52ca2,
};

// ============================================================================
// Pattern Instantiation & Algorithm Descriptors
// ============================================================================

const Sha384Pattern = hash_pattern.HashPattern(
    SYMCRYPT_SHA384_STATE,
    SYMCRYPT_SHA512_CHAINING_STATE,
    &SymCryptSha384Init,
    &SymCryptSha384Append,
    &SymCryptSha384Result,
    &SymCryptSha512AppendBlocks,
);

const Sha512Pattern = hash_pattern.HashPattern(
    SYMCRYPT_SHA512_STATE,
    SYMCRYPT_SHA512_CHAINING_STATE,
    &SymCryptSha512Init,
    &SymCryptSha512Append,
    &SymCryptSha512Result,
    &SymCryptSha512AppendBlocks,
);

const Sha512_224Pattern = hash_pattern.HashPattern(
    SYMCRYPT_SHA512_224_STATE,
    SYMCRYPT_SHA512_CHAINING_STATE,
    &SymCryptSha512_224Init,
    &SymCryptSha512_224Append,
    &SymCryptSha512_224Result,
    &SymCryptSha512AppendBlocks,
);

const Sha512_256Pattern = hash_pattern.HashPattern(
    SYMCRYPT_SHA512_256_STATE,
    SYMCRYPT_SHA512_CHAINING_STATE,
    &SymCryptSha512_256Init,
    &SymCryptSha512_256Append,
    &SymCryptSha512_256Result,
    &SymCryptSha512AppendBlocks,
);

pub export const SymCryptSha384Algorithm_default: SYMCRYPT_HASH align(SYMCRYPT_ALIGN_VALUE) = .{
    .initFunc = &Sha384Pattern.initVoid,
    .appendFunc = &Sha384Pattern.appendVoid,
    .resultFunc = &Sha384Pattern.resultVoid,
    .appendBlockFunc = &Sha384Pattern.appendBlocksVoid,
    .stateCopyFunc = &Sha384Pattern.stateCopyVoid,
    .stateSize = @sizeOf(SYMCRYPT_SHA384_STATE),
    .resultSize = SYMCRYPT_SHA384_RESULT_SIZE,
    .inputBlockSize = SYMCRYPT_SHA384_INPUT_BLOCK_SIZE,
    .chainOffset = @offsetOf(SYMCRYPT_SHA384_STATE, "chain"),
    .chainSize = @sizeOf(SYMCRYPT_SHA512_CHAINING_STATE),
};

pub export const SymCryptSha384Algorithm: PCSYMCRYPT_HASH = &SymCryptSha384Algorithm_default;

pub export const SymCryptSha512Algorithm_default: SYMCRYPT_HASH align(SYMCRYPT_ALIGN_VALUE) = .{
    .initFunc = &Sha512Pattern.initVoid,
    .appendFunc = &Sha512Pattern.appendVoid,
    .resultFunc = &Sha512Pattern.resultVoid,
    .appendBlockFunc = &Sha512Pattern.appendBlocksVoid,
    .stateCopyFunc = &Sha512Pattern.stateCopyVoid,
    .stateSize = @sizeOf(SYMCRYPT_SHA512_STATE),
    .resultSize = SYMCRYPT_SHA512_RESULT_SIZE,
    .inputBlockSize = SYMCRYPT_SHA512_INPUT_BLOCK_SIZE,
    .chainOffset = @offsetOf(SYMCRYPT_SHA512_STATE, "chain"),
    .chainSize = @sizeOf(SYMCRYPT_SHA512_CHAINING_STATE),
};

pub export const SymCryptSha512Algorithm: PCSYMCRYPT_HASH = &SymCryptSha512Algorithm_default;

pub export const SymCryptSha512_224Algorithm_default: SYMCRYPT_HASH align(SYMCRYPT_ALIGN_VALUE) = .{
    .initFunc = &Sha512_224Pattern.initVoid,
    .appendFunc = &Sha512_224Pattern.appendVoid,
    .resultFunc = &Sha512_224Pattern.resultVoid,
    .appendBlockFunc = &Sha512_224Pattern.appendBlocksVoid,
    .stateCopyFunc = &Sha512_224Pattern.stateCopyVoid,
    .stateSize = @sizeOf(SYMCRYPT_SHA512_224_STATE),
    .resultSize = SYMCRYPT_SHA512_224_RESULT_SIZE,
    .inputBlockSize = SYMCRYPT_SHA512_224_INPUT_BLOCK_SIZE,
    .chainOffset = @offsetOf(SYMCRYPT_SHA512_224_STATE, "chain"),
    .chainSize = @sizeOf(SYMCRYPT_SHA512_CHAINING_STATE),
};

pub export const SymCryptSha512_224Algorithm: PCSYMCRYPT_HASH = &SymCryptSha512_224Algorithm_default;

pub export const SymCryptSha512_256Algorithm_default: SYMCRYPT_HASH align(SYMCRYPT_ALIGN_VALUE) = .{
    .initFunc = &Sha512_256Pattern.initVoid,
    .appendFunc = &Sha512_256Pattern.appendVoid,
    .resultFunc = &Sha512_256Pattern.resultVoid,
    .appendBlockFunc = &Sha512_256Pattern.appendBlocksVoid,
    .stateCopyFunc = &Sha512_256Pattern.stateCopyVoid,
    .stateSize = @sizeOf(SYMCRYPT_SHA512_256_STATE),
    .resultSize = SYMCRYPT_SHA512_256_RESULT_SIZE,
    .inputBlockSize = SYMCRYPT_SHA512_256_INPUT_BLOCK_SIZE,
    .chainOffset = @offsetOf(SYMCRYPT_SHA512_256_STATE, "chain"),
    .chainSize = @sizeOf(SYMCRYPT_SHA512_CHAINING_STATE),
};

pub export const SymCryptSha512_256Algorithm: PCSYMCRYPT_HASH = &SymCryptSha512_256Algorithm_default;

// ============================================================================
// Public API
// ============================================================================

pub export fn SymCryptSha512StateCopy(pSrc: PCSYMCRYPT_SHA512_STATE, pDst: PSYMCRYPT_SHA512_STATE) callconv(SYMCRYPT_CALL) void {
    Sha512Pattern.stateCopy(pSrc, pDst);
}

pub export fn SymCryptSha512(pbData: PCBYTE, cbData: SIZE_T, pbResult: PBYTE) callconv(SYMCRYPT_CALL) void {
    Sha512Pattern.hash(pbData, cbData, pbResult);
}

pub export fn SymCryptSha384StateCopy(pSrc: PCSYMCRYPT_SHA384_STATE, pDst: PSYMCRYPT_SHA384_STATE) callconv(SYMCRYPT_CALL) void {
    Sha384Pattern.stateCopy(pSrc, pDst);
}

pub export fn SymCryptSha384(pbData: PCBYTE, cbData: SIZE_T, pbResult: PBYTE) callconv(SYMCRYPT_CALL) void {
    Sha384Pattern.hash(pbData, cbData, pbResult);
}

pub export fn SymCryptSha512_224StateCopy(pSrc: PCSYMCRYPT_SHA512_224_STATE, pDst: PSYMCRYPT_SHA512_224_STATE) callconv(SYMCRYPT_CALL) void {
    Sha512_224Pattern.stateCopy(pSrc, pDst);
}

pub export fn SymCryptSha512_224(pbData: PCBYTE, cbData: SIZE_T, pbResult: PBYTE) callconv(SYMCRYPT_CALL) void {
    Sha512_224Pattern.hash(pbData, cbData, pbResult);
}

pub export fn SymCryptSha512_256StateCopy(pSrc: PCSYMCRYPT_SHA512_256_STATE, pDst: PSYMCRYPT_SHA512_256_STATE) callconv(SYMCRYPT_CALL) void {
    Sha512_256Pattern.stateCopy(pSrc, pDst);
}

pub export fn SymCryptSha512_256(pbData: PCBYTE, cbData: SIZE_T, pbResult: PBYTE) callconv(SYMCRYPT_CALL) void {
    Sha512_256Pattern.hash(pbData, cbData, pbResult);
}

pub export fn SymCryptSha512Init(pState: PSYMCRYPT_SHA512_STATE) callconv(SYMCRYPT_CALL) void {
    macros.SET_MAGIC(pState);

    pState.dataLengthL = 0;
    pState.dataLengthH = 0;
    pState.bytesInBuffer = 0;

    pState.chain.H = SymCryptSha512InitialState;
}

pub export fn SymCryptSha384Init(pState: PSYMCRYPT_SHA384_STATE) callconv(SYMCRYPT_CALL) void {
    macros.SET_MAGIC(pState);

    pState.dataLengthL = 0;
    pState.dataLengthH = 0;
    pState.bytesInBuffer = 0;

    pState.chain.H = SymCryptSha384InitialState;
}

pub export fn SymCryptSha512_224Init(pState: PSYMCRYPT_SHA512_224_STATE) callconv(SYMCRYPT_CALL) void {
    macros.SET_MAGIC(pState);

    pState.dataLengthL = 0;
    pState.dataLengthH = 0;
    pState.bytesInBuffer = 0;

    pState.chain.H = SymCryptSha512_224InitialState;
}

pub export fn SymCryptSha512_256Init(pState: PSYMCRYPT_SHA512_256_STATE) callconv(SYMCRYPT_CALL) void {
    macros.SET_MAGIC(pState);

    pState.dataLengthL = 0;
    pState.dataLengthH = 0;
    pState.bytesInBuffer = 0;

    pState.chain.H = SymCryptSha512_256InitialState;
}

pub export fn SymCryptSha512Append(pState: PSYMCRYPT_SHA512_STATE, pbData: PCBYTE, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void {
    hash_pattern.hashBufferAppendWithRemaining(
        SYMCRYPT_SHA512_INPUT_BLOCK_SIZE,
        true,
        pState,
        pbData,
        cbData,
        SymCryptSha512AppendBlocks,
    );
}

pub export fn SymCryptSha384Append(pState: PSYMCRYPT_SHA384_STATE, pbData: PCBYTE, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void {
    SymCryptSha512Append(pState, pbData, cbData);
}

pub export fn SymCryptSha512_224Append(pState: PSYMCRYPT_SHA512_224_STATE, pbData: PCBYTE, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void {
    SymCryptSha512Append(pState, pbData, cbData);
}

pub export fn SymCryptSha512_256Append(pState: PSYMCRYPT_SHA512_256_STATE, pbData: PCBYTE, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void {
    SymCryptSha512Append(pState, pbData, cbData);
}

fn SymCryptSha512FinalizePadding(pState: PSYMCRYPT_SHA512_STATE) void {
    var tmp: SIZE_T = 0;
    var bytesInBuffer = pState.bytesInBuffer;

    macros.CHECK_MAGIC(pState);

    // The buffer is never completely full, so we can always put the first
    // padding byte in.
    pState.buffer[bytesInBuffer] = 0x80;
    bytesInBuffer += 1;

    if (bytesInBuffer > 128 - 16) {
        // No room for the rest of the padding. Pad with zeroes & process block
        // bytesInBuffer is at most 128, so we do not have an integer underflow
        hash.SymCryptWipe(@ptrCast(pState.buffer[bytesInBuffer..].ptr), 128 - bytesInBuffer);
        SymCryptSha512AppendBlocks(&pState.chain, &pState.buffer, 128, &tmp);
        bytesInBuffer = 0;
    }

    // Set the rest of the padding
    // We choose to wipe to the end of the buffer, as it is 16-aligned,
    // and wiping to a 16-aligned boundary is slightly faster
    hash.SymCryptWipe(@ptrCast(pState.buffer[bytesInBuffer..].ptr), 128 - bytesInBuffer);
    macros.STORE_MSBFIRST64(pState.buffer[128 - 16 ..].ptr, (pState.dataLengthH << 3) +% (pState.dataLengthL >> 61));
    macros.STORE_MSBFIRST64(pState.buffer[128 - 8 ..].ptr, pState.dataLengthL << 3);

    // Process the final block
    SymCryptSha512AppendBlocks(&pState.chain, &pState.buffer, 128, &tmp);
}

pub export fn SymCryptSha512Result(pState: PSYMCRYPT_SHA512_STATE, pbResult: PBYTE) callconv(SYMCRYPT_CALL) void {
    SymCryptSha512FinalizePadding(pState);

    // Write the output in the correct byte order
    macros.SymCryptUint64ToMsbFirst(&pState.chain.H, pbResult, 8);

    // Wipe & re-initialize
    hash.SymCryptWipeKnownSize(@ptrCast(pState), @sizeOf(SYMCRYPT_SHA512_STATE));
    SymCryptSha512Init(pState);
}

pub export fn SymCryptSha384Result(pState: PSYMCRYPT_SHA384_STATE, pbResult: PBYTE) callconv(SYMCRYPT_CALL) void {
    SymCryptSha512FinalizePadding(pState);

    // Write the output in the correct byte order
    macros.SymCryptUint64ToMsbFirst(&pState.chain.H, pbResult, 6);

    // Wipe & re-initialize
    hash.SymCryptWipeKnownSize(@ptrCast(pState), @sizeOf(SYMCRYPT_SHA384_STATE));
    SymCryptSha384Init(pState);
}

pub export fn SymCryptSha512_224Result(pState: PSYMCRYPT_SHA512_224_STATE, pbResult: PBYTE) callconv(SYMCRYPT_CALL) void {
    SymCryptSha512FinalizePadding(pState);

    // Write the output in the correct byte order
    macros.SymCryptUint64ToMsbFirst(&pState.chain.H, pbResult, 3);
    macros.STORE_MSBFIRST32(pbResult + 24, @truncate(pState.chain.H[3] >> 32));

    // Wipe & re-initialize
    hash.SymCryptWipeKnownSize(@ptrCast(pState), @sizeOf(SYMCRYPT_SHA512_224_STATE));
    SymCryptSha512_224Init(pState);
}

pub export fn SymCryptSha512_256Result(pState: PSYMCRYPT_SHA512_256_STATE, pbResult: PBYTE) callconv(SYMCRYPT_CALL) void {
    SymCryptSha512FinalizePadding(pState);

    // Write the output in the correct byte order
    macros.SymCryptUint64ToMsbFirst(&pState.chain.H, pbResult, 4);

    // Wipe & re-initialize
    hash.SymCryptWipeKnownSize(@ptrCast(pState), @sizeOf(SYMCRYPT_SHA512_256_STATE));
    SymCryptSha512_256Init(pState);
}

// ============================================================================
// Compression Function Implementations
// ============================================================================

inline fn maj(x: UINT64, y: UINT64, z: UINT64) UINT64 {
    return (((z | y) & x) | (z & y));
}

inline fn ch(x: UINT64, y: UINT64, z: UINT64) UINT64 {
    return (((z ^ y) & x) ^ z);
}

inline fn csigma0(x: UINT64) UINT64 {
    return macros.ROR64(x, 28) ^ macros.ROR64(x, 34) ^ macros.ROR64(x, 39);
}

inline fn csigma1(x: UINT64) UINT64 {
    return macros.ROR64(x, 14) ^ macros.ROR64(x, 18) ^ macros.ROR64(x, 41);
}

inline fn lsigma0(x: UINT64) UINT64 {
    return macros.ROR64(x, 1) ^ macros.ROR64(x, 8) ^ (x >> 7);
}

inline fn lsigma1(x: UINT64) UINT64 {
    return macros.ROR64(x, 19) ^ macros.ROR64(x, 61) ^ (x >> 6);
}

inline fn cround(
    a: UINT64,
    b: UINT64,
    c: UINT64,
    d: *UINT64,
    e: UINT64,
    f: UINT64,
    g: UINT64,
    h: *UINT64,
    r: usize,
    Wt: UINT64,
) void {
    h.* +%= csigma1(e) +% ch(e, f, g) +% SymCryptSha512K[r] +% Wt;
    d.* +%= h.*;
    h.* +%= csigma0(a) +% maj(a, b, c);
}

inline fn iround(
    W: *[16]UINT64,
    pbData: PCBYTE,
    a: UINT64,
    b: UINT64,
    c: UINT64,
    d: *UINT64,
    e: UINT64,
    f: UINT64,
    g: UINT64,
    h: *UINT64,
    comptime r: usize,
) void {
    const Wt = macros.LOAD_MSBFIRST64(pbData + 8 * r);
    W[r] = Wt;
    cround(a, b, c, d, e, f, g, h, r, Wt);
}

inline fn fround(
    W: *[16]UINT64,
    a: UINT64,
    b: UINT64,
    c: UINT64,
    d: *UINT64,
    e: UINT64,
    f: UINT64,
    g: UINT64,
    h: *UINT64,
    r: usize,
    comptime r16: usize,
) void {
    const Wt = lsigma1(W[(r16 + 16 - 2) & 15]) +% W[(r16 + 16 - 7) & 15] +%
        lsigma0(W[(r16 + 16 - 15) & 15]) +% W[r16 & 15];
    W[r16] = Wt;
    cround(a, b, c, d, e, f, g, h, r, Wt);
}

pub export fn SymCryptSha512AppendBlocks_ul1(
    pChain: *SYMCRYPT_SHA512_CHAINING_STATE,
    pbData_in: PCBYTE,
    cbData_in: SIZE_T,
    pcbRemaining: *SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    SymCryptSha512AppendBlocks_ull(pChain, pbData_in, cbData_in, pcbRemaining);
}

pub export fn SymCryptSha512AppendBlocks_ull(
    pChain: *SYMCRYPT_SHA512_CHAINING_STATE,
    pbData_in: PCBYTE,
    cbData_in: SIZE_T,
    pcbRemaining: *SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    var pbData = pbData_in;
    var cbData = cbData_in;
    var W: [16]UINT64 align(SYMCRYPT_ALIGN_VALUE) = undefined;

    while (cbData >= 128) {
        @setEvalBranchQuota(10000);
        var A = pChain.H[0];
        var B = pChain.H[1];
        var C = pChain.H[2];
        var D = pChain.H[3];
        var E = pChain.H[4];
        var F = pChain.H[5];
        var G = pChain.H[6];
        var H = pChain.H[7];

        // Initial rounds 0 to 15
        iround(&W, pbData, A, B, C, &D, E, F, G, &H, 0);
        iround(&W, pbData, H, A, B, &C, D, E, F, &G, 1);
        iround(&W, pbData, G, H, A, &B, C, D, E, &F, 2);
        iround(&W, pbData, F, G, H, &A, B, C, D, &E, 3);
        iround(&W, pbData, E, F, G, &H, A, B, C, &D, 4);
        iround(&W, pbData, D, E, F, &G, H, A, B, &C, 5);
        iround(&W, pbData, C, D, E, &F, G, H, A, &B, 6);
        iround(&W, pbData, B, C, D, &E, F, G, H, &A, 7);
        iround(&W, pbData, A, B, C, &D, E, F, G, &H, 8);
        iround(&W, pbData, H, A, B, &C, D, E, F, &G, 9);
        iround(&W, pbData, G, H, A, &B, C, D, E, &F, 10);
        iround(&W, pbData, F, G, H, &A, B, C, D, &E, 11);
        iround(&W, pbData, E, F, G, &H, A, B, C, &D, 12);
        iround(&W, pbData, D, E, F, &G, H, A, B, &C, 13);
        iround(&W, pbData, C, D, E, &F, G, H, A, &B, 14);
        iround(&W, pbData, B, C, D, &E, F, G, H, &A, 15);

        // Rounds 16 to 79
        var r: usize = 16;
        while (r < 80) : (r += 16) {
            fround(&W, A, B, C, &D, E, F, G, &H, r + 0, 0);
            fround(&W, H, A, B, &C, D, E, F, &G, r + 1, 1);
            fround(&W, G, H, A, &B, C, D, E, &F, r + 2, 2);
            fround(&W, F, G, H, &A, B, C, D, &E, r + 3, 3);
            fround(&W, E, F, G, &H, A, B, C, &D, r + 4, 4);
            fround(&W, D, E, F, &G, H, A, B, &C, r + 5, 5);
            fround(&W, C, D, E, &F, G, H, A, &B, r + 6, 6);
            fround(&W, B, C, D, &E, F, G, H, &A, r + 7, 7);
            fround(&W, A, B, C, &D, E, F, G, &H, r + 8, 8);
            fround(&W, H, A, B, &C, D, E, F, &G, r + 9, 9);
            fround(&W, G, H, A, &B, C, D, E, &F, r + 10, 10);
            fround(&W, F, G, H, &A, B, C, D, &E, r + 11, 11);
            fround(&W, E, F, G, &H, A, B, C, &D, r + 12, 12);
            fround(&W, D, E, F, &G, H, A, B, &C, r + 13, 13);
            fround(&W, C, D, E, &F, G, H, A, &B, r + 14, 14);
            fround(&W, B, C, D, &E, F, G, H, &A, r + 15, 15);
        }

        pChain.H[0] +%= A;
        pChain.H[1] +%= B;
        pChain.H[2] +%= C;
        pChain.H[3] +%= D;
        pChain.H[4] +%= E;
        pChain.H[5] +%= F;
        pChain.H[6] +%= G;
        pChain.H[7] +%= H;

        pbData += 128;
        cbData -= 128;
    }

    pcbRemaining.* = cbData;

    // Wipe the variables
    hash.SymCryptWipeKnownSize(@ptrCast(&W), @sizeOf(@TypeOf(W)));
}

// ============================================================================
// Vectorized 2x64 (XMM / NEON) Implementation for 32-bit x86 / ARM
// ============================================================================

const V2U64 = @Vector(2, u64);

inline fn v2Ror64(a: V2U64, comptime n: u6) V2U64 {
    const inv: u6 = @intCast(64 - @as(u7, n));
    return (a << @splat(inv)) ^ (a >> @splat(n));
}

inline fn v2Shr64(a: V2U64, comptime n: u6) V2U64 {
    return a >> @splat(n);
}

inline fn v2Maj(x: V2U64, y: V2U64, z: V2U64) V2U64 {
    return ((z | y) & x) | (z & y);
}

inline fn v2Ch(x: V2U64, y: V2U64, z: V2U64) V2U64 {
    return ((z ^ y) & x) ^ z;
}

inline fn v2Csigma0(x: V2U64) V2U64 {
    return v2Ror64(x, 28) ^ v2Ror64(x, 34) ^ v2Ror64(x, 39);
}

inline fn v2Csigma1(x: V2U64) V2U64 {
    return v2Ror64(x, 14) ^ v2Ror64(x, 18) ^ v2Ror64(x, 41);
}

inline fn v2Lsigma0(x: V2U64) V2U64 {
    return v2Ror64(x, 1) ^ v2Ror64(x, 8) ^ v2Shr64(x, 7);
}

inline fn v2Lsigma1(x: V2U64) V2U64 {
    return v2Ror64(x, 19) ^ v2Ror64(x, 61) ^ v2Shr64(x, 6);
}

inline fn v2Mod16(a: *[8]V2U64, comptime i: isize) V2U64 {
    const idx0: usize = @intCast(@mod(i, 16));
    const idx1: usize = @intCast(@mod(i + 1, 16));
    if (comptime (idx0 & 1) == 0) {
        return a[idx0 / 2];
    } else {
        return @shuffle(u64, a[idx0 / 2], a[idx1 / 2], [2]i32{ 1, -1 });
    }
}

inline fn v2Load1(x: u64) V2U64 {
    return V2U64{ x, 0 };
}

inline fn v2LoadK2(r: usize) V2U64 {
    return V2U64{ SymCryptSha512K[r], SymCryptSha512K[r + 1] };
}

inline fn v2Step1(
    a: V2U64,
    b: V2U64,
    c: V2U64,
    d: *V2U64,
    e: V2U64,
    f: V2U64,
    g: V2U64,
    h: *V2U64,
    Wt: V2U64,
) void {
    h.* +%= v2Csigma1(e) +% v2Ch(e, f, g) +% Wt;
    d.* +%= h.*;
    h.* +%= v2Csigma0(a) +% v2Maj(a, b, c);
}

inline fn v2DoRound2(
    a: *V2U64,
    b: *V2U64,
    c: *V2U64,
    d: *V2U64,
    e: *V2U64,
    f: *V2U64,
    g: *V2U64,
    h: *V2U64,
    r: usize,
    Wt: V2U64,
) void {
    const Wk = Wt +% v2LoadK2(r);
    v2Step1(a.*, b.*, c.*, d, e.*, f.*, g.*, h, Wk);
    f.* = @shuffle(u64, f.*, e.*, [2]i32{ 1, -1 });
    g.* = @shuffle(u64, g.*, f.*, [2]i32{ 1, -1 });
    b.* = @shuffle(u64, b.*, a.*, [2]i32{ 1, -1 });
    c.* = @shuffle(u64, c.*, b.*, [2]i32{ 1, -1 });
    const Wt2 = @shuffle(u64, Wk, Wk, [2]i32{ 1, 0 });
    v2Step1(h.*, a.*, b.*, c, d.*, e.*, f.*, g, Wt2);
    e.* = @shuffle(u64, e.*, d.*, [2]i32{ 1, -1 });
    f.* = @shuffle(u64, f.*, e.*, [2]i32{ 1, -1 });
    a.* = @shuffle(u64, a.*, h.*, [2]i32{ 1, -1 });
    b.* = @shuffle(u64, b.*, a.*, [2]i32{ 1, -1 });
}

inline fn v2Iround2(
    W: *[8]V2U64,
    pbData: PCBYTE,
    a: *V2U64,
    b: *V2U64,
    c: *V2U64,
    d: *V2U64,
    e: *V2U64,
    f: *V2U64,
    g: *V2U64,
    h: *V2U64,
    comptime r: usize,
) void {
    const Wt = V2U64{
        macros.LOAD_MSBFIRST64(pbData + 8 * r),
        macros.LOAD_MSBFIRST64(pbData + 8 * r + 8),
    };
    W[r / 2] = Wt;
    v2DoRound2(a, b, c, d, e, f, g, h, r, Wt);
}

inline fn v2Fround2(
    W: *[8]V2U64,
    a: *V2U64,
    b: *V2U64,
    c: *V2U64,
    d: *V2U64,
    e: *V2U64,
    f: *V2U64,
    g: *V2U64,
    h: *V2U64,
    r: usize,
    comptime r16: usize,
) void {
    const r_signed: isize = @intCast(r16);
    const Wt = v2Lsigma1(v2Mod16(W, r_signed - 2)) +%
        v2Mod16(W, r_signed - 7) +%
        v2Lsigma0(v2Mod16(W, r_signed - 15)) +%
        v2Mod16(W, r_signed);
    W[r16 / 2] = Wt;
    v2DoRound2(a, b, c, d, e, f, g, h, r, Wt);
}

pub export fn SymCryptSha512AppendBlocks_xmm(
    pChain: *SYMCRYPT_SHA512_CHAINING_STATE,
    pbData_in: PCBYTE,
    cbData_in: SIZE_T,
    pcbRemaining: *SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    @setRuntimeSafety(false);
    var pbData = pbData_in;
    var cbData = cbData_in;
    var W: [8]V2U64 align(16) = undefined;

    while (cbData >= 128) {
        var A = v2Load1(pChain.H[0]);
        var B = v2Load1(pChain.H[1]);
        var C = v2Load1(pChain.H[2]);
        var D = v2Load1(pChain.H[3]);
        var E = v2Load1(pChain.H[4]);
        var F = v2Load1(pChain.H[5]);
        var G = v2Load1(pChain.H[6]);
        var H = v2Load1(pChain.H[7]);

        v2Iround2(&W, pbData, &A, &B, &C, &D, &E, &F, &G, &H, 0);
        v2Iround2(&W, pbData, &G, &H, &A, &B, &C, &D, &E, &F, 2);
        v2Iround2(&W, pbData, &E, &F, &G, &H, &A, &B, &C, &D, 4);
        v2Iround2(&W, pbData, &C, &D, &E, &F, &G, &H, &A, &B, 6);
        v2Iround2(&W, pbData, &A, &B, &C, &D, &E, &F, &G, &H, 8);
        v2Iround2(&W, pbData, &G, &H, &A, &B, &C, &D, &E, &F, 10);
        v2Iround2(&W, pbData, &E, &F, &G, &H, &A, &B, &C, &D, 12);
        v2Iround2(&W, pbData, &C, &D, &E, &F, &G, &H, &A, &B, 14);

        var r: usize = 16;
        while (r < 80) : (r += 16) {
            v2Fround2(&W, &A, &B, &C, &D, &E, &F, &G, &H, r + 0, 0);
            v2Fround2(&W, &G, &H, &A, &B, &C, &D, &E, &F, r + 2, 2);
            v2Fround2(&W, &E, &F, &G, &H, &A, &B, &C, &D, r + 4, 4);
            v2Fround2(&W, &C, &D, &E, &F, &G, &H, &A, &B, r + 6, 6);
            v2Fround2(&W, &A, &B, &C, &D, &E, &F, &G, &H, r + 8, 8);
            v2Fround2(&W, &G, &H, &A, &B, &C, &D, &E, &F, r + 10, 10);
            v2Fround2(&W, &E, &F, &G, &H, &A, &B, &C, &D, r + 12, 12);
            v2Fround2(&W, &C, &D, &E, &F, &G, &H, &A, &B, r + 14, 14);
        }

        pChain.H[0] +%= A[0];
        pChain.H[1] +%= B[0];
        pChain.H[2] +%= C[0];
        pChain.H[3] +%= D[0];
        pChain.H[4] +%= E[0];
        pChain.H[5] +%= F[0];
        pChain.H[6] +%= G[0];
        pChain.H[7] +%= H[0];

        pbData += 128;
        cbData -= 128;
    }

    pcbRemaining.* = cbData;

    hash.SymCryptWipeKnownSize(@ptrCast(&W), @sizeOf(@TypeOf(W)));
}

pub export fn SymCryptSha512AppendBlocks_neon(
    pChain: *SYMCRYPT_SHA512_CHAINING_STATE,
    pbData_in: PCBYTE,
    cbData_in: SIZE_T,
    pcbRemaining: *SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    SymCryptSha512AppendBlocks_xmm(pChain, pbData_in, cbData_in, pcbRemaining);
}

// ============================================================================
// AppendBlocks Dispatch
// ============================================================================

pub export fn SymCryptSha512AppendBlocks(
    pChain: *SYMCRYPT_SHA512_CHAINING_STATE,
    pbData: PCBYTE,
    cbData: SIZE_T,
    pcbRemaining: *SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    if (comptime !build_options.use_asm) {
        SymCryptSha512AppendBlocks_ull(pChain, pbData, cbData, pcbRemaining);
        return;
    }

    if (comptime builtin.cpu.arch == .x86_64 or builtin.cpu.arch == .aarch64) {
        SymCryptSha512AppendBlocks_ull(pChain, pbData, cbData, pcbRemaining);
    } else if (comptime builtin.cpu.arch == .arm) {
        if (cpuFeaturesPresent(SYMCRYPT_CPU_FEATURE_NEON)) {
            SymCryptSha512AppendBlocks_neon(pChain, pbData, cbData, pcbRemaining);
        } else {
            SymCryptSha512AppendBlocks_ull(pChain, pbData, cbData, pcbRemaining);
        }
    } else if (comptime builtin.cpu.arch == .x86) {
        var saveData: SYMCRYPT_EXTENDED_SAVE_DATA = undefined;
        if (cpuFeaturesPresent(SYMCRYPT_CPU_FEATURE_SSSE3) and SymCryptSaveXmm(&saveData) == .SYMCRYPT_NO_ERROR) {
            SymCryptSha512AppendBlocks_xmm(pChain, pbData, cbData, pcbRemaining);
            SymCryptRestoreXmm(&saveData);
        } else {
            SymCryptSha512AppendBlocks_ull(pChain, pbData, cbData, pcbRemaining);
        }
    } else {
        SymCryptSha512AppendBlocks_ull(pChain, pbData, cbData, pcbRemaining);
    }
}

// ============================================================================
// State Export / Import
// ============================================================================

fn SymCryptSha512StateExportCore(
    pState: PCSYMCRYPT_SHA512_STATE,
    blobType: hash.SYMCRYPT_BLOB_TYPE,
    pbBlob: PBYTE,
) void {
    var blob: SYMCRYPT_SHA512_STATE_EXPORT_BLOB align(SYMCRYPT_ALIGN_VALUE) = undefined;

    macros.CHECK_MAGIC(pState);

    hash.SymCryptWipeKnownSize(@ptrCast(&blob), @sizeOf(SYMCRYPT_SHA512_STATE_EXPORT_BLOB));

    blob.header.magic = hash.SYMCRYPT_BLOB_MAGIC;
    blob.header.size = SYMCRYPT_SHA512_STATE_EXPORT_SIZE;
    blob.header.type = @backingInt(blobType);

    macros.SymCryptUint64ToMsbFirst(&pState.chain.H, &blob.chain, 8);
    blob.dataLengthL = pState.dataLengthL;
    blob.dataLengthH = pState.dataLengthH;
    @memcpy(blob.buffer[0..pState.bytesInBuffer], pState.buffer[0..pState.bytesInBuffer]);

    macros.ASSERT(@as(SIZE_T, @sizeOf(SYMCRYPT_SHA512_STATE_EXPORT_BLOB)) == SYMCRYPT_SHA512_STATE_EXPORT_SIZE);
    hash.SymCryptMarvin32(
        hash.SymCryptMarvin32DefaultSeed,
        @ptrCast(&blob),
        SYMCRYPT_SHA512_STATE_EXPORT_SIZE - @sizeOf(hash.SYMCRYPT_BLOB_TRAILER),
        &blob.trailer.checksum,
    );

    @memcpy(pbBlob[0..SYMCRYPT_SHA512_STATE_EXPORT_SIZE], @as([*]const BYTE, @ptrCast(&blob))[0..SYMCRYPT_SHA512_STATE_EXPORT_SIZE]);

    hash.SymCryptWipeKnownSize(@ptrCast(&blob), @sizeOf(SYMCRYPT_SHA512_STATE_EXPORT_BLOB));
}

fn SymCryptSha512StateImportCore(
    pState: PSYMCRYPT_SHA512_STATE,
    blobType: hash.SYMCRYPT_BLOB_TYPE,
    pbBlob: PCBYTE,
) SYMCRYPT_ERROR {
    var blob: SYMCRYPT_SHA512_STATE_EXPORT_BLOB align(SYMCRYPT_ALIGN_VALUE) = undefined;
    var checksum: [8]BYTE = undefined;
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;

    macros.ASSERT(@as(SIZE_T, @sizeOf(SYMCRYPT_SHA512_STATE_EXPORT_BLOB)) == SYMCRYPT_SHA512_STATE_EXPORT_SIZE);
    @memcpy(@as([*]BYTE, @ptrCast(&blob))[0..SYMCRYPT_SHA512_STATE_EXPORT_SIZE], pbBlob[0..SYMCRYPT_SHA512_STATE_EXPORT_SIZE]);

    if (blob.header.magic != hash.SYMCRYPT_BLOB_MAGIC or
        blob.header.size != SYMCRYPT_SHA512_STATE_EXPORT_SIZE or
        blob.header.type != @backingInt(blobType))
    {
        scError = .SYMCRYPT_INVALID_BLOB;
        hash.SymCryptWipeKnownSize(@ptrCast(&blob), @sizeOf(SYMCRYPT_SHA512_STATE_EXPORT_BLOB));
        return scError;
    }

    hash.SymCryptMarvin32(
        hash.SymCryptMarvin32DefaultSeed,
        @ptrCast(&blob),
        SYMCRYPT_SHA512_STATE_EXPORT_SIZE - @sizeOf(hash.SYMCRYPT_BLOB_TRAILER),
        &checksum,
    );
    if (!std.mem.eql(u8, &checksum, &blob.trailer.checksum)) {
        scError = .SYMCRYPT_INVALID_BLOB;
        hash.SymCryptWipeKnownSize(@ptrCast(&blob), @sizeOf(SYMCRYPT_SHA512_STATE_EXPORT_BLOB));
        return scError;
    }

    macros.SymCryptMsbFirstToUint64(&blob.chain, &pState.chain.H, 8);
    pState.dataLengthL = blob.dataLengthL;
    pState.dataLengthH = blob.dataLengthH;
    pState.bytesInBuffer = @intCast(blob.dataLengthL & 0x7f);
    @memcpy(pState.buffer[0..pState.bytesInBuffer], blob.buffer[0..pState.bytesInBuffer]);

    macros.SET_MAGIC(pState);

    hash.SymCryptWipeKnownSize(@ptrCast(&blob), @sizeOf(SYMCRYPT_SHA512_STATE_EXPORT_BLOB));
    return scError;
}

pub export fn SymCryptSha512StateExport(
    pState: PCSYMCRYPT_SHA512_STATE,
    pbBlob: PBYTE,
) callconv(SYMCRYPT_CALL) void {
    SymCryptSha512StateExportCore(pState, .SymCryptBlobTypeSha512State, pbBlob);
}

pub export fn SymCryptSha512StateImport(
    pState: PSYMCRYPT_SHA512_STATE,
    pbBlob: PCBYTE,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    return SymCryptSha512StateImportCore(pState, .SymCryptBlobTypeSha512State, pbBlob);
}

pub export fn SymCryptSha384StateExport(
    pState: PCSYMCRYPT_SHA384_STATE,
    pbBlob: PBYTE,
) callconv(SYMCRYPT_CALL) void {
    SymCryptSha512StateExportCore(pState, .SymCryptBlobTypeSha384State, pbBlob);
}

pub export fn SymCryptSha384StateImport(
    pState: PSYMCRYPT_SHA384_STATE,
    pbBlob: PCBYTE,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    return SymCryptSha512StateImportCore(pState, .SymCryptBlobTypeSha384State, pbBlob);
}

pub export fn SymCryptSha512_224StateExport(
    pState: PCSYMCRYPT_SHA512_224_STATE,
    pbBlob: PBYTE,
) callconv(SYMCRYPT_CALL) void {
    SymCryptSha512StateExportCore(pState, .SymCryptBlobTypeSha512_224State, pbBlob);
}

pub export fn SymCryptSha512_224StateImport(
    pState: PSYMCRYPT_SHA512_224_STATE,
    pbBlob: PCBYTE,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    return SymCryptSha512StateImportCore(pState, .SymCryptBlobTypeSha512_224State, pbBlob);
}

pub export fn SymCryptSha512_256StateExport(
    pState: PCSYMCRYPT_SHA512_256_STATE,
    pbBlob: PBYTE,
) callconv(SYMCRYPT_CALL) void {
    SymCryptSha512StateExportCore(pState, .SymCryptBlobTypeSha512_256State, pbBlob);
}

pub export fn SymCryptSha512_256StateImport(
    pState: PSYMCRYPT_SHA512_256_STATE,
    pbBlob: PCBYTE,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    return SymCryptSha512StateImportCore(pState, .SymCryptBlobTypeSha512_256State, pbBlob);
}

// ============================================================================
// Self-Test
// ============================================================================

pub export const SymCryptSha512KATAnswer: [64]BYTE = .{
    0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba,
    0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
    0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2,
    0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
    0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8,
    0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
    0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
    0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f,
};

pub export const SymCryptSha384KATAnswer: [48]BYTE = .{
    0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b,
    0xb5, 0xa0, 0x3d, 0x69, 0x9a, 0xc6, 0x50, 0x07,
    0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63,
    0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff, 0x5b, 0xed,
    0x80, 0x86, 0x07, 0x2b, 0xa1, 0xe7, 0xcc, 0x23,
    0x58, 0xba, 0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7,
};

pub export const SymCryptSha512_224KATAnswer: [28]BYTE = .{
    0x46, 0x34, 0x27, 0x0f, 0x70, 0x7b, 0x6a, 0x54,
    0xda, 0xae, 0x75, 0x30, 0x46, 0x08, 0x42, 0xe2,
    0x0e, 0x37, 0xed, 0x26, 0x5c, 0xee, 0xe9, 0xa4,
    0x3e, 0x89, 0x24, 0xaa,
};

pub export const SymCryptSha512_256KATAnswer: [32]BYTE = .{
    0x53, 0x04, 0x8e, 0x26, 0x81, 0x94, 0x1e, 0xf9,
    0x9b, 0x2e, 0x29, 0xb7, 0x6b, 0x4c, 0x7d, 0xab,
    0xe4, 0xc2, 0xd0, 0xc6, 0x34, 0xfc, 0x6d, 0x46,
    0xe0, 0xe2, 0xf1, 0x31, 0x07, 0xe7, 0xaf, 0x23,
};

pub export fn SymCryptSha512Selftest() callconv(SYMCRYPT_CALL) void {
    var res: [SYMCRYPT_SHA512_RESULT_SIZE]BYTE = undefined;

    SymCryptSha512(&hash.SymCryptTestMsg3, hash.SymCryptTestMsg3.len, &res);

    hash.SymCryptInjectError(&res, res.len);

    if (!std.mem.eql(u8, &res, &SymCryptSha512KATAnswer)) {
        macros.SymCryptFatal(comptime macros.multiCharConstant("SH51"));
    }
}

pub export fn SymCryptSha384Selftest() callconv(SYMCRYPT_CALL) void {
    var res: [SYMCRYPT_SHA384_RESULT_SIZE]BYTE = undefined;

    SymCryptSha384(&hash.SymCryptTestMsg3, hash.SymCryptTestMsg3.len, &res);

    hash.SymCryptInjectError(&res, res.len);

    if (!std.mem.eql(u8, &res, &SymCryptSha384KATAnswer)) {
        macros.SymCryptFatal(comptime macros.multiCharConstant("SH38"));
    }
}

pub export fn SymCryptSha512_224Selftest() callconv(SYMCRYPT_CALL) void {
    var res: [SYMCRYPT_SHA512_224_RESULT_SIZE]BYTE = undefined;

    SymCryptSha512_224(&hash.SymCryptTestMsg3, hash.SymCryptTestMsg3.len, &res);

    hash.SymCryptInjectError(&res, res.len);

    if (!std.mem.eql(u8, &res, &SymCryptSha512_224KATAnswer)) {
        macros.SymCryptFatal(comptime macros.multiCharConstant("SH51"));
    }
}

pub export fn SymCryptSha512_256Selftest() callconv(SYMCRYPT_CALL) void {
    var res: [SYMCRYPT_SHA512_256_RESULT_SIZE]BYTE = undefined;

    SymCryptSha512_256(&hash.SymCryptTestMsg3, hash.SymCryptTestMsg3.len, &res);

    hash.SymCryptInjectError(&res, res.len);

    if (!std.mem.eql(u8, &res, &SymCryptSha512_256KATAnswer)) {
        macros.SymCryptFatal(comptime macros.multiCharConstant("SH51"));
    }
}
