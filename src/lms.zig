//
// lms.zig
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
// Leighton-Micali Hash-Based Signatures (LMS) implementation ported from lib/lms.c.
//

const std = @import("std");
const types = @import("types.zig");
const macros = @import("macros.zig");
const equal = @import("equal.zig");
const hash = @import("hash.zig");
const sha256 = @import("sha256.zig");
const shake = @import("shake.zig");
const xmss = @import("xmss.zig");

const BYTE = types.BYTE;
const PBYTE = types.PBYTE;
const PCBYTE = types.PCBYTE;
const UINT8 = types.UINT8;
const UINT16 = types.UINT16;
const UINT32 = types.UINT32;
const UINT64 = types.UINT64;
const SIZE_T = types.SIZE_T;
const PVOID = types.PVOID;
const SYMCRYPT_ERROR = types.SYMCRYPT_ERROR;
const PCSYMCRYPT_HASH = types.PCSYMCRYPT_HASH;
const SYMCRYPT_CALL = types.SYMCRYPT_CALL;
const SYMCRYPT_ALIGN_VALUE = types.SYMCRYPT_ALIGN_VALUE;
const SYMCRYPT_ASYM_ALIGN_VALUE = types.SYMCRYPT_ASYM_ALIGN_VALUE;
const SYMCRYPT_HASH_STATE = hash.SYMCRYPT_HASH_STATE;

// ==============================================================================================
// External C Callbacks & FIPS Self-Test Declarations
// ==============================================================================================

pub extern fn SymCryptCallbackAlloc(cbData: SIZE_T) callconv(SYMCRYPT_CALL) ?PBYTE;
pub extern fn SymCryptCallbackFree(pbData: PVOID) callconv(SYMCRYPT_CALL) void;
pub extern fn SymCryptCallbackRandom(pbBuffer: PBYTE, cbBuffer: SIZE_T) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;
pub extern fn SymCryptLmsSelftest() callconv(SYMCRYPT_CALL) void;
pub extern var g_SymCryptFipsSelftestsPerformed: UINT32;

pub const SYMCRYPT_SELFTEST_ALGORITHM_LMS: UINT32 = 0x100;

// ==============================================================================================
// Constants, Enums, and Structures
// ==============================================================================================

pub const SYMCRYPT_LMS_KEY_PAIR_IDENTIFIER_SIZE: usize = 16;
pub const SYMCRYPT_LMS_MAX_N: usize = 32;
pub const SYMCRYPT_LMS_MAX_P: usize = 265;
pub const SYMCRYPT_LMS_MAX_H: usize = 25;
pub const SYMCRYPT_LMS_MAX_CUSTOM_TREE_HEIGHT: UINT32 = 31;
pub const SYMCRYPT_LMS_CHECKSUM_SIZE: UINT32 = 16;

pub const SYMCRYPT_FLAG_LMSKEY_VERIFY_ROOT: UINT32 = 0x00000001;

inline fn isValidWinternitzWidth(w: UINT32) bool {
    return (w == 1) or (w == 2) or (w == 4) or (w == 8);
}

inline fn lmsPubKeySize(cbHashOutput: SIZE_T) SIZE_T {
    return 8 + SYMCRYPT_LMS_KEY_PAIR_IDENTIFIER_SIZE + cbHashOutput;
}

inline fn lmsPrivKeySize(cbHashOutput: SIZE_T) SIZE_T {
    return lmsPubKeySize(cbHashOutput) + @sizeOf(UINT32) + cbHashOutput;
}

pub const SYMCRYPT_LMS_ALGID = enum(UINT32) {
    SYMCRYPT_LMS_SHA256_M32_H5 = 0x00000005,
    SYMCRYPT_LMS_SHA256_M32_H10 = 0x00000006,
    SYMCRYPT_LMS_SHA256_M32_H15 = 0x00000007,
    SYMCRYPT_LMS_SHA256_M32_H20 = 0x00000008,
    SYMCRYPT_LMS_SHA256_M32_H25 = 0x00000009,
    SYMCRYPT_LMS_SHA256_M24_H5 = 0x0000000A,
    SYMCRYPT_LMS_SHA256_M24_H10 = 0x0000000B,
    SYMCRYPT_LMS_SHA256_M24_H15 = 0x0000000C,
    SYMCRYPT_LMS_SHA256_M24_H20 = 0x0000000D,
    SYMCRYPT_LMS_SHA256_M24_H25 = 0x0000000E,
    SYMCRYPT_LMS_SHAKE_M32_H5 = 0x0000000F,
    SYMCRYPT_LMS_SHAKE_M32_H10 = 0x00000010,
    SYMCRYPT_LMS_SHAKE_M32_H15 = 0x00000011,
    SYMCRYPT_LMS_SHAKE_M32_H20 = 0x00000012,
    SYMCRYPT_LMS_SHAKE_M32_H25 = 0x00000013,
    SYMCRYPT_LMS_SHAKE_M24_H5 = 0x00000014,
    SYMCRYPT_LMS_SHAKE_M24_H10 = 0x00000015,
    SYMCRYPT_LMS_SHAKE_M24_H15 = 0x00000016,
    SYMCRYPT_LMS_SHAKE_M24_H20 = 0x00000017,
    SYMCRYPT_LMS_SHAKE_M24_H25 = 0x00000018,
    _,
};

pub const SYMCRYPT_LMS_OTS_ALGID = enum(UINT32) {
    SYMCRYPT_LMS_OTS_SHA256_N32_W1 = 0x00000001,
    SYMCRYPT_LMS_OTS_SHA256_N32_W2 = 0x00000002,
    SYMCRYPT_LMS_OTS_SHA256_N32_W4 = 0x00000003,
    SYMCRYPT_LMS_OTS_SHA256_N32_W8 = 0x00000004,
    SYMCRYPT_LMS_OTS_SHA256_N24_W1 = 0x00000005,
    SYMCRYPT_LMS_OTS_SHA256_N24_W2 = 0x00000006,
    SYMCRYPT_LMS_OTS_SHA256_N24_W4 = 0x00000007,
    SYMCRYPT_LMS_OTS_SHA256_N24_W8 = 0x00000008,
    SYMCRYPT_LMS_OTS_SHAKE_N32_W1 = 0x00000009,
    SYMCRYPT_LMS_OTS_SHAKE_N32_W2 = 0x0000000A,
    SYMCRYPT_LMS_OTS_SHAKE_N32_W4 = 0x0000000B,
    SYMCRYPT_LMS_OTS_SHAKE_N32_W8 = 0x0000000C,
    SYMCRYPT_LMS_OTS_SHAKE_N24_W1 = 0x0000000D,
    SYMCRYPT_LMS_OTS_SHAKE_N24_W2 = 0x0000000E,
    SYMCRYPT_LMS_OTS_SHAKE_N24_W4 = 0x0000000F,
    SYMCRYPT_LMS_OTS_SHAKE_N24_W8 = 0x00000010,
    _,
};

pub const SYMCRYPT_LMSKEY_TYPE = enum(UINT32) {
    SYMCRYPT_LMSKEY_TYPE_NONE = 0,
    SYMCRYPT_LMSKEY_TYPE_PUBLIC = 1,
    SYMCRYPT_LMSKEY_TYPE_PRIVATE = 2,
    _,
};

pub const SYMCRYPT_LMS_PARAMS = extern struct {
    lmsAlgID: UINT32 align(SYMCRYPT_ALIGN_VALUE),
    lmsOtsAlgID: UINT32,
    pLmsHashFunction: ?PCSYMCRYPT_HASH,
    nTreeHeight: UINT32,
    cbHashOutput: UINT32,
    nWinternitzChainWidth: UINT32,
    nByteStringCount: UINT32,
    nChecksumLShiftBits: UINT32,
};
pub const PSYMCRYPT_LMS_PARAMS = *SYMCRYPT_LMS_PARAMS;
pub const PCSYMCRYPT_LMS_PARAMS = *const SYMCRYPT_LMS_PARAMS;

pub const SYMCRYPT_LMS_KEY = extern struct {
    cbSize: SIZE_T align(SYMCRYPT_ASYM_ALIGN_VALUE),
    params: SYMCRYPT_LMS_PARAMS,
    nNextUnusedLeaf: UINT64,
    keyType: UINT32,
    abId: [SYMCRYPT_LMS_KEY_PAIR_IDENTIFIER_SIZE]BYTE,
    abPublicRoot: [SYMCRYPT_LMS_MAX_N]BYTE,
    abSeed: [SYMCRYPT_LMS_MAX_N]BYTE,
    magic: SIZE_T,
};
pub const PSYMCRYPT_LMS_KEY = *SYMCRYPT_LMS_KEY;
pub const PCSYMCRYPT_LMS_KEY = *const SYMCRYPT_LMS_KEY;

// ==============================================================================================
// Predefined Parameter Tables
// ==============================================================================================

const LmsHashObjects = [2]*const PCSYMCRYPT_HASH{
    &sha256.SymCryptSha256Algorithm, // 0
    &shake.SymCryptShake256HashAlgorithm, // 1
};

const SYMCRYPT_LMS_PARAMETER_PREDEFINED = struct {
    lmsAlgId: SYMCRYPT_LMS_ALGID,
    cbHashOutput: UINT8,
    nTreeHeight: UINT8,
    nHashIdx: UINT8,
};

const LmsParametersPredefined = [_]SYMCRYPT_LMS_PARAMETER_PREDEFINED{
    .{ .lmsAlgId = .SYMCRYPT_LMS_SHA256_M32_H5, .cbHashOutput = 32, .nTreeHeight = 5, .nHashIdx = 0 },
    .{ .lmsAlgId = .SYMCRYPT_LMS_SHA256_M32_H10, .cbHashOutput = 32, .nTreeHeight = 10, .nHashIdx = 0 },
    .{ .lmsAlgId = .SYMCRYPT_LMS_SHA256_M32_H15, .cbHashOutput = 32, .nTreeHeight = 15, .nHashIdx = 0 },
    .{ .lmsAlgId = .SYMCRYPT_LMS_SHA256_M32_H20, .cbHashOutput = 32, .nTreeHeight = 20, .nHashIdx = 0 },
    .{ .lmsAlgId = .SYMCRYPT_LMS_SHA256_M32_H25, .cbHashOutput = 32, .nTreeHeight = 25, .nHashIdx = 0 },
    .{ .lmsAlgId = .SYMCRYPT_LMS_SHAKE_M32_H5, .cbHashOutput = 32, .nTreeHeight = 5, .nHashIdx = 1 },
    .{ .lmsAlgId = .SYMCRYPT_LMS_SHAKE_M32_H10, .cbHashOutput = 32, .nTreeHeight = 10, .nHashIdx = 1 },
    .{ .lmsAlgId = .SYMCRYPT_LMS_SHAKE_M32_H15, .cbHashOutput = 32, .nTreeHeight = 15, .nHashIdx = 1 },
    .{ .lmsAlgId = .SYMCRYPT_LMS_SHAKE_M32_H20, .cbHashOutput = 32, .nTreeHeight = 20, .nHashIdx = 1 },
    .{ .lmsAlgId = .SYMCRYPT_LMS_SHAKE_M32_H25, .cbHashOutput = 32, .nTreeHeight = 25, .nHashIdx = 1 },
    .{ .lmsAlgId = .SYMCRYPT_LMS_SHA256_M24_H5, .cbHashOutput = 24, .nTreeHeight = 5, .nHashIdx = 0 },
    .{ .lmsAlgId = .SYMCRYPT_LMS_SHA256_M24_H10, .cbHashOutput = 24, .nTreeHeight = 10, .nHashIdx = 0 },
    .{ .lmsAlgId = .SYMCRYPT_LMS_SHA256_M24_H15, .cbHashOutput = 24, .nTreeHeight = 15, .nHashIdx = 0 },
    .{ .lmsAlgId = .SYMCRYPT_LMS_SHA256_M24_H20, .cbHashOutput = 24, .nTreeHeight = 20, .nHashIdx = 0 },
    .{ .lmsAlgId = .SYMCRYPT_LMS_SHA256_M24_H25, .cbHashOutput = 24, .nTreeHeight = 25, .nHashIdx = 0 },
    .{ .lmsAlgId = .SYMCRYPT_LMS_SHAKE_M24_H5, .cbHashOutput = 24, .nTreeHeight = 5, .nHashIdx = 1 },
    .{ .lmsAlgId = .SYMCRYPT_LMS_SHAKE_M24_H10, .cbHashOutput = 24, .nTreeHeight = 10, .nHashIdx = 1 },
    .{ .lmsAlgId = .SYMCRYPT_LMS_SHAKE_M24_H15, .cbHashOutput = 24, .nTreeHeight = 15, .nHashIdx = 1 },
    .{ .lmsAlgId = .SYMCRYPT_LMS_SHAKE_M24_H20, .cbHashOutput = 24, .nTreeHeight = 20, .nHashIdx = 1 },
    .{ .lmsAlgId = .SYMCRYPT_LMS_SHAKE_M24_H25, .cbHashOutput = 24, .nTreeHeight = 25, .nHashIdx = 1 },
};

const SYMCRYPT_LMS_OTS_PARAMETER_PREDEFINED = struct {
    lmsOtsAlgId: SYMCRYPT_LMS_OTS_ALGID,
    cbHashOutput: UINT8,
    nWidth: UINT8,
    nHashIdx: UINT8,
};

const LmsOtsParametersPredefined = [_]SYMCRYPT_LMS_OTS_PARAMETER_PREDEFINED{
    .{ .lmsOtsAlgId = .SYMCRYPT_LMS_OTS_SHA256_N32_W1, .cbHashOutput = 32, .nWidth = 1, .nHashIdx = 0 },
    .{ .lmsOtsAlgId = .SYMCRYPT_LMS_OTS_SHA256_N32_W2, .cbHashOutput = 32, .nWidth = 2, .nHashIdx = 0 },
    .{ .lmsOtsAlgId = .SYMCRYPT_LMS_OTS_SHA256_N32_W4, .cbHashOutput = 32, .nWidth = 4, .nHashIdx = 0 },
    .{ .lmsOtsAlgId = .SYMCRYPT_LMS_OTS_SHA256_N32_W8, .cbHashOutput = 32, .nWidth = 8, .nHashIdx = 0 },
    .{ .lmsOtsAlgId = .SYMCRYPT_LMS_OTS_SHAKE_N32_W1, .cbHashOutput = 32, .nWidth = 1, .nHashIdx = 1 },
    .{ .lmsOtsAlgId = .SYMCRYPT_LMS_OTS_SHAKE_N32_W2, .cbHashOutput = 32, .nWidth = 2, .nHashIdx = 1 },
    .{ .lmsOtsAlgId = .SYMCRYPT_LMS_OTS_SHAKE_N32_W4, .cbHashOutput = 32, .nWidth = 4, .nHashIdx = 1 },
    .{ .lmsOtsAlgId = .SYMCRYPT_LMS_OTS_SHAKE_N32_W8, .cbHashOutput = 32, .nWidth = 8, .nHashIdx = 1 },
    .{ .lmsOtsAlgId = .SYMCRYPT_LMS_OTS_SHA256_N24_W1, .cbHashOutput = 24, .nWidth = 1, .nHashIdx = 0 },
    .{ .lmsOtsAlgId = .SYMCRYPT_LMS_OTS_SHA256_N24_W2, .cbHashOutput = 24, .nWidth = 2, .nHashIdx = 0 },
    .{ .lmsOtsAlgId = .SYMCRYPT_LMS_OTS_SHA256_N24_W4, .cbHashOutput = 24, .nWidth = 4, .nHashIdx = 0 },
    .{ .lmsOtsAlgId = .SYMCRYPT_LMS_OTS_SHA256_N24_W8, .cbHashOutput = 24, .nWidth = 8, .nHashIdx = 0 },
    .{ .lmsOtsAlgId = .SYMCRYPT_LMS_OTS_SHAKE_N24_W1, .cbHashOutput = 24, .nWidth = 1, .nHashIdx = 1 },
    .{ .lmsOtsAlgId = .SYMCRYPT_LMS_OTS_SHAKE_N24_W2, .cbHashOutput = 24, .nWidth = 2, .nHashIdx = 1 },
    .{ .lmsOtsAlgId = .SYMCRYPT_LMS_OTS_SHAKE_N24_W4, .cbHashOutput = 24, .nWidth = 4, .nHashIdx = 1 },
    .{ .lmsOtsAlgId = .SYMCRYPT_LMS_OTS_SHAKE_N24_W8, .cbHashOutput = 24, .nWidth = 8, .nHashIdx = 1 },
};

const SYMCRYPT_LMS_D_PBLC = [2]BYTE{ 0x80, 0x80 };
const SYMCRYPT_LMS_D_MESG = [2]BYTE{ 0x81, 0x81 };
const SYMCRYPT_LMS_D_LEAF = [2]BYTE{ 0x82, 0x82 };
const SYMCRYPT_LMS_D_INTR = [2]BYTE{ 0x83, 0x83 };

// ==============================================================================================
// Internal Helper Functions
// ==============================================================================================

fn LmsHashMessage(
    pHash: PCSYMCRYPT_HASH,
    pbId: PCBYTE,
    pbLeafNumber: PCBYTE,
    pbRandomizer: PCBYTE,
    cbRandomizer: SIZE_T,
    pbMessage: PCBYTE,
    cbMessage: SIZE_T,
    pbOut: PBYTE,
    cbOut: SIZE_T,
) void {
    var state: SYMCRYPT_HASH_STATE = std.mem.zeroes(SYMCRYPT_HASH_STATE);

    hash.SymCryptHashInit(pHash, @ptrCast(&state));
    hash.SymCryptHashAppend(pHash, @ptrCast(&state), pbId, SYMCRYPT_LMS_KEY_PAIR_IDENTIFIER_SIZE);
    hash.SymCryptHashAppend(pHash, @ptrCast(&state), pbLeafNumber, @sizeOf(UINT32));
    hash.SymCryptHashAppend(pHash, @ptrCast(&state), &SYMCRYPT_LMS_D_MESG, SYMCRYPT_LMS_D_MESG.len);
    hash.SymCryptHashAppend(pHash, @ptrCast(&state), pbRandomizer, cbRandomizer);
    hash.SymCryptHashAppend(pHash, @ptrCast(&state), pbMessage, cbMessage);
    hash.SymCryptHashResult(pHash, @ptrCast(&state), pbOut, cbOut);
}

fn LmsOtskeyComputePrivate(
    pKey: PCSYMCRYPT_LMS_KEY,
    nLeafNumber: UINT32,
    nPIdx: UINT32,
    pbOtsPrivateKey: PBYTE,
) callconv(SYMCRYPT_CALL) void {
    const cbHashOutput: UINT32 = pKey.params.cbHashOutput;
    const pHash: PCSYMCRYPT_HASH = pKey.params.pLmsHashFunction.?;
    var state: SYMCRYPT_HASH_STATE = std.mem.zeroes(SYMCRYPT_HASH_STATE);
    var abTemp: [@sizeOf(UINT32) + 3]BYTE = @splat(0);

    macros.ASSERT(nLeafNumber <= ((@as(UINT32, 1) << @intCast(pKey.params.nTreeHeight)) - 1));

    macros.STORE_MSBFIRST32(&abTemp, nLeafNumber);
    macros.STORE_MSBFIRST16(@as(PBYTE, @ptrCast(&abTemp)) + @sizeOf(UINT32), @truncate(nPIdx));
    abTemp[@sizeOf(UINT32) + 2] = 0xff;

    hash.SymCryptHashInit(pHash, @ptrCast(&state));
    hash.SymCryptHashAppend(pHash, @ptrCast(&state), &pKey.abId, SYMCRYPT_LMS_KEY_PAIR_IDENTIFIER_SIZE);
    hash.SymCryptHashAppend(pHash, @ptrCast(&state), &abTemp, abTemp.len);
    hash.SymCryptHashAppend(pHash, @ptrCast(&state), &pKey.abSeed, cbHashOutput);
    hash.SymCryptHashResult(pHash, @ptrCast(&state), pbOtsPrivateKey, cbHashOutput);
}

fn LmskeyWipe(
    pKey: PSYMCRYPT_LMS_KEY,
) callconv(SYMCRYPT_CALL) void {
    macros.CHECK_MAGIC(pKey);

    hash.SymCryptWipeKnownSize(@ptrCast(&pKey.abSeed), @sizeOf(@TypeOf(pKey.abSeed)));
    hash.SymCryptWipeKnownSize(@ptrCast(&pKey.abPublicRoot), @sizeOf(@TypeOf(pKey.abPublicRoot)));
    hash.SymCryptWipeKnownSize(@ptrCast(&pKey.abId), @sizeOf(@TypeOf(pKey.abId)));
    pKey.nNextUnusedLeaf = 0;
    pKey.keyType = @backingInt(SYMCRYPT_LMSKEY_TYPE.SYMCRYPT_LMSKEY_TYPE_NONE);
}

fn LmsOtsCalculateChecksum(
    pbString: PCBYTE,
    cbString: UINT32,
    nWidth: UINT32,
    nLeftShift: UINT32,
) UINT16 {
    var sum: UINT32 = 0;
    const max: UINT32 = (@as(UINT32, 1) << @intCast(nWidth)) - 1;
    macros.ASSERT(isValidWinternitzWidth(nWidth));

    const numDigits: UINT32 = (cbString * 8) / nWidth;
    var i: UINT32 = 0;
    while (i < numDigits) : (i += 1) {
        sum = sum + max - xmss.SymCryptHbsGetDigit(nWidth, pbString, cbString, i);
    }
    return @truncate(sum << @intCast(nLeftShift));
}

fn LmsOtsSizeofSignatureFromParams(
    pParams: PCSYMCRYPT_LMS_PARAMS,
) callconv(SYMCRYPT_CALL) SIZE_T {
    const n: SIZE_T = pParams.cbHashOutput;
    const p: SIZE_T = pParams.nByteStringCount;
    var size: SIZE_T = 0;

    size += @sizeOf(UINT32); // type
    size += n; // randomizer
    size += p * n; // y[0..p-1]

    return size;
}

fn LmsOtskeySign(
    pKey: PSYMCRYPT_LMS_KEY,
    nLeafNumber: UINT64,
    pbMessage: PCBYTE,
    cbMessage: SIZE_T,
    pbRandomizer: PCBYTE,
    pbSignature: PBYTE,
    cbSignature: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    const pHash: PCSYMCRYPT_HASH = pKey.params.pLmsHashFunction.?;
    var state: SYMCRYPT_HASH_STATE = std.mem.zeroes(SYMCRYPT_HASH_STATE);
    const cbHashOutput: SIZE_T = pKey.params.cbHashOutput;
    const nWinternitzChainWidth: UINT32 = pKey.params.nWinternitzChainWidth;
    var cbRemainingBytes: SIZE_T = cbSignature;
    var en32LeafNumber: [4]BYTE = @splat(0);
    var en16Index: [2]BYTE = @splat(0);
    var abOtsPrivateKey: [SYMCRYPT_LMS_MAX_N]BYTE = @splat(0);
    var abLmsHashedMessage: [SYMCRYPT_LMS_MAX_N + @sizeOf(UINT16)]BYTE = @splat(0);
    var pbDest: PBYTE = pbSignature;

    macros.ASSERT(cbSignature == LmsOtsSizeofSignatureFromParams(&pKey.params));

    macros.STORE_MSBFIRST32(pbDest, pKey.params.lmsOtsAlgID);
    pbDest += @sizeOf(UINT32);
    cbRemainingBytes -= @sizeOf(UINT32);

    @memcpy(pbDest[0..cbHashOutput], pbRandomizer[0..cbHashOutput]);
    pbDest += cbHashOutput;
    cbRemainingBytes -= cbHashOutput;

    macros.STORE_MSBFIRST32(&en32LeafNumber, @truncate(nLeafNumber));
    LmsHashMessage(pHash, &pKey.abId, &en32LeafNumber, pbRandomizer, cbHashOutput, pbMessage, cbMessage, &abLmsHashedMessage, cbHashOutput);

    const nChecksum: UINT16 = LmsOtsCalculateChecksum(&abLmsHashedMessage, pKey.params.cbHashOutput, nWinternitzChainWidth, pKey.params.nChecksumLShiftBits);
    macros.STORE_MSBFIRST16(@as(PBYTE, @ptrCast(&abLmsHashedMessage)) + cbHashOutput, nChecksum);

    hash.SymCryptHashInit(pHash, @ptrCast(&state));
    var nIndex: UINT32 = 0;
    while (nIndex < pKey.params.nByteStringCount) : (nIndex += 1) {
        const coeff: BYTE = @truncate(xmss.SymCryptHbsGetDigit(nWinternitzChainWidth, &abLmsHashedMessage, cbHashOutput + @sizeOf(UINT16), nIndex));
        LmsOtskeyComputePrivate(pKey, @truncate(nLeafNumber), nIndex, &abOtsPrivateKey);

        macros.STORE_MSBFIRST16(&en16Index, @truncate(nIndex));

        var j: BYTE = 0;
        while (j < coeff) : (j += 1) {
            hash.SymCryptHashAppend(pHash, @ptrCast(&state), &pKey.abId, SYMCRYPT_LMS_KEY_PAIR_IDENTIFIER_SIZE);
            hash.SymCryptHashAppend(pHash, @ptrCast(&state), &en32LeafNumber, @sizeOf(UINT32));
            hash.SymCryptHashAppend(pHash, @ptrCast(&state), &en16Index, @sizeOf(UINT16));
            hash.SymCryptHashAppend(pHash, @ptrCast(&state), @ptrCast(&j), 1);
            hash.SymCryptHashAppend(pHash, @ptrCast(&state), &abOtsPrivateKey, cbHashOutput);
            hash.SymCryptHashResult(pHash, @ptrCast(&state), &abOtsPrivateKey, cbHashOutput);
        }
        @memcpy(pbDest[0..cbHashOutput], abOtsPrivateKey[0..cbHashOutput]);
        pbDest += cbHashOutput;
        cbRemainingBytes -= cbHashOutput;
    }
    macros.ASSERT(cbRemainingBytes == 0);
}

fn LmsOtskeyComputePublic(
    pKey: PCSYMCRYPT_LMS_KEY,
    nNodeIdx: UINT32,
    pbK: PBYTE,
) callconv(SYMCRYPT_CALL) void {
    const cbHashOutput: SIZE_T = pKey.params.cbHashOutput;
    const maxJ: UINT32 = (@as(UINT32, 1) << @intCast(pKey.params.nWinternitzChainWidth)) - 1;
    const pHash: PCSYMCRYPT_HASH = pKey.params.pLmsHashFunction.?;
    var statePriv: SYMCRYPT_HASH_STATE = std.mem.zeroes(SYMCRYPT_HASH_STATE);
    var statePub: SYMCRYPT_HASH_STATE = std.mem.zeroes(SYMCRYPT_HASH_STATE);
    var en32LeafNumber: [4]BYTE = @splat(0);
    var en16Index: [2]BYTE = @splat(0);
    var abNode: [SYMCRYPT_LMS_MAX_N]BYTE = @splat(0);

    macros.STORE_MSBFIRST32(&en32LeafNumber, nNodeIdx);

    hash.SymCryptHashInit(pHash, @ptrCast(&statePub));
    hash.SymCryptHashAppend(pHash, @ptrCast(&statePub), &pKey.abId, SYMCRYPT_LMS_KEY_PAIR_IDENTIFIER_SIZE);
    hash.SymCryptHashAppend(pHash, @ptrCast(&statePub), &en32LeafNumber, @sizeOf(UINT32));
    hash.SymCryptHashAppend(pHash, @ptrCast(&statePub), &SYMCRYPT_LMS_D_PBLC, SYMCRYPT_LMS_D_PBLC.len);

    hash.SymCryptHashInit(pHash, @ptrCast(&statePriv));
    var i: UINT32 = 0;
    while (i < pKey.params.nByteStringCount) : (i += 1) {
        LmsOtskeyComputePrivate(pKey, nNodeIdx, i, &abNode);
        macros.STORE_MSBFIRST16(&en16Index, @truncate(i));

        var j: UINT32 = 0;
        while (j < maxJ) : (j += 1) {
            const bJ: BYTE = @truncate(j);
            hash.SymCryptHashAppend(pHash, @ptrCast(&statePriv), &pKey.abId, SYMCRYPT_LMS_KEY_PAIR_IDENTIFIER_SIZE);
            hash.SymCryptHashAppend(pHash, @ptrCast(&statePriv), &en32LeafNumber, @sizeOf(UINT32));
            hash.SymCryptHashAppend(pHash, @ptrCast(&statePriv), &en16Index, @sizeOf(UINT16));
            hash.SymCryptHashAppend(pHash, @ptrCast(&statePriv), @ptrCast(&bJ), 1);
            hash.SymCryptHashAppend(pHash, @ptrCast(&statePriv), &abNode, cbHashOutput);
            hash.SymCryptHashResult(pHash, @ptrCast(&statePriv), &abNode, cbHashOutput);
        }
        hash.SymCryptHashAppend(pHash, @ptrCast(&statePub), &abNode, cbHashOutput);
    }
    hash.SymCryptHashResult(pHash, @ptrCast(&statePub), pbK, cbHashOutput);
}

fn LmsComputeNodeValue(
    pKey: PCSYMCRYPT_LMS_KEY,
    nIndex: UINT32,
    pbNodeValue: PBYTE,
    cbNodeValue: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    const cbHashOutput: SIZE_T = pKey.params.cbHashOutput;
    const nInternalNodes: UINT32 = @as(UINT32, 1) << @intCast(pKey.params.nTreeHeight);
    const pHash: PCSYMCRYPT_HASH = pKey.params.pLmsHashFunction.?;
    var state: SYMCRYPT_HASH_STATE = std.mem.zeroes(SYMCRYPT_HASH_STATE);
    var abTemp: [SYMCRYPT_LMS_MAX_N]BYTE = @splat(0);
    var en32Index: [4]BYTE = @splat(0);
    var abOtsPubKey: [SYMCRYPT_LMS_MAX_N]BYTE = @splat(0);

    macros.ASSERT(nIndex > 0);
    macros.ASSERT(cbNodeValue == cbHashOutput);

    macros.STORE_MSBFIRST32(&en32Index, nIndex);

    hash.SymCryptHashInit(pHash, @ptrCast(&state));
    hash.SymCryptHashAppend(pHash, @ptrCast(&state), &pKey.abId, SYMCRYPT_LMS_KEY_PAIR_IDENTIFIER_SIZE);
    hash.SymCryptHashAppend(pHash, @ptrCast(&state), &en32Index, @sizeOf(UINT32));
    if (nIndex >= nInternalNodes) {
        LmsOtskeyComputePublic(pKey, nIndex - nInternalNodes, &abOtsPubKey);

        hash.SymCryptHashAppend(pHash, @ptrCast(&state), &SYMCRYPT_LMS_D_LEAF, SYMCRYPT_LMS_D_LEAF.len);
        hash.SymCryptHashAppend(pHash, @ptrCast(&state), &abOtsPubKey, cbHashOutput);
    } else {
        hash.SymCryptHashAppend(pHash, @ptrCast(&state), &SYMCRYPT_LMS_D_INTR, SYMCRYPT_LMS_D_INTR.len);

        LmsComputeNodeValue(pKey, 2 * nIndex, &abTemp, cbHashOutput);
        hash.SymCryptHashAppend(pHash, @ptrCast(&state), &abTemp, cbHashOutput);
        hash.SymCryptWipeKnownSize(@ptrCast(&abTemp), SYMCRYPT_LMS_MAX_N);

        LmsComputeNodeValue(pKey, 2 * nIndex + 1, &abTemp, cbHashOutput);
        hash.SymCryptHashAppend(pHash, @ptrCast(&state), &abTemp, cbHashOutput);
    }
    hash.SymCryptHashResult(pHash, @ptrCast(&state), pbNodeValue, cbHashOutput);
}

// ==============================================================================================
// Public API Functions
// ==============================================================================================

pub export fn SymCryptLmsParamsFromAlgId(
    lmsAlgID: SYMCRYPT_LMS_ALGID,
    lmsOtsAlgID: SYMCRYPT_LMS_OTS_ALGID,
    pParams: PSYMCRYPT_LMS_PARAMS,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var u: UINT32 = 0;
    var v: UINT32 = 0;
    var bFound: bool = false;

    hash.SymCryptWipeKnownSize(@ptrCast(pParams), @sizeOf(SYMCRYPT_LMS_PARAMS));

    for (LmsParametersPredefined) |entry| {
        if (entry.lmsAlgId == lmsAlgID) {
            pParams.lmsAlgID = @backingInt(lmsAlgID);
            pParams.nTreeHeight = entry.nTreeHeight;
            macros.ASSERT(pParams.nTreeHeight <= SYMCRYPT_LMS_MAX_CUSTOM_TREE_HEIGHT);

            pParams.cbHashOutput = entry.cbHashOutput;

            macros.ASSERT(entry.nHashIdx < LmsHashObjects.len);
            pParams.pLmsHashFunction = LmsHashObjects[entry.nHashIdx].*;
            bFound = true;
            break;
        }
    }
    if (!bFound) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    bFound = false;
    for (LmsOtsParametersPredefined) |entry| {
        if (entry.lmsOtsAlgId == lmsOtsAlgID) {
            macros.ASSERT(entry.nHashIdx < LmsHashObjects.len);

            if (pParams.pLmsHashFunction != LmsHashObjects[entry.nHashIdx].* or
                pParams.cbHashOutput != entry.cbHashOutput)
            {
                return .SYMCRYPT_INVALID_ARGUMENT;
            }
            pParams.lmsOtsAlgID = @backingInt(lmsOtsAlgID);
            pParams.nWinternitzChainWidth = entry.nWidth;
            xmss.SymCryptHbsGetWinternitzLengths(
                pParams.cbHashOutput,
                pParams.nWinternitzChainWidth,
                &u,
                &v,
            );
            macros.ASSERT((v * pParams.nWinternitzChainWidth) <= SYMCRYPT_LMS_CHECKSUM_SIZE);
            pParams.nChecksumLShiftBits = SYMCRYPT_LMS_CHECKSUM_SIZE - (v * pParams.nWinternitzChainWidth);
            pParams.nByteStringCount = u + v;
            bFound = true;
            break;
        }
    }
    if (!bFound) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptLmsSizeofSignatureFromParams(
    pParams: PCSYMCRYPT_LMS_PARAMS,
) callconv(SYMCRYPT_CALL) SIZE_T {
    var size: SIZE_T = 0;

    size += @sizeOf(UINT32); // q
    size += LmsOtsSizeofSignatureFromParams(pParams); // LMS-OTS signature
    size += @sizeOf(UINT32); // type
    size += @as(SIZE_T, pParams.nTreeHeight) * @as(SIZE_T, pParams.cbHashOutput); // path[0..h-1]
    return size;
}

pub export fn SymCryptLmsSetParams(
    pParams: PSYMCRYPT_LMS_PARAMS,
    lmsAlgID: UINT32,
    lmsOtsAlgID: UINT32,
    pLmsHashFunction: PCSYMCRYPT_HASH,
    cbHashOutput: UINT32,
    nTreeHeight: UINT32,
    nWinternitzChainWidth: UINT32,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var u: UINT32 = 0;
    var v: UINT32 = 0;

    hash.SymCryptWipeKnownSize(@ptrCast(pParams), @sizeOf(SYMCRYPT_LMS_PARAMS));

    // nTreeHeight must be positive and maximum SYMCRYPT_LMS_MAX_CUSTOM_TREE_HEIGHT
    if (nTreeHeight == 0 or nTreeHeight > SYMCRYPT_LMS_MAX_CUSTOM_TREE_HEIGHT) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    // Output cbHashOutput cannot be larger than the hash output size or SYMCRYPT_LMS_MAX_N
    if (cbHashOutput == 0 or cbHashOutput > pLmsHashFunction.resultSize or cbHashOutput > SYMCRYPT_LMS_MAX_N) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    // Winternitz parameter must be one of 1, 2, 4, or 8
    if (!isValidWinternitzWidth(nWinternitzChainWidth)) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    pParams.lmsAlgID = lmsAlgID;
    pParams.lmsOtsAlgID = lmsOtsAlgID;
    pParams.pLmsHashFunction = pLmsHashFunction;
    pParams.nTreeHeight = nTreeHeight;
    pParams.cbHashOutput = cbHashOutput;
    pParams.nWinternitzChainWidth = nWinternitzChainWidth;
    xmss.SymCryptHbsGetWinternitzLengths(
        pParams.cbHashOutput,
        pParams.nWinternitzChainWidth,
        &u,
        &v,
    );
    pParams.nChecksumLShiftBits = SYMCRYPT_LMS_CHECKSUM_SIZE - (v * pParams.nWinternitzChainWidth);
    pParams.nByteStringCount = u + v;

    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptLmsSizeofKeyBlobFromParams(
    pParams: PCSYMCRYPT_LMS_PARAMS,
    keyType: SYMCRYPT_LMSKEY_TYPE,
    pcbKey: *SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    switch (keyType) {
        .SYMCRYPT_LMSKEY_TYPE_PUBLIC => pcbKey.* = lmsPubKeySize(pParams.cbHashOutput),
        .SYMCRYPT_LMSKEY_TYPE_PRIVATE => pcbKey.* = lmsPrivKeySize(pParams.cbHashOutput),
        else => return .SYMCRYPT_INVALID_ARGUMENT,
    }

    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptLmskeyAllocate(
    pParams: PCSYMCRYPT_LMS_PARAMS,
    flags: UINT32,
) callconv(SYMCRYPT_CALL) ?PSYMCRYPT_LMS_KEY {
    const cbSize: SIZE_T = @sizeOf(SYMCRYPT_LMS_KEY);

    if (flags != 0) {
        return null;
    }

    const pbKey = SymCryptCallbackAlloc(cbSize) orelse return null;

    hash.SymCryptWipe(@ptrCast(pbKey), cbSize);

    const aligned_ptr: [*]align(SYMCRYPT_ASYM_ALIGN_VALUE) BYTE = @alignCast(pbKey);
    const pKey: PSYMCRYPT_LMS_KEY = @ptrCast(aligned_ptr);

    pKey.cbSize = cbSize;
    pKey.params = pParams.*;
    macros.SET_MAGIC(pKey);

    return pKey;
}

pub export fn SymCryptLmskeyFree(
    pKey: PSYMCRYPT_LMS_KEY,
) callconv(SYMCRYPT_CALL) void {
    macros.CHECK_MAGIC(pKey);

    hash.SymCryptWipeKnownSize(@ptrCast(pKey), @sizeOf(SYMCRYPT_LMS_KEY));
    SymCryptCallbackFree(@ptrCast(pKey));
}

fn SymCryptLmskeyVerifyRoot(
    pKey: PCSYMCRYPT_LMS_KEY,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var abPublicRoot: [SYMCRYPT_LMS_MAX_N]BYTE = @splat(0);

    macros.CHECK_MAGIC(pKey);

    if (pKey.keyType != @backingInt(SYMCRYPT_LMSKEY_TYPE.SYMCRYPT_LMSKEY_TYPE_PRIVATE)) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    LmsComputeNodeValue(
        pKey,
        1,
        &abPublicRoot,
        pKey.params.cbHashOutput,
    );

    if (equal.SymCryptEqual(&abPublicRoot, &pKey.abPublicRoot, pKey.params.cbHashOutput) == 0) {
        return .SYMCRYPT_HBS_PUBLIC_ROOT_MISMATCH;
    }

    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptLmskeyGenerate(
    pKey: PSYMCRYPT_LMS_KEY,
    flags: UINT32,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;

    macros.CHECK_MAGIC(pKey);

    if (flags != 0) {
        scError = .SYMCRYPT_INVALID_ARGUMENT;
    } else {
        pKey.nNextUnusedLeaf = 0;

        scError = SymCryptCallbackRandom(&pKey.abId, SYMCRYPT_LMS_KEY_PAIR_IDENTIFIER_SIZE);
        if (scError == .SYMCRYPT_NO_ERROR) {
            scError = SymCryptCallbackRandom(&pKey.abSeed, pKey.params.cbHashOutput);
        }
        if (scError == .SYMCRYPT_NO_ERROR) {
            LmsComputeNodeValue(
                pKey,
                1,
                &pKey.abPublicRoot,
                pKey.params.cbHashOutput,
            );
            pKey.keyType = @backingInt(SYMCRYPT_LMSKEY_TYPE.SYMCRYPT_LMSKEY_TYPE_PRIVATE);
        }
    }

    if (scError != .SYMCRYPT_NO_ERROR) {
        LmskeyWipe(pKey);
    }
    return scError;
}

pub export fn SymCryptLmskeyGetValue(
    pKey: PCSYMCRYPT_LMS_KEY,
    keyType: SYMCRYPT_LMSKEY_TYPE,
    flags: UINT32,
    pbBlobInit: PBYTE,
    cbBlob: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    const cbHashOutput: SIZE_T = pKey.params.cbHashOutput;
    var cbKey: SIZE_T = 0;
    var pbBlob: PBYTE = pbBlobInit;

    macros.CHECK_MAGIC(pKey);

    if (flags != 0 or
        (keyType != .SYMCRYPT_LMSKEY_TYPE_PRIVATE and
            keyType != .SYMCRYPT_LMSKEY_TYPE_PUBLIC))
    {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    if (keyType == .SYMCRYPT_LMSKEY_TYPE_PRIVATE and
        pKey.keyType == @backingInt(SYMCRYPT_LMSKEY_TYPE.SYMCRYPT_LMSKEY_TYPE_PUBLIC))
    {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    _ = SymCryptLmsSizeofKeyBlobFromParams(&pKey.params, keyType, &cbKey);
    if (cbBlob != cbKey) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    macros.STORE_MSBFIRST32(pbBlob, pKey.params.lmsAlgID);
    pbBlob += @sizeOf(UINT32);

    macros.STORE_MSBFIRST32(pbBlob, pKey.params.lmsOtsAlgID);
    pbBlob += @sizeOf(UINT32);

    @memcpy(pbBlob[0..SYMCRYPT_LMS_KEY_PAIR_IDENTIFIER_SIZE], pKey.abId[0..SYMCRYPT_LMS_KEY_PAIR_IDENTIFIER_SIZE]);
    pbBlob += SYMCRYPT_LMS_KEY_PAIR_IDENTIFIER_SIZE;

    @memcpy(pbBlob[0..cbHashOutput], pKey.abPublicRoot[0..cbHashOutput]);
    pbBlob += cbHashOutput;

    if (keyType == .SYMCRYPT_LMSKEY_TYPE_PRIVATE) {
        macros.ASSERT((pKey.nNextUnusedLeaf & 0xFFFFFFFF00000000) == 0);

        macros.STORE_MSBFIRST32(pbBlob, @truncate(pKey.nNextUnusedLeaf));
        pbBlob += @sizeOf(UINT32);

        @memcpy(pbBlob[0..cbHashOutput], pKey.abSeed[0..cbHashOutput]);
    }

    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptLmskeySetValue(
    pbBlobInit: PCBYTE,
    cbBlob: SIZE_T,
    keyType: SYMCRYPT_LMSKEY_TYPE,
    flags: UINT32,
    pKey: PSYMCRYPT_LMS_KEY,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;
    var cbKey: SIZE_T = 0;
    var pbBlob: PCBYTE = pbBlobInit;

    macros.ASSERT(keyType == .SYMCRYPT_LMSKEY_TYPE_PUBLIC or keyType == .SYMCRYPT_LMSKEY_TYPE_PRIVATE);

    macros.CHECK_MAGIC(pKey);

    if ((flags & (~SYMCRYPT_FLAG_LMSKEY_VERIFY_ROOT)) != 0) {
        scError = .SYMCRYPT_INVALID_ARGUMENT;
    } else if ((flags & SYMCRYPT_FLAG_LMSKEY_VERIFY_ROOT) != 0 and
        keyType != .SYMCRYPT_LMSKEY_TYPE_PRIVATE)
    {
        scError = .SYMCRYPT_INVALID_ARGUMENT;
    } else {
        _ = SymCryptLmsSizeofKeyBlobFromParams(&pKey.params, keyType, &cbKey);
        if (cbBlob != cbKey) {
            scError = .SYMCRYPT_INVALID_ARGUMENT;
        } else {
            const lmsAlgID: UINT32 = macros.LOAD_MSBFIRST32(pbBlob);
            pbBlob += @sizeOf(UINT32);

            const lmsOtsAlgID: UINT32 = macros.LOAD_MSBFIRST32(pbBlob);
            pbBlob += @sizeOf(UINT32);

            if (lmsAlgID != pKey.params.lmsAlgID or lmsOtsAlgID != pKey.params.lmsOtsAlgID) {
                scError = .SYMCRYPT_INVALID_BLOB;
            } else {
                const cbHashOutput: SIZE_T = pKey.params.cbHashOutput;
                hash.SymCryptWipeKnownSize(@ptrCast(&pKey.abPublicRoot), @sizeOf(@TypeOf(pKey.abPublicRoot)));
                hash.SymCryptWipeKnownSize(@ptrCast(&pKey.abId), @sizeOf(@TypeOf(pKey.abId)));

                pKey.keyType = @backingInt(keyType);

                @memcpy(pKey.abId[0..SYMCRYPT_LMS_KEY_PAIR_IDENTIFIER_SIZE], pbBlob[0..SYMCRYPT_LMS_KEY_PAIR_IDENTIFIER_SIZE]);
                pbBlob += SYMCRYPT_LMS_KEY_PAIR_IDENTIFIER_SIZE;

                @memcpy(pKey.abPublicRoot[0..cbHashOutput], pbBlob[0..cbHashOutput]);
                pbBlob += cbHashOutput;

                if (keyType == .SYMCRYPT_LMSKEY_TYPE_PRIVATE) {
                    pKey.nNextUnusedLeaf = 0;
                    hash.SymCryptWipeKnownSize(@ptrCast(&pKey.abSeed), @sizeOf(@TypeOf(pKey.abSeed)));

                    pKey.nNextUnusedLeaf = macros.LOAD_MSBFIRST32(pbBlob);
                    pbBlob += @sizeOf(UINT32);

                    @memcpy(pKey.abSeed[0..cbHashOutput], pbBlob[0..cbHashOutput]);

                    if ((flags & SYMCRYPT_FLAG_LMSKEY_VERIFY_ROOT) != 0) {
                        scError = SymCryptLmskeyVerifyRoot(pKey);
                    }
                }
            }
        }
    }

    if (scError != .SYMCRYPT_NO_ERROR) {
        LmskeyWipe(pKey);
    }

    return scError;
}

pub export fn SymCryptLmsSign(
    pKey: PSYMCRYPT_LMS_KEY,
    pbMessage: PCBYTE,
    cbMessage: SIZE_T,
    flags: UINT32,
    pbSignatureInit: PBYTE,
    cbSignature: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    const cbHashOutput: SIZE_T = pKey.params.cbHashOutput;
    const nTreeHeight: UINT32 = pKey.params.nTreeHeight;
    var cbRemainingBytes: SIZE_T = cbSignature;
    const nLeavesCount: UINT32 = @as(UINT32, 1) << @intCast(nTreeHeight);
    const cbOtsSignature: SIZE_T = LmsOtsSizeofSignatureFromParams(&pKey.params);
    var abLMSRandomizer: [SYMCRYPT_LMS_MAX_N]BYTE = @splat(0);
    var pbSignature: PBYTE = pbSignatureInit;

    macros.CHECK_MAGIC(pKey);

    if (flags != 0) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    if (pKey.keyType != @backingInt(SYMCRYPT_LMSKEY_TYPE.SYMCRYPT_LMSKEY_TYPE_PRIVATE)) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    if (cbSignature != SymCryptLmsSizeofSignatureFromParams(&pKey.params)) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    const scError = SymCryptCallbackRandom(&abLMSRandomizer, cbHashOutput);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    const prevLeaf: UINT64 = @atomicRmw(UINT64, &pKey.nNextUnusedLeaf, .Add, 1, .monotonic);
    const nLeafNumber: UINT32 = @truncate(prevLeaf);
    if (prevLeaf >= nLeavesCount or nLeafNumber >= nLeavesCount) {
        pKey.nNextUnusedLeaf = nLeavesCount;
        return .SYMCRYPT_HBS_NO_OTS_KEYS_LEFT;
    }

    macros.STORE_MSBFIRST32(pbSignature, nLeafNumber);
    pbSignature += @sizeOf(UINT32);
    cbRemainingBytes -= @sizeOf(UINT32);

    LmsOtskeySign(
        pKey,
        nLeafNumber,
        pbMessage,
        cbMessage,
        &abLMSRandomizer,
        pbSignature,
        cbOtsSignature,
    );
    pbSignature += cbOtsSignature;
    cbRemainingBytes -= cbOtsSignature;

    macros.STORE_MSBFIRST32(pbSignature, pKey.params.lmsAlgID);
    pbSignature += @sizeOf(UINT32);
    cbRemainingBytes -= @sizeOf(UINT32);

    const nNodeIndex: UINT32 = nLeavesCount + nLeafNumber;
    var nIndex: UINT32 = 0;
    while (nIndex < nTreeHeight) : (nIndex += 1) {
        const nTemp: UINT32 = (nNodeIndex >> @intCast(nIndex)) ^ 1;
        LmsComputeNodeValue(
            pKey,
            nTemp,
            pbSignature,
            cbHashOutput,
        );
        pbSignature += cbHashOutput;
        cbRemainingBytes -= cbHashOutput;
    }
    macros.ASSERT(cbRemainingBytes == 0);

    return .SYMCRYPT_NO_ERROR;
}

fn LmsComputeOtsPubKeyCandidate(
    nLeafNumber: UINT32,
    pbMessage: PCBYTE,
    cbMessage: SIZE_T,
    pbOtsSignatureInit: PCBYTE,
    cbOtsSignature: SIZE_T,
    pbId: PCBYTE,
    pSigParams: PCSYMCRYPT_LMS_PARAMS,
    pbOtsPubKeyCandidate: PBYTE,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    const cbHashOutput: SIZE_T = pSigParams.cbHashOutput;
    const nWinternitzChainWidth: UINT32 = pSigParams.nWinternitzChainWidth;
    const nByteStringCount: UINT32 = pSigParams.nByteStringCount;
    const nMaxJ: UINT32 = (@as(UINT32, 1) << @intCast(nWinternitzChainWidth)) - 1;
    const pHash: PCSYMCRYPT_HASH = pSigParams.pLmsHashFunction.?;
    var state: SYMCRYPT_HASH_STATE = std.mem.zeroes(SYMCRYPT_HASH_STATE);
    var stateKc: SYMCRYPT_HASH_STATE = std.mem.zeroes(SYMCRYPT_HASH_STATE);
    var en32LeafNumber: [4]BYTE = @splat(0);
    var en16Index: [2]BYTE = @splat(0);
    var abLmsHashedMsg: [SYMCRYPT_LMS_MAX_N + @sizeOf(UINT16)]BYTE = @splat(0);
    var abTmpRes: [SYMCRYPT_LMS_MAX_N]BYTE = @splat(0);
    var pbOtsSignature: PCBYTE = pbOtsSignatureInit;

    if (cbOtsSignature != LmsOtsSizeofSignatureFromParams(pSigParams)) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    const nSigType: UINT32 = macros.LOAD_MSBFIRST32(pbOtsSignature);
    pbOtsSignature += @sizeOf(UINT32);
    if (nSigType != pSigParams.lmsOtsAlgID) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    const pbRandomizer: PCBYTE = pbOtsSignature;
    pbOtsSignature += cbHashOutput;

    macros.STORE_MSBFIRST32(&en32LeafNumber, nLeafNumber);

    LmsHashMessage(pHash, pbId, &en32LeafNumber, pbRandomizer, cbHashOutput, pbMessage, cbMessage, &abLmsHashedMsg, cbHashOutput);
    const nCksm: UINT16 = LmsOtsCalculateChecksum(&abLmsHashedMsg, pSigParams.cbHashOutput, nWinternitzChainWidth, pSigParams.nChecksumLShiftBits);
    macros.STORE_MSBFIRST16(@as(PBYTE, @ptrCast(&abLmsHashedMsg)) + cbHashOutput, nCksm);

    hash.SymCryptHashInit(pHash, @ptrCast(&stateKc));
    hash.SymCryptHashAppend(pHash, @ptrCast(&stateKc), pbId, SYMCRYPT_LMS_KEY_PAIR_IDENTIFIER_SIZE);
    hash.SymCryptHashAppend(pHash, @ptrCast(&stateKc), &en32LeafNumber, @sizeOf(UINT32));
    hash.SymCryptHashAppend(pHash, @ptrCast(&stateKc), &SYMCRYPT_LMS_D_PBLC, SYMCRYPT_LMS_D_PBLC.len);

    hash.SymCryptHashInit(pHash, @ptrCast(&state));
    var i: UINT32 = 0;
    while (i < nByteStringCount) : (i += 1) {
        const a: UINT32 = xmss.SymCryptHbsGetDigit(nWinternitzChainWidth, &abLmsHashedMsg, cbHashOutput + @sizeOf(UINT16), i);
        var tmp: PCBYTE = pbOtsSignature + (@as(SIZE_T, i) * cbHashOutput);

        macros.STORE_MSBFIRST16(&en16Index, @truncate(i));

        var j: UINT32 = a;
        while (j < nMaxJ) : (j += 1) {
            const bJ: BYTE = @truncate(j);

            hash.SymCryptHashAppend(pHash, @ptrCast(&state), pbId, SYMCRYPT_LMS_KEY_PAIR_IDENTIFIER_SIZE);
            hash.SymCryptHashAppend(pHash, @ptrCast(&state), &en32LeafNumber, @sizeOf(UINT32));
            hash.SymCryptHashAppend(pHash, @ptrCast(&state), &en16Index, @sizeOf(UINT16));
            hash.SymCryptHashAppend(pHash, @ptrCast(&state), @ptrCast(&bJ), @sizeOf(BYTE));
            hash.SymCryptHashAppend(pHash, @ptrCast(&state), tmp, cbHashOutput);
            hash.SymCryptHashResult(pHash, @ptrCast(&state), &abTmpRes, cbHashOutput);
            tmp = &abTmpRes;
        }
        hash.SymCryptHashAppend(pHash, @ptrCast(&stateKc), tmp, cbHashOutput);
    }
    hash.SymCryptHashResult(pHash, @ptrCast(&stateKc), pbOtsPubKeyCandidate, cbHashOutput);

    return .SYMCRYPT_NO_ERROR;
}

fn LmsComputeRootCandidate(
    nLeafNumber: UINT32,
    pParams: PCSYMCRYPT_LMS_PARAMS,
    pbId: PCBYTE,
    pbPath: PCBYTE,
    pbPubKeyCandidate: PCBYTE,
    pbRootCandidate: PBYTE,
) callconv(SYMCRYPT_CALL) void {
    const pHash: PCSYMCRYPT_HASH = pParams.pLmsHashFunction.?;
    var state: SYMCRYPT_HASH_STATE = std.mem.zeroes(SYMCRYPT_HASH_STATE);
    const cbHashOutput: SIZE_T = pParams.cbHashOutput;
    var nNodeNum: UINT32 = (@as(UINT32, 1) << @intCast(pParams.nTreeHeight)) + nLeafNumber;
    const pbTemp: PBYTE = pbRootCandidate;
    var en32NodeNum: [4]BYTE = @splat(0);

    macros.STORE_MSBFIRST32(&en32NodeNum, nNodeNum);
    hash.SymCryptHashInit(pHash, @ptrCast(&state));
    hash.SymCryptHashAppend(pHash, @ptrCast(&state), pbId, SYMCRYPT_LMS_KEY_PAIR_IDENTIFIER_SIZE);
    hash.SymCryptHashAppend(pHash, @ptrCast(&state), &en32NodeNum, @sizeOf(UINT32));
    hash.SymCryptHashAppend(pHash, @ptrCast(&state), &SYMCRYPT_LMS_D_LEAF, SYMCRYPT_LMS_D_LEAF.len);
    hash.SymCryptHashAppend(pHash, @ptrCast(&state), pbPubKeyCandidate, cbHashOutput);
    hash.SymCryptHashResult(pHash, @ptrCast(&state), pbTemp, cbHashOutput);

    var nIndex: UINT32 = 0;
    while (nIndex < pParams.nTreeHeight) : (nIndex += 1) {
        macros.STORE_MSBFIRST32(&en32NodeNum, nNodeNum / 2);
        hash.SymCryptHashAppend(pHash, @ptrCast(&state), pbId, SYMCRYPT_LMS_KEY_PAIR_IDENTIFIER_SIZE);
        hash.SymCryptHashAppend(pHash, @ptrCast(&state), &en32NodeNum, @sizeOf(UINT32));
        hash.SymCryptHashAppend(pHash, @ptrCast(&state), &SYMCRYPT_LMS_D_INTR, SYMCRYPT_LMS_D_INTR.len);
        const pathNodePtr: PCBYTE = pbPath + (cbHashOutput * @as(SIZE_T, nIndex));
        if ((nNodeNum % 2) != 0) {
            hash.SymCryptHashAppend(pHash, @ptrCast(&state), pathNodePtr, cbHashOutput);
            hash.SymCryptHashAppend(pHash, @ptrCast(&state), pbTemp, cbHashOutput);
        } else {
            hash.SymCryptHashAppend(pHash, @ptrCast(&state), pbTemp, cbHashOutput);
            hash.SymCryptHashAppend(pHash, @ptrCast(&state), pathNodePtr, cbHashOutput);
        }
        hash.SymCryptHashResult(pHash, @ptrCast(&state), pbTemp, cbHashOutput);
        nNodeNum /= 2;
    }
    macros.ASSERT(nNodeNum <= 1);
}

pub export fn SymCryptLmsVerifyInternal(
    pKey: PCSYMCRYPT_LMS_KEY,
    pbMessage: PCBYTE,
    cbMessage: SIZE_T,
    flags: UINT32,
    pbSignature: PCBYTE,
    cbSignature: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    macros.ASSERT(pKey.keyType != @backingInt(SYMCRYPT_LMSKEY_TYPE.SYMCRYPT_LMSKEY_TYPE_NONE));
    macros.CHECK_MAGIC(pKey);

    const cbHashOutput: SIZE_T = pKey.params.cbHashOutput;
    const pLmsKeyParams: PCSYMCRYPT_LMS_PARAMS = &pKey.params;
    var pbLocSignature: PCBYTE = pbSignature;
    var abRootCandidate: [SYMCRYPT_LMS_MAX_N]BYTE = @splat(0);
    var abOtsPubKeyCandidate: [SYMCRYPT_LMS_MAX_N]BYTE = @splat(0);

    if (flags != 0) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    if (cbSignature != SymCryptLmsSizeofSignatureFromParams(&pKey.params)) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    const nLeafNumber: UINT32 = macros.LOAD_MSBFIRST32(pbLocSignature);
    pbLocSignature += @sizeOf(UINT32);
    if (nLeafNumber >= (@as(UINT32, 1) << @intCast(pKey.params.nTreeHeight))) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    const nOtsSigtype: UINT32 = macros.LOAD_MSBFIRST32(pbLocSignature);
    pbLocSignature += @sizeOf(UINT32);

    if (nOtsSigtype != pLmsKeyParams.lmsOtsAlgID) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    pbLocSignature += cbHashOutput * (@as(SIZE_T, pKey.params.nByteStringCount) + 1);
    const nSigType: UINT32 = macros.LOAD_MSBFIRST32(pbLocSignature);
    pbLocSignature += @sizeOf(UINT32);

    if (nSigType != pLmsKeyParams.lmsAlgID) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    const scError = LmsComputeOtsPubKeyCandidate(
        nLeafNumber,
        pbMessage,
        cbMessage,
        pbSignature + @sizeOf(UINT32),
        LmsOtsSizeofSignatureFromParams(&pKey.params),
        &pKey.abId,
        pLmsKeyParams,
        &abOtsPubKeyCandidate,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    LmsComputeRootCandidate(
        nLeafNumber,
        pLmsKeyParams,
        &pKey.abId,
        pbLocSignature,
        &abOtsPubKeyCandidate,
        &abRootCandidate,
    );
    if (equal.SymCryptEqual(&abRootCandidate, &pKey.abPublicRoot, cbHashOutput) == 0) {
        return .SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE;
    }

    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptLmsVerify(
    pKey: PCSYMCRYPT_LMS_KEY,
    pbMessage: PCBYTE,
    cbMessage: SIZE_T,
    flags: UINT32,
    pbSignature: PCBYTE,
    cbSignature: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    if ((@atomicLoad(UINT32, &g_SymCryptFipsSelftestsPerformed, .unordered) & SYMCRYPT_SELFTEST_ALGORITHM_LMS) == 0) {
        SymCryptLmsSelftest();
        _ = @atomicRmw(UINT32, &g_SymCryptFipsSelftestsPerformed, .Or, SYMCRYPT_SELFTEST_ALGORITHM_LMS, .monotonic);
    }

    return SymCryptLmsVerifyInternal(
        pKey,
        pbMessage,
        cbMessage,
        flags,
        pbSignature,
        cbSignature,
    );
}

comptime {
    std.debug.assert(@alignOf(SYMCRYPT_LMS_PARAMS) == SYMCRYPT_ALIGN_VALUE);
    std.debug.assert(@alignOf(SYMCRYPT_LMS_KEY) == SYMCRYPT_ASYM_ALIGN_VALUE);
}
