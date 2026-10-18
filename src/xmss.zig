//
// xmss.zig
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
// XMSS and XMSS^MT implementation ported from lib/xmss.c.
//

const std = @import("std");
const types = @import("types.zig");
const macros = @import("macros.zig");
const equal = @import("equal.zig");
const hash = @import("hash.zig");
const sha256 = @import("sha256.zig");
const sha512 = @import("sha512.zig");
const shake = @import("shake.zig");

const BYTE = types.BYTE;
const PBYTE = types.PBYTE;
const PCBYTE = types.PCBYTE;
const UINT8 = types.UINT8;
const UINT32 = types.UINT32;
const PUINT32 = types.PUINT32;
const UINT64 = types.UINT64;
const SIZE_T = types.SIZE_T;
const BOOLEAN = types.BOOLEAN;
const PVOID = types.PVOID;
const TRUE = types.TRUE;
const FALSE = types.FALSE;
const SYMCRYPT_ERROR = types.SYMCRYPT_ERROR;
const PCSYMCRYPT_HASH = types.PCSYMCRYPT_HASH;
const SYMCRYPT_CALL = types.SYMCRYPT_CALL;
const SYMCRYPT_ALIGN_VALUE = types.SYMCRYPT_ALIGN_VALUE;
const SYMCRYPT_ASYM_ALIGN_VALUE = types.SYMCRYPT_ASYM_ALIGN_VALUE;
const SYMCRYPT_HASH_MAX_RESULT_SIZE = hash.SYMCRYPT_HASH_MAX_RESULT_SIZE;
const SYMCRYPT_HASH_STATE = hash.SYMCRYPT_HASH_STATE;
const PSYMCRYPT_HASH_STATE = hash.PSYMCRYPT_HASH_STATE;

// ==============================================================================================
// External C Callbacks & FIPS Self-Test Declarations
// ==============================================================================================

pub extern fn SymCryptCallbackAlloc(cbData: SIZE_T) callconv(SYMCRYPT_CALL) ?PBYTE;
pub extern fn SymCryptCallbackFree(pbData: PVOID) callconv(SYMCRYPT_CALL) void;
pub extern fn SymCryptCallbackRandom(pbBuffer: PBYTE, cbBuffer: SIZE_T) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;
pub extern fn SymCryptXmssSelftest() callconv(SYMCRYPT_CALL) void;
pub extern var g_SymCryptFipsSelftestsPerformed: UINT32;

pub const SYMCRYPT_SELFTEST_ALGORITHM_XMSS: UINT32 = 0x80;

// ==============================================================================================
// Constants, Enums, and Structures
// ==============================================================================================

// Maximum size of the domain separator prefix used in PRFs
pub const SYMCRYPT_XMSS_MAX_PREFIX_SIZE: usize = SYMCRYPT_HASH_MAX_RESULT_SIZE;

// PRF domain separators
pub const SYMCRYPT_XMSS_F: BYTE = 0x00;
pub const SYMCRYPT_XMSS_H: BYTE = 0x01;
pub const SYMCRYPT_XMSS_H_MSG: BYTE = 0x02;
pub const SYMCRYPT_XMSS_PRF: BYTE = 0x03;
pub const SYMCRYPT_XMSS_PRF_KEYGEN: BYTE = 0x04;

pub const SYMCRYPT_FLAG_XMSSKEY_VERIFY_ROOT: UINT32 = 0x00000001;

pub const SYMCRYPT_XMSS_ALGID = enum(UINT32) {
    SYMCRYPT_XMSS_SHA2_10_256 = 0x00000001,
    SYMCRYPT_XMSS_SHA2_16_256 = 0x00000002,
    SYMCRYPT_XMSS_SHA2_20_256 = 0x00000003,
    SYMCRYPT_XMSS_SHA2_10_512 = 0x00000004,
    SYMCRYPT_XMSS_SHA2_16_512 = 0x00000005,
    SYMCRYPT_XMSS_SHA2_20_512 = 0x00000006,
    SYMCRYPT_XMSS_SHAKE_10_256 = 0x00000007,
    SYMCRYPT_XMSS_SHAKE_16_256 = 0x00000008,
    SYMCRYPT_XMSS_SHAKE_20_256 = 0x00000009,
    SYMCRYPT_XMSS_SHAKE_10_512 = 0x0000000A,
    SYMCRYPT_XMSS_SHAKE_16_512 = 0x0000000B,
    SYMCRYPT_XMSS_SHAKE_20_512 = 0x0000000C,
    SYMCRYPT_XMSS_SHA2_10_192 = 0x0000000D,
    SYMCRYPT_XMSS_SHA2_16_192 = 0x0000000E,
    SYMCRYPT_XMSS_SHA2_20_192 = 0x0000000F,
    SYMCRYPT_XMSS_SHAKE256_10_256 = 0x00000010,
    SYMCRYPT_XMSS_SHAKE256_16_256 = 0x00000011,
    SYMCRYPT_XMSS_SHAKE256_20_256 = 0x00000012,
    SYMCRYPT_XMSS_SHAKE256_10_192 = 0x00000013,
    SYMCRYPT_XMSS_SHAKE256_16_192 = 0x00000014,
    SYMCRYPT_XMSS_SHAKE256_20_192 = 0x00000015,
    _,
};

pub const SYMCRYPT_XMSSMT_ALGID = enum(UINT32) {
    SYMCRYPT_XMSSMT_SHA2_20_2_256 = 0x00000001,
    SYMCRYPT_XMSSMT_SHA2_20_4_256 = 0x00000002,
    SYMCRYPT_XMSSMT_SHA2_40_2_256 = 0x00000003,
    SYMCRYPT_XMSSMT_SHA2_40_4_256 = 0x00000004,
    SYMCRYPT_XMSSMT_SHA2_40_8_256 = 0x00000005,
    SYMCRYPT_XMSSMT_SHA2_60_3_256 = 0x00000006,
    SYMCRYPT_XMSSMT_SHA2_60_6_256 = 0x00000007,
    SYMCRYPT_XMSSMT_SHA2_60_12_256 = 0x00000008,

    SYMCRYPT_XMSSMT_SHA2_20_2_512 = 0x00000009,
    SYMCRYPT_XMSSMT_SHA2_20_4_512 = 0x0000000A,
    SYMCRYPT_XMSSMT_SHA2_40_2_512 = 0x0000000B,
    SYMCRYPT_XMSSMT_SHA2_40_4_512 = 0x0000000C,
    SYMCRYPT_XMSSMT_SHA2_40_8_512 = 0x0000000D,
    SYMCRYPT_XMSSMT_SHA2_60_3_512 = 0x0000000E,
    SYMCRYPT_XMSSMT_SHA2_60_6_512 = 0x0000000F,
    SYMCRYPT_XMSSMT_SHA2_60_12_512 = 0x00000010,

    SYMCRYPT_XMSSMT_SHAKE_20_2_256 = 0x00000011,
    SYMCRYPT_XMSSMT_SHAKE_20_4_256 = 0x00000012,
    SYMCRYPT_XMSSMT_SHAKE_40_2_256 = 0x00000013,
    SYMCRYPT_XMSSMT_SHAKE_40_4_256 = 0x00000014,
    SYMCRYPT_XMSSMT_SHAKE_40_8_256 = 0x00000015,
    SYMCRYPT_XMSSMT_SHAKE_60_3_256 = 0x00000016,
    SYMCRYPT_XMSSMT_SHAKE_60_6_256 = 0x00000017,
    SYMCRYPT_XMSSMT_SHAKE_60_12_256 = 0x00000018,

    SYMCRYPT_XMSSMT_SHAKE_20_2_512 = 0x00000019,
    SYMCRYPT_XMSSMT_SHAKE_20_4_512 = 0x0000001A,
    SYMCRYPT_XMSSMT_SHAKE_40_2_512 = 0x0000001B,
    SYMCRYPT_XMSSMT_SHAKE_40_4_512 = 0x0000001C,
    SYMCRYPT_XMSSMT_SHAKE_40_8_512 = 0x0000001D,
    SYMCRYPT_XMSSMT_SHAKE_60_3_512 = 0x0000001E,
    SYMCRYPT_XMSSMT_SHAKE_60_6_512 = 0x0000001F,
    SYMCRYPT_XMSSMT_SHAKE_60_12_512 = 0x00000020,

    SYMCRYPT_XMSSMT_SHA2_20_2_192 = 0x00000021,
    SYMCRYPT_XMSSMT_SHA2_20_4_192 = 0x00000022,
    SYMCRYPT_XMSSMT_SHA2_40_2_192 = 0x00000023,
    SYMCRYPT_XMSSMT_SHA2_40_4_192 = 0x00000024,
    SYMCRYPT_XMSSMT_SHA2_40_8_192 = 0x00000025,
    SYMCRYPT_XMSSMT_SHA2_60_3_192 = 0x00000026,
    SYMCRYPT_XMSSMT_SHA2_60_6_192 = 0x00000027,
    SYMCRYPT_XMSSMT_SHA2_60_12_192 = 0x00000028,

    SYMCRYPT_XMSSMT_SHAKE256_20_2_256 = 0x00000029,
    SYMCRYPT_XMSSMT_SHAKE256_20_4_256 = 0x0000002A,
    SYMCRYPT_XMSSMT_SHAKE256_40_2_256 = 0x0000002B,
    SYMCRYPT_XMSSMT_SHAKE256_40_4_256 = 0x0000002C,
    SYMCRYPT_XMSSMT_SHAKE256_40_8_256 = 0x0000002D,
    SYMCRYPT_XMSSMT_SHAKE256_60_3_256 = 0x0000002E,
    SYMCRYPT_XMSSMT_SHAKE256_60_6_256 = 0x0000002F,
    SYMCRYPT_XMSSMT_SHAKE256_60_12_256 = 0x00000030,

    SYMCRYPT_XMSSMT_SHAKE256_20_2_192 = 0x00000031,
    SYMCRYPT_XMSSMT_SHAKE256_20_4_192 = 0x00000032,
    SYMCRYPT_XMSSMT_SHAKE256_40_2_192 = 0x00000033,
    SYMCRYPT_XMSSMT_SHAKE256_40_4_192 = 0x00000034,
    SYMCRYPT_XMSSMT_SHAKE256_40_8_192 = 0x00000035,
    SYMCRYPT_XMSSMT_SHAKE256_60_3_192 = 0x00000036,
    SYMCRYPT_XMSSMT_SHAKE256_60_6_192 = 0x00000037,
    SYMCRYPT_XMSSMT_SHAKE256_60_12_192 = 0x00000038,
    _,
};

pub const SYMCRYPT_XMSSKEY_TYPE = enum(UINT32) {
    SYMCRYPT_XMSSKEY_TYPE_NONE = 0,
    SYMCRYPT_XMSSKEY_TYPE_PUBLIC = 1,
    SYMCRYPT_XMSSKEY_TYPE_PRIVATE = 2,
    _,
};

pub const SYMCRYPT_XMSS_WOTSP_ALGID = enum(UINT32) {
    SYMCRYPT_XMSS_WOTSP_SHA2_256 = 0x00000001,
    SYMCRYPT_XMSS_WOTSP_SHA2_512 = 0x00000002,
    SYMCRYPT_XMSS_WOTSP_SHAKE_256 = 0x00000003,
    SYMCRYPT_XMSS_WOTSP_SHAKE_512 = 0x00000004,
    SYMCRYPT_XMSS_WOTSP_SHA2_192 = 0x00000005,
    SYMCRYPT_XMSS_WOTSP_SHAKE256_256 = 0x00000006,
    SYMCRYPT_XMSS_WOTSP_SHAKE256_192 = 0x00000007,
    _,
};

pub const SYMCRYPT_XMSS_PARAMS = extern struct {
    hash: ?PCSYMCRYPT_HASH align(SYMCRYPT_ALIGN_VALUE),
    id: UINT32,
    cbHashOutput: UINT32,
    nWinternitzWidth: UINT32,
    nTotalTreeHeight: UINT32,
    nLayers: UINT32,
    cbPrefix: UINT32,
    len1: UINT32,
    len2: UINT32,
    len: UINT32,
    nLayerHeight: UINT32,
    cbIdx: UINT32,
    nLeftShift32: UINT32,
    Reserved: [16]BYTE,
};
pub const PSYMCRYPT_XMSS_PARAMS = *SYMCRYPT_XMSS_PARAMS;
pub const PCSYMCRYPT_XMSS_PARAMS = *const SYMCRYPT_XMSS_PARAMS;

pub const SYMCRYPT_XMSS_KEY = extern struct {
    version: UINT32 align(SYMCRYPT_ASYM_ALIGN_VALUE),
    params: SYMCRYPT_XMSS_PARAMS,
    keyType: SYMCRYPT_XMSSKEY_TYPE,
    Root: [SYMCRYPT_HASH_MAX_RESULT_SIZE]BYTE,
    Seed: [SYMCRYPT_HASH_MAX_RESULT_SIZE]BYTE,
    magic: SIZE_T,
    Idx: UINT64 align(16),
    SkXmss: [SYMCRYPT_HASH_MAX_RESULT_SIZE]BYTE,
    SkPrf: [SYMCRYPT_HASH_MAX_RESULT_SIZE]BYTE,
};
pub const PSYMCRYPT_XMSS_KEY = *SYMCRYPT_XMSS_KEY;
pub const PCSYMCRYPT_XMSS_KEY = *const SYMCRYPT_XMSS_KEY;

pub const XMSS_ADRS_TYPE_OTS: UINT32 = 0;
pub const XMSS_ADRS_TYPE_LTREE: UINT32 = 1;
pub const XMSS_ADRS_TYPE_HASH_TREE: UINT32 = 2;

pub const XMSS_OTS_ADDRESS = extern struct {
    en32Leaf: [4]BYTE,
    en32Chain: [4]BYTE,
    en32Hash: [4]BYTE,
};

pub const XMSS_LTREE_ADDRESS = extern struct {
    en32Leaf: [4]BYTE,
    en32Height: [4]BYTE,
    en32Index: [4]BYTE,
};

pub const XMSS_HASHTREE_ADDRESS = extern struct {
    padding: [4]BYTE,
    en32Height: [4]BYTE,
    en32Index: [4]BYTE,
};

pub const XMSS_ADRS_UNION = extern union {
    ots: XMSS_OTS_ADDRESS,
    ltree: XMSS_LTREE_ADDRESS,
    hashtree: XMSS_HASHTREE_ADDRESS,
};

pub const XMSS_ADRS = extern struct {
    en32Layer: [4]BYTE,
    en64Tree: [8]BYTE,
    en32Type: [4]BYTE,
    u: XMSS_ADRS_UNION,
    en32KeyAndMask: [4]BYTE,
};
pub const PXMSS_ADRS = *XMSS_ADRS;

pub const SYMCRYPT_TREEHASH_NODE = extern struct {
    index: UINT32,
    height: UINT32,
    value: [1]BYTE,
};
pub const PSYMCRYPT_TREEHASH_NODE = *align(1) SYMCRYPT_TREEHASH_NODE;

pub const SYMCRYPT_XMSS_INCREMENTAL_TREEHASH_CONTEXT = extern struct {
    pParams: PCSYMCRYPT_XMSS_PARAMS,
    pbSeed: PCBYTE,
    adrs: XMSS_ADRS,
};
pub const PSYMCRYPT_XMSS_INCREMENTAL_TREEHASH_CONTEXT = *SYMCRYPT_XMSS_INCREMENTAL_TREEHASH_CONTEXT;

pub const PSYMCRYPT_INCREMENTAL_TREEHASH_FUNC = *const fn (
    pNodeLeft: PSYMCRYPT_TREEHASH_NODE,
    pNodeRight: PSYMCRYPT_TREEHASH_NODE,
    pNodeOut: PSYMCRYPT_TREEHASH_NODE,
    pContext: PSYMCRYPT_XMSS_INCREMENTAL_TREEHASH_CONTEXT,
) callconv(SYMCRYPT_CALL) void;

pub const SYMCRYPT_INCREMENTAL_TREEHASH = extern struct {
    cbNode: UINT32,
    nSize: UINT32,
    nCapacity: UINT32,
    nLastLeafIndex: UINT32,
    funcCompressNodes: PSYMCRYPT_INCREMENTAL_TREEHASH_FUNC,
    pContext: PSYMCRYPT_XMSS_INCREMENTAL_TREEHASH_CONTEXT,
    arrNodes: [1]SYMCRYPT_TREEHASH_NODE,
};
pub const PSYMCRYPT_INCREMENTAL_TREEHASH = *align(1) SYMCRYPT_INCREMENTAL_TREEHASH;

inline fn nodeValue(pNode: PSYMCRYPT_TREEHASH_NODE) PBYTE {
    return @ptrCast(&pNode.value);
}

// ==============================================================================================
// Predefined Parameter Tables
// ==============================================================================================

const XmssHashArray = [4]*const PCSYMCRYPT_HASH{
    &sha256.SymCryptSha256Algorithm, // 0
    &sha512.SymCryptSha512Algorithm, // 1
    &shake.SymCryptShake128HashAlgorithm, // 2
    &shake.SymCryptShake256HashAlgorithm, // 3
};

const SYMCRYPT_XMSS_WOTSP_PARAMS = struct {
    wotspId: SYMCRYPT_XMSS_WOTSP_ALGID,
    hashIndex: UINT8,
    n: UINT8,
    w: UINT8,
    cbPrefix: UINT8,
};

const XmssWotspParams = [_]SYMCRYPT_XMSS_WOTSP_PARAMS{
    .{ .wotspId = .SYMCRYPT_XMSS_WOTSP_SHA2_256, .hashIndex = 0, .n = 32, .w = 4, .cbPrefix = 32 },
    .{ .wotspId = .SYMCRYPT_XMSS_WOTSP_SHA2_512, .hashIndex = 1, .n = 64, .w = 4, .cbPrefix = 64 },
    .{ .wotspId = .SYMCRYPT_XMSS_WOTSP_SHAKE_256, .hashIndex = 2, .n = 32, .w = 4, .cbPrefix = 32 },
    .{ .wotspId = .SYMCRYPT_XMSS_WOTSP_SHAKE_512, .hashIndex = 3, .n = 64, .w = 4, .cbPrefix = 64 },
    .{ .wotspId = .SYMCRYPT_XMSS_WOTSP_SHA2_192, .hashIndex = 0, .n = 24, .w = 4, .cbPrefix = 4 },
    .{ .wotspId = .SYMCRYPT_XMSS_WOTSP_SHAKE256_256, .hashIndex = 3, .n = 32, .w = 4, .cbPrefix = 32 },
    .{ .wotspId = .SYMCRYPT_XMSS_WOTSP_SHAKE256_192, .hashIndex = 3, .n = 24, .w = 4, .cbPrefix = 4 },
};

const SYMCRYPT_XMSS_PARAMETER_PREDEFINED = struct {
    idAlg: UINT32,
    idWotsp: SYMCRYPT_XMSS_WOTSP_ALGID,
    h: UINT8,
    d: UINT8,
};

const XmssParametersPredefined = [_]SYMCRYPT_XMSS_PARAMETER_PREDEFINED{
    .{ .idAlg = @backingInt(SYMCRYPT_XMSS_ALGID.SYMCRYPT_XMSS_SHA2_10_256), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHA2_256, .h = 10, .d = 1 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSS_ALGID.SYMCRYPT_XMSS_SHA2_16_256), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHA2_256, .h = 16, .d = 1 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSS_ALGID.SYMCRYPT_XMSS_SHA2_20_256), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHA2_256, .h = 20, .d = 1 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSS_ALGID.SYMCRYPT_XMSS_SHA2_10_512), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHA2_512, .h = 10, .d = 1 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSS_ALGID.SYMCRYPT_XMSS_SHA2_16_512), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHA2_512, .h = 16, .d = 1 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSS_ALGID.SYMCRYPT_XMSS_SHA2_20_512), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHA2_512, .h = 20, .d = 1 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSS_ALGID.SYMCRYPT_XMSS_SHAKE_10_256), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHAKE_256, .h = 10, .d = 1 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSS_ALGID.SYMCRYPT_XMSS_SHAKE_16_256), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHAKE_256, .h = 16, .d = 1 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSS_ALGID.SYMCRYPT_XMSS_SHAKE_20_256), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHAKE_256, .h = 20, .d = 1 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSS_ALGID.SYMCRYPT_XMSS_SHAKE_10_512), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHAKE_512, .h = 10, .d = 1 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSS_ALGID.SYMCRYPT_XMSS_SHAKE_16_512), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHAKE_512, .h = 16, .d = 1 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSS_ALGID.SYMCRYPT_XMSS_SHAKE_20_512), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHAKE_512, .h = 20, .d = 1 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSS_ALGID.SYMCRYPT_XMSS_SHA2_10_192), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHA2_192, .h = 10, .d = 1 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSS_ALGID.SYMCRYPT_XMSS_SHA2_16_192), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHA2_192, .h = 16, .d = 1 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSS_ALGID.SYMCRYPT_XMSS_SHA2_20_192), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHA2_192, .h = 20, .d = 1 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSS_ALGID.SYMCRYPT_XMSS_SHAKE256_10_256), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHAKE256_256, .h = 10, .d = 1 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSS_ALGID.SYMCRYPT_XMSS_SHAKE256_16_256), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHAKE256_256, .h = 16, .d = 1 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSS_ALGID.SYMCRYPT_XMSS_SHAKE256_20_256), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHAKE256_256, .h = 20, .d = 1 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSS_ALGID.SYMCRYPT_XMSS_SHAKE256_10_192), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHAKE256_192, .h = 10, .d = 1 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSS_ALGID.SYMCRYPT_XMSS_SHAKE256_16_192), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHAKE256_192, .h = 16, .d = 1 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSS_ALGID.SYMCRYPT_XMSS_SHAKE256_20_192), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHAKE256_192, .h = 20, .d = 1 },
};

const XmssMtParametersPredefined = [_]SYMCRYPT_XMSS_PARAMETER_PREDEFINED{
    .{ .idAlg = @backingInt(SYMCRYPT_XMSSMT_ALGID.SYMCRYPT_XMSSMT_SHA2_20_2_256), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHA2_256, .h = 20, .d = 2 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSSMT_ALGID.SYMCRYPT_XMSSMT_SHA2_20_4_256), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHA2_256, .h = 20, .d = 4 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSSMT_ALGID.SYMCRYPT_XMSSMT_SHA2_40_2_256), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHA2_256, .h = 40, .d = 2 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSSMT_ALGID.SYMCRYPT_XMSSMT_SHA2_40_4_256), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHA2_256, .h = 40, .d = 4 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSSMT_ALGID.SYMCRYPT_XMSSMT_SHA2_40_8_256), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHA2_256, .h = 40, .d = 8 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSSMT_ALGID.SYMCRYPT_XMSSMT_SHA2_60_3_256), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHA2_256, .h = 60, .d = 3 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSSMT_ALGID.SYMCRYPT_XMSSMT_SHA2_60_6_256), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHA2_256, .h = 60, .d = 6 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSSMT_ALGID.SYMCRYPT_XMSSMT_SHA2_60_12_256), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHA2_256, .h = 60, .d = 12 },

    .{ .idAlg = @backingInt(SYMCRYPT_XMSSMT_ALGID.SYMCRYPT_XMSSMT_SHA2_20_2_512), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHA2_512, .h = 20, .d = 2 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSSMT_ALGID.SYMCRYPT_XMSSMT_SHA2_20_4_512), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHA2_512, .h = 20, .d = 4 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSSMT_ALGID.SYMCRYPT_XMSSMT_SHA2_40_2_512), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHA2_512, .h = 40, .d = 2 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSSMT_ALGID.SYMCRYPT_XMSSMT_SHA2_40_4_512), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHA2_512, .h = 40, .d = 4 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSSMT_ALGID.SYMCRYPT_XMSSMT_SHA2_40_8_512), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHA2_512, .h = 40, .d = 8 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSSMT_ALGID.SYMCRYPT_XMSSMT_SHA2_60_3_512), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHA2_512, .h = 60, .d = 3 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSSMT_ALGID.SYMCRYPT_XMSSMT_SHA2_60_6_512), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHA2_512, .h = 60, .d = 6 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSSMT_ALGID.SYMCRYPT_XMSSMT_SHA2_60_12_512), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHA2_512, .h = 60, .d = 12 },

    .{ .idAlg = @backingInt(SYMCRYPT_XMSSMT_ALGID.SYMCRYPT_XMSSMT_SHAKE_20_2_256), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHAKE_256, .h = 20, .d = 2 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSSMT_ALGID.SYMCRYPT_XMSSMT_SHAKE_20_4_256), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHAKE_256, .h = 20, .d = 4 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSSMT_ALGID.SYMCRYPT_XMSSMT_SHAKE_40_2_256), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHAKE_256, .h = 40, .d = 2 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSSMT_ALGID.SYMCRYPT_XMSSMT_SHAKE_40_4_256), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHAKE_256, .h = 40, .d = 4 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSSMT_ALGID.SYMCRYPT_XMSSMT_SHAKE_40_8_256), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHAKE_256, .h = 40, .d = 8 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSSMT_ALGID.SYMCRYPT_XMSSMT_SHAKE_60_3_256), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHAKE_256, .h = 60, .d = 3 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSSMT_ALGID.SYMCRYPT_XMSSMT_SHAKE_60_6_256), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHAKE_256, .h = 60, .d = 6 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSSMT_ALGID.SYMCRYPT_XMSSMT_SHAKE_60_12_256), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHAKE_256, .h = 60, .d = 12 },

    .{ .idAlg = @backingInt(SYMCRYPT_XMSSMT_ALGID.SYMCRYPT_XMSSMT_SHAKE_20_2_512), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHAKE_512, .h = 20, .d = 2 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSSMT_ALGID.SYMCRYPT_XMSSMT_SHAKE_20_4_512), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHAKE_512, .h = 20, .d = 4 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSSMT_ALGID.SYMCRYPT_XMSSMT_SHAKE_40_2_512), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHAKE_512, .h = 40, .d = 2 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSSMT_ALGID.SYMCRYPT_XMSSMT_SHAKE_40_4_512), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHAKE_512, .h = 40, .d = 4 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSSMT_ALGID.SYMCRYPT_XMSSMT_SHAKE_40_8_512), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHAKE_512, .h = 40, .d = 8 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSSMT_ALGID.SYMCRYPT_XMSSMT_SHAKE_60_3_512), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHAKE_512, .h = 60, .d = 3 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSSMT_ALGID.SYMCRYPT_XMSSMT_SHAKE_60_6_512), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHAKE_512, .h = 60, .d = 6 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSSMT_ALGID.SYMCRYPT_XMSSMT_SHAKE_60_12_512), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHAKE_512, .h = 60, .d = 12 },

    .{ .idAlg = @backingInt(SYMCRYPT_XMSSMT_ALGID.SYMCRYPT_XMSSMT_SHA2_20_2_192), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHA2_192, .h = 20, .d = 2 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSSMT_ALGID.SYMCRYPT_XMSSMT_SHA2_20_4_192), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHA2_192, .h = 20, .d = 4 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSSMT_ALGID.SYMCRYPT_XMSSMT_SHA2_40_2_192), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHA2_192, .h = 40, .d = 2 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSSMT_ALGID.SYMCRYPT_XMSSMT_SHA2_40_4_192), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHA2_192, .h = 40, .d = 4 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSSMT_ALGID.SYMCRYPT_XMSSMT_SHA2_40_8_192), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHA2_192, .h = 40, .d = 8 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSSMT_ALGID.SYMCRYPT_XMSSMT_SHA2_60_3_192), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHA2_192, .h = 60, .d = 3 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSSMT_ALGID.SYMCRYPT_XMSSMT_SHA2_60_6_192), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHA2_192, .h = 60, .d = 6 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSSMT_ALGID.SYMCRYPT_XMSSMT_SHA2_60_12_192), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHA2_192, .h = 60, .d = 12 },

    .{ .idAlg = @backingInt(SYMCRYPT_XMSSMT_ALGID.SYMCRYPT_XMSSMT_SHAKE256_20_2_256), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHAKE256_256, .h = 20, .d = 2 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSSMT_ALGID.SYMCRYPT_XMSSMT_SHAKE256_20_4_256), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHAKE256_256, .h = 20, .d = 4 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSSMT_ALGID.SYMCRYPT_XMSSMT_SHAKE256_40_2_256), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHAKE256_256, .h = 40, .d = 2 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSSMT_ALGID.SYMCRYPT_XMSSMT_SHAKE256_40_4_256), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHAKE256_256, .h = 40, .d = 4 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSSMT_ALGID.SYMCRYPT_XMSSMT_SHAKE256_40_8_256), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHAKE256_256, .h = 40, .d = 8 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSSMT_ALGID.SYMCRYPT_XMSSMT_SHAKE256_60_3_256), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHAKE256_256, .h = 60, .d = 3 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSSMT_ALGID.SYMCRYPT_XMSSMT_SHAKE256_60_6_256), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHAKE256_256, .h = 60, .d = 6 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSSMT_ALGID.SYMCRYPT_XMSSMT_SHAKE256_60_12_256), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHAKE256_256, .h = 60, .d = 12 },

    .{ .idAlg = @backingInt(SYMCRYPT_XMSSMT_ALGID.SYMCRYPT_XMSSMT_SHAKE256_20_2_192), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHAKE256_192, .h = 20, .d = 2 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSSMT_ALGID.SYMCRYPT_XMSSMT_SHAKE256_20_4_192), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHAKE256_192, .h = 20, .d = 4 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSSMT_ALGID.SYMCRYPT_XMSSMT_SHAKE256_40_2_192), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHAKE256_192, .h = 40, .d = 2 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSSMT_ALGID.SYMCRYPT_XMSSMT_SHAKE256_40_4_192), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHAKE256_192, .h = 40, .d = 4 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSSMT_ALGID.SYMCRYPT_XMSSMT_SHAKE256_40_8_192), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHAKE256_192, .h = 40, .d = 8 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSSMT_ALGID.SYMCRYPT_XMSSMT_SHAKE256_60_3_192), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHAKE256_192, .h = 60, .d = 3 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSSMT_ALGID.SYMCRYPT_XMSSMT_SHAKE256_60_6_192), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHAKE256_192, .h = 60, .d = 6 },
    .{ .idAlg = @backingInt(SYMCRYPT_XMSSMT_ALGID.SYMCRYPT_XMSSMT_SHAKE256_60_12_192), .idWotsp = .SYMCRYPT_XMSS_WOTSP_SHAKE256_192, .h = 60, .d = 12 },
};

// ==============================================================================================
// Parameter & Treehash Helper Functions
// ==============================================================================================

pub export fn SymCryptHbsGetWinternitzLengths(
    n: UINT32,
    w: UINT32,
    puLen1: *UINT32,
    puLen2: *UINT32,
) callconv(SYMCRYPT_CALL) void {
    macros.ASSERT(n > 0);
    macros.ASSERT(w >= 1 and w <= 8);

    // number of w-bit digits in an n-byte input
    const len1: UINT32 = (8 * n + (w - 1)) / w;

    // maximum value the checksum can take (each w-bit digit can have value at most 2^w-1)
    const maxChecksum: UINT32 = len1 * ((@as(UINT32, 1) << @intCast(w)) - 1);

    const msb: UINT32 = 31 - @as(UINT32, @clz(maxChecksum));

    // msb + 1 bits are required to store the maxChecksum,
    // calculate the number of w-bit blocks to represent that
    const len2: UINT32 = (msb + 1 + (w - 1)) / w;

    puLen1.* = len1;
    puLen2.* = len2;
}

pub export fn SymCryptXmssGetWotspParams(
    id: SYMCRYPT_XMSS_WOTSP_ALGID,
    pParams: PSYMCRYPT_XMSS_PARAMS,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    for (XmssWotspParams) |entry| {
        if (entry.wotspId == id) {
            macros.ASSERT(entry.hashIndex < XmssHashArray.len);
            pParams.hash = XmssHashArray[entry.hashIndex].*;
            pParams.cbHashOutput = entry.n;
            pParams.nWinternitzWidth = entry.w;
            pParams.cbPrefix = entry.cbPrefix;
            return .SYMCRYPT_NO_ERROR;
        }
    }

    return .SYMCRYPT_INVALID_ARGUMENT;
}

pub export fn SymCryptXmssDeriveParams(
    pParams: PSYMCRYPT_XMSS_PARAMS,
) callconv(SYMCRYPT_CALL) void {
    SymCryptHbsGetWinternitzLengths(
        pParams.cbHashOutput,
        pParams.nWinternitzWidth,
        &pParams.len1,
        &pParams.len2,
    );

    pParams.len = pParams.len1 + pParams.len2;

    const nChecksumBits: UINT32 = pParams.len2 * pParams.nWinternitzWidth;
    macros.ASSERT(nChecksumBits <= 32);
    pParams.nLeftShift32 = @as(UINT8, @truncate(32 - nChecksumBits));

    if (pParams.nLayers == 1) {
        // single trees have a 32-bit Idx value
        pParams.cbIdx = 4;
    } else {
        // number of bytes to store h-bits for Idx
        pParams.cbIdx = (pParams.nTotalTreeHeight + 7) / 8;
    }

    pParams.nLayerHeight = pParams.nTotalTreeHeight / pParams.nLayers;
}

pub export fn SymCryptXmssParamsFromAlgIdCommon(
    id: UINT32,
    isMultiTree: BOOLEAN,
    pParams: PSYMCRYPT_XMSS_PARAMS,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_INVALID_ARGUMENT;
    const pParameters: []const SYMCRYPT_XMSS_PARAMETER_PREDEFINED = if (isMultiTree != 0)
        &XmssMtParametersPredefined
    else
        &XmssParametersPredefined;

    hash.SymCryptWipeKnownSize(@ptrCast(pParams), @sizeOf(SYMCRYPT_XMSS_PARAMS));

    for (pParameters) |entry| {
        if (entry.idAlg == id) {
            scError = SymCryptXmssGetWotspParams(entry.idWotsp, pParams);

            if (scError == .SYMCRYPT_NO_ERROR) {
                macros.ASSERT(pParams.cbHashOutput <= SYMCRYPT_HASH_MAX_RESULT_SIZE);

                pParams.id = id;
                pParams.nTotalTreeHeight = entry.h;
                pParams.nLayers = entry.d;
                SymCryptXmssDeriveParams(pParams);
            }

            break;
        }
    }

    return scError;
}

pub export fn SymCryptXmssParamsFromAlgId(
    id: SYMCRYPT_XMSS_ALGID,
    pParams: PSYMCRYPT_XMSS_PARAMS,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    return SymCryptXmssParamsFromAlgIdCommon(@backingInt(id), FALSE, pParams);
}

pub export fn SymCryptXmssMtParamsFromAlgId(
    id: SYMCRYPT_XMSSMT_ALGID,
    pParams: PSYMCRYPT_XMSS_PARAMS,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    return SymCryptXmssParamsFromAlgIdCommon(@backingInt(id), TRUE, pParams);
}

pub export fn SymCryptXmssSetParams(
    pParamsOpt: ?PSYMCRYPT_XMSS_PARAMS,
    id: UINT32,
    pHashOpt: ?PCSYMCRYPT_HASH,
    cbHashOutput: UINT32,
    nWinternitzWidth: UINT32,
    nTotalTreeHeight: UINT32,
    nLayers: UINT32,
    cbPrefix: UINT32,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    const pParams = pParamsOpt orelse return .SYMCRYPT_INVALID_ARGUMENT;

    hash.SymCryptWipeKnownSize(@ptrCast(pParams), @sizeOf(SYMCRYPT_XMSS_PARAMS));

    const pHash = pHashOpt orelse return .SYMCRYPT_INVALID_ARGUMENT;

    // Output size n can at most be equal to the hash output size
    if (cbHashOutput == 0 or
        cbHashOutput > pHash.resultSize or
        cbHashOutput > SYMCRYPT_HASH_MAX_RESULT_SIZE)
    {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    // Winternitz parameter must be one of 1, 2, 4, or 8
    if (nWinternitzWidth == 0 or
        nWinternitzWidth > 8 or
        (nWinternitzWidth & (nWinternitzWidth - 1)) != 0)
    {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    // nTotalTreeHeight and nLayers must both be positive and
    // nLayers must divide nTotalTreeHeight
    if (nTotalTreeHeight == 0 or
        nLayers == 0 or
        (nTotalTreeHeight % nLayers) != 0)
    {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    // Layer height (tree height of one layer) can be at most 31
    if ((nTotalTreeHeight / nLayers) > 31) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    // Total tree height can be at most 63
    if (nTotalTreeHeight > 63) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    if (cbPrefix == 0 or cbPrefix > SYMCRYPT_XMSS_MAX_PREFIX_SIZE) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    pParams.id = id;
    pParams.hash = pHash;
    pParams.cbHashOutput = cbHashOutput;
    pParams.nWinternitzWidth = nWinternitzWidth;
    pParams.nTotalTreeHeight = nTotalTreeHeight;
    pParams.nLayers = nLayers;
    SymCryptXmssDeriveParams(pParams);

    pParams.cbPrefix = cbPrefix;

    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptXmssSetAdrsType(
    adrs: PXMSS_ADRS,
    adrsType: UINT32,
) callconv(SYMCRYPT_CALL) void {
    macros.STORE_MSBFIRST32(&adrs.en32Type, adrsType);
    hash.SymCryptWipeKnownSize(@ptrCast(&adrs.u), @sizeOf(XMSS_ADRS_UNION));
    macros.STORE_MSBFIRST32(&adrs.en32KeyAndMask, 0);
}

pub export fn SymCryptXmssSizeofSignatureFromParams(
    pParams: PCSYMCRYPT_XMSS_PARAMS,
) callconv(SYMCRYPT_CALL) SIZE_T {
    macros.ASSERT(pParams.nLayers != 0);
    macros.ASSERT((pParams.nTotalTreeHeight % pParams.nLayers) == 0);
    macros.ASSERT(pParams.nLayerHeight > 0);

    var size: SIZE_T = 0;
    size += pParams.cbIdx; // idx
    size += pParams.cbHashOutput; // randomness

    // WOTSP signature + authentication path for each layer
    size += @as(SIZE_T, pParams.nLayers) * (@as(SIZE_T, pParams.cbHashOutput) * (@as(SIZE_T, pParams.len) + @as(SIZE_T, pParams.nLayerHeight)));

    return size;
}

pub export fn SymCryptXmssSizeofKeyBlobFromParams(
    pParams: PCSYMCRYPT_XMSS_PARAMS,
    keyType: SYMCRYPT_XMSSKEY_TYPE,
    pcbKey: *SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;
    var cbPublicKey: SIZE_T = 0;
    var cbPrivateKey: SIZE_T = 0;

    // Public Key
    cbPublicKey += @sizeOf(UINT32); // Alg ID
    cbPublicKey += 2 * @as(SIZE_T, pParams.cbHashOutput); // Root and Seed

    // Private Key (on top of the public key)
    cbPrivateKey = cbPublicKey;
    cbPrivateKey += @sizeOf(UINT64); // Idx
    cbPrivateKey += 2 * @as(SIZE_T, pParams.cbHashOutput); // SK_XMSS and SK_PRF

    switch (keyType) {
        .SYMCRYPT_XMSSKEY_TYPE_PUBLIC => pcbKey.* = cbPublicKey,
        .SYMCRYPT_XMSSKEY_TYPE_PRIVATE => pcbKey.* = cbPrivateKey,
        else => scError = .SYMCRYPT_INVALID_ARGUMENT,
    }

    return scError;
}

pub export fn SymCryptXmsskeyAllocate(
    pParams: PCSYMCRYPT_XMSS_PARAMS,
    flags: UINT32,
) callconv(SYMCRYPT_CALL) ?PSYMCRYPT_XMSS_KEY {
    if (flags != 0) {
        return null;
    }

    const cbSize: SIZE_T = @sizeOf(SYMCRYPT_XMSS_KEY);
    const pbKey = SymCryptCallbackAlloc(cbSize) orelse return null;

    hash.SymCryptWipe(@ptrCast(pbKey), cbSize);

    const aligned_ptr: [*]align(SYMCRYPT_ASYM_ALIGN_VALUE) BYTE = @alignCast(pbKey);
    const pKey: PSYMCRYPT_XMSS_KEY = @ptrCast(aligned_ptr);

    pKey.version = 1;
    pKey.keyType = .SYMCRYPT_XMSSKEY_TYPE_NONE;
    pKey.params = pParams.*;

    macros.SET_MAGIC(pKey);

    return pKey;
}

pub export fn SymCryptXmsskeyFree(
    pKey: PSYMCRYPT_XMSS_KEY,
) callconv(SYMCRYPT_CALL) void {
    macros.CHECK_MAGIC(pKey);
    hash.SymCryptWipeKnownSize(@ptrCast(pKey), @sizeOf(SYMCRYPT_XMSS_KEY));
    SymCryptCallbackFree(@ptrCast(pKey));
}

// ==============================================================================================
// Incremental Treehash Functions
// ==============================================================================================

pub export fn SymCryptHbsIncrementalTreehashInit(
    nLeaves: UINT32,
    pbBuffer: PBYTE,
    cbBuffer: SIZE_T,
    cbHashResult: UINT32,
    funcCompressNodes: PSYMCRYPT_INCREMENTAL_TREEHASH_FUNC,
    pContext: PSYMCRYPT_XMSS_INCREMENTAL_TREEHASH_CONTEXT,
) callconv(SYMCRYPT_CALL) PSYMCRYPT_INCREMENTAL_TREEHASH {
    macros.ASSERT(cbBuffer >= SymCryptHbsSizeofScratchBytesForIncrementalTreehash(cbHashResult, nLeaves));

    const pIncHash: PSYMCRYPT_INCREMENTAL_TREEHASH = @ptrCast(pbBuffer);

    pIncHash.cbNode = 2 * @sizeOf(UINT32) + cbHashResult;
    pIncHash.nSize = 0;
    pIncHash.nCapacity = SymCryptHbsIncrementalTreehashStackDepth(nLeaves);
    pIncHash.nLastLeafIndex = 0;
    pIncHash.funcCompressNodes = funcCompressNodes;
    pIncHash.pContext = pContext;

    return pIncHash;
}

pub export fn SymCryptHbsIncrementalTreehashGetNode(
    pIncHash: PSYMCRYPT_INCREMENTAL_TREEHASH,
    index: SIZE_T,
) callconv(SYMCRYPT_CALL) PSYMCRYPT_TREEHASH_NODE {
    var pNode: PBYTE = @ptrCast(&pIncHash.arrNodes);
    pNode += index * @as(SIZE_T, pIncHash.cbNode);
    return @ptrCast(pNode);
}

pub export fn SymCryptHbsIncrementalTreehashAllocNode(
    pIncHash: PSYMCRYPT_INCREMENTAL_TREEHASH,
    nLeafIndex: UINT32,
) callconv(SYMCRYPT_CALL) PSYMCRYPT_TREEHASH_NODE {
    macros.ASSERT(pIncHash.nSize < pIncHash.nCapacity);

    const pNode = SymCryptHbsIncrementalTreehashGetNode(pIncHash, pIncHash.nSize);

    pNode.height = 0;
    pNode.index = nLeafIndex;

    pIncHash.nSize += 1;

    return pNode;
}

pub export fn SymCryptHbsIncrementalTreehashGetTopNodes(
    pIncHash: PSYMCRYPT_INCREMENTAL_TREEHASH,
    ppNodeLeft: *?PSYMCRYPT_TREEHASH_NODE,
    ppNodeRight: *?PSYMCRYPT_TREEHASH_NODE,
) callconv(SYMCRYPT_CALL) void {
    ppNodeRight.* = if (pIncHash.nSize < 1) null else SymCryptHbsIncrementalTreehashGetNode(pIncHash, pIncHash.nSize - 1);
    ppNodeLeft.* = if (pIncHash.nSize < 2) null else SymCryptHbsIncrementalTreehashGetNode(pIncHash, pIncHash.nSize - 2);
}

pub export fn SymCryptHbsIncrementalTreehashProcessCommon(
    pIncHash: PSYMCRYPT_INCREMENTAL_TREEHASH,
    fFinal: BOOLEAN,
) callconv(SYMCRYPT_CALL) ?PSYMCRYPT_TREEHASH_NODE {
    var pNodeLeft: ?PSYMCRYPT_TREEHASH_NODE = null;
    var pNodeRight: ?PSYMCRYPT_TREEHASH_NODE = null;

    macros.ASSERT(pIncHash.nSize > 0);

    SymCryptHbsIncrementalTreehashGetTopNodes(pIncHash, &pNodeLeft, &pNodeRight);

    while (pNodeLeft != null and
        ((fFinal != 0) or (pNodeLeft.?.height == pNodeRight.?.height)))
    {
        pIncHash.funcCompressNodes(
            pNodeLeft.?,
            pNodeRight.?,
            pNodeLeft.?,
            pIncHash.pContext,
        );

        pIncHash.nSize -= 1;

        SymCryptHbsIncrementalTreehashGetTopNodes(pIncHash, &pNodeLeft, &pNodeRight);
    }

    return pNodeRight;
}

pub export fn SymCryptHbsIncrementalTreehashProcess(
    pIncHash: PSYMCRYPT_INCREMENTAL_TREEHASH,
) callconv(SYMCRYPT_CALL) ?PSYMCRYPT_TREEHASH_NODE {
    return SymCryptHbsIncrementalTreehashProcessCommon(pIncHash, FALSE);
}

pub export fn SymCryptHbsIncrementalTreehashFinalize(
    pIncHash: PSYMCRYPT_INCREMENTAL_TREEHASH,
) callconv(SYMCRYPT_CALL) ?PSYMCRYPT_TREEHASH_NODE {
    return SymCryptHbsIncrementalTreehashProcessCommon(pIncHash, TRUE);
}

pub export fn SymCryptHbsIncrementalTreehashStackDepth(
    nLeaves: UINT32,
) callconv(SYMCRYPT_CALL) UINT32 {
    // Minimum height binary tree that contains nLeaves many leaves is h+1
    const h: UINT32 = 31 - @as(UINT32, @clz(nLeaves));

    // Tree root computation will require a stack of depth equal to tree height plus 1
    return h + 2;
}

pub export fn SymCryptHbsSizeofScratchBytesForIncrementalTreehash(
    cbNode: UINT32,
    nLeaves: UINT32,
) callconv(SYMCRYPT_CALL) SIZE_T {
    const nodeSize: SIZE_T = @as(SIZE_T, cbNode) + 2 * @sizeOf(UINT32);
    var result: SIZE_T = @sizeOf(SYMCRYPT_INCREMENTAL_TREEHASH) - @sizeOf(SYMCRYPT_TREEHASH_NODE);

    result += nodeSize * @as(SIZE_T, SymCryptHbsIncrementalTreehashStackDepth(nLeaves));
    return result;
}

// ==============================================================================================
// XMSS PRF, Chain, and Tree Operations
// ==============================================================================================

pub export fn SymCryptXmssPrfInit(
    hashAlg: PCSYMCRYPT_HASH,
    PrfType: BYTE,
    prefixLength: SIZE_T,
    state: PSYMCRYPT_HASH_STATE,
) callconv(SYMCRYPT_CALL) void {
    var prefix: [SYMCRYPT_XMSS_MAX_PREFIX_SIZE]BYTE = undefined;

    macros.ASSERT(prefixLength > 0 and prefixLength <= SYMCRYPT_XMSS_MAX_PREFIX_SIZE);

    hash.SymCryptWipe(@ptrCast(&prefix), prefixLength);
    prefix[prefixLength - 1] = PrfType;

    hash.SymCryptHashInit(hashAlg, @ptrCast(state));
    hash.SymCryptHashAppend(hashAlg, @ptrCast(state), &prefix, prefixLength);
}

pub export fn SymCryptXmssPrfKey(
    pParams: PCSYMCRYPT_XMSS_PARAMS,
    pbKey: PCBYTE,
    cbKey: SIZE_T,
    pState: PSYMCRYPT_HASH_STATE,
) callconv(SYMCRYPT_CALL) void {
    SymCryptXmssPrfInit(pParams.hash.?, SYMCRYPT_XMSS_PRF, pParams.cbPrefix, pState);
    hash.SymCryptHashAppend(pParams.hash.?, @ptrCast(pState), pbKey, cbKey);
}

pub export fn SymCryptXmssPrf(
    pParams: PCSYMCRYPT_XMSS_PARAMS,
    PrfType: BYTE,
    pbKey: PCBYTE,
    cbKey: SIZE_T,
    pbMsg: PCBYTE,
    cbMsg: SIZE_T,
    pbOutput: PBYTE,
) callconv(SYMCRYPT_CALL) void {
    var state: SYMCRYPT_HASH_STATE = undefined;

    SymCryptXmssPrfInit(pParams.hash.?, PrfType, pParams.cbPrefix, &state);
    hash.SymCryptHashAppend(pParams.hash.?, @ptrCast(&state), pbKey, cbKey);
    hash.SymCryptHashAppend(pParams.hash.?, @ptrCast(&state), pbMsg, cbMsg);
    hash.SymCryptHashResult(pParams.hash.?, @ptrCast(&state), pbOutput, pParams.cbHashOutput);
}

pub export fn SymCryptXmssRandHash(
    pParams: PCSYMCRYPT_XMSS_PARAMS,
    adrs: PXMSS_ADRS,
    pbSeed: PCBYTE,
    pbLeft: PCBYTE,
    pbRight: PCBYTE,
    pbOutput: PBYTE,
) callconv(SYMCRYPT_CALL) void {
    var key: [SYMCRYPT_HASH_MAX_RESULT_SIZE]BYTE = undefined;
    var bitmask: [2 * SYMCRYPT_HASH_MAX_RESULT_SIZE]BYTE = undefined;
    var stateKeyed: SYMCRYPT_HASH_STATE = undefined;
    var stateMask: SYMCRYPT_HASH_STATE = undefined;
    defer {
        hash.SymCryptWipeKnownSize(@ptrCast(&key), @sizeOf(@TypeOf(key)));
        hash.SymCryptWipeKnownSize(@ptrCast(&bitmask), @sizeOf(@TypeOf(bitmask)));
        hash.SymCryptWipeKnownSize(@ptrCast(&stateKeyed), @sizeOf(@TypeOf(stateKeyed)));
        hash.SymCryptWipeKnownSize(@ptrCast(&stateMask), @sizeOf(@TypeOf(stateMask)));
    }
    const cbHashOutput: SIZE_T = pParams.cbHashOutput;

    macros.ASSERT(cbHashOutput <= SYMCRYPT_HASH_MAX_RESULT_SIZE);

    SymCryptXmssPrfKey(pParams, pbSeed, cbHashOutput, &stateKeyed);

    macros.STORE_MSBFIRST32(&adrs.en32KeyAndMask, 1);
    hash.SymCryptHashStateCopy(pParams.hash.?, @ptrCast(&stateKeyed), @ptrCast(&stateMask));
    hash.SymCryptHashAppend(pParams.hash.?, @ptrCast(&stateMask), @ptrCast(adrs), @sizeOf(XMSS_ADRS));
    hash.SymCryptHashResult(pParams.hash.?, @ptrCast(&stateMask), &bitmask, cbHashOutput);

    macros.STORE_MSBFIRST32(&adrs.en32KeyAndMask, 2);
    hash.SymCryptHashStateCopy(pParams.hash.?, @ptrCast(&stateKeyed), @ptrCast(&stateMask));
    hash.SymCryptHashAppend(pParams.hash.?, @ptrCast(&stateMask), @ptrCast(adrs), @sizeOf(XMSS_ADRS));
    hash.SymCryptHashResult(pParams.hash.?, @ptrCast(&stateMask), @as(PBYTE, @ptrCast(&bitmask)) + cbHashOutput, cbHashOutput);

    macros.STORE_MSBFIRST32(&adrs.en32KeyAndMask, 0);
    hash.SymCryptHashAppend(pParams.hash.?, @ptrCast(&stateKeyed), @ptrCast(adrs), @sizeOf(XMSS_ADRS));
    hash.SymCryptHashResult(pParams.hash.?, @ptrCast(&stateKeyed), &key, cbHashOutput);

    hash.SymCryptXorBytes(&bitmask, pbLeft, &bitmask, cbHashOutput);
    hash.SymCryptXorBytes(@as(PCBYTE, @ptrCast(&bitmask)) + cbHashOutput, pbRight, @as(PBYTE, @ptrCast(&bitmask)) + cbHashOutput, cbHashOutput);

    SymCryptXmssPrf(pParams, SYMCRYPT_XMSS_H, &key, cbHashOutput, &bitmask, 2 * cbHashOutput, pbOutput);
}

pub export fn SymCryptXmssTreeNodeCompress(
    pNodeLeft: PSYMCRYPT_TREEHASH_NODE,
    pNodeRight: PSYMCRYPT_TREEHASH_NODE,
    pNodeOut: PSYMCRYPT_TREEHASH_NODE,
    pCtxIncHash: PSYMCRYPT_XMSS_INCREMENTAL_TREEHASH_CONTEXT,
) callconv(SYMCRYPT_CALL) void {
    macros.STORE_MSBFIRST32(&pCtxIncHash.adrs.u.hashtree.en32Height, pNodeLeft.height);
    macros.STORE_MSBFIRST32(&pCtxIncHash.adrs.u.hashtree.en32Index, pNodeLeft.index / 2);

    SymCryptXmssRandHash(
        pCtxIncHash.pParams,
        &pCtxIncHash.adrs,
        pCtxIncHash.pbSeed,
        nodeValue(pNodeLeft),
        nodeValue(pNodeRight),
        nodeValue(pNodeOut),
    );

    pNodeOut.index = pNodeLeft.index / 2;
    pNodeOut.height = pNodeLeft.height + 1;
}

pub export fn SymCryptXmssLtreeNodeCompress(
    pNodeLeft: PSYMCRYPT_TREEHASH_NODE,
    pNodeRight: PSYMCRYPT_TREEHASH_NODE,
    pNodeOut: PSYMCRYPT_TREEHASH_NODE,
    pCtxIncHash: PSYMCRYPT_XMSS_INCREMENTAL_TREEHASH_CONTEXT,
) callconv(SYMCRYPT_CALL) void {
    macros.STORE_MSBFIRST32(&pCtxIncHash.adrs.u.ltree.en32Height, pNodeLeft.height);
    macros.STORE_MSBFIRST32(&pCtxIncHash.adrs.u.ltree.en32Index, pNodeLeft.index / 2);

    SymCryptXmssRandHash(
        pCtxIncHash.pParams,
        &pCtxIncHash.adrs,
        pCtxIncHash.pbSeed,
        nodeValue(pNodeLeft),
        nodeValue(pNodeRight),
        nodeValue(pNodeOut),
    );

    pNodeOut.index = pNodeLeft.index / 2;
    pNodeOut.height = pNodeLeft.height + 1;
}

pub export fn SymCryptXmssCreateWotspSecret(
    pParams: PCSYMCRYPT_XMSS_PARAMS,
    pbSkXmss: PCBYTE,
    pbSeed: PCBYTE,
    adrs: PXMSS_ADRS,
    pbOutput: PBYTE,
) callconv(SYMCRYPT_CALL) void {
    var state: SYMCRYPT_HASH_STATE = undefined;

    SymCryptXmssPrfInit(pParams.hash.?, SYMCRYPT_XMSS_PRF_KEYGEN, pParams.cbPrefix, &state);
    hash.SymCryptHashAppend(pParams.hash.?, @ptrCast(&state), pbSkXmss, pParams.cbHashOutput);
    hash.SymCryptHashAppend(pParams.hash.?, @ptrCast(&state), pbSeed, pParams.cbHashOutput);
    hash.SymCryptHashAppend(pParams.hash.?, @ptrCast(&state), @ptrCast(adrs), @sizeOf(XMSS_ADRS));
    hash.SymCryptHashResult(pParams.hash.?, @ptrCast(&state), pbOutput, pParams.cbHashOutput);
}

pub export fn SymCryptXmssChain(
    pParams: PCSYMCRYPT_XMSS_PARAMS,
    pbInput: PCBYTE,
    startIndex: UINT32,
    steps: UINT32,
    pbSeed: PCBYTE,
    adrs: PXMSS_ADRS,
    pbOutput: PBYTE,
) callconv(SYMCRYPT_CALL) void {
    var tmp: [SYMCRYPT_HASH_MAX_RESULT_SIZE]BYTE = undefined;
    var key: [SYMCRYPT_HASH_MAX_RESULT_SIZE]BYTE = undefined;
    var bm: [SYMCRYPT_HASH_MAX_RESULT_SIZE]BYTE = undefined;
    var stateKey: SYMCRYPT_HASH_STATE = undefined;
    var stateMask: SYMCRYPT_HASH_STATE = undefined;
    defer {
        hash.SymCryptWipeKnownSize(@ptrCast(&tmp), @sizeOf(@TypeOf(tmp)));
        hash.SymCryptWipeKnownSize(@ptrCast(&key), @sizeOf(@TypeOf(key)));
        hash.SymCryptWipeKnownSize(@ptrCast(&bm), @sizeOf(@TypeOf(bm)));
        hash.SymCryptWipeKnownSize(@ptrCast(&stateKey), @sizeOf(@TypeOf(stateKey)));
        hash.SymCryptWipeKnownSize(@ptrCast(&stateMask), @sizeOf(@TypeOf(stateMask)));
    }
    const cbHashOutput: SIZE_T = pParams.cbHashOutput;

    @memcpy(tmp[0..cbHashOutput], pbInput[0..cbHashOutput]);

    var i: UINT32 = startIndex;
    while (i < startIndex + steps) : (i += 1) {
        macros.STORE_MSBFIRST32(&adrs.u.ots.en32Hash, i);

        SymCryptXmssPrfKey(pParams, pbSeed, cbHashOutput, &stateKey);
        hash.SymCryptHashStateCopy(pParams.hash.?, @ptrCast(&stateKey), @ptrCast(&stateMask));

        macros.STORE_MSBFIRST32(&adrs.en32KeyAndMask, 0);
        hash.SymCryptHashAppend(pParams.hash.?, @ptrCast(&stateKey), @ptrCast(adrs), @sizeOf(XMSS_ADRS));
        hash.SymCryptHashResult(pParams.hash.?, @ptrCast(&stateKey), &key, cbHashOutput);

        macros.STORE_MSBFIRST32(&adrs.en32KeyAndMask, 1);
        hash.SymCryptHashAppend(pParams.hash.?, @ptrCast(&stateMask), @ptrCast(adrs), @sizeOf(XMSS_ADRS));
        hash.SymCryptHashResult(pParams.hash.?, @ptrCast(&stateMask), &bm, cbHashOutput);

        hash.SymCryptXorBytes(&tmp, &bm, &tmp, cbHashOutput);

        SymCryptXmssPrf(pParams, SYMCRYPT_XMSS_F, &key, cbHashOutput, &tmp, cbHashOutput, &tmp);
    }

    // reset used ADRS fields
    macros.STORE_MSBFIRST32(&adrs.u.ots.en32Hash, 0);
    macros.STORE_MSBFIRST32(&adrs.en32KeyAndMask, 0);

    @memcpy(pbOutput[0..cbHashOutput], tmp[0..cbHashOutput]);
}

pub export fn SymCryptXmssCreateWotspPublickey(
    pParams: PCSYMCRYPT_XMSS_PARAMS,
    adrs: PXMSS_ADRS,
    uLeaf: UINT32,
    pbSkXmss: PCBYTE,
    pbSeed: PCBYTE,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
    pbOutput: PBYTE,
) callconv(SYMCRYPT_CALL) void {
    var ctxIncHash: SYMCRYPT_XMSS_INCREMENTAL_TREEHASH_CONTEXT = undefined;

    macros.ASSERT(cbScratch >= SymCryptHbsSizeofScratchBytesForIncrementalTreehash(pParams.cbHashOutput, pParams.len));

    SymCryptXmssSetAdrsType(adrs, XMSS_ADRS_TYPE_LTREE);
    macros.STORE_MSBFIRST32(&adrs.u.ltree.en32Leaf, uLeaf);

    ctxIncHash.adrs = adrs.*;
    ctxIncHash.pParams = pParams;
    ctxIncHash.pbSeed = pbSeed;

    const pIncHash = SymCryptHbsIncrementalTreehashInit(
        pParams.len,
        pbScratch,
        cbScratch,
        pParams.cbHashOutput,
        &SymCryptXmssLtreeNodeCompress,
        &ctxIncHash,
    );

    const maxChainSteps: UINT32 = (@as(UINT32, 1) << @intCast(pParams.nWinternitzWidth)) - 1;
    var i: UINT32 = 0;
    while (i < pParams.len) : (i += 1) {
        const pNode = SymCryptHbsIncrementalTreehashAllocNode(pIncHash, i);

        SymCryptXmssSetAdrsType(adrs, XMSS_ADRS_TYPE_OTS);
        macros.STORE_MSBFIRST32(&adrs.u.ots.en32Leaf, uLeaf);
        macros.STORE_MSBFIRST32(&adrs.u.ots.en32Chain, i);

        SymCryptXmssCreateWotspSecret(
            pParams,
            pbSkXmss,
            pbSeed,
            adrs,
            nodeValue(pNode),
        );

        SymCryptXmssChain(
            pParams,
            nodeValue(pNode),
            0,
            maxChainSteps,
            pbSeed,
            adrs,
            nodeValue(pNode),
        );

        _ = SymCryptHbsIncrementalTreehashProcess(pIncHash);
    }

    const pRootNode = SymCryptHbsIncrementalTreehashFinalize(pIncHash).?;

    @memcpy(pbOutput[0..pParams.cbHashOutput], nodeValue(pRootNode)[0..pParams.cbHashOutput]);
}

pub export fn SymCryptXmssComputeSubtreeRoot(
    pParams: PCSYMCRYPT_XMSS_PARAMS,
    adrs: PXMSS_ADRS,
    pbSkXmss: PCBYTE,
    pbSeed: PCBYTE,
    uLeaf: UINT32,
    uHeight: UINT32,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
    pbRoot: PBYTE,
) callconv(SYMCRYPT_CALL) void {
    var ctxIncHash: SYMCRYPT_XMSS_INCREMENTAL_TREEHASH_CONTEXT = undefined;

    macros.ASSERT(uHeight < 32);
    macros.ASSERT((uLeaf & ((@as(UINT32, 1) << @intCast(uHeight)) - 1)) == 0);
    macros.ASSERT(pParams.nLayerHeight < 32);

    const nLayerLeaves: UINT32 = @as(UINT32, 1) << @intCast(pParams.nLayerHeight);
    const cbScratchTree: SIZE_T = SymCryptHbsSizeofScratchBytesForIncrementalTreehash(pParams.cbHashOutput, nLayerLeaves);
    const cbScratchLtree: SIZE_T = SymCryptHbsSizeofScratchBytesForIncrementalTreehash(pParams.cbHashOutput, pParams.len);

    macros.ASSERT(cbScratch >= (cbScratchTree + cbScratchLtree));

    const pbScratchTree: PBYTE = pbScratch;
    const pbScratchLtree: PBYTE = pbScratch + cbScratchTree;

    SymCryptXmssSetAdrsType(adrs, XMSS_ADRS_TYPE_HASH_TREE);

    ctxIncHash.adrs = adrs.*;
    ctxIncHash.pParams = pParams;
    ctxIncHash.pbSeed = pbSeed;

    const nSubtreeLeaves: UINT32 = @as(UINT32, 1) << @intCast(uHeight);
    const pIncHash = SymCryptHbsIncrementalTreehashInit(
        nSubtreeLeaves,
        pbScratchTree,
        cbScratchTree,
        pParams.cbHashOutput,
        &SymCryptXmssTreeNodeCompress,
        &ctxIncHash,
    );

    var nLeafIndex: UINT32 = uLeaf;
    while (nLeafIndex < uLeaf + nSubtreeLeaves) : (nLeafIndex += 1) {
        const pNode = SymCryptHbsIncrementalTreehashAllocNode(pIncHash, nLeafIndex);

        SymCryptXmssCreateWotspPublickey(
            pParams,
            adrs,
            nLeafIndex,
            pbSkXmss,
            pbSeed,
            pbScratchLtree,
            cbScratchLtree,
            nodeValue(pNode),
        );

        _ = SymCryptHbsIncrementalTreehashProcess(pIncHash);
    }

    const pRootNode = SymCryptHbsIncrementalTreehashFinalize(pIncHash).?;

    @memcpy(pbRoot[0..pParams.cbHashOutput], nodeValue(pRootNode)[0..pParams.cbHashOutput]);
}

pub export fn SymCryptXmssComputePublicRoot(
    pParams: PCSYMCRYPT_XMSS_PARAMS,
    pbSeedOpt: ?PCBYTE,
    cbSeed: SIZE_T,
    pbSkXmssOpt: ?PCBYTE,
    cbSkXmss: SIZE_T,
    pbRootOpt: ?PBYTE,
    cbRoot: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    macros.ASSERT(pParams.nLayerHeight < 32);

    const pbRoot = pbRootOpt orelse return .SYMCRYPT_INVALID_ARGUMENT;
    const pbSeed = pbSeedOpt orelse return .SYMCRYPT_INVALID_ARGUMENT;
    const pbSkXmss = pbSkXmssOpt orelse return .SYMCRYPT_INVALID_ARGUMENT;

    if (cbRoot != pParams.cbHashOutput or
        cbSeed != pParams.cbHashOutput or
        cbSkXmss != pParams.cbHashOutput)
    {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    const nLayerLeaves: UINT32 = @as(UINT32, 1) << @intCast(pParams.nLayerHeight);
    var cbScratch: SIZE_T = 0;
    cbScratch += SymCryptHbsSizeofScratchBytesForIncrementalTreehash(pParams.cbHashOutput, nLayerLeaves);
    cbScratch += SymCryptHbsSizeofScratchBytesForIncrementalTreehash(pParams.cbHashOutput, pParams.len);

    macros.ASSERT(cbScratch > 0);
    const pbScratch = SymCryptCallbackAlloc(cbScratch) orelse return .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
    defer {
        hash.SymCryptWipe(@ptrCast(pbScratch), cbScratch);
        SymCryptCallbackFree(@ptrCast(pbScratch));
    }

    var adrs: XMSS_ADRS = undefined;
    hash.SymCryptWipeKnownSize(@ptrCast(&adrs), @sizeOf(XMSS_ADRS));
    macros.STORE_MSBFIRST32(&adrs.en32Layer, pParams.nLayers - 1);

    SymCryptXmssComputeSubtreeRoot(
        pParams,
        &adrs,
        pbSkXmss,
        pbSeed,
        0,
        pParams.nLayerHeight,
        pbScratch,
        cbScratch,
        pbRoot,
    );

    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptXmsskeyVerifyRoot(
    pKey: PCSYMCRYPT_XMSS_KEY,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var Root: [SYMCRYPT_HASH_MAX_RESULT_SIZE]BYTE = undefined;

    macros.CHECK_MAGIC(pKey);

    if (pKey.keyType != .SYMCRYPT_XMSSKEY_TYPE_PRIVATE) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    hash.SymCryptWipeKnownSize(@ptrCast(&Root), @sizeOf(@TypeOf(Root)));

    const scError = SymCryptXmssComputePublicRoot(
        &pKey.params,
        &pKey.Seed,
        pKey.params.cbHashOutput,
        &pKey.SkXmss,
        pKey.params.cbHashOutput,
        &Root,
        pKey.params.cbHashOutput,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    if (equal.SymCryptEqual(&Root, &pKey.Root, pKey.params.cbHashOutput) == 0) {
        return .SYMCRYPT_HBS_PUBLIC_ROOT_MISMATCH;
    }

    return .SYMCRYPT_NO_ERROR;
}

// ==============================================================================================
// Key Generation, Import, Export
// ==============================================================================================

pub export fn SymCryptXmsskeyGenerate(
    pKey: PSYMCRYPT_XMSS_KEY,
    flags: UINT32,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;

    macros.CHECK_MAGIC(pKey);

    if (flags != 0) {
        scError = .SYMCRYPT_INVALID_ARGUMENT;
    } else {
        // Wipe key material
        hash.SymCryptWipeKnownSize(@ptrCast(&pKey.Root), @sizeOf(@TypeOf(pKey.Root)));
        hash.SymCryptWipeKnownSize(@ptrCast(&pKey.Seed), @sizeOf(@TypeOf(pKey.Seed)));
        hash.SymCryptWipeKnownSize(@ptrCast(&pKey.SkPrf), @sizeOf(@TypeOf(pKey.SkPrf)));
        hash.SymCryptWipeKnownSize(@ptrCast(&pKey.SkXmss), @sizeOf(@TypeOf(pKey.SkXmss)));
        pKey.Idx = 0;

        scError = SymCryptCallbackRandom(&pKey.SkPrf, pKey.params.cbHashOutput);
        if (scError == .SYMCRYPT_NO_ERROR) {
            scError = SymCryptCallbackRandom(&pKey.SkXmss, pKey.params.cbHashOutput);
        }
        if (scError == .SYMCRYPT_NO_ERROR) {
            scError = SymCryptCallbackRandom(&pKey.Seed, pKey.params.cbHashOutput);
        }
        if (scError == .SYMCRYPT_NO_ERROR) {
            // Compute public root from the private key
            scError = SymCryptXmssComputePublicRoot(
                &pKey.params,
                &pKey.Seed,
                pKey.params.cbHashOutput,
                &pKey.SkXmss,
                pKey.params.cbHashOutput,
                &pKey.Root,
                pKey.params.cbHashOutput,
            );
        }
        if (scError == .SYMCRYPT_NO_ERROR) {
            pKey.keyType = .SYMCRYPT_XMSSKEY_TYPE_PRIVATE;
        }
    }

    if (scError != .SYMCRYPT_NO_ERROR) {
        hash.SymCryptWipeKnownSize(@ptrCast(&pKey.SkPrf), @sizeOf(@TypeOf(pKey.SkPrf)));
        hash.SymCryptWipeKnownSize(@ptrCast(&pKey.SkXmss), @sizeOf(@TypeOf(pKey.SkXmss)));
        pKey.keyType = .SYMCRYPT_XMSSKEY_TYPE_NONE;
    }

    return scError;
}

pub export fn SymCryptXmsskeySetValue(
    pbInputInit: PCBYTE,
    cbInput: SIZE_T,
    keyType: SYMCRYPT_XMSSKEY_TYPE,
    flags: UINT32,
    pKey: PSYMCRYPT_XMSS_KEY,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;
    var pbInput: PCBYTE = pbInputInit;
    var cbKey: SIZE_T = 0;

    macros.ASSERT(keyType == .SYMCRYPT_XMSSKEY_TYPE_PUBLIC or keyType == .SYMCRYPT_XMSSKEY_TYPE_PRIVATE);

    macros.CHECK_MAGIC(pKey);

    if ((flags & (~SYMCRYPT_FLAG_XMSSKEY_VERIFY_ROOT)) != 0 or
        (keyType != .SYMCRYPT_XMSSKEY_TYPE_PUBLIC and keyType != .SYMCRYPT_XMSSKEY_TYPE_PRIVATE))
    {
        scError = .SYMCRYPT_INVALID_ARGUMENT;
    } else if ((flags & SYMCRYPT_FLAG_XMSSKEY_VERIFY_ROOT) != 0 and
        keyType != .SYMCRYPT_XMSSKEY_TYPE_PRIVATE)
    {
        // Public root validation can only be performed for private keys
        scError = .SYMCRYPT_INVALID_ARGUMENT;
    } else {
        _ = SymCryptXmssSizeofKeyBlobFromParams(&pKey.params, keyType, &cbKey);

        if (cbInput != cbKey) {
            scError = .SYMCRYPT_INVALID_ARGUMENT;
        } else {
            const uAlgId: UINT32 = macros.LOAD_MSBFIRST32(pbInput);
            pbInput += @sizeOf(UINT32);

            if (uAlgId != pKey.params.id) {
                scError = .SYMCRYPT_INVALID_BLOB;
            } else {
                const cbHashOutput: SIZE_T = pKey.params.cbHashOutput;

                // Wipe private key material
                pKey.Idx = 0;
                hash.SymCryptWipeKnownSize(@ptrCast(&pKey.SkPrf), @sizeOf(@TypeOf(pKey.SkPrf)));
                hash.SymCryptWipeKnownSize(@ptrCast(&pKey.SkXmss), @sizeOf(@TypeOf(pKey.SkXmss)));

                pKey.keyType = keyType;

                @memcpy(pKey.Root[0..cbHashOutput], pbInput[0..cbHashOutput]);
                pbInput += cbHashOutput;

                @memcpy(pKey.Seed[0..cbHashOutput], pbInput[0..cbHashOutput]);
                pbInput += cbHashOutput;

                if (keyType == .SYMCRYPT_XMSSKEY_TYPE_PRIVATE) {
                    pKey.Idx = macros.LOAD_MSBFIRST64(pbInput);
                    pbInput += @sizeOf(UINT64);

                    @memcpy(pKey.SkXmss[0..cbHashOutput], pbInput[0..cbHashOutput]);
                    pbInput += cbHashOutput;

                    @memcpy(pKey.SkPrf[0..cbHashOutput], pbInput[0..cbHashOutput]);
                    pbInput += cbHashOutput;

                    if ((flags & SYMCRYPT_FLAG_XMSSKEY_VERIFY_ROOT) != 0) {
                        scError = SymCryptXmsskeyVerifyRoot(pKey);
                    }
                }
            }
        }
    }

    if (scError != .SYMCRYPT_NO_ERROR) {
        hash.SymCryptWipeKnownSize(@ptrCast(&pKey.SkPrf), @sizeOf(@TypeOf(pKey.SkPrf)));
        hash.SymCryptWipeKnownSize(@ptrCast(&pKey.SkXmss), @sizeOf(@TypeOf(pKey.SkXmss)));
        pKey.keyType = .SYMCRYPT_XMSSKEY_TYPE_NONE;
    }

    return scError;
}

pub export fn SymCryptXmsskeyGetValue(
    pKey: PCSYMCRYPT_XMSS_KEY,
    keyType: SYMCRYPT_XMSSKEY_TYPE,
    flags: UINT32,
    pbOutputInit: PBYTE,
    cbOutput: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var pbOutput: PBYTE = pbOutputInit;
    var cbKey: SIZE_T = 0;

    macros.ASSERT(keyType == .SYMCRYPT_XMSSKEY_TYPE_PUBLIC or keyType == .SYMCRYPT_XMSSKEY_TYPE_PRIVATE);

    macros.CHECK_MAGIC(pKey);

    if (flags != 0 or
        (keyType != .SYMCRYPT_XMSSKEY_TYPE_PUBLIC and keyType != .SYMCRYPT_XMSSKEY_TYPE_PRIVATE) or
        pKey.keyType == .SYMCRYPT_XMSSKEY_TYPE_NONE)
    {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    // Cannot export private key from a public key object
    if (keyType == .SYMCRYPT_XMSSKEY_TYPE_PRIVATE and pKey.keyType != .SYMCRYPT_XMSSKEY_TYPE_PRIVATE) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    _ = SymCryptXmssSizeofKeyBlobFromParams(&pKey.params, keyType, &cbKey);

    if (cbOutput != cbKey) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    const cbHashOutput: SIZE_T = pKey.params.cbHashOutput;

    // Public Key: Alg Id | Root | Seed
    macros.STORE_MSBFIRST32(pbOutput, pKey.params.id);
    pbOutput += @sizeOf(UINT32);

    @memcpy(pbOutput[0..cbHashOutput], pKey.Root[0..cbHashOutput]);
    pbOutput += cbHashOutput;

    @memcpy(pbOutput[0..cbHashOutput], pKey.Seed[0..cbHashOutput]);
    pbOutput += cbHashOutput;

    if (keyType == .SYMCRYPT_XMSSKEY_TYPE_PRIVATE) {
        // Private Key: Idx | SK_XMSS | SK_PRF
        macros.STORE_MSBFIRST64(pbOutput, pKey.Idx);
        pbOutput += @sizeOf(UINT64);

        @memcpy(pbOutput[0..cbHashOutput], pKey.SkXmss[0..cbHashOutput]);
        pbOutput += cbHashOutput;

        @memcpy(pbOutput[0..cbHashOutput], pKey.SkPrf[0..cbHashOutput]);
        pbOutput += cbHashOutput;
    }

    return .SYMCRYPT_NO_ERROR;
}

// ==============================================================================================
// Digit Extraction, Signature Helpers, Verification, and Signing
// ==============================================================================================

pub export fn SymCryptHbsGetDigit(
    width: UINT32,
    pbBuffer: PCBYTE,
    cbBuffer: SIZE_T,
    index: UINT32,
) callconv(SYMCRYPT_CALL) UINT32 {
    macros.ASSERT(width == 1 or width == 2 or width == 4 or width == 8);
    macros.ASSERT(@as(SIZE_T, index) < ((cbBuffer * 8) / @as(SIZE_T, width)));

    const digitsPerByte: UINT32 = 8 / width;
    var value: BYTE = pbBuffer[index / digitsPerByte];
    const shiftAmount: u3 = @intCast(width * (digitsPerByte - 1 - (index % digitsPerByte)));

    value >>= shiftAmount;
    value &= @truncate((@as(UINT32, 1) << @intCast(width)) - 1);

    return value;
}

pub export fn SymCryptXmssTreeRootFromAuthenticationPath(
    pParams: PCSYMCRYPT_XMSS_PARAMS,
    adrs: PXMSS_ADRS,
    uLeaf: UINT32,
    pbStartingNode: PCBYTE,
    pbAuthNodes: PCBYTE,
    pbSeed: PCBYTE,
    pbOutput: PBYTE,
) callconv(SYMCRYPT_CALL) void {
    var node: [SYMCRYPT_HASH_MAX_RESULT_SIZE]BYTE = undefined;
    var tmp: [SYMCRYPT_HASH_MAX_RESULT_SIZE]BYTE = undefined;
    var uNodeIndex: UINT32 = uLeaf;
    const cbHashOutput: SIZE_T = pParams.cbHashOutput;

    @memcpy(node[0..cbHashOutput], pbStartingNode[0..cbHashOutput]);

    SymCryptXmssSetAdrsType(adrs, XMSS_ADRS_TYPE_HASH_TREE);
    macros.STORE_MSBFIRST32(&adrs.u.hashtree.en32Index, uNodeIndex);

    var i: UINT32 = 0;
    while (i < pParams.nLayerHeight) : (i += 1) {
        macros.STORE_MSBFIRST32(&adrs.u.hashtree.en32Height, i);

        const authNodePtr: PCBYTE = pbAuthNodes + (cbHashOutput * @as(SIZE_T, i));
        if (((uLeaf >> @intCast(i)) & 1) == 0) {
            uNodeIndex = uNodeIndex / 2;
            macros.STORE_MSBFIRST32(&adrs.u.hashtree.en32Index, uNodeIndex);
            SymCryptXmssRandHash(pParams, adrs, pbSeed, &node, authNodePtr, &tmp);
        } else {
            uNodeIndex = (uNodeIndex - 1) / 2;
            macros.STORE_MSBFIRST32(&adrs.u.hashtree.en32Index, uNodeIndex);
            SymCryptXmssRandHash(pParams, adrs, pbSeed, authNodePtr, &node, &tmp);
        }

        @memcpy(node[0..cbHashOutput], tmp[0..cbHashOutput]);
    }

    @memcpy(pbOutput[0..cbHashOutput], node[0..cbHashOutput]);
}

pub export fn SymCryptXmssRandomizedHash(
    pParams: PCSYMCRYPT_XMSS_PARAMS,
    Idx: UINT64,
    pbRandomizer: PCBYTE,
    pbRoot: PCBYTE,
    pbMsg: PCBYTE,
    cbMsg: SIZE_T,
    pbOutput: PBYTE,
) callconv(SYMCRYPT_CALL) void {
    var state: SYMCRYPT_HASH_STATE = undefined;
    var idxBuf: [SYMCRYPT_HASH_MAX_RESULT_SIZE]BYTE = undefined;
    const cbHashOutput: SIZE_T = pParams.cbHashOutput;

    hash.SymCryptWipe(@ptrCast(&idxBuf), cbHashOutput);
    macros.STORE_MSBFIRST64(@as(PBYTE, @ptrCast(&idxBuf)) + (cbHashOutput - @sizeOf(UINT64)), Idx);

    SymCryptXmssPrfInit(pParams.hash.?, SYMCRYPT_XMSS_H_MSG, pParams.cbPrefix, &state);
    hash.SymCryptHashAppend(pParams.hash.?, @ptrCast(&state), pbRandomizer, cbHashOutput);
    hash.SymCryptHashAppend(pParams.hash.?, @ptrCast(&state), pbRoot, cbHashOutput);
    hash.SymCryptHashAppend(pParams.hash.?, @ptrCast(&state), &idxBuf, cbHashOutput);
    hash.SymCryptHashAppend(pParams.hash.?, @ptrCast(&state), pbMsg, cbMsg);
    hash.SymCryptHashResult(pParams.hash.?, @ptrCast(&state), pbOutput, cbHashOutput);
}

pub export fn SymCryptXmssWotspPublickeyFromSignature(
    pParams: PCSYMCRYPT_XMSS_PARAMS,
    adrs: PXMSS_ADRS,
    idx: UINT32,
    pbMsg: PCBYTE,
    pbSeed: PCBYTE,
    pbSignature: PCBYTE,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
    pbOutput: PBYTE,
) callconv(SYMCRYPT_CALL) void {
    var digit: UINT32 = 0;
    var checksum: UINT32 = 0;
    var en32Checksum: [4]BYTE = undefined;
    const maxChainIndex: UINT32 = (@as(UINT32, 1) << @intCast(pParams.nWinternitzWidth)) - 1;
    var ctxIncHash: SYMCRYPT_XMSS_INCREMENTAL_TREEHASH_CONTEXT = undefined;

    SymCryptXmssSetAdrsType(adrs, XMSS_ADRS_TYPE_LTREE);
    macros.STORE_MSBFIRST32(&adrs.u.ltree.en32Leaf, idx);

    ctxIncHash.adrs = adrs.*;
    ctxIncHash.pParams = pParams;
    ctxIncHash.pbSeed = pbSeed;

    const pIncHash = SymCryptHbsIncrementalTreehashInit(
        pParams.len,
        pbScratch,
        cbScratch,
        pParams.cbHashOutput,
        &SymCryptXmssLtreeNodeCompress,
        &ctxIncHash,
    );

    var i: UINT32 = 0;
    while (i < pParams.len) : (i += 1) {
        if (i < pParams.len1) {
            digit = SymCryptHbsGetDigit(pParams.nWinternitzWidth, pbMsg, pParams.cbHashOutput, i);
            checksum += maxChainIndex - digit;
        } else {
            if (i == pParams.len1) {
                checksum <<= @intCast(pParams.nLeftShift32);
                macros.STORE_MSBFIRST32(&en32Checksum, checksum);
            }

            digit = SymCryptHbsGetDigit(pParams.nWinternitzWidth, &en32Checksum, @sizeOf(@TypeOf(en32Checksum)), i - pParams.len1);
        }

        const pNode = SymCryptHbsIncrementalTreehashAllocNode(pIncHash, i);

        SymCryptXmssSetAdrsType(adrs, XMSS_ADRS_TYPE_OTS);
        macros.STORE_MSBFIRST32(&adrs.u.ots.en32Leaf, idx);
        macros.STORE_MSBFIRST32(&adrs.u.ots.en32Chain, i);

        SymCryptXmssChain(
            pParams,
            pbSignature + (@as(SIZE_T, pParams.cbHashOutput) * @as(SIZE_T, i)),
            digit,
            maxChainIndex - digit,
            pbSeed,
            adrs,
            nodeValue(pNode),
        );

        _ = SymCryptHbsIncrementalTreehashProcess(pIncHash);
    }

    const pRootNode = SymCryptHbsIncrementalTreehashFinalize(pIncHash).?;

    @memcpy(pbOutput[0..pParams.cbHashOutput], nodeValue(pRootNode)[0..pParams.cbHashOutput]);
}

pub export fn SymCryptXmssTreeRootFromSignature(
    pParams: PCSYMCRYPT_XMSS_PARAMS,
    adrs: PXMSS_ADRS,
    pbSeed: PCBYTE,
    pbHash: PCBYTE,
    uLeaf: UINT32,
    pbWotspSig: PCBYTE,
    pbAuthNodes: PCBYTE,
    pbOutput: PBYTE,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    var WotspPublickey: [SYMCRYPT_HASH_MAX_RESULT_SIZE]BYTE = undefined;

    SymCryptXmssWotspPublickeyFromSignature(
        pParams,
        adrs,
        uLeaf,
        pbHash,
        pbSeed,
        pbWotspSig,
        pbScratch,
        cbScratch,
        &WotspPublickey,
    );

    SymCryptXmssTreeRootFromAuthenticationPath(
        pParams,
        adrs,
        uLeaf,
        &WotspPublickey,
        pbAuthNodes,
        pbSeed,
        pbOutput,
    );
}

pub export fn SymCryptXmssSizeofWotspSignature(
    pParams: PCSYMCRYPT_XMSS_PARAMS,
) callconv(SYMCRYPT_CALL) SIZE_T {
    return @as(SIZE_T, pParams.cbHashOutput) * @as(SIZE_T, pParams.len);
}

pub export fn SymCryptXmssSizeofAuthNodes(
    pParams: PCSYMCRYPT_XMSS_PARAMS,
) callconv(SYMCRYPT_CALL) SIZE_T {
    return @as(SIZE_T, pParams.cbHashOutput) * @as(SIZE_T, pParams.nLayerHeight);
}

pub export fn SymCryptXmssSignatureGetIdx(
    pParams: PCSYMCRYPT_XMSS_PARAMS,
    pbSig: PCBYTE,
) callconv(SYMCRYPT_CALL) UINT64 {
    var Idx: UINT64 = 0;

    macros.ASSERT(pParams.cbIdx > 0 and pParams.cbIdx <= @sizeOf(UINT64));

    var i: UINT32 = 0;
    while (i < pParams.cbIdx) : (i += 1) {
        Idx <<= 8;
        Idx |= @as(UINT64, pbSig[i]);
    }

    return Idx;
}

pub export fn SymCryptXmssSignatureGetRandomness(
    pParams: PCSYMCRYPT_XMSS_PARAMS,
    pbSig: PCBYTE,
) callconv(SYMCRYPT_CALL) PBYTE {
    var pb: PBYTE = @constCast(pbSig);
    pb += pParams.cbIdx;
    return pb;
}

pub export fn SymCryptXmssSignatureGetWotspSig(
    pParams: PCSYMCRYPT_XMSS_PARAMS,
    pbSig: PCBYTE,
    uLayer: UINT32,
) callconv(SYMCRYPT_CALL) PBYTE {
    var pb: PBYTE = SymCryptXmssSignatureGetRandomness(pParams, pbSig);
    pb += pParams.cbHashOutput;
    pb += @as(SIZE_T, uLayer) * (SymCryptXmssSizeofWotspSignature(pParams) + SymCryptXmssSizeofAuthNodes(pParams));
    return pb;
}

pub export fn SymCryptXmssSignatureGetAuthNodes(
    pParams: PCSYMCRYPT_XMSS_PARAMS,
    pbSig: PCBYTE,
    uLayer: UINT32,
) callconv(SYMCRYPT_CALL) PBYTE {
    var pb: PBYTE = SymCryptXmssSignatureGetWotspSig(pParams, pbSig, uLayer);
    pb += SymCryptXmssSizeofWotspSignature(pParams);
    return pb;
}

pub export fn SymCryptXmssVerifyInternal(
    pKey: PSYMCRYPT_XMSS_KEY,
    pbMessage: PCBYTE,
    cbMessage: SIZE_T,
    flags: UINT32,
    pbSignatureOpt: ?PCBYTE,
    cbSignature: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    const pParams: PCSYMCRYPT_XMSS_PARAMS = &pKey.params;
    var RandomizedHash: [SYMCRYPT_HASH_MAX_RESULT_SIZE]BYTE = undefined;
    var ComputedRoot: [SYMCRYPT_HASH_MAX_RESULT_SIZE]BYTE = undefined;
    var adrs: XMSS_ADRS = undefined;

    macros.CHECK_MAGIC(pKey);
    macros.ASSERT(pParams.nLayerHeight < 32);

    const pbSignature = pbSignatureOpt orelse return .SYMCRYPT_INVALID_ARGUMENT;
    if (flags != 0 or
        cbSignature != SymCryptXmssSizeofSignatureFromParams(pParams) or
        pKey.keyType == .SYMCRYPT_XMSSKEY_TYPE_NONE)
    {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    const nLayerLeaves: UINT32 = @as(UINT32, 1) << @intCast(pParams.nLayerHeight);
    var cbScratch: SIZE_T = 0;
    cbScratch += SymCryptHbsSizeofScratchBytesForIncrementalTreehash(pParams.cbHashOutput, pParams.len);
    cbScratch += SymCryptHbsSizeofScratchBytesForIncrementalTreehash(pParams.cbHashOutput, nLayerLeaves);

    const pbScratch = SymCryptCallbackAlloc(cbScratch) orelse return .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
    defer {
        hash.SymCryptWipe(@ptrCast(pbScratch), cbScratch);
        SymCryptCallbackFree(@ptrCast(pbScratch));
    }

    const pbRandomness: PBYTE = SymCryptXmssSignatureGetRandomness(pParams, pbSignature);
    var Idx: UINT64 = SymCryptXmssSignatureGetIdx(pParams, pbSignature);

    SymCryptXmssRandomizedHash(
        pParams,
        Idx,
        pbRandomness,
        &pKey.Root,
        pbMessage,
        cbMessage,
        &RandomizedHash,
    );

    hash.SymCryptWipeKnownSize(@ptrCast(&adrs), @sizeOf(XMSS_ADRS));

    const LeafMask: UINT64 = (@as(UINT64, 1) << @intCast(pParams.nLayerHeight)) - 1;
    var uLayer: UINT32 = 0;
    while (uLayer < pParams.nLayers) : (uLayer += 1) {
        const uTree: UINT64 = Idx >> @intCast(pParams.nLayerHeight);
        const uLeaf: UINT32 = @truncate(Idx & LeafMask);

        macros.STORE_MSBFIRST32(&adrs.en32Layer, uLayer);
        macros.STORE_MSBFIRST64(&adrs.en64Tree, uTree);
        SymCryptXmssTreeRootFromSignature(
            pParams,
            &adrs,
            &pKey.Seed,
            if (uLayer == 0) &RandomizedHash else &ComputedRoot,
            uLeaf,
            SymCryptXmssSignatureGetWotspSig(pParams, pbSignature, uLayer),
            SymCryptXmssSignatureGetAuthNodes(pParams, pbSignature, uLayer),
            &ComputedRoot,
            pbScratch,
            cbScratch,
        );

        Idx >>= @intCast(pParams.nLayerHeight);
    }

    if (equal.SymCryptEqual(&ComputedRoot, &pKey.Root, pParams.cbHashOutput) == 0) {
        return .SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE;
    }

    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptXmssVerify(
    pKey: PSYMCRYPT_XMSS_KEY,
    pbMessage: PCBYTE,
    cbMessage: SIZE_T,
    flags: UINT32,
    pbSignature: ?PCBYTE,
    cbSignature: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    if (types.DO_FIPS_SELFTESTS) {
        if ((@atomicLoad(UINT32, &g_SymCryptFipsSelftestsPerformed, .unordered) & SYMCRYPT_SELFTEST_ALGORITHM_XMSS) == 0) {
            SymCryptXmssSelftest();
            _ = @atomicRmw(UINT32, &g_SymCryptFipsSelftestsPerformed, .Or, SYMCRYPT_SELFTEST_ALGORITHM_XMSS, .monotonic);
        }
    }

    return SymCryptXmssVerifyInternal(
        pKey,
        pbMessage,
        cbMessage,
        flags,
        pbSignature,
        cbSignature,
    );
}

pub export fn SymCryptXmssWotspSign(
    pParams: PCSYMCRYPT_XMSS_PARAMS,
    adrs: PXMSS_ADRS,
    pbInput: PCBYTE,
    uLeaf: UINT32,
    pbSeed: PCBYTE,
    pbSkXmss: PCBYTE,
    pbOutput: PBYTE,
) callconv(SYMCRYPT_CALL) void {
    var node: [SYMCRYPT_HASH_MAX_RESULT_SIZE]BYTE = undefined;
    var nChecksum: UINT32 = 0;
    var en32Checksum: [4]BYTE = undefined;
    var digit: UINT32 = 0;
    const maxChainIndex: UINT32 = (@as(UINT32, 1) << @intCast(pParams.nWinternitzWidth)) - 1;

    SymCryptXmssSetAdrsType(adrs, XMSS_ADRS_TYPE_OTS);
    macros.STORE_MSBFIRST32(&adrs.u.ots.en32Leaf, uLeaf);

    var i: UINT32 = 0;
    while (i < pParams.len) : (i += 1) {
        macros.STORE_MSBFIRST32(&adrs.u.ots.en32Chain, i);
        SymCryptXmssCreateWotspSecret(
            pParams,
            pbSkXmss,
            pbSeed,
            adrs,
            &node,
        );

        if (i < pParams.len1) {
            digit = SymCryptHbsGetDigit(pParams.nWinternitzWidth, pbInput, pParams.cbHashOutput, i);
            nChecksum += maxChainIndex - digit;
        } else {
            if (i == pParams.len1) {
                nChecksum <<= @intCast(pParams.nLeftShift32);
                macros.STORE_MSBFIRST32(&en32Checksum, nChecksum);
            }

            digit = SymCryptHbsGetDigit(pParams.nWinternitzWidth, &en32Checksum, @sizeOf(@TypeOf(en32Checksum)), i - pParams.len1);
        }

        SymCryptXmssChain(
            pParams,
            &node,
            0,
            digit,
            pbSeed,
            adrs,
            pbOutput + (@as(SIZE_T, i) * @as(SIZE_T, pParams.cbHashOutput)),
        );
    }

    hash.SymCryptWipeKnownSize(@ptrCast(&node), @sizeOf(@TypeOf(node)));
}

pub export fn SymCryptXmssTreeSignHash(
    pParams: PCSYMCRYPT_XMSS_PARAMS,
    adrs: PXMSS_ADRS,
    pbSkXmss: PCBYTE,
    pbSeed: PCBYTE,
    pbHash: PCBYTE,
    Idx: UINT32,
    pbWotspSig: PBYTE,
    pbAuthNodes: PBYTE,
    pbRootOpt: ?PBYTE,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    var WotspPublicKey: [SYMCRYPT_HASH_MAX_RESULT_SIZE]BYTE = undefined;

    SymCryptXmssWotspSign(
        pParams,
        adrs,
        pbHash,
        Idx,
        pbSeed,
        pbSkXmss,
        pbWotspSig,
    );

    // Generate authentication path
    var h: UINT32 = 0;
    while (h < pParams.nLayerHeight) : (h += 1) {
        const shift: u5 = @intCast(h);
        const uLeaf: UINT32 = ((Idx >> shift) ^ 1) << shift;
        SymCryptXmssComputeSubtreeRoot(
            pParams,
            adrs,
            pbSkXmss,
            pbSeed,
            uLeaf,
            h,
            pbScratch,
            cbScratch,
            pbAuthNodes + (@as(SIZE_T, h) * @as(SIZE_T, pParams.cbHashOutput)),
        );
    }

    if (pbRootOpt) |pbRoot| {
        SymCryptXmssCreateWotspPublickey(
            pParams,
            adrs,
            Idx,
            pbSkXmss,
            pbSeed,
            pbScratch,
            cbScratch,
            &WotspPublicKey,
        );

        SymCryptXmssTreeRootFromAuthenticationPath(
            pParams,
            adrs,
            Idx,
            &WotspPublicKey,
            pbAuthNodes,
            pbSeed,
            pbRoot,
        );
    }
}

pub export fn SymCryptXmssComputeRandomness(
    pKey: PCSYMCRYPT_XMSS_KEY,
    Idx: UINT64,
    pbRandomness: PBYTE,
) callconv(SYMCRYPT_CALL) void {
    var IdxBuffer: [32]BYTE = undefined;

    hash.SymCryptWipeKnownSize(@ptrCast(&IdxBuffer), @sizeOf(@TypeOf(IdxBuffer)));
    macros.STORE_MSBFIRST64(@as(PBYTE, @ptrCast(&IdxBuffer)) + (@sizeOf(@TypeOf(IdxBuffer)) - @sizeOf(UINT64)), Idx);

    SymCryptXmssPrf(
        &pKey.params,
        SYMCRYPT_XMSS_PRF,
        &pKey.SkPrf,
        pKey.params.cbHashOutput,
        &IdxBuffer,
        @sizeOf(@TypeOf(IdxBuffer)),
        pbRandomness,
    );
}

pub export fn SymCryptXmssSign(
    pKey: PSYMCRYPT_XMSS_KEY,
    pbMessage: PCBYTE,
    cbMessage: SIZE_T,
    flags: UINT32,
    pbSignatureOpt: ?PBYTE,
    cbSignature: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    const pParams: PSYMCRYPT_XMSS_PARAMS = &pKey.params;
    var en64Idx: [8]BYTE = undefined;
    var Randomness: [SYMCRYPT_HASH_MAX_RESULT_SIZE]BYTE = undefined;
    var RandomizedHash: [SYMCRYPT_HASH_MAX_RESULT_SIZE]BYTE = undefined;
    var TreeRoot: [SYMCRYPT_HASH_MAX_RESULT_SIZE]BYTE = undefined;
    var adrs: XMSS_ADRS = undefined;

    macros.CHECK_MAGIC(pKey);
    macros.ASSERT(pParams.nLayerHeight < 32);

    const pbSignature = pbSignatureOpt orelse return .SYMCRYPT_INVALID_ARGUMENT;
    if (flags != 0 or
        cbSignature != SymCryptXmssSizeofSignatureFromParams(pParams) or
        pKey.keyType != .SYMCRYPT_XMSSKEY_TYPE_PRIVATE)
    {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    const nLayerLeaves: UINT32 = @as(UINT32, 1) << @intCast(pParams.nLayerHeight);
    var cbScratch: SIZE_T = 0;
    cbScratch += SymCryptHbsSizeofScratchBytesForIncrementalTreehash(pParams.cbHashOutput, pParams.len);
    cbScratch += SymCryptHbsSizeofScratchBytesForIncrementalTreehash(pParams.cbHashOutput, nLayerLeaves);

    const pbScratch = SymCryptCallbackAlloc(cbScratch) orelse return .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
    defer {
        hash.SymCryptWipe(@ptrCast(pbScratch), cbScratch);
        SymCryptCallbackFree(@ptrCast(pbScratch));
    }

    var Idx: UINT64 = @atomicRmw(UINT64, &pKey.Idx, .Add, 1, .monotonic);
    const maxLeaves: UINT64 = @as(UINT64, 1) << @intCast(pParams.nTotalTreeHeight);
    if (Idx >= maxLeaves) {
        pKey.Idx = maxLeaves;
        return .SYMCRYPT_HBS_NO_OTS_KEYS_LEFT;
    }

    macros.STORE_MSBFIRST64(&en64Idx, Idx);
    const cbIdx: SIZE_T = pParams.cbIdx;
    @memcpy(pbSignature[0..cbIdx], en64Idx[(@sizeOf(@TypeOf(en64Idx)) - cbIdx)..][0..cbIdx]);

    const cbHashOutput: SIZE_T = pKey.params.cbHashOutput;
    SymCryptXmssComputeRandomness(pKey, Idx, &Randomness);
    @memcpy(SymCryptXmssSignatureGetRandomness(pParams, pbSignature)[0..cbHashOutput], Randomness[0..cbHashOutput]);

    SymCryptXmssRandomizedHash(&pKey.params, Idx, &Randomness, &pKey.Root, pbMessage, cbMessage, &RandomizedHash);

    hash.SymCryptWipeKnownSize(@ptrCast(&adrs), @sizeOf(XMSS_ADRS));

    const LeafMask: UINT64 = (@as(UINT64, 1) << @intCast(pParams.nLayerHeight)) - 1;
    var uLayer: UINT32 = 0;
    while (uLayer < pParams.nLayers) : (uLayer += 1) {
        const uTree: UINT64 = Idx >> @intCast(pParams.nLayerHeight);
        const uLeaf: UINT32 = @truncate(Idx & LeafMask);

        macros.STORE_MSBFIRST32(&adrs.en32Layer, uLayer);
        macros.STORE_MSBFIRST64(&adrs.en64Tree, uTree);

        SymCryptXmssTreeSignHash(
            &pKey.params,
            &adrs,
            &pKey.SkXmss,
            &pKey.Seed,
            if (uLayer == 0) &RandomizedHash else &TreeRoot,
            uLeaf,
            SymCryptXmssSignatureGetWotspSig(pParams, pbSignature, uLayer),
            SymCryptXmssSignatureGetAuthNodes(pParams, pbSignature, uLayer),
            if (uLayer == (pParams.nLayers - 1)) null else &TreeRoot,
            pbScratch,
            cbScratch,
        );

        Idx >>= @intCast(pParams.nLayerHeight);
    }

    return .SYMCRYPT_NO_ERROR;
}

comptime {
    std.debug.assert(@sizeOf(XMSS_ADRS) == 32);
    std.debug.assert(@sizeOf(SYMCRYPT_TREEHASH_NODE) == 12);
    std.debug.assert(@alignOf(SYMCRYPT_XMSS_PARAMS) == SYMCRYPT_ALIGN_VALUE);
    std.debug.assert(@alignOf(SYMCRYPT_XMSS_KEY) == SYMCRYPT_ASYM_ALIGN_VALUE);
    std.debug.assert((@offsetOf(SYMCRYPT_XMSS_KEY, "Idx") % 16) == 0);
}
