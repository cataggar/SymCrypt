//
// types.zig
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
// Core C ABI types, constants, enums, and virtual table structures matching
// inc/symcrypt.h, inc/symcrypt_internal.h, inc/symcrypt_low_level.h, and lib/sc_lib.h.
//

const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");

// ==============================================================================================
// Build Configuration & Version Constants
// ==============================================================================================

pub const IGNORE_PLATFORM: bool = !build_options.use_asm;
pub const DO_FIPS_SELFTESTS: bool = build_options.fips_build;
pub const USE_FIPS_ENTROPY: bool = build_options.fips_build;
pub const DEBUG: bool = builtin.mode == .debug;

pub const CODE_VERSION_API: u32 = @intCast(build_options.symcrypt_version.major);
pub const CODE_VERSION_MINOR: u32 = @intCast(build_options.symcrypt_version.minor);
pub const CODE_VERSION_PATCH: u32 = @intCast(build_options.symcrypt_version.patch);
pub const SYMCRYPT_API_VERSION: u32 = (CODE_VERSION_API << 16) | CODE_VERSION_MINOR;

pub const CPU_X86: bool = builtin.cpu.arch == .x86 and !IGNORE_PLATFORM;
pub const CPU_AMD64: bool = builtin.cpu.arch == .x86_64 and !IGNORE_PLATFORM;
pub const CPU_ARM: bool = builtin.cpu.arch == .arm and !IGNORE_PLATFORM;
pub const CPU_ARM64: bool = builtin.cpu.arch == .aarch64 and !IGNORE_PLATFORM;
pub const CPU_UNKNOWN: bool = IGNORE_PLATFORM;

// ==============================================================================================
// Calling Convention & Alignment
// ==============================================================================================

pub const SYMCRYPT_CALL: std.builtin.CallingConvention =
    if (CPU_X86)
        .{ .x86_fastcall = .{} }
    else
        .c;

pub const SYMCRYPT_ALIGN_VALUE: usize = if (CPU_X86)
    4
else if (CPU_ARM)
    8
else
    16;

// ==============================================================================================
// Basic Types
// ==============================================================================================

pub const BYTE = u8;
pub const PBYTE = [*]u8;
pub const PCBYTE = [*]const u8;

pub const CHAR = u8;

pub const INT8 = i8;
pub const PINT8 = [*]i8;
pub const UINT8 = u8;
pub const PUINT8 = [*]u8;

pub const INT16 = i16;
pub const PINT16 = [*]i16;
pub const UINT16 = u16;
pub const PUINT16 = [*]u16;
pub const PCUINT16 = [*]const u16;

pub const INT32 = i32;
pub const PINT32 = [*]i32;
pub const UINT32 = u32;
pub const PUINT32 = [*]u32;
pub const PCUINT32 = [*]const u32;

pub const INT64 = i64;
pub const PINT64 = [*]i64;
pub const UINT64 = u64;
pub const PUINT64 = [*]u64;
pub const PCUINT64 = [*]const u64;

pub const SIZE_T = usize;
pub const PSIZE_T = *usize;

pub const BOOL = c_int;
pub const BOOLEAN = u8;

pub const PVOID = ?*anyopaque;
pub const PCVOID = ?*const anyopaque;

pub const TRUE: u8 = 1;
pub const FALSE: u8 = 0;

pub const UINT32_MAX: u32 = 0xffffffff;
pub const SIZE_T_MAX: usize = std.math.maxInt(usize);

const is_native_64 = CPU_AMD64 or CPU_ARM64;
pub const NATIVE_INT = if (is_native_64) INT64 else INT32;
pub const NATIVE_UINT = if (is_native_64) UINT64 else UINT32;
pub const NATIVE_BITS: comptime_int = if (is_native_64) 64 else 32;
pub const NATIVE_BYTES: comptime_int = if (is_native_64) 8 else 4;
pub const NATIVE_BYTES_LOG2: comptime_int = if (is_native_64) 3 else 2;

// ==============================================================================================
// CPU Feature Flags
// ==============================================================================================

pub const SYMCRYPT_CPU_FEATURES = UINT32;

pub const SYMCRYPT_CPU_FEATURE_NEON: u32 = 0x01;
pub const SYMCRYPT_CPU_FEATURE_NEON_AES: u32 = 0x02;
pub const SYMCRYPT_CPU_FEATURE_NEON_PMULL: u32 = 0x04;
pub const SYMCRYPT_CPU_FEATURE_NEON_SHA256: u32 = 0x08;

pub const SYMCRYPT_CPU_FEATURE_SSE2: u32 = 0x0001;
pub const SYMCRYPT_CPU_FEATURE_SSSE3: u32 = 0x0002;
pub const SYMCRYPT_CPU_FEATURE_AESNI: u32 = 0x0004;
pub const SYMCRYPT_CPU_FEATURE_PCLMULQDQ: u32 = 0x0008;
pub const SYMCRYPT_CPU_FEATURE_AVX2: u32 = 0x0010;
pub const SYMCRYPT_CPU_FEATURE_SAVEXMM_NOFAIL: u32 = 0x0020;
pub const SYMCRYPT_CPU_FEATURE_SHANI: u32 = 0x0040;
pub const SYMCRYPT_CPU_FEATURE_BMI2: u32 = 0x0080;
pub const SYMCRYPT_CPU_FEATURE_ADX: u32 = 0x0100;
pub const SYMCRYPT_CPU_FEATURE_RDRAND: u32 = 0x0200;
pub const SYMCRYPT_CPU_FEATURE_RDSEED: u32 = 0x0400;
pub const SYMCRYPT_CPU_FEATURE_VAES: u32 = 0x0800;
pub const SYMCRYPT_CPU_FEATURE_AVX512: u32 = 0x1000;
pub const SYMCRYPT_CPU_FEATURE_CMPXCHG16B: u32 = 0x2000;
pub const SYMCRYPT_CPU_FEATURE_SAVEYMM_NOFAIL: u32 = 0x4000;
pub const SYMCRYPT_CPU_FEATURE_SAVEZMM_NOFAIL: u32 = 0x8000;

pub const SYMCRYPT_FLAG_LIB_INITIALIZED: u32 = 0x00000001;

// ==============================================================================================
// Error Codes & Algorithm ID Enums
// ==============================================================================================

pub const SYMCRYPT_ERROR = enum(c_int) {
    SYMCRYPT_NO_ERROR = 0,
    SYMCRYPT_UNUSED = 0x8000,
    SYMCRYPT_WRONG_KEY_SIZE = 0x8001,
    SYMCRYPT_WRONG_BLOCK_SIZE = 0x8002,
    SYMCRYPT_WRONG_DATA_SIZE = 0x8003,
    SYMCRYPT_WRONG_NONCE_SIZE = 0x8004,
    SYMCRYPT_WRONG_TAG_SIZE = 0x8005,
    SYMCRYPT_WRONG_ITERATION_COUNT = 0x8006,
    SYMCRYPT_AUTHENTICATION_FAILURE = 0x8007,
    SYMCRYPT_EXTERNAL_FAILURE = 0x8008,
    SYMCRYPT_FIPS_FAILURE = 0x8009,
    SYMCRYPT_HARDWARE_FAILURE = 0x800a,
    SYMCRYPT_NOT_IMPLEMENTED = 0x800b,
    SYMCRYPT_INVALID_BLOB = 0x800c,
    SYMCRYPT_BUFFER_TOO_SMALL = 0x800d,
    SYMCRYPT_INVALID_ARGUMENT = 0x800e,
    SYMCRYPT_MEMORY_ALLOCATION_FAILURE = 0x800f,
    SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE = 0x8010,
    SYMCRYPT_INCOMPATIBLE_FORMAT = 0x8011,
    SYMCRYPT_VALUE_TOO_LARGE = 0x8012,
    SYMCRYPT_SESSION_REPLAY_FAILURE = 0x8013,
    SYMCRYPT_HBS_NO_OTS_KEYS_LEFT = 0x8014,
    SYMCRYPT_HBS_PUBLIC_ROOT_MISMATCH = 0x8015,
    _,
};

pub const SYMCRYPT_NO_ERROR = SYMCRYPT_ERROR.SYMCRYPT_NO_ERROR;
pub const SYMCRYPT_UNUSED = SYMCRYPT_ERROR.SYMCRYPT_UNUSED;
pub const SYMCRYPT_WRONG_KEY_SIZE = SYMCRYPT_ERROR.SYMCRYPT_WRONG_KEY_SIZE;
pub const SYMCRYPT_WRONG_BLOCK_SIZE = SYMCRYPT_ERROR.SYMCRYPT_WRONG_BLOCK_SIZE;
pub const SYMCRYPT_WRONG_DATA_SIZE = SYMCRYPT_ERROR.SYMCRYPT_WRONG_DATA_SIZE;
pub const SYMCRYPT_WRONG_NONCE_SIZE = SYMCRYPT_ERROR.SYMCRYPT_WRONG_NONCE_SIZE;
pub const SYMCRYPT_WRONG_TAG_SIZE = SYMCRYPT_ERROR.SYMCRYPT_WRONG_TAG_SIZE;
pub const SYMCRYPT_WRONG_ITERATION_COUNT = SYMCRYPT_ERROR.SYMCRYPT_WRONG_ITERATION_COUNT;
pub const SYMCRYPT_AUTHENTICATION_FAILURE = SYMCRYPT_ERROR.SYMCRYPT_AUTHENTICATION_FAILURE;
pub const SYMCRYPT_EXTERNAL_FAILURE = SYMCRYPT_ERROR.SYMCRYPT_EXTERNAL_FAILURE;
pub const SYMCRYPT_FIPS_FAILURE = SYMCRYPT_ERROR.SYMCRYPT_FIPS_FAILURE;
pub const SYMCRYPT_HARDWARE_FAILURE = SYMCRYPT_ERROR.SYMCRYPT_HARDWARE_FAILURE;
pub const SYMCRYPT_NOT_IMPLEMENTED = SYMCRYPT_ERROR.SYMCRYPT_NOT_IMPLEMENTED;
pub const SYMCRYPT_INVALID_BLOB = SYMCRYPT_ERROR.SYMCRYPT_INVALID_BLOB;
pub const SYMCRYPT_BUFFER_TOO_SMALL = SYMCRYPT_ERROR.SYMCRYPT_BUFFER_TOO_SMALL;
pub const SYMCRYPT_INVALID_ARGUMENT = SYMCRYPT_ERROR.SYMCRYPT_INVALID_ARGUMENT;
pub const SYMCRYPT_MEMORY_ALLOCATION_FAILURE = SYMCRYPT_ERROR.SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
pub const SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE = SYMCRYPT_ERROR.SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE;
pub const SYMCRYPT_INCOMPATIBLE_FORMAT = SYMCRYPT_ERROR.SYMCRYPT_INCOMPATIBLE_FORMAT;
pub const SYMCRYPT_VALUE_TOO_LARGE = SYMCRYPT_ERROR.SYMCRYPT_VALUE_TOO_LARGE;
pub const SYMCRYPT_SESSION_REPLAY_FAILURE = SYMCRYPT_ERROR.SYMCRYPT_SESSION_REPLAY_FAILURE;
pub const SYMCRYPT_HBS_NO_OTS_KEYS_LEFT = SYMCRYPT_ERROR.SYMCRYPT_HBS_NO_OTS_KEYS_LEFT;
pub const SYMCRYPT_HBS_PUBLIC_ROOT_MISMATCH = SYMCRYPT_ERROR.SYMCRYPT_HBS_PUBLIC_ROOT_MISMATCH;

pub const SYMCRYPT_HASH_ID = enum(c_int) {
    SYMCRYPT_HASH_ID_NULL = 0,
    SYMCRYPT_HASH_ID_MD2 = 1,
    SYMCRYPT_HASH_ID_MD4 = 2,
    SYMCRYPT_HASH_ID_MD5 = 3,
    SYMCRYPT_HASH_ID_SHA1 = 4,
    SYMCRYPT_HASH_ID_SHA224 = 5,
    SYMCRYPT_HASH_ID_SHA256 = 6,
    SYMCRYPT_HASH_ID_SHA384 = 7,
    SYMCRYPT_HASH_ID_SHA512 = 8,
    SYMCRYPT_HASH_ID_SHA512_224 = 9,
    SYMCRYPT_HASH_ID_SHA512_256 = 10,
    SYMCRYPT_HASH_ID_SHA3_224 = 11,
    SYMCRYPT_HASH_ID_SHA3_256 = 12,
    SYMCRYPT_HASH_ID_SHA3_384 = 13,
    SYMCRYPT_HASH_ID_SHA3_512 = 14,
    SYMCRYPT_HASH_ID_SHAKE128 = 15,
    SYMCRYPT_HASH_ID_SHAKE256 = 16,
    _,
};

pub const SYMCRYPT_MAC_ID = enum(c_int) {
    SYMCRYPT_MAC_ID_NULL = 0,
    SYMCRYPT_MAC_ID_HMAC_MD5 = 1,
    SYMCRYPT_MAC_ID_HMAC_SHA1 = 2,
    SYMCRYPT_MAC_ID_HMAC_SHA224 = 3,
    SYMCRYPT_MAC_ID_HMAC_SHA256 = 4,
    SYMCRYPT_MAC_ID_HMAC_SHA384 = 5,
    SYMCRYPT_MAC_ID_HMAC_SHA512 = 6,
    SYMCRYPT_MAC_ID_HMAC_SHA512_224 = 7,
    SYMCRYPT_MAC_ID_HMAC_SHA512_256 = 8,
    SYMCRYPT_MAC_ID_HMAC_SHA3_224 = 9,
    SYMCRYPT_MAC_ID_HMAC_SHA3_256 = 10,
    SYMCRYPT_MAC_ID_HMAC_SHA3_384 = 11,
    SYMCRYPT_MAC_ID_HMAC_SHA3_512 = 12,
    SYMCRYPT_MAC_ID_AES_CMAC = 13,
    SYMCRYPT_MAC_ID_KMAC_128 = 14,
    SYMCRYPT_MAC_ID_KMAC_256 = 15,
    _,
};

pub const SYMCRYPT_BLOCKCIPHER_ID = enum(c_int) {
    SYMCRYPT_BLOCKCIPHER_ID_NULL = 0,
    SYMCRYPT_BLOCKCIPHER_ID_AES = 1,
    SYMCRYPT_BLOCKCIPHER_ID_DES = 2,
    SYMCRYPT_BLOCKCIPHER_ID_3DES = 3,
    SYMCRYPT_BLOCKCIPHER_ID_DESX = 4,
    SYMCRYPT_BLOCKCIPHER_ID_RC2 = 5,
    _,
};

pub const SYMCRYPT_ECURVE_ID = enum(c_int) {
    SYMCRYPT_ECURVE_ID_NULL = 0,
    SYMCRYPT_ECURVE_ID_NIST_P192 = 1,
    SYMCRYPT_ECURVE_ID_NIST_P224 = 2,
    SYMCRYPT_ECURVE_ID_NIST_P256 = 3,
    SYMCRYPT_ECURVE_ID_NIST_P384 = 4,
    SYMCRYPT_ECURVE_ID_NIST_P521 = 5,
    SYMCRYPT_ECURVE_ID_NUMS_P256T1 = 6,
    SYMCRYPT_ECURVE_ID_NUMS_P384T1 = 7,
    SYMCRYPT_ECURVE_ID_NUMS_P512T1 = 8,
    SYMCRYPT_ECURVE_ID_CURVE25519 = 9,
    _,
};

pub const SYMCRYPT_OID_LIST_ID = enum(c_int) {
    SYMCRYPT_OID_LIST_ID_NULL = 0,
    SYMCRYPT_OID_LIST_ID_MD5 = 1,
    SYMCRYPT_OID_LIST_ID_SHA1 = 2,
    SYMCRYPT_OID_LIST_ID_SHA224 = 3,
    SYMCRYPT_OID_LIST_ID_SHA256 = 4,
    SYMCRYPT_OID_LIST_ID_SHA384 = 5,
    SYMCRYPT_OID_LIST_ID_SHA512 = 6,
    SYMCRYPT_OID_LIST_ID_SHA512_224 = 7,
    SYMCRYPT_OID_LIST_ID_SHA512_256 = 8,
    SYMCRYPT_OID_LIST_ID_SHA3_224 = 9,
    SYMCRYPT_OID_LIST_ID_SHA3_256 = 10,
    SYMCRYPT_OID_LIST_ID_SHA3_384 = 11,
    SYMCRYPT_OID_LIST_ID_SHA3_512 = 12,
    SYMCRYPT_OID_LIST_ID_SHAKE128 = 13,
    SYMCRYPT_OID_LIST_ID_SHAKE256 = 14,
    _,
};

pub const SYMCRYPT_ECURVE_TYPE = enum(c_int) {
    SYMCRYPT_ECURVE_TYPE_NULL = 0,
    SYMCRYPT_ECURVE_TYPE_SHORT_WEIERSTRASS = 1,
    SYMCRYPT_ECURVE_TYPE_TWISTED_EDWARDS = 2,
    SYMCRYPT_ECURVE_TYPE_MONTGOMERY = 3,
    _,
};

pub const SYMCRYPT_DLGROUP_FIPS = enum(c_int) {
    SYMCRYPT_DLGROUP_FIPS_NONE = 0,
    SYMCRYPT_DLGROUP_FIPS_186_2 = 1,
    SYMCRYPT_DLGROUP_FIPS_186_3 = 2,
    _,
};

pub const SYMCRYPT_DLGROUP_DH_SAFEPRIMETYPE = enum(c_int) {
    SYMCRYPT_DLGROUP_DH_SAFEPRIMETYPE_NONE = 0,
    SYMCRYPT_DLGROUP_DH_SAFEPRIMETYPE_IKE_3526 = 1,
    SYMCRYPT_DLGROUP_DH_SAFEPRIMETYPE_TLS_7919 = 2,
    _,
};

pub const SYMCRYPT_HASH_OPERATION_TYPE = enum(c_int) {
    SYMCRYPT_HASH_OPERATION_APPEND = 1,
    SYMCRYPT_HASH_OPERATION_RESULT = 2,
    _,
};

// ==============================================================================================
// Core Function Pointers & Vtable Extern Structs
// ==============================================================================================

pub const SYMCRYPT_OID = extern struct {
    cbOID: UINT32,
    pbOID: ?PCBYTE,
};
pub const PSYMCRYPT_OID = *SYMCRYPT_OID;
pub const PCSYMCRYPT_OID = *const SYMCRYPT_OID;

pub const PSYMCRYPT_HASH_INIT_FUNC = *const fn (pState: PVOID) callconv(SYMCRYPT_CALL) void;
pub const PSYMCRYPT_HASH_APPEND_FUNC = *const fn (pState: PVOID, pbData: PCBYTE, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void;
pub const PSYMCRYPT_HASH_RESULT_FUNC = *const fn (pState: PVOID, pbResult: PVOID) callconv(SYMCRYPT_CALL) void;
pub const PSYMCRYPT_HASH_APPEND_BLOCKS_FUNC = *const fn (pChain: PVOID, pbData: PCBYTE, cbData: SIZE_T, pcbRemaining: *SIZE_T) callconv(SYMCRYPT_CALL) void;
pub const PSYMCRYPT_HASH_STATE_COPY_FUNC = *const fn (pStateSrc: PCVOID, pStateDst: PVOID) callconv(SYMCRYPT_CALL) void;

pub const SYMCRYPT_HASH = extern struct {
    initFunc: ?PSYMCRYPT_HASH_INIT_FUNC align(SYMCRYPT_ALIGN_VALUE),
    appendFunc: ?PSYMCRYPT_HASH_APPEND_FUNC,
    resultFunc: ?PSYMCRYPT_HASH_RESULT_FUNC,
    appendBlockFunc: ?PSYMCRYPT_HASH_APPEND_BLOCKS_FUNC,
    stateCopyFunc: ?PSYMCRYPT_HASH_STATE_COPY_FUNC,
    stateSize: UINT32,
    resultSize: UINT32,
    inputBlockSize: UINT32,
    chainOffset: UINT32,
    chainSize: UINT32,
};
pub const PSYMCRYPT_HASH = *SYMCRYPT_HASH;
pub const PCSYMCRYPT_HASH = *const SYMCRYPT_HASH;

pub const PSYMCRYPT_MAC_EXPAND_KEY = *const fn (pExpandedKey: PVOID, pbKey: PCBYTE, cbKey: SIZE_T) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;
pub const PSYMCRYPT_MAC_INIT = *const fn (pState: PVOID, pExpandedKey: PCVOID) callconv(SYMCRYPT_CALL) void;
pub const PSYMCRYPT_MAC_APPEND = *const fn (pState: PVOID, pbData: PCBYTE, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void;
pub const PSYMCRYPT_MAC_RESULT = *const fn (pState: PVOID, pbResult: PVOID) callconv(SYMCRYPT_CALL) void;
pub const PSYMCRYPT_MAC_RESULT_EX = *const fn (pState: PVOID, pbResult: PVOID, cbResult: SIZE_T) callconv(SYMCRYPT_CALL) void;

pub const SYMCRYPT_MAC = extern struct {
    expandKeyFunc: ?PSYMCRYPT_MAC_EXPAND_KEY,
    initFunc: ?PSYMCRYPT_MAC_INIT,
    appendFunc: ?PSYMCRYPT_MAC_APPEND,
    resultFunc: ?PSYMCRYPT_MAC_RESULT,
    expandedKeySize: SIZE_T,
    stateSize: SIZE_T,
    resultSize: SIZE_T,
    ppHashAlgorithm: ?*const ?PCSYMCRYPT_HASH,
    outerChainingStateOffset: UINT32,
};
pub const PSYMCRYPT_MAC = *SYMCRYPT_MAC;
pub const PCSYMCRYPT_MAC = *const SYMCRYPT_MAC;

pub const SYMCRYPT_MAX_BLOCK_SIZE: usize = 32;

pub const PSYMCRYPT_BLOCKCIPHER_EXPAND_KEY = *const fn (pExpandedKey: PVOID, pbKey: PCBYTE, cbKey: SIZE_T) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;
pub const PSYMCRYPT_BLOCKCIPHER_CRYPT = *const fn (pExpandedKey: PCVOID, pbSrc: PCBYTE, pbDst: PBYTE) callconv(SYMCRYPT_CALL) void;
pub const PSYMCRYPT_BLOCKCIPHER_CRYPT_ECB = *const fn (pExpandedKey: PCVOID, pbSrc: PCBYTE, pbDst: PBYTE, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void;
pub const PSYMCRYPT_BLOCKCIPHER_CRYPT_MODE = *const fn (pExpandedKey: PCVOID, pbChainingValue: PBYTE, pbSrc: PCBYTE, pbDst: PBYTE, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void;
pub const PSYMCRYPT_BLOCKCIPHER_MAC_MODE = *const fn (pExpandedKey: PCVOID, pbChainingValue: PBYTE, pbSrc: PCBYTE, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void;
pub const PSYMCRYPT_BLOCKCIPHER_AEADPART_MODE = *const fn (pState: PVOID, pbSrc: PCBYTE, pbDst: PBYTE, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void;

pub const SYMCRYPT_BLOCKCIPHER = extern struct {
    expandKeyFunc: ?PSYMCRYPT_BLOCKCIPHER_EXPAND_KEY,
    encryptFunc: ?PSYMCRYPT_BLOCKCIPHER_CRYPT,
    decryptFunc: ?PSYMCRYPT_BLOCKCIPHER_CRYPT,
    ecbEncryptFunc: ?PSYMCRYPT_BLOCKCIPHER_CRYPT_ECB,
    ecbDecryptFunc: ?PSYMCRYPT_BLOCKCIPHER_CRYPT_ECB,
    cbcEncryptFunc: ?PSYMCRYPT_BLOCKCIPHER_CRYPT_MODE,
    cbcDecryptFunc: ?PSYMCRYPT_BLOCKCIPHER_CRYPT_MODE,
    cbcMacFunc: ?PSYMCRYPT_BLOCKCIPHER_MAC_MODE,
    ctrMsb64Func: ?PSYMCRYPT_BLOCKCIPHER_CRYPT_MODE,
    gcmEncryptPartFunc: ?PSYMCRYPT_BLOCKCIPHER_AEADPART_MODE,
    gcmDecryptPartFunc: ?PSYMCRYPT_BLOCKCIPHER_AEADPART_MODE,
    blockSize: SIZE_T,
    expandedKeySize: SIZE_T,
};
pub const PSYMCRYPT_BLOCKCIPHER = *SYMCRYPT_BLOCKCIPHER;
pub const PCSYMCRYPT_BLOCKCIPHER = *const SYMCRYPT_BLOCKCIPHER;

pub const SYMCRYPT_SCSTABLE = extern struct {
    groupSize: UINT32,
    interleaveSize: UINT32,
    nElements: UINT32,
    elementSize: UINT32,
    pbTableData: ?PBYTE,
    cbTableData: UINT32,
};
pub const PSYMCRYPT_SCSTABLE = *SYMCRYPT_SCSTABLE;
pub const PCSYMCRYPT_SCSTABLE = *const SYMCRYPT_SCSTABLE;

pub const SYMCRYPT_UINT32_MAP = extern struct {
    from: UINT32,
    to: UINT32,
};
pub const PSYMCRYPT_UINT32_MAP = *SYMCRYPT_UINT32_MAP;
pub const PCSYMCRYPT_UINT32_MAP = *const SYMCRYPT_UINT32_MAP;
