//
// hpke_internal.zig
//
// Internal types, constants, and external declarations for symcrypt_plus
// (EC encoding and HPKE).
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

const std = @import("std");
const builtin = @import("builtin");

pub const SYMCRYPT_CALL: std.builtin.CallingConvention = if (builtin.cpu.arch == .x86 and builtin.os.tag == .windows)
    .{ .x86_fastcall = .{} }
else
    .c;

pub const BYTE = u8;
pub const PBYTE = [*]u8;
pub const PCBYTE = [*]const u8;
pub const UINT8 = u8;
pub const UINT16 = u16;
pub const UINT32 = u32;
pub const UINT64 = u64;
pub const SIZE_T = usize;
pub const PSIZE_T = *usize;
pub const BOOLEAN = u8;
pub const PVOID = *anyopaque;
pub const PCVOID = *const anyopaque;

pub const SYMCRYPT_ALIGN_VALUE: usize = 16;
pub const SYMCRYPT_ASYM_ALIGN_VALUE: usize = 32;

pub const SYMCRYPT_ERROR = enum(c_uint) {
    SYMCRYPT_NO_ERROR = 0,
    SYMCRYPT_UNUSED = 0x8000,
    SYMCRYPT_WRONG_KEY_SIZE,
    SYMCRYPT_WRONG_BLOCK_SIZE,
    SYMCRYPT_WRONG_DATA_SIZE,
    SYMCRYPT_WRONG_NONCE_SIZE,
    SYMCRYPT_WRONG_TAG_SIZE,
    SYMCRYPT_WRONG_ITERATION_COUNT,
    SYMCRYPT_AUTHENTICATION_FAILURE,
    SYMCRYPT_EXTERNAL_FAILURE,
    SYMCRYPT_FIPS_FAILURE,
    SYMCRYPT_HARDWARE_FAILURE,
    SYMCRYPT_NOT_IMPLEMENTED,
    SYMCRYPT_INVALID_BLOB,
    SYMCRYPT_BUFFER_TOO_SMALL,
    SYMCRYPT_INVALID_ARGUMENT,
    SYMCRYPT_MEMORY_ALLOCATION_FAILURE,
    SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE,
    SYMCRYPT_INCOMPATIBLE_FORMAT,
    SYMCRYPT_VALUE_TOO_LARGE,
    SYMCRYPT_SESSION_REPLAY_FAILURE,
    SYMCRYPT_HBS_NO_OTS_KEYS_LEFT,
    SYMCRYPT_HBS_PUBLIC_ROOT_MISMATCH,
};

pub inline fn SYMCRYPT_MULTICHAR4(c0: u8, c1: u8, c2: u8, c3: u8) UINT32 {
    return (@as(UINT32, c0) << 24) | (@as(UINT32, c1) << 16) | (@as(UINT32, c2) << 8) | @as(UINT32, c3);
}

pub inline fn SYMCRYPT_MAGIC_VALUE(p: anytype) SIZE_T {
    return @intFromPtr(p) +% @as(SIZE_T, SYMCRYPT_MULTICHAR4('s', '1', 'm', 'v')) +% @sizeOf(@TypeOf(p.*));
}

pub inline fn SYMCRYPT_SET_MAGIC(p: anytype) void {
    p.magic = SYMCRYPT_MAGIC_VALUE(p);
}

pub inline fn SYMCRYPT_CHECK_MAGIC(p: anytype) void {
    if (p.magic != SYMCRYPT_MAGIC_VALUE(p)) {
        SymCryptFatal(SYMCRYPT_MULTICHAR4('m', 'a', 'g', 'c'));
    }
}

pub inline fn SYMCRYPT_ASSERT(cond: bool) void {
    if (!cond) {
        SymCryptFatal(SYMCRYPT_MULTICHAR4('a', 's', 'r', 't'));
    }
}

pub inline fn SYMCRYPT_STORE_MSBFIRST16(pb: *[2]u8, x: UINT16) void {
    std.mem.writeInt(u16, pb, x, .big);
}

pub inline fn SYMCRYPT_LOAD_MSBFIRST64(pb: *const [8]u8) UINT64 {
    return std.mem.readInt(u64, pb, .big);
}

pub inline fn SYMCRYPT_STORE_MSBFIRST64(pb: *[8]u8, x: UINT64) void {
    std.mem.writeInt(u64, pb, x, .big);
}

// ============================================================================
// Core SymCrypt external functions
// ============================================================================

pub extern fn SymCryptCallbackAlloc(nBytes: SIZE_T) callconv(SYMCRYPT_CALL) ?PVOID;
pub extern fn SymCryptCallbackFree(pMem: PVOID) callconv(SYMCRYPT_CALL) void;
pub extern fn SymCryptFatal(fatalCode: UINT32) callconv(SYMCRYPT_CALL) noreturn;
pub extern fn SymCryptWipe(pbData: PVOID, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void;

pub inline fn SymCryptWipeKnownSize(pbData: PVOID, cbData: SIZE_T) void {
    SymCryptWipe(pbData, cbData);
}

// ============================================================================
// EC / ECDH declarations
// ============================================================================

pub const SYMCRYPT_NUMBER_FORMAT = enum(c_uint) {
    SYMCRYPT_NUMBER_FORMAT_NULL = 0,
    SYMCRYPT_NUMBER_FORMAT_LSB_FIRST = 1,
    SYMCRYPT_NUMBER_FORMAT_MSB_FIRST = 2,
};

pub const SYMCRYPT_ECPOINT_FORMAT = enum(c_uint) {
    SYMCRYPT_ECPOINT_FORMAT_NULL = 0,
    SYMCRYPT_ECPOINT_FORMAT_X = 1,
    SYMCRYPT_ECPOINT_FORMAT_XY = 2,
};

pub const SYMCRYPT_ECURVE_ID = enum(c_uint) {
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
};

pub const SYMCRYPT_FLAG_KEY_NO_FIPS: UINT32 = 0x00000100;
pub const SYMCRYPT_FLAG_ECKEY_ECDSA: UINT32 = 0x00001000;
pub const SYMCRYPT_FLAG_ECKEY_ECDH: UINT32 = 0x00002000;

pub const SYMCRYPT_ECURVE_PARAMS = opaque {};
pub const PCSYMCRYPT_ECURVE_PARAMS = *const SYMCRYPT_ECURVE_PARAMS;

pub const SYMCRYPT_ECURVE = opaque {};
pub const PSYMCRYPT_ECURVE = *SYMCRYPT_ECURVE;
pub const PCSYMCRYPT_ECURVE = *const SYMCRYPT_ECURVE;

pub const SYMCRYPT_ECKEY = opaque {};
pub const PSYMCRYPT_ECKEY = *SYMCRYPT_ECKEY;
pub const PCSYMCRYPT_ECKEY = *const SYMCRYPT_ECKEY;

pub extern fn SymCryptGetEcurveParams(
    ecurveId: SYMCRYPT_ECURVE_ID,
) callconv(SYMCRYPT_CALL) ?PCSYMCRYPT_ECURVE_PARAMS;

pub extern fn SymCryptEcurveAllocate(
    pParams: PCSYMCRYPT_ECURVE_PARAMS,
    flags: UINT32,
) callconv(SYMCRYPT_CALL) ?PSYMCRYPT_ECURVE;

pub extern fn SymCryptEcurveFree(
    pCurve: PSYMCRYPT_ECURVE,
) callconv(SYMCRYPT_CALL) void;

pub extern fn SymCryptEckeyAllocate(
    pCurve: PCSYMCRYPT_ECURVE,
) callconv(SYMCRYPT_CALL) ?PSYMCRYPT_ECKEY;

pub extern fn SymCryptEckeyFree(
    pkObj: PSYMCRYPT_ECKEY,
) callconv(SYMCRYPT_CALL) void;

pub extern fn SymCryptEckeySizeofPublicKey(
    pkEckey: PCSYMCRYPT_ECKEY,
    ecPointFormat: SYMCRYPT_ECPOINT_FORMAT,
) callconv(SYMCRYPT_CALL) UINT32;

pub extern fn SymCryptEckeySizeofPrivateKey(
    pkEckey: PCSYMCRYPT_ECKEY,
) callconv(SYMCRYPT_CALL) UINT32;

pub extern fn SymCryptEckeySetValue(
    pbPrivateKey: ?PCBYTE,
    cbPrivateKey: SIZE_T,
    pbPublicKey: ?PCBYTE,
    cbPublicKey: SIZE_T,
    numFormat: SYMCRYPT_NUMBER_FORMAT,
    ecPointFormat: SYMCRYPT_ECPOINT_FORMAT,
    flags: UINT32,
    pkDst: PSYMCRYPT_ECKEY,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;

pub extern fn SymCryptEckeyGetValue(
    pkSrc: PCSYMCRYPT_ECKEY,
    pbPrivateKey: ?PBYTE,
    cbPrivateKey: SIZE_T,
    pbPublicKey: ?PBYTE,
    cbPublicKey: SIZE_T,
    numFormat: SYMCRYPT_NUMBER_FORMAT,
    ecPointFormat: SYMCRYPT_ECPOINT_FORMAT,
    flags: UINT32,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;

pub extern fn SymCryptEckeySetRandom(
    flags: UINT32,
    pkDst: PSYMCRYPT_ECKEY,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;

pub extern fn SymCryptEcDhSecretAgreement(
    pkPrivate: PCSYMCRYPT_ECKEY,
    pkPublic: PCSYMCRYPT_ECKEY,
    numFormat: SYMCRYPT_NUMBER_FORMAT,
    flags: UINT32,
    pbAgreedSecret: PBYTE,
    cbAgreedSecret: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;

// ============================================================================
// EC IETF Encoding declarations (inc/symcrypt_plus/symcrypt_ec_encoding.h)
// ============================================================================

pub const SYMCRYPT_ECKEY_IETF_PRIVATE_KEY_FORMAT = enum(c_uint) {
    SYMCRYPT_ECKEY_IETF_PRIVATE_KEY_FORMAT_NULL = 0,
    SYMCRYPT_ECKEY_IETF_PRIVATE_KEY_FORMAT_NIST_SCALAR = 1,
    SYMCRYPT_ECKEY_IETF_PRIVATE_KEY_FORMAT_C25519 = 2,
    _,
};

pub const SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT = enum(c_uint) {
    SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT_NULL = 0,
    SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT_SEC1_UNCOMPRESSED = 1,
    SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT_RAW_X_LE = 2,
    _,
};

// ============================================================================
// ML-KEM and Composite ML-KEM declarations
// ============================================================================

pub const SYMCRYPT_MLKEM_PARAMS = enum(c_uint) {
    SYMCRYPT_MLKEM_PARAMS_NULL = 0,
    SYMCRYPT_MLKEM_PARAMS_MLKEM512 = 1,
    SYMCRYPT_MLKEM_PARAMS_MLKEM768 = 2,
    SYMCRYPT_MLKEM_PARAMS_MLKEM1024 = 3,
};

pub const SYMCRYPT_MLKEMKEY_FORMAT = enum(c_uint) {
    SYMCRYPT_MLKEMKEY_FORMAT_NULL = 0,
    SYMCRYPT_MLKEMKEY_FORMAT_PRIVATE_SEED = 1,
    SYMCRYPT_MLKEMKEY_FORMAT_DECAPSULATION_KEY = 2,
    SYMCRYPT_MLKEMKEY_FORMAT_ENCAPSULATION_KEY = 3,
};

pub const SYMCRYPT_MLKEM_AGREED_SECRET_SIZE: UINT16 = 32;
pub const SYMCRYPT_MLKEM_PRIVATE_SEED_SIZE: UINT16 = 64;
pub const SYMCRYPT_MLKEM_CIPHERTEXT_SIZE_MLKEM512: UINT16 = 768;
pub const SYMCRYPT_MLKEM_CIPHERTEXT_SIZE_MLKEM768: UINT16 = 1088;
pub const SYMCRYPT_MLKEM_CIPHERTEXT_SIZE_MLKEM1024: UINT16 = 1568;
pub const SYMCRYPT_MLKEM_ENCAPSULATION_KEY_SIZE_MLKEM512: UINT16 = 800;
pub const SYMCRYPT_MLKEM_ENCAPSULATION_KEY_SIZE_MLKEM768: UINT16 = 1184;
pub const SYMCRYPT_MLKEM_ENCAPSULATION_KEY_SIZE_MLKEM1024: UINT16 = 1568;

pub const SYMCRYPT_MLKEMKEY = opaque {};
pub const PSYMCRYPT_MLKEMKEY = *SYMCRYPT_MLKEMKEY;
pub const PCSYMCRYPT_MLKEMKEY = *const SYMCRYPT_MLKEMKEY;

pub extern fn SymCryptMlKemkeyAllocate(
    params: SYMCRYPT_MLKEM_PARAMS,
) callconv(SYMCRYPT_CALL) ?PSYMCRYPT_MLKEMKEY;

pub extern fn SymCryptMlKemkeyFree(
    pkMlKemkey: PSYMCRYPT_MLKEMKEY,
) callconv(SYMCRYPT_CALL) void;

pub extern fn SymCryptMlKemkeyGenerate(
    pkMlKemkey: PSYMCRYPT_MLKEMKEY,
    flags: UINT32,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;

pub extern fn SymCryptMlKemkeySetValue(
    pbSrc: PCBYTE,
    cbSrc: SIZE_T,
    mlKemkeyFormat: SYMCRYPT_MLKEMKEY_FORMAT,
    flags: UINT32,
    pkMlKemkey: PSYMCRYPT_MLKEMKEY,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;

pub extern fn SymCryptMlKemkeyGetValue(
    pkMlKemkey: PCSYMCRYPT_MLKEMKEY,
    pbDst: PBYTE,
    cbDst: SIZE_T,
    mlKemkeyFormat: SYMCRYPT_MLKEMKEY_FORMAT,
    flags: UINT32,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;

pub extern fn SymCryptMlKemEncapsulate(
    pkMlKemkey: PCSYMCRYPT_MLKEMKEY,
    pbAgreedSecret: PBYTE,
    cbAgreedSecret: SIZE_T,
    pbCiphertext: PBYTE,
    cbCiphertext: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;

pub extern fn SymCryptMlKemDecapsulate(
    pkMlKemkey: PCSYMCRYPT_MLKEMKEY,
    pbCiphertext: PCBYTE,
    cbCiphertext: SIZE_T,
    pbAgreedSecret: PBYTE,
    cbAgreedSecret: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;

pub const SYMCRYPT_COMPOSITE_MLKEM_PARAMS = enum(c_uint) {
    SYMCRYPT_COMPOSITE_MLKEM_PARAMS_NULL = 0,
    SYMCRYPT_COMPOSITE_MLKEM_PARAMS_MLKEM768_P256 = 1,
    SYMCRYPT_COMPOSITE_MLKEM_PARAMS_MLKEM768_X25519 = 2,
    SYMCRYPT_COMPOSITE_MLKEM_PARAMS_MLKEM1024_P384 = 3,
};

pub const SYMCRYPT_COMPOSITE_MLKEMKEY_FORMAT = enum(c_uint) {
    SYMCRYPT_COMPOSITE_MLKEMKEY_FORMAT_NULL = 0,
    SYMCRYPT_COMPOSITE_MLKEMKEY_FORMAT_IRTF_PRIVATE_SEED = 1,
    SYMCRYPT_COMPOSITE_MLKEMKEY_FORMAT_LAMPS_PRIVATE_KEY = 2,
    SYMCRYPT_COMPOSITE_MLKEMKEY_FORMAT_PUBLIC_KEY = 3,
};

pub const SYMCRYPT_COMPOSITE_MLKEM_IRTF_PRIVATE_SEED_SIZE: UINT16 = 32;
pub const SYMCRYPT_COMPOSITE_MLKEM_PUBLIC_KEY_SIZE_MLKEM768_P256: UINT16 = 1249;
pub const SYMCRYPT_COMPOSITE_MLKEM_PUBLIC_KEY_SIZE_MLKEM768_X25519: UINT16 = 1216;
pub const SYMCRYPT_COMPOSITE_MLKEM_PUBLIC_KEY_SIZE_MLKEM1024_P384: UINT16 = 1665;
pub const SYMCRYPT_COMPOSITE_MLKEM_CIPHERTEXT_SIZE_MLKEM768_P256: UINT16 = 1153;
pub const SYMCRYPT_COMPOSITE_MLKEM_CIPHERTEXT_SIZE_MLKEM768_X25519: UINT16 = 1120;
pub const SYMCRYPT_COMPOSITE_MLKEM_CIPHERTEXT_SIZE_MLKEM1024_P384: UINT16 = 1665;

pub const SYMCRYPT_COMPOSITE_MLKEMKEY = opaque {};
pub const PSYMCRYPT_COMPOSITE_MLKEMKEY = *SYMCRYPT_COMPOSITE_MLKEMKEY;
pub const PCSYMCRYPT_COMPOSITE_MLKEMKEY = *const SYMCRYPT_COMPOSITE_MLKEMKEY;

pub extern fn SymCryptCompositeMlKemkeyAllocate(
    params: SYMCRYPT_COMPOSITE_MLKEM_PARAMS,
) callconv(SYMCRYPT_CALL) ?PSYMCRYPT_COMPOSITE_MLKEMKEY;

pub extern fn SymCryptCompositeMlKemkeyFree(
    pkCompositeMlKemkey: PSYMCRYPT_COMPOSITE_MLKEMKEY,
) callconv(SYMCRYPT_CALL) void;

pub extern fn SymCryptCompositeMlKemkeyGenerate(
    pkCompositeMlKemkey: PSYMCRYPT_COMPOSITE_MLKEMKEY,
    flags: UINT32,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;

pub extern fn SymCryptCompositeMlKemkeySetValue(
    pbSrc: PCBYTE,
    cbSrc: SIZE_T,
    compositeMlKemkeyFormat: SYMCRYPT_COMPOSITE_MLKEMKEY_FORMAT,
    flags: UINT32,
    pkCompositeMlKemkey: PSYMCRYPT_COMPOSITE_MLKEMKEY,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;

pub extern fn SymCryptCompositeMlKemkeyGetValue(
    pkCompositeMlKemkey: PCSYMCRYPT_COMPOSITE_MLKEMKEY,
    pbDst: PBYTE,
    cbDst: SIZE_T,
    compositeMlKemkeyFormat: SYMCRYPT_COMPOSITE_MLKEMKEY_FORMAT,
    flags: UINT32,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;

pub extern fn SymCryptCompositeMlKemEncapsulate(
    pkCompositeMlKemkey: PCSYMCRYPT_COMPOSITE_MLKEMKEY,
    pbAgreedSecret: PBYTE,
    cbAgreedSecret: SIZE_T,
    pbCiphertext: PBYTE,
    cbCiphertext: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;

pub extern fn SymCryptCompositeMlKemDecapsulate(
    pkCompositeMlKemkey: PCSYMCRYPT_COMPOSITE_MLKEMKEY,
    pbCiphertext: PCBYTE,
    cbCiphertext: SIZE_T,
    pbAgreedSecret: PBYTE,
    cbAgreedSecret: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;

// ============================================================================
// KDF / Hash / MAC declarations
// ============================================================================

pub const SYMCRYPT_MAC_ID = enum(c_uint) {
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
};

pub const SYMCRYPT_MAC = opaque {};
pub const PCSYMCRYPT_MAC = *const SYMCRYPT_MAC;

pub extern fn SymCryptGetMacAlgorithm(
    macId: SYMCRYPT_MAC_ID,
) callconv(SYMCRYPT_CALL) ?PCSYMCRYPT_MAC;

pub const SYMCRYPT_MAC_MAX_RESULT_SIZE: usize = 64;

pub const SYMCRYPT_SHA512_CHAINING_STATE = extern struct {
    H: [8]UINT64 align(16),
};

pub const SYMCRYPT_SHA512_STATE = extern struct {
    bytesInBuffer: UINT32,
    magic: SIZE_T,
    dataLengthL: UINT64,
    dataLengthH: UINT64,
    buffer: [128]BYTE align(16),
    chain: SYMCRYPT_SHA512_CHAINING_STATE,
};

pub const SYMCRYPT_KECCAK_STATE = extern struct {
    state: [25]UINT64 align(16),
    inputBlockSize: UINT32,
    stateIndex: UINT32,
    paddingValue: UINT8,
    squeezeMode: BOOLEAN,
};

pub const SYMCRYPT_SHA3_512_STATE = extern struct {
    ks: SYMCRYPT_KECCAK_STATE,
    magic: SIZE_T,
};

pub const SYMCRYPT_HASH_STATE = extern union {
    sha512State: SYMCRYPT_SHA512_STATE,
    sha3_512State: SYMCRYPT_SHA3_512_STATE,
};

pub const SYMCRYPT_HMAC_SHA512_EXPANDED_KEY = extern struct {
    innerState: SYMCRYPT_SHA512_CHAINING_STATE,
    outerState: SYMCRYPT_SHA512_CHAINING_STATE,
    magic: SIZE_T,
};

pub const SYMCRYPT_HMAC_EXPANDED_KEY = extern struct {
    pHash: ?PCVOID align(16),
    innerState: SYMCRYPT_HASH_STATE,
    outerState: SYMCRYPT_HASH_STATE,
    magic: SIZE_T,
};

pub const SYMCRYPT_AES_EXPANDED_KEY = extern struct {
    RoundKey: [29][4][4]BYTE align(16),
    lastEncRoundKey: ?*[4][4]BYTE,
    lastDecRoundKey: ?*[4][4]BYTE,
    magic: SIZE_T,
};

pub const SYMCRYPT_AES_CMAC_EXPANDED_KEY = extern struct {
    aesKey: SYMCRYPT_AES_EXPANDED_KEY,
    K1: [16]BYTE,
    K2: [16]BYTE,
    magic: SIZE_T,
};

pub const SYMCRYPT_KMAC256_EXPANDED_KEY = extern struct {
    ks: SYMCRYPT_KECCAK_STATE,
    magic: SIZE_T,
};

pub const SYMCRYPT_MAC_EXPANDED_KEY = extern union {
    sha512Key: SYMCRYPT_HMAC_SHA512_EXPANDED_KEY,
    sha3_512Key: SYMCRYPT_HMAC_EXPANDED_KEY,
    aescmacKey: SYMCRYPT_AES_CMAC_EXPANDED_KEY,
    kmac256Key: SYMCRYPT_KMAC256_EXPANDED_KEY,
};

pub const SYMCRYPT_HKDF_EXPANDED_KEY = extern struct {
    macKey: SYMCRYPT_MAC_EXPANDED_KEY,
    macAlg: ?PCSYMCRYPT_MAC,
};
pub const PSYMCRYPT_HKDF_EXPANDED_KEY = *SYMCRYPT_HKDF_EXPANDED_KEY;
pub const PCSYMCRYPT_HKDF_EXPANDED_KEY = *const SYMCRYPT_HKDF_EXPANDED_KEY;

pub extern fn SymCryptHkdfExtractPrk(
    macAlgorithm: PCSYMCRYPT_MAC,
    pbIkm: ?PCBYTE,
    cbIkm: SIZE_T,
    pbSalt: ?PCBYTE,
    cbSalt: SIZE_T,
    pbPrk: PBYTE,
    cbPrk: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;

pub extern fn SymCryptHkdfPrkExpandKey(
    pExpandedKey: PSYMCRYPT_HKDF_EXPANDED_KEY,
    macAlgorithm: PCSYMCRYPT_MAC,
    pbPrk: PCBYTE,
    cbPrk: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;

pub extern fn SymCryptHkdfDerive(
    pExpandedKey: PCSYMCRYPT_HKDF_EXPANDED_KEY,
    pbInfo: ?PCBYTE,
    cbInfo: SIZE_T,
    pbResult: PBYTE,
    cbResult: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;

pub const SYMCRYPT_SHAKE128_STATE = extern struct {
    ks: SYMCRYPT_KECCAK_STATE,
    magic: SIZE_T,
};
pub const PSYMCRYPT_SHAKE128_STATE = *SYMCRYPT_SHAKE128_STATE;

pub const SYMCRYPT_SHAKE256_STATE = extern struct {
    ks: SYMCRYPT_KECCAK_STATE,
    magic: SIZE_T,
};
pub const PSYMCRYPT_SHAKE256_STATE = *SYMCRYPT_SHAKE256_STATE;

pub extern fn SymCryptShake128Init(pState: PSYMCRYPT_SHAKE128_STATE) callconv(SYMCRYPT_CALL) void;
pub extern fn SymCryptShake128Append(pState: PSYMCRYPT_SHAKE128_STATE, pbData: PCBYTE, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void;
pub extern fn SymCryptShake128Extract(pState: PSYMCRYPT_SHAKE128_STATE, pbResult: PBYTE, cbResult: SIZE_T, bWipe: BOOLEAN) callconv(SYMCRYPT_CALL) void;

pub extern fn SymCryptShake256Init(pState: PSYMCRYPT_SHAKE256_STATE) callconv(SYMCRYPT_CALL) void;
pub extern fn SymCryptShake256Append(pState: PSYMCRYPT_SHAKE256_STATE, pbData: PCBYTE, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void;
pub extern fn SymCryptShake256Extract(pState: PSYMCRYPT_SHAKE256_STATE, pbResult: PBYTE, cbResult: SIZE_T, bWipe: BOOLEAN) callconv(SYMCRYPT_CALL) void;

// ============================================================================
// AEAD (AES-GCM & ChaCha20-Poly1305) declarations
// ============================================================================

pub const SYMCRYPT_BLOCKCIPHER_ID = enum(c_uint) {
    SYMCRYPT_BLOCKCIPHER_ID_NULL = 0,
    SYMCRYPT_BLOCKCIPHER_ID_AES = 1,
    SYMCRYPT_BLOCKCIPHER_ID_DES = 2,
    SYMCRYPT_BLOCKCIPHER_ID_3DES = 3,
    SYMCRYPT_BLOCKCIPHER_ID_DESX = 4,
    SYMCRYPT_BLOCKCIPHER_ID_RC2 = 5,
};

pub const SYMCRYPT_BLOCKCIPHER = opaque {};
pub const PCSYMCRYPT_BLOCKCIPHER = *const SYMCRYPT_BLOCKCIPHER;

pub extern fn SymCryptGetBlockCipher(
    blockCipherId: SYMCRYPT_BLOCKCIPHER_ID,
) callconv(SYMCRYPT_CALL) ?PCSYMCRYPT_BLOCKCIPHER;

pub const SYMCRYPT_GCM_MAX_KEY_SIZE: usize = 32;
pub const SYMCRYPT_GF128_FIELD_SIZE: usize = 128;

pub const SYMCRYPT_GF128_ELEMENT = extern struct {
    ull: [2]UINT64 align(16),
};

pub const SYMCRYPT_GHASH_EXPANDED_KEY = if (builtin.cpu.arch == .x86)
    extern struct {
        tableOffset: UINT32 align(16),
        tableSpace: [(SYMCRYPT_GF128_FIELD_SIZE + 1) * @sizeOf(SYMCRYPT_GF128_ELEMENT)]BYTE,
    }
else
    extern struct {
        table: [SYMCRYPT_GF128_FIELD_SIZE]SYMCRYPT_GF128_ELEMENT align(16),
    };

pub const SYMCRYPT_GCM_SUPPORTED_BLOCKCIPHER_KEYS = extern union {
    aes: SYMCRYPT_AES_EXPANDED_KEY,
};

pub const SYMCRYPT_GCM_EXPANDED_KEY = extern struct {
    ghashKey: SYMCRYPT_GHASH_EXPANDED_KEY,
    pBlockCipher: ?PCSYMCRYPT_BLOCKCIPHER,
    blockcipherKey: SYMCRYPT_GCM_SUPPORTED_BLOCKCIPHER_KEYS,
    cbKey: SIZE_T,
    abKey: [SYMCRYPT_GCM_MAX_KEY_SIZE]BYTE,
    magic: SIZE_T,
};
pub const PSYMCRYPT_GCM_EXPANDED_KEY = *SYMCRYPT_GCM_EXPANDED_KEY;
pub const PCSYMCRYPT_GCM_EXPANDED_KEY = *const SYMCRYPT_GCM_EXPANDED_KEY;

pub const SYMCRYPT_GCM_MAX_DATA_SIZE: UINT64 = (@as(UINT64, 1) << 36) - 32;
pub const SYMCRYPT_CHACHA20_POLY1305_MAX_DATA_SIZE: UINT64 = ((@as(UINT64, 1) << 32) - 1) * 64;

pub extern fn SymCryptGcmExpandKey(
    pExpandedKey: PSYMCRYPT_GCM_EXPANDED_KEY,
    pBlockCipher: PCSYMCRYPT_BLOCKCIPHER,
    pbKey: PCBYTE,
    cbKey: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;

pub extern fn SymCryptGcmEncrypt(
    pExpandedKey: PCSYMCRYPT_GCM_EXPANDED_KEY,
    pbNonce: PCBYTE,
    cbNonce: SIZE_T,
    pbAuthData: ?PCBYTE,
    cbAuthData: SIZE_T,
    pbSrc: ?PCBYTE,
    pbDst: PBYTE,
    cbData: SIZE_T,
    pbTag: PBYTE,
    cbTag: SIZE_T,
) callconv(SYMCRYPT_CALL) void;

pub extern fn SymCryptGcmDecrypt(
    pExpandedKey: PCSYMCRYPT_GCM_EXPANDED_KEY,
    pbNonce: PCBYTE,
    cbNonce: SIZE_T,
    pbAuthData: ?PCBYTE,
    cbAuthData: SIZE_T,
    pbSrc: PCBYTE,
    pbDst: ?PBYTE,
    cbData: SIZE_T,
    pbTag: PCBYTE,
    cbTag: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;

pub extern fn SymCryptChaCha20Poly1305Encrypt(
    pbKey: PCBYTE,
    cbKey: SIZE_T,
    pbNonce: PCBYTE,
    cbNonce: SIZE_T,
    pbAuthData: ?PCBYTE,
    cbAuthData: SIZE_T,
    pbSrc: ?PCBYTE,
    pbDst: PBYTE,
    cbData: SIZE_T,
    pbTag: PBYTE,
    cbTag: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;

pub extern fn SymCryptChaCha20Poly1305Decrypt(
    pbKey: PCBYTE,
    cbKey: SIZE_T,
    pbNonce: PCBYTE,
    cbNonce: SIZE_T,
    pbAuthData: ?PCBYTE,
    cbAuthData: SIZE_T,
    pbSrc: PCBYTE,
    pbDst: ?PBYTE,
    cbData: SIZE_T,
    pbTag: PCBYTE,
    cbTag: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;

// ============================================================================
// HPKE public & internal types (symcrypt_hpke.h and hpke_internal.h)
// ============================================================================

pub const SYMCRYPT_HPKE_KEM_ID = enum(c_uint) {
    SYMCRYPT_HPKE_KEM_ID_NULL = 0x0000,
    SYMCRYPT_HPKE_KEM_ID_DHKEM_P256 = 0x0010,
    SYMCRYPT_HPKE_KEM_ID_DHKEM_P384 = 0x0011,
    SYMCRYPT_HPKE_KEM_ID_DHKEM_P521 = 0x0012,
    SYMCRYPT_HPKE_KEM_ID_DHKEM_X25519 = 0x0020,
    SYMCRYPT_HPKE_KEM_ID_MLKEM_512 = 0x0040,
    SYMCRYPT_HPKE_KEM_ID_MLKEM_768 = 0x0041,
    SYMCRYPT_HPKE_KEM_ID_MLKEM_1024 = 0x0042,
    SYMCRYPT_HPKE_KEM_ID_MLKEM768_P256 = 0x0050,
    SYMCRYPT_HPKE_KEM_ID_MLKEM1024_P384 = 0x0051,
    SYMCRYPT_HPKE_KEM_ID_MLKEM768_X25519 = 0x647a,
    _,
};

pub const SYMCRYPT_HPKE_KDF_ID = enum(c_uint) {
    SYMCRYPT_HPKE_KDF_ID_NULL = 0x0000,
    SYMCRYPT_HPKE_KDF_ID_HKDF_SHA256 = 0x0001,
    SYMCRYPT_HPKE_KDF_ID_HKDF_SHA384 = 0x0002,
    SYMCRYPT_HPKE_KDF_ID_HKDF_SHA512 = 0x0003,
    SYMCRYPT_HPKE_KDF_ID_SHAKE128 = 0x0010,
    SYMCRYPT_HPKE_KDF_ID_SHAKE256 = 0x0011,
    _,
};

pub const SYMCRYPT_HPKE_AEAD_ID = enum(c_uint) {
    SYMCRYPT_HPKE_AEAD_ID_NULL = 0x0000,
    SYMCRYPT_HPKE_AEAD_ID_AESGCM128 = 0x0001,
    SYMCRYPT_HPKE_AEAD_ID_AESGCM256 = 0x0002,
    SYMCRYPT_HPKE_AEAD_ID_CHACHA20POLY1305 = 0x0003,
    SYMCRYPT_HPKE_AEAD_ID_EXPORT_ONLY = 0xFFFF,
    _,
};

pub const SYMCRYPT_HPKEKEY_FORMAT = enum(c_uint) {
    SYMCRYPT_HPKEKEY_FORMAT_NULL = 0,
    SYMCRYPT_HPKEKEY_FORMAT_PRIVATE_KEY = 1,
    SYMCRYPT_HPKEKEY_FORMAT_PUBLIC_KEY = 2,
    _,
};

pub const SYMCRYPT_HPKE_CIPHERSUITE = extern struct {
    kemId: UINT16,
    kdfId: UINT16,
    aeadId: UINT16,
};

pub const SYMCRYPT_HPKE_MAX_EXPORT_SIZE: usize = 16384;
pub const SYMCRYPT_HPKE_MAX_INFO_SIZE: usize = SYMCRYPT_HPKE_MAX_EXPORT_SIZE;

// KEM-related size bounds
pub const SYMCRYPT_HPKE_KEM_MAX_SHARED_SECRET_SIZE: usize = 64;
pub const SYMCRYPT_HPKE_KEM_MAX_ENCAPS_CIPHERTEXT_SIZE: usize = 1665;
pub const SYMCRYPT_HPKE_KEM_MAX_PUBLIC_KEY_SIZE: usize = 1665;

pub const SYMCRYPT_HPKE_DHKEM_P256_SHARED_SECRET_SIZE: UINT16 = 32;
pub const SYMCRYPT_HPKE_DHKEM_P384_SHARED_SECRET_SIZE: UINT16 = 48;
pub const SYMCRYPT_HPKE_DHKEM_P521_SHARED_SECRET_SIZE: UINT16 = 64;
pub const SYMCRYPT_HPKE_DHKEM_X25519_SHARED_SECRET_SIZE: UINT16 = 32;

pub const SYMCRYPT_HPKE_DHKEM_P256_SCALAR_SIZE: UINT16 = 32;
pub const SYMCRYPT_HPKE_DHKEM_P384_SCALAR_SIZE: UINT16 = 48;
pub const SYMCRYPT_HPKE_DHKEM_P521_SCALAR_SIZE: UINT16 = 66;
pub const SYMCRYPT_HPKE_DHKEM_X25519_SCALAR_SIZE: UINT16 = 32;

pub const SYMCRYPT_HPKE_DHKEM_SEC1_TAG_SIZE: UINT16 = 1;
pub const SYMCRYPT_HPKE_DHKEM_P256_PUBLIC_KEY_SIZE: UINT16 = SYMCRYPT_HPKE_DHKEM_SEC1_TAG_SIZE + 2 * SYMCRYPT_HPKE_DHKEM_P256_SCALAR_SIZE;
pub const SYMCRYPT_HPKE_DHKEM_P384_PUBLIC_KEY_SIZE: UINT16 = SYMCRYPT_HPKE_DHKEM_SEC1_TAG_SIZE + 2 * SYMCRYPT_HPKE_DHKEM_P384_SCALAR_SIZE;
pub const SYMCRYPT_HPKE_DHKEM_P521_PUBLIC_KEY_SIZE: UINT16 = SYMCRYPT_HPKE_DHKEM_SEC1_TAG_SIZE + 2 * SYMCRYPT_HPKE_DHKEM_P521_SCALAR_SIZE;
pub const SYMCRYPT_HPKE_DHKEM_X25519_PUBLIC_KEY_SIZE: UINT16 = 32;

// KDF-related size bounds
pub const SYMCRYPT_HPKE_KDF_MAX_HASH_SIZE: usize = 64;
pub const SYMCRYPT_HPKE_KDF_MAX_IKM_SIZE: usize = 128;

// AEAD-related size bounds
pub const SYMCRYPT_HPKE_AEAD_MAX_KEY_SIZE: usize = 32;
pub const SYMCRYPT_HPKE_AEAD_MAX_NONCE_SIZE: usize = 12;
pub const SYMCRYPT_HPKE_AEAD_MAX_TAG_SIZE: usize = 16;

// HPKE version label & suite_id prefix sizes
pub const SYMCRYPT_HPKE_VERSION_LABEL = "HPKE-v1";
pub const SYMCRYPT_HPKE_VERSION_LABEL_SIZE: usize = 7;
pub const SYMCRYPT_HPKE_KEM_SUITE_ID_SIZE: usize = 5;
pub const SYMCRYPT_HPKE_SUITE_ID_SIZE: usize = 10;

// Sequence number limit: 2^64 - 2^32
pub const SYMCRYPT_HPKE_SEQ_LIMIT: UINT64 = 0xFFFFFFFF00000000;

// HPKE modes
pub const SYMCRYPT_HPKE_MODE_BASE: BYTE = 0x00;
pub const SYMCRYPT_HPKE_MODE_PSK: BYTE = 0x01;

pub const SYMCRYPT_HPKE_KEM_PARAMS = extern struct {
    kemId: UINT16,
    cbSharedSecret: UINT16,
    cbEnc: UINT16,
    cbPublicKey: UINT16,
    cbPrivateKey: UINT16,
};
pub const PSYMCRYPT_HPKE_KEM_PARAMS = *SYMCRYPT_HPKE_KEM_PARAMS;
pub const PCSYMCRYPT_HPKE_KEM_PARAMS = *const SYMCRYPT_HPKE_KEM_PARAMS;

pub const SYMCRYPT_HPKE_AEAD_PARAMS = extern struct {
    aeadId: UINT16,
    cbKey: UINT16,
    cbNonce: UINT16,
    cbTag: UINT16,
};
pub const PSYMCRYPT_HPKE_AEAD_PARAMS = *SYMCRYPT_HPKE_AEAD_PARAMS;
pub const PCSYMCRYPT_HPKE_AEAD_PARAMS = *const SYMCRYPT_HPKE_AEAD_PARAMS;

pub const SYMCRYPT_HPKE_CONTEXT_STATE = enum(c_uint) {
    SYMCRYPT_HPKE_CONTEXT_STATE_UNINITIALIZED = 0,
    SYMCRYPT_HPKE_CONTEXT_STATE_SENDER = 1,
    SYMCRYPT_HPKE_CONTEXT_STATE_RECIPIENT = 2,
    _,
};

pub const SYMCRYPT_HPKEKEY = extern struct {
    ciphersuite: SYMCRYPT_HPKE_CIPHERSUITE align(SYMCRYPT_ALIGN_VALUE),
    kemParams: SYMCRYPT_HPKE_KEM_PARAMS,
    pKemKeyData: ?PVOID,
    magic: SIZE_T,
};
pub const PSYMCRYPT_HPKEKEY = *SYMCRYPT_HPKEKEY;
pub const PCSYMCRYPT_HPKEKEY = *const SYMCRYPT_HPKEKEY;

pub const SYMCRYPT_HPKECONTEXT = extern struct {
    ciphersuite: SYMCRYPT_HPKE_CIPHERSUITE align(SYMCRYPT_ALIGN_VALUE),
    aeadParams: SYMCRYPT_HPKE_AEAD_PARAMS,
    key: [SYMCRYPT_HPKE_AEAD_MAX_KEY_SIZE]BYTE,
    baseNonce: [SYMCRYPT_HPKE_AEAD_MAX_NONCE_SIZE]BYTE,
    exporterSecret: [SYMCRYPT_HPKE_KDF_MAX_HASH_SIZE]BYTE,
    gcmExpandedKey: SYMCRYPT_GCM_EXPANDED_KEY,
    fGcmKeyExpanded: BOOLEAN,
    seqNum: UINT64 align(8),
    state: SYMCRYPT_HPKE_CONTEXT_STATE,
    magic: SIZE_T,
};
pub const PSYMCRYPT_HPKECONTEXT = *SYMCRYPT_HPKECONTEXT;
pub const PCSYMCRYPT_HPKECONTEXT = *const SYMCRYPT_HPKECONTEXT;
