//
// hmac.zig
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
// Generic HMAC implementation, comptime HMAC pattern generator (MD5, SHA-1,
// SHA-2 family), and SHA-3 HMAC wrappers.
//

const std = @import("std");
const types = @import("types.zig");
const macros = @import("macros.zig");

const BYTE = types.BYTE;
const PBYTE = types.PBYTE;
const PCBYTE = types.PCBYTE;
const UINT8 = types.UINT8;
const UINT32 = types.UINT32;
const UINT64 = types.UINT64;
const SIZE_T = types.SIZE_T;
const BOOLEAN = types.BOOLEAN;
const PVOID = types.PVOID;
const PCVOID = types.PCVOID;
const SYMCRYPT_ERROR = types.SYMCRYPT_ERROR;
const SYMCRYPT_CALL = types.SYMCRYPT_CALL;
const SYMCRYPT_ALIGN_VALUE = types.SYMCRYPT_ALIGN_VALUE;
const PCSYMCRYPT_HASH = types.PCSYMCRYPT_HASH;
const SYMCRYPT_MAC = types.SYMCRYPT_MAC;
const PCSYMCRYPT_MAC = types.PCSYMCRYPT_MAC;

pub const HMAC_IPAD_BYTE: u8 = 0x36;
pub const HMAC_OPAD_BYTE: u8 = 0x5c;

// ==============================================================================================
// Hash Result & Input Block Size Constants
// ==============================================================================================

pub const SYMCRYPT_MD2_RESULT_SIZE: usize = 16;
pub const SYMCRYPT_MD2_INPUT_BLOCK_SIZE: usize = 16;

pub const SYMCRYPT_MD4_RESULT_SIZE: usize = 16;
pub const SYMCRYPT_MD4_INPUT_BLOCK_SIZE: usize = 64;

pub const SYMCRYPT_MD5_RESULT_SIZE: usize = 16;
pub const SYMCRYPT_MD5_INPUT_BLOCK_SIZE: usize = 64;

pub const SYMCRYPT_SHA1_RESULT_SIZE: usize = 20;
pub const SYMCRYPT_SHA1_INPUT_BLOCK_SIZE: usize = 64;

pub const SYMCRYPT_SHA224_RESULT_SIZE: usize = 28;
pub const SYMCRYPT_SHA224_INPUT_BLOCK_SIZE: usize = 64;

pub const SYMCRYPT_SHA256_RESULT_SIZE: usize = 32;
pub const SYMCRYPT_SHA256_INPUT_BLOCK_SIZE: usize = 64;

pub const SYMCRYPT_SHA384_RESULT_SIZE: usize = 48;
pub const SYMCRYPT_SHA384_INPUT_BLOCK_SIZE: usize = 128;

pub const SYMCRYPT_SHA512_RESULT_SIZE: usize = 64;
pub const SYMCRYPT_SHA512_INPUT_BLOCK_SIZE: usize = 128;

pub const SYMCRYPT_SHA512_224_RESULT_SIZE: usize = 28;
pub const SYMCRYPT_SHA512_224_INPUT_BLOCK_SIZE: usize = 128;

pub const SYMCRYPT_SHA512_256_RESULT_SIZE: usize = 32;
pub const SYMCRYPT_SHA512_256_INPUT_BLOCK_SIZE: usize = 128;

pub const SYMCRYPT_SHA3_224_RESULT_SIZE: usize = 28;
pub const SYMCRYPT_SHA3_224_INPUT_BLOCK_SIZE: usize = 144;

pub const SYMCRYPT_SHA3_256_RESULT_SIZE: usize = 32;
pub const SYMCRYPT_SHA3_256_INPUT_BLOCK_SIZE: usize = 136;

pub const SYMCRYPT_SHA3_384_RESULT_SIZE: usize = 48;
pub const SYMCRYPT_SHA3_384_INPUT_BLOCK_SIZE: usize = 104;

pub const SYMCRYPT_SHA3_512_RESULT_SIZE: usize = 64;
pub const SYMCRYPT_SHA3_512_INPUT_BLOCK_SIZE: usize = 72;

pub const SYMCRYPT_HMAC_MD5_RESULT_SIZE = SYMCRYPT_MD5_RESULT_SIZE;
pub const SYMCRYPT_HMAC_MD5_INPUT_BLOCK_SIZE = SYMCRYPT_MD5_INPUT_BLOCK_SIZE;

pub const SYMCRYPT_HMAC_SHA1_RESULT_SIZE = SYMCRYPT_SHA1_RESULT_SIZE;
pub const SYMCRYPT_HMAC_SHA1_INPUT_BLOCK_SIZE = SYMCRYPT_SHA1_INPUT_BLOCK_SIZE;

pub const SYMCRYPT_HMAC_SHA224_RESULT_SIZE = SYMCRYPT_SHA224_RESULT_SIZE;
pub const SYMCRYPT_HMAC_SHA224_INPUT_BLOCK_SIZE = SYMCRYPT_SHA224_INPUT_BLOCK_SIZE;

pub const SYMCRYPT_HMAC_SHA256_RESULT_SIZE = SYMCRYPT_SHA256_RESULT_SIZE;
pub const SYMCRYPT_HMAC_SHA256_INPUT_BLOCK_SIZE = SYMCRYPT_SHA256_INPUT_BLOCK_SIZE;

pub const SYMCRYPT_HMAC_SHA384_RESULT_SIZE = SYMCRYPT_SHA384_RESULT_SIZE;
pub const SYMCRYPT_HMAC_SHA384_INPUT_BLOCK_SIZE = SYMCRYPT_SHA384_INPUT_BLOCK_SIZE;

pub const SYMCRYPT_HMAC_SHA512_RESULT_SIZE = SYMCRYPT_SHA512_RESULT_SIZE;
pub const SYMCRYPT_HMAC_SHA512_INPUT_BLOCK_SIZE = SYMCRYPT_SHA512_INPUT_BLOCK_SIZE;

pub const SYMCRYPT_HMAC_SHA512_224_RESULT_SIZE = SYMCRYPT_SHA512_224_RESULT_SIZE;
pub const SYMCRYPT_HMAC_SHA512_224_INPUT_BLOCK_SIZE = SYMCRYPT_SHA512_224_INPUT_BLOCK_SIZE;

pub const SYMCRYPT_HMAC_SHA512_256_RESULT_SIZE = SYMCRYPT_SHA512_256_RESULT_SIZE;
pub const SYMCRYPT_HMAC_SHA512_256_INPUT_BLOCK_SIZE = SYMCRYPT_SHA512_256_INPUT_BLOCK_SIZE;

pub const SYMCRYPT_HMAC_SHA3_224_RESULT_SIZE = SYMCRYPT_SHA3_224_RESULT_SIZE;
pub const SYMCRYPT_HMAC_SHA3_224_INPUT_BLOCK_SIZE = SYMCRYPT_SHA3_224_INPUT_BLOCK_SIZE;

pub const SYMCRYPT_HMAC_SHA3_256_RESULT_SIZE = SYMCRYPT_SHA3_256_RESULT_SIZE;
pub const SYMCRYPT_HMAC_SHA3_256_INPUT_BLOCK_SIZE = SYMCRYPT_SHA3_256_INPUT_BLOCK_SIZE;

pub const SYMCRYPT_HMAC_SHA3_384_RESULT_SIZE = SYMCRYPT_SHA3_384_RESULT_SIZE;
pub const SYMCRYPT_HMAC_SHA3_384_INPUT_BLOCK_SIZE = SYMCRYPT_SHA3_384_INPUT_BLOCK_SIZE;

pub const SYMCRYPT_HMAC_SHA3_512_RESULT_SIZE = SYMCRYPT_SHA3_512_RESULT_SIZE;
pub const SYMCRYPT_HMAC_SHA3_512_INPUT_BLOCK_SIZE = SYMCRYPT_SHA3_512_INPUT_BLOCK_SIZE;

// ==============================================================================================
// Hash Chaining State & Hash State Structures (matching inc/symcrypt_internal.h)
// ==============================================================================================

pub const SYMCRYPT_MD2_CHAINING_STATE = extern struct {
    C: [16]BYTE align(SYMCRYPT_ALIGN_VALUE),
    X: [48]BYTE,
};

pub const SYMCRYPT_MD2_STATE = extern struct {
    bytesInBuffer: UINT32 align(SYMCRYPT_ALIGN_VALUE),
    magic: SIZE_T,
    dataLengthL: UINT64,
    dataLengthH: UINT64,
    buffer: [16]BYTE align(SYMCRYPT_ALIGN_VALUE),
    chain: SYMCRYPT_MD2_CHAINING_STATE,
};

pub const SYMCRYPT_MD4_CHAINING_STATE = extern struct {
    H: [4]UINT32 align(SYMCRYPT_ALIGN_VALUE),
};

pub const SYMCRYPT_MD4_STATE = extern struct {
    bytesInBuffer: UINT32 align(SYMCRYPT_ALIGN_VALUE),
    magic: SIZE_T,
    dataLengthL: UINT64,
    dataLengthH: UINT64,
    buffer: [64]BYTE align(SYMCRYPT_ALIGN_VALUE),
    chain: SYMCRYPT_MD4_CHAINING_STATE,
};

pub const SYMCRYPT_MD5_CHAINING_STATE = extern struct {
    H: [4]UINT32 align(SYMCRYPT_ALIGN_VALUE),
};
pub const PSYMCRYPT_MD5_CHAINING_STATE = *SYMCRYPT_MD5_CHAINING_STATE;

pub const SYMCRYPT_MD5_STATE = extern struct {
    bytesInBuffer: UINT32 align(SYMCRYPT_ALIGN_VALUE),
    magic: SIZE_T,
    dataLengthL: UINT64,
    dataLengthH: UINT64,
    buffer: [64]BYTE align(SYMCRYPT_ALIGN_VALUE),
    chain: SYMCRYPT_MD5_CHAINING_STATE,
};
pub const PSYMCRYPT_MD5_STATE = *SYMCRYPT_MD5_STATE;
pub const PCSYMCRYPT_MD5_STATE = *const SYMCRYPT_MD5_STATE;

pub const SYMCRYPT_SHA1_CHAINING_STATE = extern struct {
    H: [5]UINT32 align(SYMCRYPT_ALIGN_VALUE),
};
pub const PSYMCRYPT_SHA1_CHAINING_STATE = *SYMCRYPT_SHA1_CHAINING_STATE;

pub const SYMCRYPT_SHA1_STATE = extern struct {
    bytesInBuffer: UINT32 align(SYMCRYPT_ALIGN_VALUE),
    magic: SIZE_T,
    dataLengthL: UINT64,
    dataLengthH: UINT64,
    buffer: [64]BYTE align(SYMCRYPT_ALIGN_VALUE),
    chain: SYMCRYPT_SHA1_CHAINING_STATE,
};
pub const PSYMCRYPT_SHA1_STATE = *SYMCRYPT_SHA1_STATE;
pub const PCSYMCRYPT_SHA1_STATE = *const SYMCRYPT_SHA1_STATE;

pub const SYMCRYPT_SHA256_CHAINING_STATE = extern struct {
    H: [8]UINT32 align(SYMCRYPT_ALIGN_VALUE),
};
pub const PSYMCRYPT_SHA256_CHAINING_STATE = *SYMCRYPT_SHA256_CHAINING_STATE;

pub const SYMCRYPT_SHA256_STATE = extern struct {
    bytesInBuffer: UINT32 align(SYMCRYPT_ALIGN_VALUE),
    magic: SIZE_T,
    dataLengthL: UINT64,
    dataLengthH: UINT64,
    buffer: [64]BYTE align(SYMCRYPT_ALIGN_VALUE),
    chain: SYMCRYPT_SHA256_CHAINING_STATE,
};
pub const PSYMCRYPT_SHA256_STATE = *SYMCRYPT_SHA256_STATE;
pub const PCSYMCRYPT_SHA256_STATE = *const SYMCRYPT_SHA256_STATE;

pub const SYMCRYPT_SHA224_STATE = extern struct {
    bytesInBuffer: UINT32 align(SYMCRYPT_ALIGN_VALUE),
    magic: SIZE_T,
    dataLengthL: UINT64,
    dataLengthH: UINT64,
    buffer: [64]BYTE align(SYMCRYPT_ALIGN_VALUE),
    chain: SYMCRYPT_SHA256_CHAINING_STATE,
};
pub const PSYMCRYPT_SHA224_STATE = *SYMCRYPT_SHA224_STATE;
pub const PCSYMCRYPT_SHA224_STATE = *const SYMCRYPT_SHA224_STATE;

pub const SYMCRYPT_SHA512_CHAINING_STATE = extern struct {
    H: [8]UINT64 align(SYMCRYPT_ALIGN_VALUE),
};
pub const PSYMCRYPT_SHA512_CHAINING_STATE = *SYMCRYPT_SHA512_CHAINING_STATE;

pub const SYMCRYPT_SHA512_STATE = extern struct {
    bytesInBuffer: UINT32 align(SYMCRYPT_ALIGN_VALUE),
    magic: SIZE_T,
    dataLengthL: UINT64,
    dataLengthH: UINT64,
    buffer: [128]BYTE align(SYMCRYPT_ALIGN_VALUE),
    chain: SYMCRYPT_SHA512_CHAINING_STATE,
};
pub const PSYMCRYPT_SHA512_STATE = *SYMCRYPT_SHA512_STATE;
pub const PCSYMCRYPT_SHA512_STATE = *const SYMCRYPT_SHA512_STATE;

pub const SYMCRYPT_SHA384_STATE = extern struct {
    bytesInBuffer: UINT32 align(SYMCRYPT_ALIGN_VALUE),
    magic: SIZE_T,
    dataLengthL: UINT64,
    dataLengthH: UINT64,
    buffer: [128]BYTE align(SYMCRYPT_ALIGN_VALUE),
    chain: SYMCRYPT_SHA512_CHAINING_STATE,
};
pub const PSYMCRYPT_SHA384_STATE = *SYMCRYPT_SHA384_STATE;
pub const PCSYMCRYPT_SHA384_STATE = *const SYMCRYPT_SHA384_STATE;

pub const SYMCRYPT_SHA512_224_STATE = extern struct {
    bytesInBuffer: UINT32 align(SYMCRYPT_ALIGN_VALUE),
    magic: SIZE_T,
    dataLengthL: UINT64,
    dataLengthH: UINT64,
    buffer: [128]BYTE align(SYMCRYPT_ALIGN_VALUE),
    chain: SYMCRYPT_SHA512_CHAINING_STATE,
};
pub const PSYMCRYPT_SHA512_224_STATE = *SYMCRYPT_SHA512_224_STATE;
pub const PCSYMCRYPT_SHA512_224_STATE = *const SYMCRYPT_SHA512_224_STATE;

pub const SYMCRYPT_SHA512_256_STATE = extern struct {
    bytesInBuffer: UINT32 align(SYMCRYPT_ALIGN_VALUE),
    magic: SIZE_T,
    dataLengthL: UINT64,
    dataLengthH: UINT64,
    buffer: [128]BYTE align(SYMCRYPT_ALIGN_VALUE),
    chain: SYMCRYPT_SHA512_CHAINING_STATE,
};
pub const PSYMCRYPT_SHA512_256_STATE = *SYMCRYPT_SHA512_256_STATE;
pub const PCSYMCRYPT_SHA512_256_STATE = *const SYMCRYPT_SHA512_256_STATE;

pub const SYMCRYPT_KECCAK_STATE = extern struct {
    state: [25]UINT64 align(SYMCRYPT_ALIGN_VALUE),
    inputBlockSize: UINT32,
    stateIndex: UINT32,
    paddingValue: UINT8,
    squeezeMode: BOOLEAN,
};

pub const SYMCRYPT_SHA3_224_STATE = extern struct {
    ks: SYMCRYPT_KECCAK_STATE align(SYMCRYPT_ALIGN_VALUE),
    magic: SIZE_T,
};

pub const SYMCRYPT_SHA3_256_STATE = extern struct {
    ks: SYMCRYPT_KECCAK_STATE align(SYMCRYPT_ALIGN_VALUE),
    magic: SIZE_T,
};

pub const SYMCRYPT_SHA3_384_STATE = extern struct {
    ks: SYMCRYPT_KECCAK_STATE align(SYMCRYPT_ALIGN_VALUE),
    magic: SIZE_T,
};

pub const SYMCRYPT_SHA3_512_STATE = extern struct {
    ks: SYMCRYPT_KECCAK_STATE align(SYMCRYPT_ALIGN_VALUE),
    magic: SIZE_T,
};

pub const SYMCRYPT_HASH_STATE = extern union {
    md2State: SYMCRYPT_MD2_STATE,
    md4State: SYMCRYPT_MD4_STATE,
    md5State: SYMCRYPT_MD5_STATE,
    sha1State: SYMCRYPT_SHA1_STATE,
    sha224State: SYMCRYPT_SHA224_STATE,
    sha256State: SYMCRYPT_SHA256_STATE,
    sha384State: SYMCRYPT_SHA384_STATE,
    sha512State: SYMCRYPT_SHA512_STATE,
    sha512_224State: SYMCRYPT_SHA512_224_STATE,
    sha512_256State: SYMCRYPT_SHA512_256_STATE,
    sha3_224State: SYMCRYPT_SHA3_224_STATE,
    sha3_256State: SYMCRYPT_SHA3_256_STATE,
    sha3_384State: SYMCRYPT_SHA3_384_STATE,
    sha3_512State: SYMCRYPT_SHA3_512_STATE,
};
pub const PSYMCRYPT_HASH_STATE = *SYMCRYPT_HASH_STATE;
pub const PCSYMCRYPT_HASH_STATE = *const SYMCRYPT_HASH_STATE;

// ==============================================================================================
// HMAC Key & State Structures (matching inc/symcrypt_internal.h)
// ==============================================================================================

pub const SYMCRYPT_HMAC_EXPANDED_KEY = extern struct {
    pHash: PCSYMCRYPT_HASH align(SYMCRYPT_ALIGN_VALUE),
    innerState: SYMCRYPT_HASH_STATE,
    outerState: SYMCRYPT_HASH_STATE,
    magic: SIZE_T,
};
pub const PSYMCRYPT_HMAC_EXPANDED_KEY = *SYMCRYPT_HMAC_EXPANDED_KEY;
pub const PCSYMCRYPT_HMAC_EXPANDED_KEY = *const SYMCRYPT_HMAC_EXPANDED_KEY;

pub const SYMCRYPT_HMAC_STATE = extern struct {
    pKey: ?PCSYMCRYPT_HMAC_EXPANDED_KEY align(SYMCRYPT_ALIGN_VALUE),
    hash: SYMCRYPT_HASH_STATE,
    magic: SIZE_T,
};
pub const PSYMCRYPT_HMAC_STATE = *SYMCRYPT_HMAC_STATE;
pub const PCSYMCRYPT_HMAC_STATE = *const SYMCRYPT_HMAC_STATE;

pub fn HmacExpandedKeyType(comptime ChainingState: type) type {
    return extern struct {
        innerState: ChainingState align(SYMCRYPT_ALIGN_VALUE),
        outerState: ChainingState,
        magic: SIZE_T,
    };
}

pub fn HmacStateType(comptime HashState: type, comptime ExpandedKey: type) type {
    return extern struct {
        hash: HashState align(SYMCRYPT_ALIGN_VALUE),
        pKey: ?*const ExpandedKey,
        magic: SIZE_T,
    };
}

pub const SYMCRYPT_HMAC_MD5_EXPANDED_KEY = HmacExpandedKeyType(SYMCRYPT_MD5_CHAINING_STATE);
pub const PSYMCRYPT_HMAC_MD5_EXPANDED_KEY = *SYMCRYPT_HMAC_MD5_EXPANDED_KEY;
pub const PCSYMCRYPT_HMAC_MD5_EXPANDED_KEY = *const SYMCRYPT_HMAC_MD5_EXPANDED_KEY;

pub const SYMCRYPT_HMAC_MD5_STATE = HmacStateType(SYMCRYPT_MD5_STATE, SYMCRYPT_HMAC_MD5_EXPANDED_KEY);
pub const PSYMCRYPT_HMAC_MD5_STATE = *SYMCRYPT_HMAC_MD5_STATE;
pub const PCSYMCRYPT_HMAC_MD5_STATE = *const SYMCRYPT_HMAC_MD5_STATE;

pub const SYMCRYPT_HMAC_SHA1_EXPANDED_KEY = HmacExpandedKeyType(SYMCRYPT_SHA1_CHAINING_STATE);
pub const PSYMCRYPT_HMAC_SHA1_EXPANDED_KEY = *SYMCRYPT_HMAC_SHA1_EXPANDED_KEY;
pub const PCSYMCRYPT_HMAC_SHA1_EXPANDED_KEY = *const SYMCRYPT_HMAC_SHA1_EXPANDED_KEY;

pub const SYMCRYPT_HMAC_SHA1_STATE = HmacStateType(SYMCRYPT_SHA1_STATE, SYMCRYPT_HMAC_SHA1_EXPANDED_KEY);
pub const PSYMCRYPT_HMAC_SHA1_STATE = *SYMCRYPT_HMAC_SHA1_STATE;
pub const PCSYMCRYPT_HMAC_SHA1_STATE = *const SYMCRYPT_HMAC_SHA1_STATE;

pub const SYMCRYPT_HMAC_SHA224_EXPANDED_KEY = HmacExpandedKeyType(SYMCRYPT_SHA256_CHAINING_STATE);
pub const PSYMCRYPT_HMAC_SHA224_EXPANDED_KEY = *SYMCRYPT_HMAC_SHA224_EXPANDED_KEY;
pub const PCSYMCRYPT_HMAC_SHA224_EXPANDED_KEY = *const SYMCRYPT_HMAC_SHA224_EXPANDED_KEY;

pub const SYMCRYPT_HMAC_SHA224_STATE = HmacStateType(SYMCRYPT_SHA224_STATE, SYMCRYPT_HMAC_SHA224_EXPANDED_KEY);
pub const PSYMCRYPT_HMAC_SHA224_STATE = *SYMCRYPT_HMAC_SHA224_STATE;
pub const PCSYMCRYPT_HMAC_SHA224_STATE = *const SYMCRYPT_HMAC_SHA224_STATE;

pub const SYMCRYPT_HMAC_SHA256_EXPANDED_KEY = HmacExpandedKeyType(SYMCRYPT_SHA256_CHAINING_STATE);
pub const PSYMCRYPT_HMAC_SHA256_EXPANDED_KEY = *SYMCRYPT_HMAC_SHA256_EXPANDED_KEY;
pub const PCSYMCRYPT_HMAC_SHA256_EXPANDED_KEY = *const SYMCRYPT_HMAC_SHA256_EXPANDED_KEY;

pub const SYMCRYPT_HMAC_SHA256_STATE = HmacStateType(SYMCRYPT_SHA256_STATE, SYMCRYPT_HMAC_SHA256_EXPANDED_KEY);
pub const PSYMCRYPT_HMAC_SHA256_STATE = *SYMCRYPT_HMAC_SHA256_STATE;
pub const PCSYMCRYPT_HMAC_SHA256_STATE = *const SYMCRYPT_HMAC_SHA256_STATE;

pub const SYMCRYPT_HMAC_SHA384_EXPANDED_KEY = HmacExpandedKeyType(SYMCRYPT_SHA512_CHAINING_STATE);
pub const PSYMCRYPT_HMAC_SHA384_EXPANDED_KEY = *SYMCRYPT_HMAC_SHA384_EXPANDED_KEY;
pub const PCSYMCRYPT_HMAC_SHA384_EXPANDED_KEY = *const SYMCRYPT_HMAC_SHA384_EXPANDED_KEY;

pub const SYMCRYPT_HMAC_SHA384_STATE = HmacStateType(SYMCRYPT_SHA384_STATE, SYMCRYPT_HMAC_SHA384_EXPANDED_KEY);
pub const PSYMCRYPT_HMAC_SHA384_STATE = *SYMCRYPT_HMAC_SHA384_STATE;
pub const PCSYMCRYPT_HMAC_SHA384_STATE = *const SYMCRYPT_HMAC_SHA384_STATE;

pub const SYMCRYPT_HMAC_SHA512_EXPANDED_KEY = HmacExpandedKeyType(SYMCRYPT_SHA512_CHAINING_STATE);
pub const PSYMCRYPT_HMAC_SHA512_EXPANDED_KEY = *SYMCRYPT_HMAC_SHA512_EXPANDED_KEY;
pub const PCSYMCRYPT_HMAC_SHA512_EXPANDED_KEY = *const SYMCRYPT_HMAC_SHA512_EXPANDED_KEY;

pub const SYMCRYPT_HMAC_SHA512_STATE = HmacStateType(SYMCRYPT_SHA512_STATE, SYMCRYPT_HMAC_SHA512_EXPANDED_KEY);
pub const PSYMCRYPT_HMAC_SHA512_STATE = *SYMCRYPT_HMAC_SHA512_STATE;
pub const PCSYMCRYPT_HMAC_SHA512_STATE = *const SYMCRYPT_HMAC_SHA512_STATE;

pub const SYMCRYPT_HMAC_SHA512_224_EXPANDED_KEY = HmacExpandedKeyType(SYMCRYPT_SHA512_CHAINING_STATE);
pub const PSYMCRYPT_HMAC_SHA512_224_EXPANDED_KEY = *SYMCRYPT_HMAC_SHA512_224_EXPANDED_KEY;
pub const PCSYMCRYPT_HMAC_SHA512_224_EXPANDED_KEY = *const SYMCRYPT_HMAC_SHA512_224_EXPANDED_KEY;

pub const SYMCRYPT_HMAC_SHA512_224_STATE = HmacStateType(SYMCRYPT_SHA512_224_STATE, SYMCRYPT_HMAC_SHA512_224_EXPANDED_KEY);
pub const PSYMCRYPT_HMAC_SHA512_224_STATE = *SYMCRYPT_HMAC_SHA512_224_STATE;
pub const PCSYMCRYPT_HMAC_SHA512_224_STATE = *const SYMCRYPT_HMAC_SHA512_224_STATE;

pub const SYMCRYPT_HMAC_SHA512_256_EXPANDED_KEY = HmacExpandedKeyType(SYMCRYPT_SHA512_CHAINING_STATE);
pub const PSYMCRYPT_HMAC_SHA512_256_EXPANDED_KEY = *SYMCRYPT_HMAC_SHA512_256_EXPANDED_KEY;
pub const PCSYMCRYPT_HMAC_SHA512_256_EXPANDED_KEY = *const SYMCRYPT_HMAC_SHA512_256_EXPANDED_KEY;

pub const SYMCRYPT_HMAC_SHA512_256_STATE = HmacStateType(SYMCRYPT_SHA512_256_STATE, SYMCRYPT_HMAC_SHA512_256_EXPANDED_KEY);
pub const PSYMCRYPT_HMAC_SHA512_256_STATE = *SYMCRYPT_HMAC_SHA512_256_STATE;
pub const PCSYMCRYPT_HMAC_SHA512_256_STATE = *const SYMCRYPT_HMAC_SHA512_256_STATE;

pub const SYMCRYPT_HMAC_SHA3_224_EXPANDED_KEY = extern struct {
    generic: SYMCRYPT_HMAC_EXPANDED_KEY align(SYMCRYPT_ALIGN_VALUE),
};
pub const PSYMCRYPT_HMAC_SHA3_224_EXPANDED_KEY = *SYMCRYPT_HMAC_SHA3_224_EXPANDED_KEY;
pub const PCSYMCRYPT_HMAC_SHA3_224_EXPANDED_KEY = *const SYMCRYPT_HMAC_SHA3_224_EXPANDED_KEY;

pub const SYMCRYPT_HMAC_SHA3_224_STATE = extern struct {
    generic: SYMCRYPT_HMAC_STATE align(SYMCRYPT_ALIGN_VALUE),
};
pub const PSYMCRYPT_HMAC_SHA3_224_STATE = *SYMCRYPT_HMAC_SHA3_224_STATE;
pub const PCSYMCRYPT_HMAC_SHA3_224_STATE = *const SYMCRYPT_HMAC_SHA3_224_STATE;

pub const SYMCRYPT_HMAC_SHA3_256_EXPANDED_KEY = extern struct {
    generic: SYMCRYPT_HMAC_EXPANDED_KEY align(SYMCRYPT_ALIGN_VALUE),
};
pub const PSYMCRYPT_HMAC_SHA3_256_EXPANDED_KEY = *SYMCRYPT_HMAC_SHA3_256_EXPANDED_KEY;
pub const PCSYMCRYPT_HMAC_SHA3_256_EXPANDED_KEY = *const SYMCRYPT_HMAC_SHA3_256_EXPANDED_KEY;

pub const SYMCRYPT_HMAC_SHA3_256_STATE = extern struct {
    generic: SYMCRYPT_HMAC_STATE align(SYMCRYPT_ALIGN_VALUE),
};
pub const PSYMCRYPT_HMAC_SHA3_256_STATE = *SYMCRYPT_HMAC_SHA3_256_STATE;
pub const PCSYMCRYPT_HMAC_SHA3_256_STATE = *const SYMCRYPT_HMAC_SHA3_256_STATE;

pub const SYMCRYPT_HMAC_SHA3_384_EXPANDED_KEY = extern struct {
    generic: SYMCRYPT_HMAC_EXPANDED_KEY align(SYMCRYPT_ALIGN_VALUE),
};
pub const PSYMCRYPT_HMAC_SHA3_384_EXPANDED_KEY = *SYMCRYPT_HMAC_SHA3_384_EXPANDED_KEY;
pub const PCSYMCRYPT_HMAC_SHA3_384_EXPANDED_KEY = *const SYMCRYPT_HMAC_SHA3_384_EXPANDED_KEY;

pub const SYMCRYPT_HMAC_SHA3_384_STATE = extern struct {
    generic: SYMCRYPT_HMAC_STATE align(SYMCRYPT_ALIGN_VALUE),
};
pub const PSYMCRYPT_HMAC_SHA3_384_STATE = *SYMCRYPT_HMAC_SHA3_384_STATE;
pub const PCSYMCRYPT_HMAC_SHA3_384_STATE = *const SYMCRYPT_HMAC_SHA3_384_STATE;

pub const SYMCRYPT_HMAC_SHA3_512_EXPANDED_KEY = extern struct {
    generic: SYMCRYPT_HMAC_EXPANDED_KEY align(SYMCRYPT_ALIGN_VALUE),
};
pub const PSYMCRYPT_HMAC_SHA3_512_EXPANDED_KEY = *SYMCRYPT_HMAC_SHA3_512_EXPANDED_KEY;
pub const PCSYMCRYPT_HMAC_SHA3_512_EXPANDED_KEY = *const SYMCRYPT_HMAC_SHA3_512_EXPANDED_KEY;

pub const SYMCRYPT_HMAC_SHA3_512_STATE = extern struct {
    generic: SYMCRYPT_HMAC_STATE align(SYMCRYPT_ALIGN_VALUE),
};
pub const PSYMCRYPT_HMAC_SHA3_512_STATE = *SYMCRYPT_HMAC_SHA3_512_STATE;
pub const PCSYMCRYPT_HMAC_SHA3_512_STATE = *const SYMCRYPT_HMAC_SHA3_512_STATE;

// ==============================================================================================
// External C Declarations (Hash Primitives, Wipe, Selftest Globals)
// ==============================================================================================

extern fn SymCryptWipe(pbData: PVOID, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptInjectError(pbBuf: PBYTE, cbBuf: SIZE_T) callconv(SYMCRYPT_CALL) void;

extern const SymCryptTestMsg3: [3]BYTE;
extern const SymCryptTestKey32: [32]BYTE;

extern fn SymCryptHash(pHash: PCSYMCRYPT_HASH, pbData: ?PCBYTE, cbData: SIZE_T, pbResult: PBYTE, cbResult: SIZE_T) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptHashInit(pHash: PCSYMCRYPT_HASH, pState: PVOID) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptHashAppend(pHash: PCSYMCRYPT_HASH, pState: PVOID, pbData: ?PCBYTE, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptHashResult(pHash: PCSYMCRYPT_HASH, pState: PVOID, pbResult: PBYTE, cbResult: SIZE_T) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptHashStateCopy(pHash: PCSYMCRYPT_HASH, pSrc: PCVOID, pDst: PVOID) callconv(SYMCRYPT_CALL) void;

extern const SymCryptMd5Algorithm: PCSYMCRYPT_HASH;
extern fn SymCryptMd5Init(pState: PSYMCRYPT_MD5_STATE) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptMd5Append(pState: PSYMCRYPT_MD5_STATE, pbData: ?PCBYTE, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptMd5Result(pState: PSYMCRYPT_MD5_STATE, pbResult: PBYTE) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptMd5StateCopy(pSrc: PCSYMCRYPT_MD5_STATE, pDst: PSYMCRYPT_MD5_STATE) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptMd5AppendBlocks(pChain: PSYMCRYPT_MD5_CHAINING_STATE, pbData: PCBYTE, cbData: SIZE_T, pcbRemaining: *SIZE_T) callconv(SYMCRYPT_CALL) void;

extern const SymCryptSha1Algorithm: PCSYMCRYPT_HASH;
extern fn SymCryptSha1Init(pState: PSYMCRYPT_SHA1_STATE) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptSha1Append(pState: PSYMCRYPT_SHA1_STATE, pbData: ?PCBYTE, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptSha1Result(pState: PSYMCRYPT_SHA1_STATE, pbResult: PBYTE) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptSha1StateCopy(pSrc: PCSYMCRYPT_SHA1_STATE, pDst: PSYMCRYPT_SHA1_STATE) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptSha1AppendBlocks(pChain: PSYMCRYPT_SHA1_CHAINING_STATE, pbData: PCBYTE, cbData: SIZE_T, pcbRemaining: *SIZE_T) callconv(SYMCRYPT_CALL) void;

extern const SymCryptSha224Algorithm: PCSYMCRYPT_HASH;
extern fn SymCryptSha224Init(pState: PSYMCRYPT_SHA224_STATE) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptSha224Append(pState: PSYMCRYPT_SHA224_STATE, pbData: ?PCBYTE, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptSha224Result(pState: PSYMCRYPT_SHA224_STATE, pbResult: PBYTE) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptSha224StateCopy(pSrc: PCSYMCRYPT_SHA224_STATE, pDst: PSYMCRYPT_SHA224_STATE) callconv(SYMCRYPT_CALL) void;

extern const SymCryptSha256Algorithm: PCSYMCRYPT_HASH;
extern fn SymCryptSha256Init(pState: PSYMCRYPT_SHA256_STATE) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptSha256Append(pState: PSYMCRYPT_SHA256_STATE, pbData: ?PCBYTE, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptSha256Result(pState: PSYMCRYPT_SHA256_STATE, pbResult: PBYTE) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptSha256StateCopy(pSrc: PCSYMCRYPT_SHA256_STATE, pDst: PSYMCRYPT_SHA256_STATE) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptSha256AppendBlocks(pChain: PSYMCRYPT_SHA256_CHAINING_STATE, pbData: PCBYTE, cbData: SIZE_T, pcbRemaining: *SIZE_T) callconv(SYMCRYPT_CALL) void;

extern const SymCryptSha384Algorithm: PCSYMCRYPT_HASH;
extern fn SymCryptSha384Init(pState: PSYMCRYPT_SHA384_STATE) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptSha384Append(pState: PSYMCRYPT_SHA384_STATE, pbData: ?PCBYTE, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptSha384Result(pState: PSYMCRYPT_SHA384_STATE, pbResult: PBYTE) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptSha384StateCopy(pSrc: PCSYMCRYPT_SHA384_STATE, pDst: PSYMCRYPT_SHA384_STATE) callconv(SYMCRYPT_CALL) void;

extern const SymCryptSha512Algorithm: PCSYMCRYPT_HASH;
extern fn SymCryptSha512Init(pState: PSYMCRYPT_SHA512_STATE) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptSha512Append(pState: PSYMCRYPT_SHA512_STATE, pbData: ?PCBYTE, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptSha512Result(pState: PSYMCRYPT_SHA512_STATE, pbResult: PBYTE) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptSha512StateCopy(pSrc: PCSYMCRYPT_SHA512_STATE, pDst: PSYMCRYPT_SHA512_STATE) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptSha512AppendBlocks(pChain: PSYMCRYPT_SHA512_CHAINING_STATE, pbData: PCBYTE, cbData: SIZE_T, pcbRemaining: *SIZE_T) callconv(SYMCRYPT_CALL) void;

extern const SymCryptSha512_224Algorithm: PCSYMCRYPT_HASH;
extern fn SymCryptSha512_224Init(pState: PSYMCRYPT_SHA512_224_STATE) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptSha512_224Append(pState: PSYMCRYPT_SHA512_224_STATE, pbData: ?PCBYTE, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptSha512_224Result(pState: PSYMCRYPT_SHA512_224_STATE, pbResult: PBYTE) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptSha512_224StateCopy(pSrc: PCSYMCRYPT_SHA512_224_STATE, pDst: PSYMCRYPT_SHA512_224_STATE) callconv(SYMCRYPT_CALL) void;

extern const SymCryptSha512_256Algorithm: PCSYMCRYPT_HASH;
extern fn SymCryptSha512_256Init(pState: PSYMCRYPT_SHA512_256_STATE) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptSha512_256Append(pState: PSYMCRYPT_SHA512_256_STATE, pbData: ?PCBYTE, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptSha512_256Result(pState: PSYMCRYPT_SHA512_256_STATE, pbResult: PBYTE) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptSha512_256StateCopy(pSrc: PCSYMCRYPT_SHA512_256_STATE, pDst: PSYMCRYPT_SHA512_256_STATE) callconv(SYMCRYPT_CALL) void;

extern const SymCryptSha3_224Algorithm: PCSYMCRYPT_HASH;
extern const SymCryptSha3_256Algorithm: PCSYMCRYPT_HASH;
extern const SymCryptSha3_384Algorithm: PCSYMCRYPT_HASH;
extern const SymCryptSha3_512Algorithm: PCSYMCRYPT_HASH;

// ==============================================================================================
// SymCryptWipeKnownSize Helper (matching inc/symcrypt_internal.h)
// ==============================================================================================

const WIPE_FUNCTION_LIMIT: usize = if (types.CPU_X86 or types.CPU_ARM)
    32
else if (types.CPU_AMD64 or types.CPU_ARM64)
    64
else
    0;

pub inline fn SymCryptWipeKnownSize(pbData: anytype, comptime cbDataInit: usize) void {
    if (WIPE_FUNCTION_LIMIT == 0 or cbDataInit > WIPE_FUNCTION_LIMIT) {
        SymCryptWipe(@ptrCast(pbData), cbDataInit);
    } else {
        const pb: [*]u8 = @ptrCast(pbData);
        comptime var cbData: usize = cbDataInit;
        if ((cbData & 1) != 0) {
            cbData -= 1;
            macros.FORCE_WRITE8(pb + cbData, 0);
        }
        if ((cbData & 2) != 0) {
            cbData -= 2;
            macros.FORCE_WRITE16(pb + cbData, 0);
        }
        if ((cbData & 4) != 0) {
            cbData -= 4;
            macros.FORCE_WRITE32(pb + cbData, 0);
        }
        if ((cbData & 8) != 0) {
            cbData -= 8;
            macros.FORCE_WRITE64(pb + cbData, 0);
        }
        if ((cbData & 16) != 0) {
            cbData -= 16;
            macros.FORCE_WRITE64(pb + cbData, 0);
            macros.FORCE_WRITE64(pb + cbData + 8, 0);
        }
        if ((cbData & 32) != 0) {
            cbData -= 32;
            macros.FORCE_WRITE64(pb + cbData, 0);
            macros.FORCE_WRITE64(pb + cbData + 8, 0);
            macros.FORCE_WRITE64(pb + cbData + 16, 0);
            macros.FORCE_WRITE64(pb + cbData + 24, 0);
        }
        if (WIPE_FUNCTION_LIMIT >= 64 and (cbData & 64) != 0) {
            cbData -= 64;
            macros.FORCE_WRITE64(pb + cbData, 0);
            macros.FORCE_WRITE64(pb + cbData + 8, 0);
            macros.FORCE_WRITE64(pb + cbData + 16, 0);
            macros.FORCE_WRITE64(pb + cbData + 24, 0);
            macros.FORCE_WRITE64(pb + cbData + 32, 0);
            macros.FORCE_WRITE64(pb + cbData + 40, 0);
            macros.FORCE_WRITE64(pb + cbData + 48, 0);
            macros.FORCE_WRITE64(pb + cbData + 56, 0);
        }
    }
}

// ==============================================================================================
// Generic HMAC Implementation (port of lib/hmac.c)
// ==============================================================================================

pub export fn SymCryptHmacStateCopy(
    pSrc: PCSYMCRYPT_HMAC_STATE,
    pExpandedKey: ?PCSYMCRYPT_HMAC_EXPANDED_KEY,
    pDst: PSYMCRYPT_HMAC_STATE,
) callconv(SYMCRYPT_CALL) void {
    macros.CHECK_MAGIC(pSrc);

    const pHash = pSrc.pKey.?.pHash;

    SymCryptHashStateCopy(pHash, &pSrc.hash, &pDst.hash);

    if (pExpandedKey) |pKey| {
        macros.CHECK_MAGIC(pKey);
        pDst.pKey = pKey;
    } else {
        macros.CHECK_MAGIC(pSrc.pKey.?);
        pDst.pKey = pSrc.pKey;
    }
    macros.SET_MAGIC(pDst);
}

pub export fn SymCryptHmacKeyCopy(
    pSrc: PCSYMCRYPT_HMAC_EXPANDED_KEY,
    pDst: PSYMCRYPT_HMAC_EXPANDED_KEY,
) callconv(SYMCRYPT_CALL) void {
    macros.CHECK_MAGIC(pSrc);

    SymCryptHashStateCopy(pSrc.pHash, &pSrc.innerState, &pDst.innerState);
    SymCryptHashStateCopy(pSrc.pHash, &pSrc.outerState, &pDst.outerState);

    pDst.pHash = pSrc.pHash;

    macros.SET_MAGIC(pDst);
}

pub export fn SymCryptHmacExpandKey(
    pHash: PCSYMCRYPT_HASH,
    pExpandedKey: PSYMCRYPT_HMAC_EXPANDED_KEY,
    pbKey: ?PCBYTE,
    cbKey: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var iblock: [SYMCRYPT_SHA3_224_INPUT_BLOCK_SIZE]BYTE align(SYMCRYPT_ALIGN_VALUE) = @splat(0);

    macros.ASSERT(@sizeOf(@TypeOf(iblock)) >= pHash.inputBlockSize);
    macros.ASSERT(@sizeOf(@TypeOf(iblock)) >= pHash.resultSize);
    macros.ASSERT(pHash.inputBlockSize % 8 == 0);

    if (cbKey <= pHash.inputBlockSize) {
        if (cbKey > 0) {
            @memcpy(iblock[0..cbKey], pbKey.?[0..cbKey]);
        }
    } else {
        SymCryptHash(pHash, pbKey, cbKey, &iblock, pHash.resultSize);
    }

    macros.XorByteIntoBuffer(&iblock, pHash.inputBlockSize / 8, HMAC_IPAD_BYTE);

    SymCryptHashInit(pHash, &pExpandedKey.innerState);
    SymCryptHashInit(pHash, &pExpandedKey.outerState);

    SymCryptHashAppend(pHash, &pExpandedKey.innerState, &iblock, pHash.inputBlockSize);

    macros.XorByteIntoBuffer(&iblock, pHash.inputBlockSize / 8, HMAC_IPAD_BYTE ^ HMAC_OPAD_BYTE);

    SymCryptHashAppend(pHash, &pExpandedKey.outerState, &iblock, pHash.inputBlockSize);

    SymCryptWipeKnownSize(&iblock, @sizeOf(@TypeOf(iblock)));

    pExpandedKey.pHash = pHash;

    macros.SET_MAGIC(pExpandedKey);

    return .SYMCRYPT_NO_ERROR;
}

pub noinline fn SymCryptHmacInit(
    pState: PSYMCRYPT_HMAC_STATE,
    pExpandedKey: PCSYMCRYPT_HMAC_EXPANDED_KEY,
) callconv(SYMCRYPT_CALL) void {
    macros.CHECK_MAGIC(pExpandedKey);

    SymCryptHashStateCopy(pExpandedKey.pHash, &pExpandedKey.innerState, &pState.hash);

    pState.pKey = pExpandedKey;

    macros.SET_MAGIC(pState);
}

pub export fn SymCryptHmacAppend(
    pState: PSYMCRYPT_HMAC_STATE,
    pbData: ?PCBYTE,
    cbData: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    SymCryptHashAppend(pState.pKey.?.pHash, &pState.hash, pbData, cbData);
}

pub noinline fn SymCryptHmacResult(
    pState: PSYMCRYPT_HMAC_STATE,
    pbResult: PBYTE,
) callconv(SYMCRYPT_CALL) void {
    var innerRes: [64]BYTE = undefined;

    const pHash = pState.pKey.?.pHash;

    macros.ASSERT(@sizeOf(@TypeOf(innerRes)) >= pHash.resultSize);

    macros.CHECK_MAGIC(pState);

    SymCryptHashResult(pHash, &pState.hash, &innerRes, pHash.resultSize);

    const pKey = pState.pKey.?;
    macros.CHECK_MAGIC(pKey);

    SymCryptHashStateCopy(pHash, &pKey.outerState, &pState.hash);

    SymCryptHashAppend(pHash, &pState.hash, &innerRes, pHash.resultSize);

    SymCryptHashResult(pHash, &pState.hash, pbResult, pHash.resultSize);

    SymCryptWipeKnownSize(&innerRes, @sizeOf(@TypeOf(innerRes)));
    pState.pKey = null;
}

pub noinline fn SymCryptHmac(
    pExpandedKey: PCSYMCRYPT_HMAC_EXPANDED_KEY,
    pbData: ?PCBYTE,
    cbData: SIZE_T,
    pbResult: PBYTE,
) callconv(SYMCRYPT_CALL) void {
    var state: SYMCRYPT_HMAC_STATE = undefined;

    SymCryptHmacInit(&state, pExpandedKey);
    SymCryptHmacAppend(&state, pbData, cbData);
    SymCryptHmacResult(&state, pbResult);
}

comptime {
    @export(&SymCryptHmacInit, .{ .name = "SymCryptHmacInit" });
    @export(&SymCryptHmacResult, .{ .name = "SymCryptHmacResult" });
    @export(&SymCryptHmac, .{ .name = "SymCryptHmac" });
}

// ==============================================================================================
// Comptime HMAC Pattern Generator (replaces lib/hmac_pattern.c)
// ==============================================================================================

fn HmacPattern(comptime Config: type) type {
    return struct {
        pub const ExpandedKey = Config.ExpandedKey;
        pub const State = Config.State;
        pub const HashState = Config.HashState;
        pub const input_block_size: usize = Config.input_block_size;
        pub const result_size: usize = Config.result_size;

        inline fn setDataLength(hash: *HashState, len: u64) void {
            hash.dataLengthL = len;
            if (Config.clear_data_length_h) {
                hash.dataLengthH = 0;
            }
        }

        pub fn stateCopy(
            pSrc: *const State,
            pExpandedKey: ?*const ExpandedKey,
            pDst: *State,
        ) callconv(SYMCRYPT_CALL) void {
            macros.CHECK_MAGIC(pSrc);

            Config.hashStateCopy(&pSrc.hash, &pDst.hash);

            if (pExpandedKey) |pKey| {
                macros.CHECK_MAGIC(pKey);
                pDst.pKey = pKey;
            } else {
                macros.CHECK_MAGIC(pSrc.pKey.?);
                pDst.pKey = pSrc.pKey;
            }
            macros.SET_MAGIC(pDst);
        }

        pub fn keyCopy(
            pSrc: *const ExpandedKey,
            pDst: *ExpandedKey,
        ) callconv(SYMCRYPT_CALL) void {
            macros.CHECK_MAGIC(pSrc);
            pDst.* = pSrc.*;
            macros.SET_MAGIC(pDst);
        }

        pub fn expandKey(
            pExpandedKey: *ExpandedKey,
            pbKey: ?PCBYTE,
            cbKey: SIZE_T,
        ) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
            var hashState: HashState = undefined;
            var iblock: [input_block_size]BYTE align(SYMCRYPT_ALIGN_VALUE) = @splat(0);
            var tmp: SIZE_T = undefined;

            macros.SET_MAGIC(pExpandedKey);

            Config.hashInit(&hashState);

            if (cbKey <= iblock.len) {
                if (cbKey > 0) {
                    @memcpy(iblock[0..cbKey], pbKey.?[0..cbKey]);
                }
            } else {
                Config.hashAppend(&hashState, pbKey, cbKey);
                Config.hashResult(&hashState, &iblock);
            }

            macros.XorByteIntoBuffer(&iblock, iblock.len / 8, HMAC_IPAD_BYTE);

            pExpandedKey.innerState = hashState.chain;
            pExpandedKey.outerState = hashState.chain;

            Config.hashAppendBlocks(&pExpandedKey.innerState, &iblock, iblock.len, &tmp);

            macros.XorByteIntoBuffer(&iblock, iblock.len / 8, HMAC_IPAD_BYTE ^ HMAC_OPAD_BYTE);

            Config.hashAppendBlocks(&pExpandedKey.outerState, &iblock, iblock.len, &tmp);

            SymCryptWipeKnownSize(&iblock, @sizeOf(@TypeOf(iblock)));
            SymCryptWipeKnownSize(&hashState, @sizeOf(HashState));

            return .SYMCRYPT_NO_ERROR;
        }

        pub noinline fn init(
            pState: *State,
            pExpandedKey: *const ExpandedKey,
        ) callconv(SYMCRYPT_CALL) void {
            macros.CHECK_MAGIC(pExpandedKey);

            macros.SET_MAGIC(pState);

            macros.SET_MAGIC(&pState.hash);
            pState.hash.chain = pExpandedKey.innerState;
            setDataLength(&pState.hash, input_block_size);
            pState.hash.bytesInBuffer = 0;
            pState.pKey = pExpandedKey;
        }

        pub fn append(
            pState: *State,
            pbData: ?PCBYTE,
            cbData: SIZE_T,
        ) callconv(SYMCRYPT_CALL) void {
            Config.hashAppend(&pState.hash, pbData, cbData);
        }

        pub noinline fn result(
            pState: *State,
            pbResult: PBYTE,
        ) callconv(SYMCRYPT_CALL) void {
            var innerRes: [result_size]BYTE = undefined;

            macros.CHECK_MAGIC(pState);

            Config.hashResult(&pState.hash, &innerRes);

            const pKey = pState.pKey.?;
            macros.CHECK_MAGIC(pKey);

            pState.hash.chain = pKey.outerState;

            @memcpy(pState.hash.buffer[0..result_size], innerRes[0..result_size]);
            setDataLength(&pState.hash, input_block_size + result_size);
            pState.hash.bytesInBuffer = result_size;

            Config.hashResult(&pState.hash, pbResult);

            SymCryptWipe(@ptrCast(&innerRes), result_size);
            pState.pKey = null;
        }

        pub noinline fn mac(
            pExpandedKey: *const ExpandedKey,
            pbData: ?PCBYTE,
            cbData: SIZE_T,
            pbResult: PBYTE,
        ) callconv(SYMCRYPT_CALL) void {
            var state: State = undefined;

            init(&state, pExpandedKey);
            append(&state, pbData, cbData);
            result(&state, pbResult);
        }

        pub fn selftest() callconv(SYMCRYPT_CALL) void {
            var xKey: ExpandedKey = undefined;
            var res: [result_size]BYTE = undefined;

            _ = expandKey(&xKey, &SymCryptTestKey32, Config.selftest_key_size);
            mac(&xKey, &SymCryptTestMsg3, SymCryptTestMsg3.len, &res);

            SymCryptInjectError(&res, res.len);

            if (!std.mem.eql(u8, &res, &Config.kat)) {
                macros.SymCryptFatal(comptime macros.multiCharConstant(Config.fatal_code));
            }
        }

        pub const algorithm_default: SYMCRYPT_MAC = .{
            .expandKeyFunc = @ptrCast(&expandKey),
            .initFunc = @ptrCast(&init),
            .appendFunc = @ptrCast(&append),
            .resultFunc = @ptrCast(&result),
            .expandedKeySize = @sizeOf(ExpandedKey),
            .stateSize = @sizeOf(State),
            .resultSize = result_size,
            .ppHashAlgorithm = @ptrCast(Config.pp_hash_algorithm),
            .outerChainingStateOffset = Config.outer_chaining_state_offset,
        };

        pub const algorithm: PCSYMCRYPT_MAC = &algorithm_default;

        comptime {
            const prefix = "SymCryptHmac" ++ Config.name;
            @export(&expandKey, .{ .name = prefix ++ "ExpandKey" });
            @export(&keyCopy, .{ .name = prefix ++ "KeyCopy" });
            @export(&mac, .{ .name = prefix });
            @export(&stateCopy, .{ .name = prefix ++ "StateCopy" });
            @export(&init, .{ .name = prefix ++ "Init" });
            @export(&append, .{ .name = prefix ++ "Append" });
            @export(&result, .{ .name = prefix ++ "Result" });
            @export(&selftest, .{ .name = prefix ++ "Selftest" });
            @export(&algorithm_default, .{ .name = prefix ++ "Algorithm_default" });
            @export(&algorithm, .{ .name = prefix ++ "Algorithm" });
        }
    };
}

// ==============================================================================================
// Comptime SHA-3 Generic HMAC Wrapper Generator (replaces lib/hmacsha3_*.c)
// ==============================================================================================

fn HmacSha3Wrapper(comptime Config: type) type {
    return struct {
        pub const ExpandedKey = Config.ExpandedKey;
        pub const State = Config.State;
        pub const result_size: usize = Config.result_size;

        pub fn expandKey(
            pExpandedKey: *ExpandedKey,
            pbKey: ?PCBYTE,
            cbKey: SIZE_T,
        ) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
            return SymCryptHmacExpandKey(Config.pp_hash_algorithm.*, &pExpandedKey.generic, pbKey, cbKey);
        }

        pub fn keyCopy(
            pSrc: *const ExpandedKey,
            pDst: *ExpandedKey,
        ) callconv(SYMCRYPT_CALL) void {
            SymCryptHmacKeyCopy(&pSrc.generic, &pDst.generic);
        }

        pub fn mac(
            pExpandedKey: *const ExpandedKey,
            pbData: ?PCBYTE,
            cbData: SIZE_T,
            pbResult: PBYTE,
        ) callconv(SYMCRYPT_CALL) void {
            SymCryptHmac(&pExpandedKey.generic, pbData, cbData, pbResult);
        }

        pub fn stateCopy(
            pSrc: *const State,
            pExpandedKey: ?*const ExpandedKey,
            pDst: *State,
        ) callconv(SYMCRYPT_CALL) void {
            SymCryptHmacStateCopy(
                &pSrc.generic,
                if (pExpandedKey) |pKey| &pKey.generic else null,
                &pDst.generic,
            );
        }

        pub fn init(
            pState: *State,
            pExpandedKey: *const ExpandedKey,
        ) callconv(SYMCRYPT_CALL) void {
            SymCryptHmacInit(&pState.generic, &pExpandedKey.generic);
        }

        pub fn append(
            pState: *State,
            pbData: ?PCBYTE,
            cbData: SIZE_T,
        ) callconv(SYMCRYPT_CALL) void {
            SymCryptHmacAppend(&pState.generic, pbData, cbData);
        }

        pub fn result(
            pState: *State,
            pbResult: PBYTE,
        ) callconv(SYMCRYPT_CALL) void {
            SymCryptHmacResult(&pState.generic, pbResult);
        }

        pub fn selftest() callconv(SYMCRYPT_CALL) void {
            var xKey: ExpandedKey = undefined;
            var res: [result_size]BYTE = undefined;

            _ = expandKey(&xKey, &SymCryptTestKey32, Config.selftest_key_size);
            mac(&xKey, &SymCryptTestMsg3, SymCryptTestMsg3.len, &res);

            SymCryptInjectError(&res, res.len);

            if (!std.mem.eql(u8, &res, &Config.kat)) {
                macros.SymCryptFatal(comptime macros.multiCharConstant(Config.fatal_code));
            }
        }

        pub const algorithm_default: SYMCRYPT_MAC = .{
            .expandKeyFunc = @ptrCast(&expandKey),
            .initFunc = @ptrCast(&init),
            .appendFunc = @ptrCast(&append),
            .resultFunc = @ptrCast(&result),
            .expandedKeySize = @sizeOf(ExpandedKey),
            .stateSize = @sizeOf(State),
            .resultSize = result_size,
            .ppHashAlgorithm = @ptrCast(Config.pp_hash_algorithm),
            .outerChainingStateOffset = @offsetOf(SYMCRYPT_HMAC_EXPANDED_KEY, "outerState"),
        };

        pub const algorithm: PCSYMCRYPT_MAC = &algorithm_default;

        comptime {
            const prefix = "SymCryptHmac" ++ Config.name;
            @export(&expandKey, .{ .name = prefix ++ "ExpandKey" });
            @export(&keyCopy, .{ .name = prefix ++ "KeyCopy" });
            @export(&mac, .{ .name = prefix });
            @export(&stateCopy, .{ .name = prefix ++ "StateCopy" });
            @export(&init, .{ .name = prefix ++ "Init" });
            @export(&append, .{ .name = prefix ++ "Append" });
            @export(&result, .{ .name = prefix ++ "Result" });
            @export(&selftest, .{ .name = prefix ++ "Selftest" });
            @export(&algorithm_default, .{ .name = prefix ++ "Algorithm_default" });
            @export(&algorithm, .{ .name = prefix ++ "Algorithm" });
        }
    };
}

// ==============================================================================================
// Algorithm Instantiations
// ==============================================================================================

pub const HmacMd5 = HmacPattern(struct {
    pub const name = "Md5";
    pub const ExpandedKey = SYMCRYPT_HMAC_MD5_EXPANDED_KEY;
    pub const State = SYMCRYPT_HMAC_MD5_STATE;
    pub const HashState = SYMCRYPT_MD5_STATE;
    pub const input_block_size = SYMCRYPT_MD5_INPUT_BLOCK_SIZE;
    pub const result_size = SYMCRYPT_MD5_RESULT_SIZE;
    pub const clear_data_length_h = false;
    pub const hashInit = SymCryptMd5Init;
    pub const hashAppend = SymCryptMd5Append;
    pub const hashResult = SymCryptMd5Result;
    pub const hashStateCopy = SymCryptMd5StateCopy;
    pub const hashAppendBlocks = SymCryptMd5AppendBlocks;
    pub const pp_hash_algorithm = &SymCryptMd5Algorithm;
    pub const outer_chaining_state_offset: UINT32 = 0;
    pub const selftest_key_size: usize = 16;
    pub const fatal_code = "hmd5";
    pub const kat = [16]BYTE{
        0x77, 0x33, 0x69, 0x79, 0x9e, 0x54, 0xeb, 0x49,
        0xff, 0x21, 0xe6, 0xf9, 0x63, 0xe5, 0xbb, 0x49,
    };
});

pub const HmacSha1 = HmacPattern(struct {
    pub const name = "Sha1";
    pub const ExpandedKey = SYMCRYPT_HMAC_SHA1_EXPANDED_KEY;
    pub const State = SYMCRYPT_HMAC_SHA1_STATE;
    pub const HashState = SYMCRYPT_SHA1_STATE;
    pub const input_block_size = SYMCRYPT_SHA1_INPUT_BLOCK_SIZE;
    pub const result_size = SYMCRYPT_SHA1_RESULT_SIZE;
    pub const clear_data_length_h = false;
    pub const hashInit = SymCryptSha1Init;
    pub const hashAppend = SymCryptSha1Append;
    pub const hashResult = SymCryptSha1Result;
    pub const hashStateCopy = SymCryptSha1StateCopy;
    pub const hashAppendBlocks = SymCryptSha1AppendBlocks;
    pub const pp_hash_algorithm = &SymCryptSha1Algorithm;
    pub const outer_chaining_state_offset: UINT32 = @offsetOf(SYMCRYPT_HMAC_SHA1_EXPANDED_KEY, "outerState");
    pub const selftest_key_size: usize = 16;
    pub const fatal_code = "hSh1";
    pub const kat = [20]BYTE{
        0x2a, 0x29, 0x85, 0x40, 0x23, 0xba, 0x2e, 0xf1,
        0x49, 0x0f, 0x8c, 0xd8, 0x97, 0xa8, 0xcc, 0x6b,
        0x55, 0x7b, 0x2a, 0x12,
    };
});

pub const HmacSha224 = HmacPattern(struct {
    pub const name = "Sha224";
    pub const ExpandedKey = SYMCRYPT_HMAC_SHA224_EXPANDED_KEY;
    pub const State = SYMCRYPT_HMAC_SHA224_STATE;
    pub const HashState = SYMCRYPT_SHA224_STATE;
    pub const input_block_size = SYMCRYPT_SHA224_INPUT_BLOCK_SIZE;
    pub const result_size = SYMCRYPT_SHA224_RESULT_SIZE;
    pub const clear_data_length_h = false;
    pub const hashInit = SymCryptSha224Init;
    pub const hashAppend = SymCryptSha224Append;
    pub const hashResult = SymCryptSha224Result;
    pub const hashStateCopy = SymCryptSha224StateCopy;
    pub const hashAppendBlocks = SymCryptSha256AppendBlocks;
    pub const pp_hash_algorithm = &SymCryptSha224Algorithm;
    pub const outer_chaining_state_offset: UINT32 = @offsetOf(SYMCRYPT_HMAC_SHA224_EXPANDED_KEY, "outerState");
    pub const selftest_key_size: usize = 16;
    pub const fatal_code = "hsh4";
    pub const kat = [28]BYTE{
        0x3e, 0x1c, 0x48, 0x2f, 0x66, 0x49, 0x67, 0xa9,
        0xad, 0x4f, 0x76, 0x52, 0x36, 0xf8, 0x5a, 0x1f,
        0x63, 0x5b, 0x34, 0xe9, 0x35, 0x71, 0x62, 0x35,
        0xa2, 0x9e, 0x61, 0xb1,
    };
});

pub const HmacSha256 = HmacPattern(struct {
    pub const name = "Sha256";
    pub const ExpandedKey = SYMCRYPT_HMAC_SHA256_EXPANDED_KEY;
    pub const State = SYMCRYPT_HMAC_SHA256_STATE;
    pub const HashState = SYMCRYPT_SHA256_STATE;
    pub const input_block_size = SYMCRYPT_SHA256_INPUT_BLOCK_SIZE;
    pub const result_size = SYMCRYPT_SHA256_RESULT_SIZE;
    pub const clear_data_length_h = false;
    pub const hashInit = SymCryptSha256Init;
    pub const hashAppend = SymCryptSha256Append;
    pub const hashResult = SymCryptSha256Result;
    pub const hashStateCopy = SymCryptSha256StateCopy;
    pub const hashAppendBlocks = SymCryptSha256AppendBlocks;
    pub const pp_hash_algorithm = &SymCryptSha256Algorithm;
    pub const outer_chaining_state_offset: UINT32 = @offsetOf(SYMCRYPT_HMAC_SHA256_EXPANDED_KEY, "outerState");
    pub const selftest_key_size: usize = 16;
    pub const fatal_code = "hsh2";
    pub const kat = [32]BYTE{
        0xd6, 0x01, 0xcc, 0x17, 0x75, 0x59, 0xb0, 0x24,
        0x84, 0x59, 0x78, 0x7f, 0x7e, 0x80, 0x4e, 0xd7,
        0xf2, 0x76, 0x89, 0xb5, 0x99, 0x5c, 0x59, 0xb6,
        0x61, 0x80, 0x2d, 0x96, 0x82, 0xfd, 0xf8, 0xd2,
    };
});

pub const HmacSha384 = HmacPattern(struct {
    pub const name = "Sha384";
    pub const ExpandedKey = SYMCRYPT_HMAC_SHA384_EXPANDED_KEY;
    pub const State = SYMCRYPT_HMAC_SHA384_STATE;
    pub const HashState = SYMCRYPT_SHA384_STATE;
    pub const input_block_size = SYMCRYPT_SHA384_INPUT_BLOCK_SIZE;
    pub const result_size = SYMCRYPT_SHA384_RESULT_SIZE;
    pub const clear_data_length_h = true;
    pub const hashInit = SymCryptSha384Init;
    pub const hashAppend = SymCryptSha384Append;
    pub const hashResult = SymCryptSha384Result;
    pub const hashStateCopy = SymCryptSha384StateCopy;
    pub const hashAppendBlocks = SymCryptSha512AppendBlocks;
    pub const pp_hash_algorithm = &SymCryptSha384Algorithm;
    pub const outer_chaining_state_offset: UINT32 = @offsetOf(SYMCRYPT_HMAC_SHA384_EXPANDED_KEY, "outerState");
    pub const selftest_key_size: usize = 16;
    pub const fatal_code = "hsh3";
    pub const kat = [48]BYTE{
        0x67, 0xdb, 0x9d, 0x4d, 0x66, 0xed, 0xf2, 0xe7, 0x2b, 0x88, 0xb8, 0x50, 0x55, 0x68, 0xa0, 0x00,
        0xa9, 0x83, 0x2b, 0xa3, 0x5e, 0x4f, 0xde, 0xcf, 0xe5, 0x38, 0x9a, 0x5d, 0x92, 0x79, 0x81, 0x53,
        0x6d, 0xdb, 0x94, 0xc0, 0xf6, 0xc0, 0xbd, 0x94, 0xc4, 0x18, 0x96, 0x4b, 0xbe, 0x4b, 0x6c, 0xf2,
    };
});

pub const HmacSha512 = HmacPattern(struct {
    pub const name = "Sha512";
    pub const ExpandedKey = SYMCRYPT_HMAC_SHA512_EXPANDED_KEY;
    pub const State = SYMCRYPT_HMAC_SHA512_STATE;
    pub const HashState = SYMCRYPT_SHA512_STATE;
    pub const input_block_size = SYMCRYPT_SHA512_INPUT_BLOCK_SIZE;
    pub const result_size = SYMCRYPT_SHA512_RESULT_SIZE;
    pub const clear_data_length_h = true;
    pub const hashInit = SymCryptSha512Init;
    pub const hashAppend = SymCryptSha512Append;
    pub const hashResult = SymCryptSha512Result;
    pub const hashStateCopy = SymCryptSha512StateCopy;
    pub const hashAppendBlocks = SymCryptSha512AppendBlocks;
    pub const pp_hash_algorithm = &SymCryptSha512Algorithm;
    pub const outer_chaining_state_offset: UINT32 = @offsetOf(SYMCRYPT_HMAC_SHA512_EXPANDED_KEY, "outerState");
    pub const selftest_key_size: usize = 16;
    pub const fatal_code = "hsh5";
    pub const kat = [64]BYTE{
        0x07, 0x64, 0xa6, 0x58, 0xeb, 0x3e, 0x2f, 0xb0, 0x2c, 0x06, 0x72, 0x93, 0xcd, 0xaa, 0x3c, 0x05,
        0x28, 0x73, 0x15, 0xf2, 0xd3, 0xb4, 0x5a, 0x28, 0x10, 0x20, 0x1e, 0x26, 0xc3, 0x89, 0x35, 0x48,
        0xe9, 0xea, 0xca, 0x72, 0xf0, 0x2e, 0x04, 0x19, 0x20, 0x31, 0x71, 0x68, 0xb5, 0x7a, 0x86, 0x40,
        0x29, 0x1b, 0x3b, 0xb7, 0xaa, 0x4a, 0x5f, 0xaf, 0x80, 0x26, 0xb4, 0xad, 0x23, 0x5a, 0xc4, 0x25,
    };
});

pub const HmacSha512_224 = HmacPattern(struct {
    pub const name = "Sha512_224";
    pub const ExpandedKey = SYMCRYPT_HMAC_SHA512_224_EXPANDED_KEY;
    pub const State = SYMCRYPT_HMAC_SHA512_224_STATE;
    pub const HashState = SYMCRYPT_SHA512_224_STATE;
    pub const input_block_size = SYMCRYPT_SHA512_224_INPUT_BLOCK_SIZE;
    pub const result_size = SYMCRYPT_SHA512_224_RESULT_SIZE;
    pub const clear_data_length_h = true;
    pub const hashInit = SymCryptSha512_224Init;
    pub const hashAppend = SymCryptSha512_224Append;
    pub const hashResult = SymCryptSha512_224Result;
    pub const hashStateCopy = SymCryptSha512_224StateCopy;
    pub const hashAppendBlocks = SymCryptSha512AppendBlocks;
    pub const pp_hash_algorithm = &SymCryptSha512_224Algorithm;
    pub const outer_chaining_state_offset: UINT32 = @offsetOf(SYMCRYPT_HMAC_SHA512_224_EXPANDED_KEY, "outerState");
    pub const selftest_key_size: usize = 16;
    pub const fatal_code = "hsh4";
    pub const kat = [28]BYTE{
        0x62, 0xc9, 0x59, 0xc7, 0x5b, 0x3c, 0xb2, 0xaf,
        0x95, 0xf5, 0x59, 0x73, 0x2c, 0x46, 0x1d, 0x72,
        0x06, 0x9e, 0xf9, 0x52, 0x9a, 0x8d, 0x84, 0x1a,
        0x73, 0x97, 0xa6, 0x9c,
    };
});

pub const HmacSha512_256 = HmacPattern(struct {
    pub const name = "Sha512_256";
    pub const ExpandedKey = SYMCRYPT_HMAC_SHA512_256_EXPANDED_KEY;
    pub const State = SYMCRYPT_HMAC_SHA512_256_STATE;
    pub const HashState = SYMCRYPT_SHA512_256_STATE;
    pub const input_block_size = SYMCRYPT_SHA512_256_INPUT_BLOCK_SIZE;
    pub const result_size = SYMCRYPT_SHA512_256_RESULT_SIZE;
    pub const clear_data_length_h = true;
    pub const hashInit = SymCryptSha512_256Init;
    pub const hashAppend = SymCryptSha512_256Append;
    pub const hashResult = SymCryptSha512_256Result;
    pub const hashStateCopy = SymCryptSha512_256StateCopy;
    pub const hashAppendBlocks = SymCryptSha512AppendBlocks;
    pub const pp_hash_algorithm = &SymCryptSha512_256Algorithm;
    pub const outer_chaining_state_offset: UINT32 = @offsetOf(SYMCRYPT_HMAC_SHA512_256_EXPANDED_KEY, "outerState");
    pub const selftest_key_size: usize = 16;
    pub const fatal_code = "hsh4";
    pub const kat = [32]BYTE{
        0x79, 0x44, 0xb9, 0x97, 0xc0, 0xaa, 0xf7, 0x11,
        0xdd, 0xb3, 0x78, 0x60, 0x68, 0xdb, 0x2b, 0xa1,
        0x40, 0x80, 0x4f, 0xdc, 0xb7, 0x02, 0x7b, 0x6a,
        0xe9, 0x9f, 0x5a, 0x38, 0xc8, 0x28, 0x67, 0x4c,
    };
});

pub const HmacSha3_224 = HmacSha3Wrapper(struct {
    pub const name = "Sha3_224";
    pub const ExpandedKey = SYMCRYPT_HMAC_SHA3_224_EXPANDED_KEY;
    pub const State = SYMCRYPT_HMAC_SHA3_224_STATE;
    pub const result_size = SYMCRYPT_HMAC_SHA3_224_RESULT_SIZE;
    pub const pp_hash_algorithm = &SymCryptSha3_224Algorithm;
    pub const selftest_key_size: usize = 16;
    pub const fatal_code = "hsh3";
    pub const kat = [28]BYTE{
        0x10, 0x90, 0xac, 0xa1, 0xd5, 0xad, 0xc4, 0x12,
        0xf5, 0xe7, 0xb4, 0xdf, 0xd2, 0x87, 0x09, 0xdd,
        0x24, 0x82, 0xc0, 0x4a, 0x5e, 0x9a, 0x3b, 0xf0,
        0xc3, 0x35, 0x7e, 0x12,
    };
});

pub const HmacSha3_256 = HmacSha3Wrapper(struct {
    pub const name = "Sha3_256";
    pub const ExpandedKey = SYMCRYPT_HMAC_SHA3_256_EXPANDED_KEY;
    pub const State = SYMCRYPT_HMAC_SHA3_256_STATE;
    pub const result_size = SYMCRYPT_HMAC_SHA3_256_RESULT_SIZE;
    pub const pp_hash_algorithm = &SymCryptSha3_256Algorithm;
    pub const selftest_key_size: usize = 16;
    pub const fatal_code = "hsh3";
    pub const kat = [32]BYTE{
        0x18, 0xe8, 0x2e, 0xa4, 0x5a, 0x94, 0x07, 0xcc,
        0xb7, 0x87, 0x29, 0x16, 0x80, 0x99, 0xd6, 0xc6,
        0x73, 0x1b, 0x56, 0x2e, 0x0d, 0x16, 0x67, 0x5a,
        0x1f, 0xe2, 0xe3, 0xd6, 0x81, 0x56, 0x52, 0x77,
    };
});

pub const HmacSha3_384 = HmacSha3Wrapper(struct {
    pub const name = "Sha3_384";
    pub const ExpandedKey = SYMCRYPT_HMAC_SHA3_384_EXPANDED_KEY;
    pub const State = SYMCRYPT_HMAC_SHA3_384_STATE;
    pub const result_size = SYMCRYPT_HMAC_SHA3_384_RESULT_SIZE;
    pub const pp_hash_algorithm = &SymCryptSha3_384Algorithm;
    pub const selftest_key_size: usize = 24;
    pub const fatal_code = "hsh3";
    pub const kat = [48]BYTE{
        0x8f, 0xc4, 0x8a, 0x84, 0xb5, 0xa7, 0xa1, 0x36,
        0x3c, 0x3b, 0x4b, 0x21, 0x3c, 0xfb, 0x65, 0x36,
        0xa6, 0x2b, 0xa3, 0x4c, 0x12, 0x33, 0xa1, 0x27,
        0xbc, 0xfc, 0xb2, 0xd7, 0xae, 0xaf, 0x30, 0x6b,
        0xc9, 0xe6, 0x90, 0xfd, 0xf1, 0xfa, 0x12, 0x61,
        0xa4, 0x7e, 0xb2, 0x27, 0x1a, 0xeb, 0xf1, 0x34,
    };
});

pub const HmacSha3_512 = HmacSha3Wrapper(struct {
    pub const name = "Sha3_512";
    pub const ExpandedKey = SYMCRYPT_HMAC_SHA3_512_EXPANDED_KEY;
    pub const State = SYMCRYPT_HMAC_SHA3_512_STATE;
    pub const result_size = SYMCRYPT_HMAC_SHA3_512_RESULT_SIZE;
    pub const pp_hash_algorithm = &SymCryptSha3_512Algorithm;
    pub const selftest_key_size: usize = 32;
    pub const fatal_code = "hsh3";
    pub const kat = [64]BYTE{
        0x83, 0x3b, 0x31, 0xe7, 0x77, 0xd6, 0xb3, 0x3d,
        0x75, 0x23, 0xa5, 0x79, 0xcc, 0x3b, 0xeb, 0x27,
        0x6f, 0xd6, 0x52, 0x57, 0x54, 0xc4, 0xc5, 0x4b,
        0x2d, 0x5a, 0x34, 0x7d, 0x36, 0x24, 0x07, 0x91,
        0x7a, 0x3c, 0x62, 0x6e, 0x7e, 0xdb, 0x8e, 0x49,
        0x3b, 0x42, 0xc8, 0xe5, 0xa6, 0x96, 0xd5, 0xe6,
        0x6b, 0xa7, 0xad, 0x20, 0x00, 0xeb, 0x6c, 0xff,
        0x76, 0xcb, 0x1e, 0xc0, 0x30, 0x13, 0x0e, 0x81,
    };
});

// ==============================================================================================
// Public Zig Symbol Aliases
// ==============================================================================================

pub const SymCryptHmacMd5ExpandKey = HmacMd5.expandKey;
pub const SymCryptHmacMd5KeyCopy = HmacMd5.keyCopy;
pub const SymCryptHmacMd5 = HmacMd5.mac;
pub const SymCryptHmacMd5StateCopy = HmacMd5.stateCopy;
pub const SymCryptHmacMd5Init = HmacMd5.init;
pub const SymCryptHmacMd5Append = HmacMd5.append;
pub const SymCryptHmacMd5Result = HmacMd5.result;
pub const SymCryptHmacMd5Selftest = HmacMd5.selftest;
pub const SymCryptHmacMd5Algorithm_default = HmacMd5.algorithm_default;
pub const SymCryptHmacMd5Algorithm = HmacMd5.algorithm;

pub const SymCryptHmacSha1ExpandKey = HmacSha1.expandKey;
pub const SymCryptHmacSha1KeyCopy = HmacSha1.keyCopy;
pub const SymCryptHmacSha1 = HmacSha1.mac;
pub const SymCryptHmacSha1StateCopy = HmacSha1.stateCopy;
pub const SymCryptHmacSha1Init = HmacSha1.init;
pub const SymCryptHmacSha1Append = HmacSha1.append;
pub const SymCryptHmacSha1Result = HmacSha1.result;
pub const SymCryptHmacSha1Selftest = HmacSha1.selftest;
pub const SymCryptHmacSha1Algorithm_default = HmacSha1.algorithm_default;
pub const SymCryptHmacSha1Algorithm = HmacSha1.algorithm;

pub const SymCryptHmacSha224ExpandKey = HmacSha224.expandKey;
pub const SymCryptHmacSha224KeyCopy = HmacSha224.keyCopy;
pub const SymCryptHmacSha224 = HmacSha224.mac;
pub const SymCryptHmacSha224StateCopy = HmacSha224.stateCopy;
pub const SymCryptHmacSha224Init = HmacSha224.init;
pub const SymCryptHmacSha224Append = HmacSha224.append;
pub const SymCryptHmacSha224Result = HmacSha224.result;
pub const SymCryptHmacSha224Selftest = HmacSha224.selftest;
pub const SymCryptHmacSha224Algorithm_default = HmacSha224.algorithm_default;
pub const SymCryptHmacSha224Algorithm = HmacSha224.algorithm;

pub const SymCryptHmacSha256ExpandKey = HmacSha256.expandKey;
pub const SymCryptHmacSha256KeyCopy = HmacSha256.keyCopy;
pub const SymCryptHmacSha256 = HmacSha256.mac;
pub const SymCryptHmacSha256StateCopy = HmacSha256.stateCopy;
pub const SymCryptHmacSha256Init = HmacSha256.init;
pub const SymCryptHmacSha256Append = HmacSha256.append;
pub const SymCryptHmacSha256Result = HmacSha256.result;
pub const SymCryptHmacSha256Selftest = HmacSha256.selftest;
pub const SymCryptHmacSha256Algorithm_default = HmacSha256.algorithm_default;
pub const SymCryptHmacSha256Algorithm = HmacSha256.algorithm;

pub const SymCryptHmacSha384ExpandKey = HmacSha384.expandKey;
pub const SymCryptHmacSha384KeyCopy = HmacSha384.keyCopy;
pub const SymCryptHmacSha384 = HmacSha384.mac;
pub const SymCryptHmacSha384StateCopy = HmacSha384.stateCopy;
pub const SymCryptHmacSha384Init = HmacSha384.init;
pub const SymCryptHmacSha384Append = HmacSha384.append;
pub const SymCryptHmacSha384Result = HmacSha384.result;
pub const SymCryptHmacSha384Selftest = HmacSha384.selftest;
pub const SymCryptHmacSha384Algorithm_default = HmacSha384.algorithm_default;
pub const SymCryptHmacSha384Algorithm = HmacSha384.algorithm;

pub const SymCryptHmacSha512ExpandKey = HmacSha512.expandKey;
pub const SymCryptHmacSha512KeyCopy = HmacSha512.keyCopy;
pub const SymCryptHmacSha512 = HmacSha512.mac;
pub const SymCryptHmacSha512StateCopy = HmacSha512.stateCopy;
pub const SymCryptHmacSha512Init = HmacSha512.init;
pub const SymCryptHmacSha512Append = HmacSha512.append;
pub const SymCryptHmacSha512Result = HmacSha512.result;
pub const SymCryptHmacSha512Selftest = HmacSha512.selftest;
pub const SymCryptHmacSha512Algorithm_default = HmacSha512.algorithm_default;
pub const SymCryptHmacSha512Algorithm = HmacSha512.algorithm;

pub const SymCryptHmacSha512_224ExpandKey = HmacSha512_224.expandKey;
pub const SymCryptHmacSha512_224KeyCopy = HmacSha512_224.keyCopy;
pub const SymCryptHmacSha512_224 = HmacSha512_224.mac;
pub const SymCryptHmacSha512_224StateCopy = HmacSha512_224.stateCopy;
pub const SymCryptHmacSha512_224Init = HmacSha512_224.init;
pub const SymCryptHmacSha512_224Append = HmacSha512_224.append;
pub const SymCryptHmacSha512_224Result = HmacSha512_224.result;
pub const SymCryptHmacSha512_224Selftest = HmacSha512_224.selftest;
pub const SymCryptHmacSha512_224Algorithm_default = HmacSha512_224.algorithm_default;
pub const SymCryptHmacSha512_224Algorithm = HmacSha512_224.algorithm;

pub const SymCryptHmacSha512_256ExpandKey = HmacSha512_256.expandKey;
pub const SymCryptHmacSha512_256KeyCopy = HmacSha512_256.keyCopy;
pub const SymCryptHmacSha512_256 = HmacSha512_256.mac;
pub const SymCryptHmacSha512_256StateCopy = HmacSha512_256.stateCopy;
pub const SymCryptHmacSha512_256Init = HmacSha512_256.init;
pub const SymCryptHmacSha512_256Append = HmacSha512_256.append;
pub const SymCryptHmacSha512_256Result = HmacSha512_256.result;
pub const SymCryptHmacSha512_256Selftest = HmacSha512_256.selftest;
pub const SymCryptHmacSha512_256Algorithm_default = HmacSha512_256.algorithm_default;
pub const SymCryptHmacSha512_256Algorithm = HmacSha512_256.algorithm;

pub const SymCryptHmacSha3_224ExpandKey = HmacSha3_224.expandKey;
pub const SymCryptHmacSha3_224KeyCopy = HmacSha3_224.keyCopy;
pub const SymCryptHmacSha3_224 = HmacSha3_224.mac;
pub const SymCryptHmacSha3_224StateCopy = HmacSha3_224.stateCopy;
pub const SymCryptHmacSha3_224Init = HmacSha3_224.init;
pub const SymCryptHmacSha3_224Append = HmacSha3_224.append;
pub const SymCryptHmacSha3_224Result = HmacSha3_224.result;
pub const SymCryptHmacSha3_224Selftest = HmacSha3_224.selftest;
pub const SymCryptHmacSha3_224Algorithm_default = HmacSha3_224.algorithm_default;
pub const SymCryptHmacSha3_224Algorithm = HmacSha3_224.algorithm;

pub const SymCryptHmacSha3_256ExpandKey = HmacSha3_256.expandKey;
pub const SymCryptHmacSha3_256KeyCopy = HmacSha3_256.keyCopy;
pub const SymCryptHmacSha3_256 = HmacSha3_256.mac;
pub const SymCryptHmacSha3_256StateCopy = HmacSha3_256.stateCopy;
pub const SymCryptHmacSha3_256Init = HmacSha3_256.init;
pub const SymCryptHmacSha3_256Append = HmacSha3_256.append;
pub const SymCryptHmacSha3_256Result = HmacSha3_256.result;
pub const SymCryptHmacSha3_256Selftest = HmacSha3_256.selftest;
pub const SymCryptHmacSha3_256Algorithm_default = HmacSha3_256.algorithm_default;
pub const SymCryptHmacSha3_256Algorithm = HmacSha3_256.algorithm;

pub const SymCryptHmacSha3_384ExpandKey = HmacSha3_384.expandKey;
pub const SymCryptHmacSha3_384KeyCopy = HmacSha3_384.keyCopy;
pub const SymCryptHmacSha3_384 = HmacSha3_384.mac;
pub const SymCryptHmacSha3_384StateCopy = HmacSha3_384.stateCopy;
pub const SymCryptHmacSha3_384Init = HmacSha3_384.init;
pub const SymCryptHmacSha3_384Append = HmacSha3_384.append;
pub const SymCryptHmacSha3_384Result = HmacSha3_384.result;
pub const SymCryptHmacSha3_384Selftest = HmacSha3_384.selftest;
pub const SymCryptHmacSha3_384Algorithm_default = HmacSha3_384.algorithm_default;
pub const SymCryptHmacSha3_384Algorithm = HmacSha3_384.algorithm;

pub const SymCryptHmacSha3_512ExpandKey = HmacSha3_512.expandKey;
pub const SymCryptHmacSha3_512KeyCopy = HmacSha3_512.keyCopy;
pub const SymCryptHmacSha3_512 = HmacSha3_512.mac;
pub const SymCryptHmacSha3_512StateCopy = HmacSha3_512.stateCopy;
pub const SymCryptHmacSha3_512Init = HmacSha3_512.init;
pub const SymCryptHmacSha3_512Append = HmacSha3_512.append;
pub const SymCryptHmacSha3_512Result = HmacSha3_512.result;
pub const SymCryptHmacSha3_512Selftest = HmacSha3_512.selftest;
pub const SymCryptHmacSha3_512Algorithm_default = HmacSha3_512.algorithm_default;
pub const SymCryptHmacSha3_512Algorithm = HmacSha3_512.algorithm;

comptime {
    _ = HmacMd5;
    _ = HmacSha1;
    _ = HmacSha224;
    _ = HmacSha256;
    _ = HmacSha384;
    _ = HmacSha512;
    _ = HmacSha512_224;
    _ = HmacSha512_256;
    _ = HmacSha3_224;
    _ = HmacSha3_256;
    _ = HmacSha3_384;
    _ = HmacSha3_512;

    std.debug.assert(@alignOf(SYMCRYPT_HMAC_EXPANDED_KEY) == SYMCRYPT_ALIGN_VALUE);
    std.debug.assert(@alignOf(SYMCRYPT_HMAC_STATE) == SYMCRYPT_ALIGN_VALUE);
    std.debug.assert(@alignOf(SYMCRYPT_HMAC_MD5_EXPANDED_KEY) == SYMCRYPT_ALIGN_VALUE);
    std.debug.assert(@alignOf(SYMCRYPT_HMAC_SHA1_EXPANDED_KEY) == SYMCRYPT_ALIGN_VALUE);
    std.debug.assert(@alignOf(SYMCRYPT_HMAC_SHA256_EXPANDED_KEY) == SYMCRYPT_ALIGN_VALUE);
    std.debug.assert(@alignOf(SYMCRYPT_HMAC_SHA512_EXPANDED_KEY) == SYMCRYPT_ALIGN_VALUE);
}
