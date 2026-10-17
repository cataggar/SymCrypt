//
// kmac.zig
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
// KMAC128 and KMAC256 (NIST SP 800-185) implementations, ported from
// lib/kmac.c and lib/kmac_pattern.c.
//

const std = @import("std");
const types = @import("types.zig");
const macros = @import("macros.zig");
const hash = @import("hash.zig");
const sha3 = @import("sha3.zig");
const shake = @import("shake.zig");

const BYTE = types.BYTE;
const PBYTE = types.PBYTE;
const PCBYTE = types.PCBYTE;
const SIZE_T = types.SIZE_T;
const BOOLEAN = types.BOOLEAN;
const TRUE = types.TRUE;
const FALSE = types.FALSE;
const PVOID = types.PVOID;
const PCVOID = types.PCVOID;
const SYMCRYPT_ERROR = types.SYMCRYPT_ERROR;
const SYMCRYPT_MAC = types.SYMCRYPT_MAC;
const PCSYMCRYPT_MAC = types.PCSYMCRYPT_MAC;
const SYMCRYPT_CALL = types.SYMCRYPT_CALL;
const SYMCRYPT_ALIGN_VALUE = types.SYMCRYPT_ALIGN_VALUE;

extern const SymCryptTestKey32: [32]BYTE;
extern const SymCryptTestMsg16: [16]BYTE;

// ==============================================================================================
// Constants & State Types
// ==============================================================================================

pub const SYMCRYPT_KMAC128_RESULT_SIZE: usize = shake.SYMCRYPT_CSHAKE128_RESULT_SIZE;
pub const SYMCRYPT_KMAC128_INPUT_BLOCK_SIZE: usize = shake.SYMCRYPT_CSHAKE128_INPUT_BLOCK_SIZE;

pub const SYMCRYPT_KMAC256_RESULT_SIZE: usize = shake.SYMCRYPT_CSHAKE256_RESULT_SIZE;
pub const SYMCRYPT_KMAC256_INPUT_BLOCK_SIZE: usize = shake.SYMCRYPT_CSHAKE256_INPUT_BLOCK_SIZE;

pub const SYMCRYPT_KMAC128_EXPANDED_KEY = hash.SYMCRYPT_SHA3_STATE;
pub const PSYMCRYPT_KMAC128_EXPANDED_KEY = *SYMCRYPT_KMAC128_EXPANDED_KEY;
pub const PCSYMCRYPT_KMAC128_EXPANDED_KEY = *const SYMCRYPT_KMAC128_EXPANDED_KEY;

pub const SYMCRYPT_KMAC128_STATE = hash.SYMCRYPT_SHA3_STATE;
pub const PSYMCRYPT_KMAC128_STATE = *SYMCRYPT_KMAC128_STATE;
pub const PCSYMCRYPT_KMAC128_STATE = *const SYMCRYPT_KMAC128_STATE;

pub const SYMCRYPT_KMAC256_EXPANDED_KEY = hash.SYMCRYPT_SHA3_STATE;
pub const PSYMCRYPT_KMAC256_EXPANDED_KEY = *SYMCRYPT_KMAC256_EXPANDED_KEY;
pub const PCSYMCRYPT_KMAC256_EXPANDED_KEY = *const SYMCRYPT_KMAC256_EXPANDED_KEY;

pub const SYMCRYPT_KMAC256_STATE = hash.SYMCRYPT_SHA3_STATE;
pub const PSYMCRYPT_KMAC256_STATE = *SYMCRYPT_KMAC256_STATE;
pub const PCSYMCRYPT_KMAC256_STATE = *const SYMCRYPT_KMAC256_STATE;

// ==============================================================================================
// Comptime Generic KMAC Pattern (replacing lib/kmac_pattern.c)
// ==============================================================================================

pub fn KmacPattern(
    comptime ExpandedKeyType: type,
    comptime StateType: type,
    comptime CShakeStateType: type,
    comptime cshakeInitFn: *const fn (*CShakeStateType, ?PCBYTE, SIZE_T, ?PCBYTE, SIZE_T) callconv(SYMCRYPT_CALL) void,
    comptime result_size: SIZE_T,
    comptime selftest_key_size: SIZE_T,
    comptime kat_answer: *const [result_size]BYTE,
) type {
    comptime {
        std.debug.assert(@sizeOf(ExpandedKeyType) == @sizeOf(CShakeStateType));
        std.debug.assert(@sizeOf(StateType) == @sizeOf(ExpandedKeyType));
    }

    return struct {
        const nameString = [4]BYTE{ 0x4b, 0x4d, 0x41, 0x43 }; // "KMAC"

        pub noinline fn kmac(
            pExpandedKey: *const ExpandedKeyType,
            pbInput: PCBYTE,
            cbInput: SIZE_T,
            pbResult: PBYTE,
        ) callconv(SYMCRYPT_CALL) void {
            var state: StateType = undefined;

            init(&state, pExpandedKey);
            append(&state, pbInput, cbInput);
            result(&state, pbResult);
        }

        pub noinline fn kmacEx(
            pExpandedKey: *const ExpandedKeyType,
            pbInput: PCBYTE,
            cbInput: SIZE_T,
            pbResult: PBYTE,
            cbResult: SIZE_T,
        ) callconv(SYMCRYPT_CALL) void {
            var state: StateType = undefined;

            init(&state, pExpandedKey);
            append(&state, pbInput, cbInput);
            resultEx(&state, pbResult, cbResult);
        }

        pub fn expandKey(
            pExpandedKey: *ExpandedKeyType,
            pbKey: PCBYTE,
            cbKey: SIZE_T,
        ) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
            return expandKeyEx(pExpandedKey, pbKey, cbKey, null, 0);
        }

        pub fn expandKeyEx(
            pExpandedKey: *ExpandedKeyType,
            pbKey: PCBYTE,
            cbKey: SIZE_T,
            pbCustomizationString: ?PCBYTE,
            cbCustomizationString: SIZE_T,
        ) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
            cshakeInitFn(
                @ptrCast(pExpandedKey),
                &nameString,
                nameString.len,
                pbCustomizationString,
                cbCustomizationString,
            );

            const pks = &pExpandedKey.ks;

            shake.SymCryptKeccakAppendEncodeTimes8(pks, pks.inputBlockSize / 8, TRUE);
            shake.SymCryptKeccakAppendEncodedString(pks, pbKey, cbKey);

            if (pks.stateIndex != 0) {
                sha3.SymCryptKeccakZeroAppendBlock(pks);
            }

            return .SYMCRYPT_NO_ERROR;
        }

        pub fn init(
            pState: *StateType,
            pExpandedKey: *const ExpandedKeyType,
        ) callconv(SYMCRYPT_CALL) void {
            macros.CHECK_MAGIC(pExpandedKey);
            pState.* = pExpandedKey.*;
            macros.SET_MAGIC(pState);
        }

        pub fn append(
            pState: *StateType,
            pbData: PCBYTE,
            cbData: SIZE_T,
        ) callconv(SYMCRYPT_CALL) void {
            macros.ASSERT(pState.ks.squeezeMode == FALSE);
            sha3.SymCryptKeccakAppend(&pState.ks, pbData, cbData);
        }

        pub fn extract(
            pState: *StateType,
            pbOutput: PBYTE,
            cbOutput: SIZE_T,
            bWipe: BOOLEAN,
        ) callconv(SYMCRYPT_CALL) void {
            if (pState.ks.squeezeMode == FALSE) {
                shake.SymCryptKeccakAppendEncodeTimes8(&pState.ks, 0, FALSE);
            }

            sha3.SymCryptKeccakExtract(&pState.ks, pbOutput, cbOutput, bWipe);
        }

        pub fn result(
            pState: *StateType,
            pbOutput: PBYTE,
        ) callconv(SYMCRYPT_CALL) void {
            resultEx(pState, pbOutput, result_size);
        }

        pub fn resultEx(
            pState: *StateType,
            pbOutput: PBYTE,
            cbOutput: SIZE_T,
        ) callconv(SYMCRYPT_CALL) void {
            if (pState.ks.squeezeMode == FALSE) {
                shake.SymCryptKeccakAppendEncodeTimes8(&pState.ks, cbOutput, FALSE);
            }

            sha3.SymCryptKeccakExtract(&pState.ks, pbOutput, cbOutput, TRUE);
        }

        pub fn keyCopy(
            pSrc: *const ExpandedKeyType,
            pDst: *ExpandedKeyType,
        ) callconv(SYMCRYPT_CALL) void {
            macros.CHECK_MAGIC(pSrc);
            pDst.* = pSrc.*;
            macros.SET_MAGIC(pDst);
        }

        pub fn stateCopy(
            pSrc: *const StateType,
            pDst: *StateType,
        ) callconv(SYMCRYPT_CALL) void {
            macros.CHECK_MAGIC(pSrc);
            pDst.* = pSrc.*;
            macros.SET_MAGIC(pDst);
        }

        pub fn expandKeyVoid(pExpandedKey: PVOID, pbKey: PCBYTE, cbKey: SIZE_T) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
            return expandKey(@ptrCast(@alignCast(pExpandedKey.?)), pbKey, cbKey);
        }

        pub fn initVoid(pState: PVOID, pExpandedKey: PCVOID) callconv(SYMCRYPT_CALL) void {
            init(@ptrCast(@alignCast(pState.?)), @ptrCast(@alignCast(pExpandedKey.?)));
        }

        pub fn appendVoid(pState: PVOID, pbData: PCBYTE, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void {
            append(@ptrCast(@alignCast(pState.?)), pbData, cbData);
        }

        pub fn resultVoid(pState: PVOID, pbResult: PVOID) callconv(SYMCRYPT_CALL) void {
            result(@ptrCast(@alignCast(pState.?)), @ptrCast(pbResult.?));
        }

        pub fn selftest() callconv(SYMCRYPT_CALL) void {
            var res: [result_size]BYTE = undefined;
            const Sstr = [_]BYTE{'S'};
            var expandedKey: ExpandedKeyType = undefined;

            _ = expandKeyEx(&expandedKey, &SymCryptTestKey32, selftest_key_size, &Sstr, Sstr.len);

            kmac(&expandedKey, &SymCryptTestMsg16, SymCryptTestMsg16.len, &res);

            hash.SymCryptInjectError(&res, res.len);

            if (!std.mem.eql(u8, &res, kat_answer)) {
                macros.SymCryptFatal(macros.multiCharConstant("kmac"));
            }
        }
    };
}

// ==============================================================================================
// KMAC128 (from lib/kmac.c)
// ==============================================================================================

const kmac128KATAnswer: [SYMCRYPT_KMAC128_RESULT_SIZE]BYTE = .{
    0xea, 0xe9, 0xde, 0xd3, 0xee, 0x2f, 0x34, 0x8a,
    0xd6, 0xd2, 0xcb, 0x70, 0x4b, 0xba, 0xd4, 0x47,
    0x15, 0x32, 0x46, 0x82, 0x8e, 0x41, 0x3a, 0xf5,
    0xf5, 0x62, 0x96, 0x1a, 0xf7, 0x67, 0x48, 0xc1,
};

const Kmac128Impl = KmacPattern(
    SYMCRYPT_KMAC128_EXPANDED_KEY,
    SYMCRYPT_KMAC128_STATE,
    shake.SYMCRYPT_CSHAKE128_STATE,
    &shake.SymCryptCShake128Init,
    SYMCRYPT_KMAC128_RESULT_SIZE,
    16,
    &kmac128KATAnswer,
);

pub export const SymCryptKmac128Algorithm_Default: SYMCRYPT_MAC = .{
    .expandKeyFunc = &Kmac128Impl.expandKeyVoid,
    .initFunc = &Kmac128Impl.initVoid,
    .appendFunc = &Kmac128Impl.appendVoid,
    .resultFunc = &Kmac128Impl.resultVoid,
    .expandedKeySize = @sizeOf(SYMCRYPT_KMAC128_EXPANDED_KEY),
    .stateSize = @sizeOf(SYMCRYPT_KMAC128_STATE),
    .resultSize = SYMCRYPT_KMAC128_RESULT_SIZE,
    .ppHashAlgorithm = null,
    .outerChainingStateOffset = 0,
};

pub export const SymCryptKmac128Algorithm: PCSYMCRYPT_MAC = &SymCryptKmac128Algorithm_Default;

pub export fn SymCryptKmac128(
    pExpandedKey: PCSYMCRYPT_KMAC128_EXPANDED_KEY,
    pbInput: PCBYTE,
    cbInput: SIZE_T,
    pbResult: PBYTE,
) callconv(SYMCRYPT_CALL) void {
    Kmac128Impl.kmac(pExpandedKey, pbInput, cbInput, pbResult);
}

pub export fn SymCryptKmac128Ex(
    pExpandedKey: PCSYMCRYPT_KMAC128_EXPANDED_KEY,
    pbInput: PCBYTE,
    cbInput: SIZE_T,
    pbResult: PBYTE,
    cbResult: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    Kmac128Impl.kmacEx(pExpandedKey, pbInput, cbInput, pbResult, cbResult);
}

pub export fn SymCryptKmac128ExpandKey(
    pExpandedKey: PSYMCRYPT_KMAC128_EXPANDED_KEY,
    pbKey: PCBYTE,
    cbKey: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    return Kmac128Impl.expandKey(pExpandedKey, pbKey, cbKey);
}

pub export fn SymCryptKmac128ExpandKeyEx(
    pExpandedKey: PSYMCRYPT_KMAC128_EXPANDED_KEY,
    pbKey: PCBYTE,
    cbKey: SIZE_T,
    pbCustomizationString: ?PCBYTE,
    cbCustomizationString: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    return Kmac128Impl.expandKeyEx(pExpandedKey, pbKey, cbKey, pbCustomizationString, cbCustomizationString);
}

pub export fn SymCryptKmac128Init(
    pState: PSYMCRYPT_KMAC128_STATE,
    pExpandedKey: PCSYMCRYPT_KMAC128_EXPANDED_KEY,
) callconv(SYMCRYPT_CALL) void {
    Kmac128Impl.init(pState, pExpandedKey);
}

pub export fn SymCryptKmac128Append(
    pState: PSYMCRYPT_KMAC128_STATE,
    pbData: PCBYTE,
    cbData: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    Kmac128Impl.append(pState, pbData, cbData);
}

pub export fn SymCryptKmac128Extract(
    pState: PSYMCRYPT_KMAC128_STATE,
    pbOutput: PBYTE,
    cbOutput: SIZE_T,
    bWipe: BOOLEAN,
) callconv(SYMCRYPT_CALL) void {
    Kmac128Impl.extract(pState, pbOutput, cbOutput, bWipe);
}

pub export fn SymCryptKmac128Result(
    pState: PSYMCRYPT_KMAC128_STATE,
    pbOutput: PBYTE,
) callconv(SYMCRYPT_CALL) void {
    Kmac128Impl.result(pState, pbOutput);
}

pub export fn SymCryptKmac128ResultEx(
    pState: PSYMCRYPT_KMAC128_STATE,
    pbOutput: PBYTE,
    cbOutput: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    Kmac128Impl.resultEx(pState, pbOutput, cbOutput);
}

pub export fn SymCryptKmac128KeyCopy(
    pSrc: PCSYMCRYPT_KMAC128_EXPANDED_KEY,
    pDst: PSYMCRYPT_KMAC128_EXPANDED_KEY,
) callconv(SYMCRYPT_CALL) void {
    Kmac128Impl.keyCopy(pSrc, pDst);
}

pub export fn SymCryptKmac128StateCopy(
    pSrc: PCSYMCRYPT_KMAC128_STATE,
    pDst: PSYMCRYPT_KMAC128_STATE,
) callconv(SYMCRYPT_CALL) void {
    Kmac128Impl.stateCopy(pSrc, pDst);
}

pub export fn SymCryptKmac128Selftest() callconv(SYMCRYPT_CALL) void {
    Kmac128Impl.selftest();
}

// ==============================================================================================
// KMAC256 (from lib/kmac.c)
// ==============================================================================================

const kmac256KATAnswer: [SYMCRYPT_KMAC256_RESULT_SIZE]BYTE = .{
    0xa9, 0x1d, 0x09, 0x00, 0x71, 0x0c, 0x63, 0xc5, 0x0f, 0xb6, 0x4d, 0xfa, 0xd8, 0x75, 0x4d, 0x78,
    0x2d, 0xc0, 0x82, 0x4b, 0x87, 0x97, 0xda, 0xf2, 0x36, 0xde, 0xe9, 0x35, 0x69, 0x2e, 0x50, 0x81,
    0x0a, 0xea, 0x3b, 0x05, 0xaf, 0x1b, 0x82, 0x3b, 0xc8, 0xa1, 0x9e, 0xe9, 0x9c, 0x5f, 0xd5, 0x5a,
    0x20, 0x92, 0x89, 0x46, 0xa4, 0xe4, 0x1a, 0xdd, 0x3d, 0xb6, 0x47, 0x4d, 0xf2, 0xa5, 0xfc, 0x73,
};

const Kmac256Impl = KmacPattern(
    SYMCRYPT_KMAC256_EXPANDED_KEY,
    SYMCRYPT_KMAC256_STATE,
    shake.SYMCRYPT_CSHAKE256_STATE,
    &shake.SymCryptCShake256Init,
    SYMCRYPT_KMAC256_RESULT_SIZE,
    32,
    &kmac256KATAnswer,
);

pub export const SymCryptKmac256Algorithm_Default: SYMCRYPT_MAC = .{
    .expandKeyFunc = &Kmac256Impl.expandKeyVoid,
    .initFunc = &Kmac256Impl.initVoid,
    .appendFunc = &Kmac256Impl.appendVoid,
    .resultFunc = &Kmac256Impl.resultVoid,
    .expandedKeySize = @sizeOf(SYMCRYPT_KMAC256_EXPANDED_KEY),
    .stateSize = @sizeOf(SYMCRYPT_KMAC256_STATE),
    .resultSize = SYMCRYPT_KMAC256_RESULT_SIZE,
    .ppHashAlgorithm = null,
    .outerChainingStateOffset = 0,
};

pub export const SymCryptKmac256Algorithm: PCSYMCRYPT_MAC = &SymCryptKmac256Algorithm_Default;

pub export fn SymCryptKmac256(
    pExpandedKey: PCSYMCRYPT_KMAC256_EXPANDED_KEY,
    pbInput: PCBYTE,
    cbInput: SIZE_T,
    pbResult: PBYTE,
) callconv(SYMCRYPT_CALL) void {
    Kmac256Impl.kmac(pExpandedKey, pbInput, cbInput, pbResult);
}

pub export fn SymCryptKmac256Ex(
    pExpandedKey: PCSYMCRYPT_KMAC256_EXPANDED_KEY,
    pbInput: PCBYTE,
    cbInput: SIZE_T,
    pbResult: PBYTE,
    cbResult: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    Kmac256Impl.kmacEx(pExpandedKey, pbInput, cbInput, pbResult, cbResult);
}

pub export fn SymCryptKmac256ExpandKey(
    pExpandedKey: PSYMCRYPT_KMAC256_EXPANDED_KEY,
    pbKey: PCBYTE,
    cbKey: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    return Kmac256Impl.expandKey(pExpandedKey, pbKey, cbKey);
}

pub export fn SymCryptKmac256ExpandKeyEx(
    pExpandedKey: PSYMCRYPT_KMAC256_EXPANDED_KEY,
    pbKey: PCBYTE,
    cbKey: SIZE_T,
    pbCustomizationString: ?PCBYTE,
    cbCustomizationString: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    return Kmac256Impl.expandKeyEx(pExpandedKey, pbKey, cbKey, pbCustomizationString, cbCustomizationString);
}

pub export fn SymCryptKmac256Init(
    pState: PSYMCRYPT_KMAC256_STATE,
    pExpandedKey: PCSYMCRYPT_KMAC256_EXPANDED_KEY,
) callconv(SYMCRYPT_CALL) void {
    Kmac256Impl.init(pState, pExpandedKey);
}

pub export fn SymCryptKmac256Append(
    pState: PSYMCRYPT_KMAC256_STATE,
    pbData: PCBYTE,
    cbData: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    Kmac256Impl.append(pState, pbData, cbData);
}

pub export fn SymCryptKmac256Extract(
    pState: PSYMCRYPT_KMAC256_STATE,
    pbOutput: PBYTE,
    cbOutput: SIZE_T,
    bWipe: BOOLEAN,
) callconv(SYMCRYPT_CALL) void {
    Kmac256Impl.extract(pState, pbOutput, cbOutput, bWipe);
}

pub export fn SymCryptKmac256Result(
    pState: PSYMCRYPT_KMAC256_STATE,
    pbOutput: PBYTE,
) callconv(SYMCRYPT_CALL) void {
    Kmac256Impl.result(pState, pbOutput);
}

pub export fn SymCryptKmac256ResultEx(
    pState: PSYMCRYPT_KMAC256_STATE,
    pbOutput: PBYTE,
    cbOutput: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    Kmac256Impl.resultEx(pState, pbOutput, cbOutput);
}

pub export fn SymCryptKmac256KeyCopy(
    pSrc: PCSYMCRYPT_KMAC256_EXPANDED_KEY,
    pDst: PSYMCRYPT_KMAC256_EXPANDED_KEY,
) callconv(SYMCRYPT_CALL) void {
    Kmac256Impl.keyCopy(pSrc, pDst);
}

pub export fn SymCryptKmac256StateCopy(
    pSrc: PCSYMCRYPT_KMAC256_STATE,
    pDst: PSYMCRYPT_KMAC256_STATE,
) callconv(SYMCRYPT_CALL) void {
    Kmac256Impl.stateCopy(pSrc, pDst);
}

pub export fn SymCryptKmac256Selftest() callconv(SYMCRYPT_CALL) void {
    Kmac256Impl.selftest();
}
