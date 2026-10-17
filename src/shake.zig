//
// shake.zig
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
// SHAKE128, SHAKE256 (FIPS 202) and cSHAKE128, cSHAKE256 (NIST SP 800-185)
// implementations, ported from lib/shake.c, lib/shake_pattern.c, and lib/cshake_pattern.c.
//

const std = @import("std");
const types = @import("types.zig");
const macros = @import("macros.zig");
const hash = @import("hash.zig");
const hash_pattern = @import("hash_pattern.zig");
const sha3 = @import("sha3.zig");

const BYTE = types.BYTE;
const PBYTE = types.PBYTE;
const PCBYTE = types.PCBYTE;
const UINT8 = types.UINT8;
const UINT32 = types.UINT32;
const UINT64 = types.UINT64;
const SIZE_T = types.SIZE_T;
const BOOLEAN = types.BOOLEAN;
const TRUE = types.TRUE;
const FALSE = types.FALSE;
const SYMCRYPT_ERROR = types.SYMCRYPT_ERROR;
const SYMCRYPT_HASH = types.SYMCRYPT_HASH;
const PCSYMCRYPT_HASH = types.PCSYMCRYPT_HASH;
const SYMCRYPT_OID = types.SYMCRYPT_OID;
const SYMCRYPT_CALL = types.SYMCRYPT_CALL;
const SYMCRYPT_ALIGN_VALUE = types.SYMCRYPT_ALIGN_VALUE;

// ==============================================================================================
// Constants & State Types
// ==============================================================================================

pub const SYMCRYPT_SHAKE128_RESULT_SIZE: usize = 32;
pub const SYMCRYPT_SHAKE128_INPUT_BLOCK_SIZE: usize = 168;
pub const SYMCRYPT_SHAKE128_STATE_EXPORT_SIZE: usize = sha3.SYMCRYPT_KECCAK_STATE_EXPORT_SIZE;
pub const SYMCRYPT_SHAKE128_OID_COUNT: usize = 2;

pub const SYMCRYPT_SHAKE256_RESULT_SIZE: usize = 64;
pub const SYMCRYPT_SHAKE256_INPUT_BLOCK_SIZE: usize = 136;
pub const SYMCRYPT_SHAKE256_STATE_EXPORT_SIZE: usize = sha3.SYMCRYPT_KECCAK_STATE_EXPORT_SIZE;
pub const SYMCRYPT_SHAKE256_OID_COUNT: usize = 2;

pub const SYMCRYPT_CSHAKE128_RESULT_SIZE: usize = SYMCRYPT_SHAKE128_RESULT_SIZE;
pub const SYMCRYPT_CSHAKE128_INPUT_BLOCK_SIZE: usize = SYMCRYPT_SHAKE128_INPUT_BLOCK_SIZE;

pub const SYMCRYPT_CSHAKE256_RESULT_SIZE: usize = SYMCRYPT_SHAKE256_RESULT_SIZE;
pub const SYMCRYPT_CSHAKE256_INPUT_BLOCK_SIZE: usize = SYMCRYPT_SHAKE256_INPUT_BLOCK_SIZE;

pub const SYMCRYPT_KECCAK_STATE = sha3.SYMCRYPT_KECCAK_STATE;
pub const PSYMCRYPT_KECCAK_STATE = sha3.PSYMCRYPT_KECCAK_STATE;
pub const PCSYMCRYPT_KECCAK_STATE = sha3.PCSYMCRYPT_KECCAK_STATE;

pub const SYMCRYPT_SHAKE128_STATE = hash.SYMCRYPT_SHA3_STATE;
pub const PSYMCRYPT_SHAKE128_STATE = *SYMCRYPT_SHAKE128_STATE;
pub const PCSYMCRYPT_SHAKE128_STATE = *const SYMCRYPT_SHAKE128_STATE;

pub const SYMCRYPT_SHAKE256_STATE = hash.SYMCRYPT_SHA3_STATE;
pub const PSYMCRYPT_SHAKE256_STATE = *SYMCRYPT_SHAKE256_STATE;
pub const PCSYMCRYPT_SHAKE256_STATE = *const SYMCRYPT_SHAKE256_STATE;

pub const SYMCRYPT_CSHAKE128_STATE = hash.SYMCRYPT_SHA3_STATE;
pub const PSYMCRYPT_CSHAKE128_STATE = *SYMCRYPT_CSHAKE128_STATE;
pub const PCSYMCRYPT_CSHAKE128_STATE = *const SYMCRYPT_CSHAKE128_STATE;

pub const SYMCRYPT_CSHAKE256_STATE = hash.SYMCRYPT_SHA3_STATE;
pub const PSYMCRYPT_CSHAKE256_STATE = *SYMCRYPT_CSHAKE256_STATE;
pub const PCSYMCRYPT_CSHAKE256_STATE = *const SYMCRYPT_CSHAKE256_STATE;

pub const SYMCRYPT_SHAKE128_STATE_EXPORT_BLOB = sha3.SYMCRYPT_KECCAK_STATE_EXPORT_BLOB;
pub const SYMCRYPT_SHAKE256_STATE_EXPORT_BLOB = sha3.SYMCRYPT_KECCAK_STATE_EXPORT_BLOB;

// ==============================================================================================
// OID Lists
// ==============================================================================================

pub const SymCryptShake128OidList: [SYMCRYPT_SHAKE128_OID_COUNT]SYMCRYPT_OID = .{
    .{ .cbOID = 13, .pbOID = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x0b\x05\x00" },
    .{ .cbOID = 11, .pbOID = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x0b" },
};

pub const SymCryptShake256OidList: [SYMCRYPT_SHAKE256_OID_COUNT]SYMCRYPT_OID = .{
    .{ .cbOID = 13, .pbOID = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x0c\x05\x00" },
    .{ .cbOID = 11, .pbOID = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x0c" },
};

// ==============================================================================================
// Comptime Generic SHAKE Pattern (replacing lib/shake_pattern.c)
// ==============================================================================================

pub fn ShakePattern(
    comptime StateType: type,
    comptime input_block_size: UINT32,
    comptime result_size: SIZE_T,
    comptime blob_type: hash.SYMCRYPT_BLOB_TYPE,
    comptime kat_answer: *const [result_size]BYTE,
    comptime fatal_code: u32,
) type {
    return struct {
        fn dummyAppendBlocks(_: *UINT64, _: PCBYTE, _: SIZE_T, _: *SIZE_T) callconv(SYMCRYPT_CALL) void {}

        pub const BasePattern = hash_pattern.HashPattern(
            StateType,
            UINT64,
            &init,
            &append,
            &result,
            &dummyAppendBlocks,
        );

        pub fn shakeDefault(
            pbData: PCBYTE,
            cbData: SIZE_T,
            pbResult: PBYTE,
        ) callconv(SYMCRYPT_CALL) void {
            shake(pbData, cbData, pbResult, result_size);
        }

        pub noinline fn shake(
            pbData: PCBYTE,
            cbData: SIZE_T,
            pbResult: PBYTE,
            cbResult: SIZE_T,
        ) callconv(SYMCRYPT_CALL) void {
            var state: StateType = undefined;

            init(&state);
            append(&state, pbData, cbData);
            extract(&state, pbResult, cbResult, TRUE);
        }

        pub fn stateCopy(
            pSrc: *const StateType,
            pDst: *StateType,
        ) callconv(SYMCRYPT_CALL) void {
            macros.CHECK_MAGIC(pSrc);
            pDst.* = pSrc.*;
            macros.SET_MAGIC(pDst);
        }

        pub fn init(pState: *StateType) callconv(SYMCRYPT_CALL) void {
            sha3.SymCryptKeccakInit(&pState.ks, input_block_size, sha3.SYMCRYPT_SHAKE_PADDING_VALUE);
            macros.SET_MAGIC(pState);
        }

        pub fn append(
            pState: *StateType,
            pbData: PCBYTE,
            cbData: SIZE_T,
        ) callconv(SYMCRYPT_CALL) void {
            sha3.SymCryptKeccakAppend(&pState.ks, pbData, cbData);
        }

        pub fn extract(
            pState: *StateType,
            pbResult: PBYTE,
            cbResult: SIZE_T,
            bWipe: BOOLEAN,
        ) callconv(SYMCRYPT_CALL) void {
            sha3.SymCryptKeccakExtract(&pState.ks, pbResult, cbResult, bWipe);
        }

        pub fn result(
            pState: *StateType,
            pbResult: PBYTE,
        ) callconv(SYMCRYPT_CALL) void {
            sha3.SymCryptKeccakExtract(&pState.ks, pbResult, result_size, TRUE);
        }

        pub fn stateExport(
            pState: *const StateType,
            pbBlob: PBYTE,
        ) callconv(SYMCRYPT_CALL) void {
            macros.CHECK_MAGIC(pState);
            sha3.SymCryptKeccakStateExport(blob_type, &pState.ks, pbBlob);
        }

        pub fn stateImport(
            pState: *StateType,
            pbBlob: PCBYTE,
        ) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
            const scError = sha3.SymCryptKeccakStateImport(blob_type, &pState.ks, pbBlob);
            if (scError == .SYMCRYPT_NO_ERROR) {
                macros.SET_MAGIC(pState);
            }
            return scError;
        }

        pub fn selftest() callconv(SYMCRYPT_CALL) void {
            var res: [result_size]BYTE = undefined;

            shake(&hash.SymCryptTestMsg3, hash.SymCryptTestMsg3.len, &res, res.len);

            hash.SymCryptInjectError(&res, res.len);

            if (!std.mem.eql(u8, &res, kat_answer)) {
                macros.SymCryptFatal(fatal_code);
            }
        }
    };
}

// ==============================================================================================
// Comptime Generic cSHAKE Pattern (replacing lib/cshake_pattern.c)
// ==============================================================================================

pub fn CShakePattern(
    comptime StateType: type,
    comptime ShakeStateType: type,
    comptime shakeInitFn: *const fn (*ShakeStateType) callconv(SYMCRYPT_CALL) void,
    comptime result_size: SIZE_T,
    comptime kat_answer: *const [result_size]BYTE,
) type {
    comptime {
        std.debug.assert(@sizeOf(StateType) == @sizeOf(ShakeStateType));
    }

    return struct {
        pub noinline fn cshake(
            pbFunctionNameString: ?PCBYTE,
            cbFunctionNameString: SIZE_T,
            pbCustomizationString: ?PCBYTE,
            cbCustomizationString: SIZE_T,
            pbData: PCBYTE,
            cbData: SIZE_T,
            pbResult: PBYTE,
            cbResult: SIZE_T,
        ) callconv(SYMCRYPT_CALL) void {
            var state: StateType = undefined;

            init(
                &state,
                pbFunctionNameString,
                cbFunctionNameString,
                pbCustomizationString,
                cbCustomizationString,
            );

            append(&state, pbData, cbData);
            extract(&state, pbResult, cbResult, TRUE);
        }

        pub fn init(
            pState: *StateType,
            pbFunctionNameString: ?PCBYTE,
            cbFunctionNameString: SIZE_T,
            pbCustomizationString: ?PCBYTE,
            cbCustomizationString: SIZE_T,
        ) callconv(SYMCRYPT_CALL) void {
            shakeInitFn(@ptrCast(pState));

            if (cbFunctionNameString != 0 or cbCustomizationString != 0) {
                pState.ks.paddingValue = sha3.SYMCRYPT_CSHAKE_PADDING_VALUE;

                SymCryptCShakeEncodeInputStrings(
                    &pState.ks,
                    pbFunctionNameString,
                    cbFunctionNameString,
                    pbCustomizationString,
                    cbCustomizationString,
                );
            }

            macros.SET_MAGIC(pState);
        }

        pub fn append(
            pState: *StateType,
            pbData: PCBYTE,
            cbData: SIZE_T,
        ) callconv(SYMCRYPT_CALL) void {
            if (pState.ks.squeezeMode != FALSE) {
                pState.ks.paddingValue = sha3.SYMCRYPT_SHAKE_PADDING_VALUE;
            }

            sha3.SymCryptKeccakAppend(&pState.ks, pbData, cbData);
        }

        pub fn extract(
            pState: *StateType,
            pbResult: PBYTE,
            cbResult: SIZE_T,
            bWipe: BOOLEAN,
        ) callconv(SYMCRYPT_CALL) void {
            sha3.SymCryptKeccakExtract(&pState.ks, pbResult, cbResult, bWipe);

            if (bWipe != FALSE) {
                pState.ks.paddingValue = sha3.SYMCRYPT_SHAKE_PADDING_VALUE;
            }
        }

        pub fn result(
            pState: *StateType,
            pbResult: PBYTE,
        ) callconv(SYMCRYPT_CALL) void {
            sha3.SymCryptKeccakExtract(&pState.ks, pbResult, result_size, TRUE);
            pState.ks.paddingValue = sha3.SYMCRYPT_SHAKE_PADDING_VALUE;
        }

        pub fn stateCopy(
            pSrc: *const StateType,
            pDst: *StateType,
        ) callconv(SYMCRYPT_CALL) void {
            macros.CHECK_MAGIC(pSrc);
            pDst.* = pSrc.*;
            macros.SET_MAGIC(pDst);
        }

        pub fn selftest() callconv(SYMCRYPT_CALL) void {
            var res: [result_size]BYTE = undefined;
            const Nstr = [_]BYTE{'N'};
            const Sstr = [_]BYTE{'S'};

            cshake(
                &Nstr,
                Nstr.len,
                &Sstr,
                Sstr.len,
                &hash.SymCryptTestMsg3,
                hash.SymCryptTestMsg3.len,
                &res,
                res.len,
            );

            hash.SymCryptInjectError(&res, res.len);

            if (!std.mem.eql(u8, &res, kat_answer)) {
                macros.SymCryptFatal(macros.multiCharConstant("cshk"));
            }
        }
    };
}

// ==============================================================================================
// SHAKE128 (from lib/shake.c)
// ==============================================================================================

const shake128KATAnswer: [SYMCRYPT_SHAKE128_RESULT_SIZE]BYTE = .{
    0x58, 0x81, 0x09, 0x2d, 0xd8, 0x18, 0xbf, 0x5c,
    0xf8, 0xa3, 0xdd, 0xb7, 0x93, 0xfb, 0xcb, 0xa7,
    0x40, 0x97, 0xd5, 0xc5, 0x26, 0xa6, 0xd3, 0x5f,
    0x97, 0xb8, 0x33, 0x51, 0x94, 0x0f, 0x2c, 0xc8,
};

const Shake128Impl = ShakePattern(
    SYMCRYPT_SHAKE128_STATE,
    SYMCRYPT_SHAKE128_INPUT_BLOCK_SIZE,
    SYMCRYPT_SHAKE128_RESULT_SIZE,
    .SymCryptBlobTypeShake128State,
    &shake128KATAnswer,
    macros.multiCharConstant("shk1"),
);

pub export const SymCryptShake128HashAlgorithm_default: SYMCRYPT_HASH align(SYMCRYPT_ALIGN_VALUE) = .{
    .initFunc = &Shake128Impl.BasePattern.initVoid,
    .appendFunc = &Shake128Impl.BasePattern.appendVoid,
    .resultFunc = &Shake128Impl.BasePattern.resultVoid,
    .appendBlockFunc = null,
    .stateCopyFunc = &Shake128Impl.BasePattern.stateCopyVoid,
    .stateSize = @sizeOf(SYMCRYPT_SHAKE128_STATE),
    .resultSize = SYMCRYPT_SHAKE128_RESULT_SIZE,
    .inputBlockSize = SYMCRYPT_SHAKE128_INPUT_BLOCK_SIZE,
    .chainOffset = @offsetOf(SYMCRYPT_SHAKE128_STATE, "ks") + @offsetOf(SYMCRYPT_KECCAK_STATE, "state"),
    .chainSize = @sizeOf([25]UINT64),
};

pub export const SymCryptShake128HashAlgorithm: PCSYMCRYPT_HASH = &SymCryptShake128HashAlgorithm_default;

pub export fn SymCryptShake128Default(pbData: PCBYTE, cbData: SIZE_T, pbResult: PBYTE) callconv(SYMCRYPT_CALL) void {
    Shake128Impl.shakeDefault(pbData, cbData, pbResult);
}

pub export fn SymCryptShake128(pbData: PCBYTE, cbData: SIZE_T, pbResult: PBYTE, cbResult: SIZE_T) callconv(SYMCRYPT_CALL) void {
    Shake128Impl.shake(pbData, cbData, pbResult, cbResult);
}

pub export fn SymCryptShake128StateCopy(pSrc: PCSYMCRYPT_SHAKE128_STATE, pDst: PSYMCRYPT_SHAKE128_STATE) callconv(SYMCRYPT_CALL) void {
    Shake128Impl.stateCopy(pSrc, pDst);
}

pub export fn SymCryptShake128Init(pState: PSYMCRYPT_SHAKE128_STATE) callconv(SYMCRYPT_CALL) void {
    Shake128Impl.init(pState);
}

pub export fn SymCryptShake128Append(pState: PSYMCRYPT_SHAKE128_STATE, pbData: PCBYTE, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void {
    Shake128Impl.append(pState, pbData, cbData);
}

pub export fn SymCryptShake128Extract(pState: PSYMCRYPT_SHAKE128_STATE, pbResult: PBYTE, cbResult: SIZE_T, bWipe: BOOLEAN) callconv(SYMCRYPT_CALL) void {
    Shake128Impl.extract(pState, pbResult, cbResult, bWipe);
}

pub export fn SymCryptShake128Result(pState: PSYMCRYPT_SHAKE128_STATE, pbResult: PBYTE) callconv(SYMCRYPT_CALL) void {
    Shake128Impl.result(pState, pbResult);
}

pub export fn SymCryptShake128StateExport(pState: PCSYMCRYPT_SHAKE128_STATE, pbBlob: PBYTE) callconv(SYMCRYPT_CALL) void {
    Shake128Impl.stateExport(pState, pbBlob);
}

pub export fn SymCryptShake128StateImport(pState: PSYMCRYPT_SHAKE128_STATE, pbBlob: PCBYTE) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    return Shake128Impl.stateImport(pState, pbBlob);
}

pub export fn SymCryptShake128Selftest() callconv(SYMCRYPT_CALL) void {
    Shake128Impl.selftest();
}

// ==============================================================================================
// SHAKE256 (from lib/shake.c)
// ==============================================================================================

const shake256KATAnswer: [SYMCRYPT_SHAKE256_RESULT_SIZE]BYTE = .{
    0x48, 0x33, 0x66, 0x60, 0x13, 0x60, 0xa8, 0x77, 0x1c, 0x68, 0x63, 0x08, 0x0c, 0xc4, 0x11, 0x4d,
    0x8d, 0xb4, 0x45, 0x30, 0xf8, 0xf1, 0xe1, 0xee, 0x4f, 0x94, 0xea, 0x37, 0xe7, 0x8b, 0x57, 0x39,
    0xd5, 0xa1, 0x5b, 0xef, 0x18, 0x6a, 0x53, 0x86, 0xc7, 0x57, 0x44, 0xc0, 0x52, 0x7e, 0x1f, 0xaa,
    0x9f, 0x87, 0x26, 0xe4, 0x62, 0xa1, 0x2a, 0x4f, 0xeb, 0x06, 0xbd, 0x88, 0x01, 0xe7, 0x51, 0xe4,
};

const Shake256Impl = ShakePattern(
    SYMCRYPT_SHAKE256_STATE,
    SYMCRYPT_SHAKE256_INPUT_BLOCK_SIZE,
    SYMCRYPT_SHAKE256_RESULT_SIZE,
    .SymCryptBlobTypeShake256State,
    &shake256KATAnswer,
    macros.multiCharConstant("shk2"),
);

pub export const SymCryptShake256HashAlgorithm_default: SYMCRYPT_HASH align(SYMCRYPT_ALIGN_VALUE) = .{
    .initFunc = &Shake256Impl.BasePattern.initVoid,
    .appendFunc = &Shake256Impl.BasePattern.appendVoid,
    .resultFunc = &Shake256Impl.BasePattern.resultVoid,
    .appendBlockFunc = null,
    .stateCopyFunc = &Shake256Impl.BasePattern.stateCopyVoid,
    .stateSize = @sizeOf(SYMCRYPT_SHAKE256_STATE),
    .resultSize = SYMCRYPT_SHAKE256_RESULT_SIZE,
    .inputBlockSize = SYMCRYPT_SHAKE256_INPUT_BLOCK_SIZE,
    .chainOffset = @offsetOf(SYMCRYPT_SHAKE256_STATE, "ks") + @offsetOf(SYMCRYPT_KECCAK_STATE, "state"),
    .chainSize = @sizeOf([25]UINT64),
};

pub export const SymCryptShake256HashAlgorithm: PCSYMCRYPT_HASH = &SymCryptShake256HashAlgorithm_default;

pub export fn SymCryptShake256Default(pbData: PCBYTE, cbData: SIZE_T, pbResult: PBYTE) callconv(SYMCRYPT_CALL) void {
    Shake256Impl.shakeDefault(pbData, cbData, pbResult);
}

pub export fn SymCryptShake256(pbData: PCBYTE, cbData: SIZE_T, pbResult: PBYTE, cbResult: SIZE_T) callconv(SYMCRYPT_CALL) void {
    Shake256Impl.shake(pbData, cbData, pbResult, cbResult);
}

pub export fn SymCryptShake256StateCopy(pSrc: PCSYMCRYPT_SHAKE256_STATE, pDst: PSYMCRYPT_SHAKE256_STATE) callconv(SYMCRYPT_CALL) void {
    Shake256Impl.stateCopy(pSrc, pDst);
}

pub export fn SymCryptShake256Init(pState: PSYMCRYPT_SHAKE256_STATE) callconv(SYMCRYPT_CALL) void {
    Shake256Impl.init(pState);
}

pub export fn SymCryptShake256Append(pState: PSYMCRYPT_SHAKE256_STATE, pbData: PCBYTE, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void {
    Shake256Impl.append(pState, pbData, cbData);
}

pub export fn SymCryptShake256Extract(pState: PSYMCRYPT_SHAKE256_STATE, pbResult: PBYTE, cbResult: SIZE_T, bWipe: BOOLEAN) callconv(SYMCRYPT_CALL) void {
    Shake256Impl.extract(pState, pbResult, cbResult, bWipe);
}

pub export fn SymCryptShake256Result(pState: PSYMCRYPT_SHAKE256_STATE, pbResult: PBYTE) callconv(SYMCRYPT_CALL) void {
    Shake256Impl.result(pState, pbResult);
}

pub export fn SymCryptShake256StateExport(pState: PCSYMCRYPT_SHAKE256_STATE, pbBlob: PBYTE) callconv(SYMCRYPT_CALL) void {
    Shake256Impl.stateExport(pState, pbBlob);
}

pub export fn SymCryptShake256StateImport(pState: PSYMCRYPT_SHAKE256_STATE, pbBlob: PCBYTE) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    return Shake256Impl.stateImport(pState, pbBlob);
}

pub export fn SymCryptShake256Selftest() callconv(SYMCRYPT_CALL) void {
    Shake256Impl.selftest();
}

// ==============================================================================================
// cSHAKE128 (from lib/shake.c)
// ==============================================================================================

const cshake128KATAnswer: [SYMCRYPT_CSHAKE128_RESULT_SIZE]BYTE = .{
    0x14, 0xe5, 0xdf, 0xf3, 0xae, 0xfd, 0xfe, 0x8e,
    0xa6, 0xae, 0xed, 0xfd, 0x99, 0xe6, 0x84, 0x74,
    0xbc, 0x61, 0xb9, 0xd6, 0x17, 0x4e, 0x9f, 0x4a,
    0xe3, 0xbd, 0x87, 0xdf, 0x0e, 0xf2, 0x16, 0xdb,
};

const CShake128Impl = CShakePattern(
    SYMCRYPT_CSHAKE128_STATE,
    SYMCRYPT_SHAKE128_STATE,
    &SymCryptShake128Init,
    SYMCRYPT_CSHAKE128_RESULT_SIZE,
    &cshake128KATAnswer,
);

pub export fn SymCryptCShake128(
    pbFunctionNameString: ?PCBYTE,
    cbFunctionNameString: SIZE_T,
    pbCustomizationString: ?PCBYTE,
    cbCustomizationString: SIZE_T,
    pbData: PCBYTE,
    cbData: SIZE_T,
    pbResult: PBYTE,
    cbResult: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    CShake128Impl.cshake(
        pbFunctionNameString,
        cbFunctionNameString,
        pbCustomizationString,
        cbCustomizationString,
        pbData,
        cbData,
        pbResult,
        cbResult,
    );
}

pub export fn SymCryptCShake128Init(
    pState: PSYMCRYPT_CSHAKE128_STATE,
    pbFunctionNameString: ?PCBYTE,
    cbFunctionNameString: SIZE_T,
    pbCustomizationString: ?PCBYTE,
    cbCustomizationString: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    CShake128Impl.init(
        pState,
        pbFunctionNameString,
        cbFunctionNameString,
        pbCustomizationString,
        cbCustomizationString,
    );
}

pub export fn SymCryptCShake128Append(
    pState: PSYMCRYPT_CSHAKE128_STATE,
    pbData: PCBYTE,
    cbData: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    CShake128Impl.append(pState, pbData, cbData);
}

pub export fn SymCryptCShake128Extract(
    pState: PSYMCRYPT_CSHAKE128_STATE,
    pbResult: PBYTE,
    cbResult: SIZE_T,
    bWipe: BOOLEAN,
) callconv(SYMCRYPT_CALL) void {
    CShake128Impl.extract(pState, pbResult, cbResult, bWipe);
}

pub export fn SymCryptCShake128Result(
    pState: PSYMCRYPT_CSHAKE128_STATE,
    pbResult: PBYTE,
) callconv(SYMCRYPT_CALL) void {
    CShake128Impl.result(pState, pbResult);
}

pub export fn SymCryptCShake128StateCopy(
    pSrc: PCSYMCRYPT_CSHAKE128_STATE,
    pDst: PSYMCRYPT_CSHAKE128_STATE,
) callconv(SYMCRYPT_CALL) void {
    CShake128Impl.stateCopy(pSrc, pDst);
}

pub export fn SymCryptCShake128Selftest() callconv(SYMCRYPT_CALL) void {
    CShake128Impl.selftest();
}

// ==============================================================================================
// cSHAKE256 (from lib/shake.c)
// ==============================================================================================

const cshake256KATAnswer: [SYMCRYPT_CSHAKE256_RESULT_SIZE]BYTE = .{
    0x4d, 0xe8, 0x71, 0x6c, 0x4a, 0x16, 0x7e, 0x28, 0x2c, 0x18, 0xc5, 0x1e, 0xed, 0xa6, 0x00, 0xb8,
    0x91, 0x92, 0x4f, 0xea, 0x2e, 0x20, 0x7f, 0x71, 0x2c, 0xfd, 0xe2, 0x95, 0xfd, 0x1c, 0x67, 0x32,
    0x31, 0x49, 0x98, 0x23, 0xc0, 0x5e, 0x6a, 0xe3, 0x89, 0xad, 0x4d, 0xa2, 0x32, 0x9c, 0xc9, 0x2e,
    0x0f, 0xd6, 0x90, 0xb9, 0xee, 0x91, 0x0e, 0x86, 0xf7, 0x1d, 0x03, 0x88, 0xb5, 0x95, 0x61, 0x95,
};

const CShake256Impl = CShakePattern(
    SYMCRYPT_CSHAKE256_STATE,
    SYMCRYPT_SHAKE256_STATE,
    &SymCryptShake256Init,
    SYMCRYPT_CSHAKE256_RESULT_SIZE,
    &cshake256KATAnswer,
);

pub export fn SymCryptCShake256(
    pbFunctionNameString: ?PCBYTE,
    cbFunctionNameString: SIZE_T,
    pbCustomizationString: ?PCBYTE,
    cbCustomizationString: SIZE_T,
    pbData: PCBYTE,
    cbData: SIZE_T,
    pbResult: PBYTE,
    cbResult: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    CShake256Impl.cshake(
        pbFunctionNameString,
        cbFunctionNameString,
        pbCustomizationString,
        cbCustomizationString,
        pbData,
        cbData,
        pbResult,
        cbResult,
    );
}

pub export fn SymCryptCShake256Init(
    pState: PSYMCRYPT_CSHAKE256_STATE,
    pbFunctionNameString: ?PCBYTE,
    cbFunctionNameString: SIZE_T,
    pbCustomizationString: ?PCBYTE,
    cbCustomizationString: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    CShake256Impl.init(
        pState,
        pbFunctionNameString,
        cbFunctionNameString,
        pbCustomizationString,
        cbCustomizationString,
    );
}

pub export fn SymCryptCShake256Append(
    pState: PSYMCRYPT_CSHAKE256_STATE,
    pbData: PCBYTE,
    cbData: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    CShake256Impl.append(pState, pbData, cbData);
}

pub export fn SymCryptCShake256Extract(
    pState: PSYMCRYPT_CSHAKE256_STATE,
    pbResult: PBYTE,
    cbResult: SIZE_T,
    bWipe: BOOLEAN,
) callconv(SYMCRYPT_CALL) void {
    CShake256Impl.extract(pState, pbResult, cbResult, bWipe);
}

pub export fn SymCryptCShake256Result(
    pState: PSYMCRYPT_CSHAKE256_STATE,
    pbResult: PBYTE,
) callconv(SYMCRYPT_CALL) void {
    CShake256Impl.result(pState, pbResult);
}

pub export fn SymCryptCShake256StateCopy(
    pSrc: PCSYMCRYPT_CSHAKE256_STATE,
    pDst: PSYMCRYPT_CSHAKE256_STATE,
) callconv(SYMCRYPT_CALL) void {
    CShake256Impl.stateCopy(pSrc, pDst);
}

pub export fn SymCryptCShake256Selftest() callconv(SYMCRYPT_CALL) void {
    CShake256Impl.selftest();
}

// ==============================================================================================
// cSHAKE Helper Functions (from lib/shake.c)
// ==============================================================================================

pub export fn SymCryptCShakeEncodeInputStrings(
    pState: PSYMCRYPT_KECCAK_STATE,
    pbFunctionNameString: ?PCBYTE,
    cbFunctionNameString: SIZE_T,
    pbCustomizationString: ?PCBYTE,
    cbCustomizationString: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    macros.ASSERT((cbFunctionNameString > 0) or (cbCustomizationString > 0));

    SymCryptKeccakAppendEncodeTimes8(pState, pState.inputBlockSize / 8, TRUE);

    SymCryptKeccakAppendEncodedString(pState, pbFunctionNameString, cbFunctionNameString);
    SymCryptKeccakAppendEncodedString(pState, pbCustomizationString, cbCustomizationString);

    if (pState.stateIndex != 0) {
        sha3.SymCryptKeccakZeroAppendBlock(pState);
    }
}

pub export fn SymCryptKeccakEncodeTimes8(
    uInput: UINT64,
    pbOutputIn: PBYTE,
    cbOutput: SIZE_T,
    bLeftEncode: BOOLEAN,
) callconv(SYMCRYPT_CALL) SIZE_T {
    var encoding: [1 + @sizeOf(UINT64)]BYTE = undefined;
    var pbOutput = pbOutputIn;

    macros.ASSERT(cbOutput >= (1 + @sizeOf(@TypeOf(encoding))));

    encoding[0] = @truncate(uInput >> 61);
    macros.STORE_MSBFIRST64(encoding[1..].ptr, uInput *% 8);

    var length: SIZE_T = 1;
    var pbMsb: PCBYTE = encoding[encoding.len - 1 ..].ptr;

    var i: usize = 0;
    while (i < encoding.len) : (i += 1) {
        if (encoding[i] != 0 and length == 1) {
            length = encoding.len - i;
            pbMsb = encoding[i..].ptr;
        }
    }

    const ret: SIZE_T = 1 + length;

    if (bLeftEncode != FALSE) {
        pbOutput[0] = @truncate(length);
        pbOutput += 1;
    }

    @memcpy(pbOutput[0..length], pbMsb[0..length]);

    if (bLeftEncode == FALSE) {
        pbOutput[length] = @truncate(length);
    }

    return ret;
}

pub export fn SymCryptKeccakAppendEncodeTimes8(
    pState: PSYMCRYPT_KECCAK_STATE,
    uValue: UINT64,
    bLeftEncode: BOOLEAN,
) callconv(SYMCRYPT_CALL) void {
    var encoding: [1 + (1 + @sizeOf(UINT64))]BYTE = undefined;

    const ret = SymCryptKeccakEncodeTimes8(uValue, &encoding, encoding.len, bLeftEncode);

    sha3.SymCryptKeccakAppend(pState, &encoding, ret);
}

pub export fn SymCryptKeccakAppendEncodedString(
    pState: PSYMCRYPT_KECCAK_STATE,
    pbString: ?PCBYTE,
    cbString: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    SymCryptKeccakAppendEncodeTimes8(pState, cbString, TRUE);
    if (cbString > 0) {
        sha3.SymCryptKeccakAppend(pState, pbString.?, cbString);
    } else {
        const empty: [1]BYTE = .{0};
        sha3.SymCryptKeccakAppend(pState, &empty, 0);
    }
}
