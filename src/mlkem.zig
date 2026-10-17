//
// mlkem.zig
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
// High-level ML-KEM API functions ported from lib/mlkem.c.
//

const std = @import("std");
const types = @import("types.zig");
const macros = @import("macros.zig");
const equal = @import("equal.zig");
const scs_tools = @import("scs_tools.zig");
const hash = @import("hash.zig");
const sha3 = @import("sha3.zig");
const shake = @import("shake.zig");
const prim = @import("mlkem_primitives.zig");

const BYTE = types.BYTE;
const PBYTE = types.PBYTE;
const PCBYTE = types.PCBYTE;
const UINT8 = types.UINT8;
const UINT32 = types.UINT32;
const SIZE_T = types.SIZE_T;
const BOOLEAN = types.BOOLEAN;
const PVOID = types.PVOID;
const SYMCRYPT_ERROR = types.SYMCRYPT_ERROR;
const SYMCRYPT_CALL = types.SYMCRYPT_CALL;

const SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS = prim.SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS;
const SYMCRYPT_MLKEM_PRIVATE_SEED_SIZE = prim.SYMCRYPT_MLKEM_PRIVATE_SEED_SIZE;
const SYMCRYPT_MLKEM_SIZEOF_AGREED_SECRET = prim.SYMCRYPT_MLKEM_SIZEOF_AGREED_SECRET;
const SYMCRYPT_MLKEM_SIZEOF_ENCAPS_RANDOM = prim.SYMCRYPT_MLKEM_SIZEOF_ENCAPS_RANDOM;
const SYMCRYPT_INTERNAL_MLKEM_SIZEOF_POLYRINGELEMENT = prim.SYMCRYPT_INTERNAL_MLKEM_SIZEOF_POLYRINGELEMENT;
const SYMCRYPT_MLKEM_VECTOR = prim.SYMCRYPT_MLKEM_VECTOR;
const SYMCRYPT_MLKEM_MATRIX = prim.SYMCRYPT_MLKEM_MATRIX;
const SYMCRYPT_MLKEM_INTERNAL_PARAMS = prim.SYMCRYPT_MLKEM_INTERNAL_PARAMS;
const PSYMCRYPT_MLKEM_INTERNAL_PARAMS = prim.PSYMCRYPT_MLKEM_INTERNAL_PARAMS;
const PCSYMCRYPT_MLKEM_INTERNAL_PARAMS = prim.PCSYMCRYPT_MLKEM_INTERNAL_PARAMS;
const SYMCRYPT_MLKEMKEY = prim.SYMCRYPT_MLKEMKEY;
const PSYMCRYPT_MLKEMKEY = prim.PSYMCRYPT_MLKEMKEY;
const PCSYMCRYPT_MLKEMKEY = prim.PCSYMCRYPT_MLKEMKEY;
const SYMCRYPT_MLKEM_PARAMS = prim.SYMCRYPT_MLKEM_PARAMS;
const SYMCRYPT_MLKEMKEY_FORMAT = prim.SYMCRYPT_MLKEMKEY_FORMAT;
const SYMCRYPT_MLKEM_INTERNAL_COMPUTATION_TEMPORARIES = prim.SYMCRYPT_MLKEM_INTERNAL_COMPUTATION_TEMPORARIES;
const PSYMCRYPT_MLKEM_INTERNAL_COMPUTATION_TEMPORARIES = prim.PSYMCRYPT_MLKEM_INTERNAL_COMPUTATION_TEMPORARIES;

// ==============================================================================================
// External C Callbacks & FIPS Self-Test Declarations
// ==============================================================================================

pub extern fn SymCryptCallbackAlloc(cbData: SIZE_T) callconv(SYMCRYPT_CALL) ?PBYTE;
pub extern fn SymCryptCallbackFree(pbData: PVOID) callconv(SYMCRYPT_CALL) void;
pub extern fn SymCryptCallbackRandom(pbBuffer: PBYTE, cbBuffer: SIZE_T) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;
pub extern fn SymCryptMlKemSelftest() callconv(SYMCRYPT_CALL) void;
pub extern var g_SymCryptFipsSelftestsPerformed: UINT32;

pub const SYMCRYPT_FLAG_KEY_NO_FIPS: UINT32 = 0x100;
pub const SYMCRYPT_FLAG_KEY_MINIMAL_VALIDATION: UINT32 = 0x200;
pub const SYMCRYPT_SELFTEST_ALGORITHM_MLKEM: UINT32 = 0x40;

// ==============================================================================================
// Parameter Sets
// ==============================================================================================

const NROWS_MLKEM512: UINT8 = 2;
const NROWS_MLKEM768: UINT8 = 3;
const NROWS_MLKEM1024: UINT8 = 4;

pub export const SymCryptMlKemInternalParamsMlKem512: SYMCRYPT_MLKEM_INTERNAL_PARAMS = .{
    .params = @backingInt(SYMCRYPT_MLKEM_PARAMS.MLKEM512),
    .cbPolyElement = @intCast(SYMCRYPT_INTERNAL_MLKEM_SIZEOF_POLYRINGELEMENT),
    .cbVector = @intCast(@sizeOf(SYMCRYPT_MLKEM_VECTOR) + (@as(usize, NROWS_MLKEM512) * SYMCRYPT_INTERNAL_MLKEM_SIZEOF_POLYRINGELEMENT)),
    .cbMatrix = @intCast(@sizeOf(SYMCRYPT_MLKEM_MATRIX) + (@as(usize, NROWS_MLKEM512) * @as(usize, NROWS_MLKEM512) * SYMCRYPT_INTERNAL_MLKEM_SIZEOF_POLYRINGELEMENT)),
    .nRows = NROWS_MLKEM512,
    .nEta1 = 3,
    .nEta2 = 2,
    .nBitsOfU = 10,
    .nBitsOfV = 4,
};

pub export const SymCryptMlKemInternalParamsMlKem768: SYMCRYPT_MLKEM_INTERNAL_PARAMS = .{
    .params = @backingInt(SYMCRYPT_MLKEM_PARAMS.MLKEM768),
    .cbPolyElement = @intCast(SYMCRYPT_INTERNAL_MLKEM_SIZEOF_POLYRINGELEMENT),
    .cbVector = @intCast(@sizeOf(SYMCRYPT_MLKEM_VECTOR) + (@as(usize, NROWS_MLKEM768) * SYMCRYPT_INTERNAL_MLKEM_SIZEOF_POLYRINGELEMENT)),
    .cbMatrix = @intCast(@sizeOf(SYMCRYPT_MLKEM_MATRIX) + (@as(usize, NROWS_MLKEM768) * @as(usize, NROWS_MLKEM768) * SYMCRYPT_INTERNAL_MLKEM_SIZEOF_POLYRINGELEMENT)),
    .nRows = NROWS_MLKEM768,
    .nEta1 = 2,
    .nEta2 = 2,
    .nBitsOfU = 10,
    .nBitsOfV = 4,
};

pub export const SymCryptMlKemInternalParamsMlKem1024: SYMCRYPT_MLKEM_INTERNAL_PARAMS = .{
    .params = @backingInt(SYMCRYPT_MLKEM_PARAMS.MLKEM1024),
    .cbPolyElement = @intCast(SYMCRYPT_INTERNAL_MLKEM_SIZEOF_POLYRINGELEMENT),
    .cbVector = @intCast(@sizeOf(SYMCRYPT_MLKEM_VECTOR) + (@as(usize, NROWS_MLKEM1024) * SYMCRYPT_INTERNAL_MLKEM_SIZEOF_POLYRINGELEMENT)),
    .cbMatrix = @intCast(@sizeOf(SYMCRYPT_MLKEM_MATRIX) + (@as(usize, NROWS_MLKEM1024) * @as(usize, NROWS_MLKEM1024) * SYMCRYPT_INTERNAL_MLKEM_SIZEOF_POLYRINGELEMENT)),
    .nRows = NROWS_MLKEM1024,
    .nEta1 = 2,
    .nEta2 = 2,
    .nBitsOfU = 11,
    .nBitsOfV = 5,
};

inline fn sizeofEncodedUncompressedVector(nRows: usize) usize {
    return 384 * nRows;
}

inline fn sizeofFormatDecapsulationKey(nRows: usize) usize {
    return (2 * sizeofEncodedUncompressedVector(nRows)) + (3 * 32);
}

inline fn sizeofFormatEncapsulationKey(nRows: usize) usize {
    return sizeofEncodedUncompressedVector(nRows) + 32;
}

comptime {
    std.debug.assert(sizeofFormatDecapsulationKey(NROWS_MLKEM512) == prim.SYMCRYPT_MLKEM_DECAPSULATION_KEY_SIZE_MLKEM512);
    std.debug.assert(sizeofFormatDecapsulationKey(NROWS_MLKEM768) == prim.SYMCRYPT_MLKEM_DECAPSULATION_KEY_SIZE_MLKEM768);
    std.debug.assert(sizeofFormatDecapsulationKey(NROWS_MLKEM1024) == prim.SYMCRYPT_MLKEM_DECAPSULATION_KEY_SIZE_MLKEM1024);

    std.debug.assert(sizeofFormatEncapsulationKey(NROWS_MLKEM512) == prim.SYMCRYPT_MLKEM_ENCAPSULATION_KEY_SIZE_MLKEM512);
    std.debug.assert(sizeofFormatEncapsulationKey(NROWS_MLKEM768) == prim.SYMCRYPT_MLKEM_ENCAPSULATION_KEY_SIZE_MLKEM768);
    std.debug.assert(sizeofFormatEncapsulationKey(NROWS_MLKEM1024) == prim.SYMCRYPT_MLKEM_ENCAPSULATION_KEY_SIZE_MLKEM1024);
}

fn SymCryptMlKemkeyGetInternalParamsFromParams(
    params: SYMCRYPT_MLKEM_PARAMS,
    pInternalParams: PSYMCRYPT_MLKEM_INTERNAL_PARAMS,
) SYMCRYPT_ERROR {
    switch (params) {
        .MLKEM512 => pInternalParams.* = SymCryptMlKemInternalParamsMlKem512,
        .MLKEM768 => pInternalParams.* = SymCryptMlKemInternalParamsMlKem768,
        .MLKEM1024 => pInternalParams.* = SymCryptMlKemInternalParamsMlKem1024,
        else => return .SYMCRYPT_INVALID_ARGUMENT,
    }
    return .SYMCRYPT_NO_ERROR;
}

fn SymCryptMlKemkeyInitialize(
    pInternalParams: PCSYMCRYPT_MLKEM_INTERNAL_PARAMS,
    pbKey: PBYTE,
    cbKey: UINT32,
) ?PSYMCRYPT_MLKEMKEY {
    hash.SymCryptWipe(pbKey, cbKey);

    const aligned_ptr: [*]align(types.SYMCRYPT_ASYM_ALIGN_VALUE) BYTE = @alignCast(pbKey);
    const pKey: PSYMCRYPT_MLKEMKEY = @ptrCast(aligned_ptr);
    var pbCurr: PBYTE = pbKey + @sizeOf(SYMCRYPT_MLKEMKEY);

    pKey.fAlgorithmInfo = 0;
    pKey.params = pInternalParams.*;
    pKey.cbTotalSize = cbKey;
    pKey.hasPrivateSeed = 0;
    pKey.hasPrivateKey = 0;

    const pmAtranspose = prim.SymCryptMlKemMatrixCreate(pbCurr, pInternalParams.cbMatrix, pInternalParams.nRows) orelse return null;
    pKey.pmAtranspose = pmAtranspose;
    pbCurr += pInternalParams.cbMatrix;

    const pvt = prim.SymCryptMlKemVectorCreate(pbCurr, pInternalParams.cbVector, pInternalParams.nRows) orelse return null;
    pKey.pvt = pvt;
    pbCurr += pInternalParams.cbVector;

    const pvs = prim.SymCryptMlKemVectorCreate(pbCurr, pInternalParams.cbVector, pInternalParams.nRows) orelse return null;
    pKey.pvs = pvs;
    pbCurr += pInternalParams.cbVector;

    macros.ASSERT(pbCurr == (pbKey + cbKey));
    macros.SET_MAGIC(pKey);

    return pKey;
}

// ==============================================================================================
// Public API Functions
// ==============================================================================================

pub export fn SymCryptMlKemkeyAllocate(
    params: SYMCRYPT_MLKEM_PARAMS,
) callconv(SYMCRYPT_CALL) ?PSYMCRYPT_MLKEMKEY {
    var internalParams: SYMCRYPT_MLKEM_INTERNAL_PARAMS = undefined;
    const scError = SymCryptMlKemkeyGetInternalParamsFromParams(params, &internalParams);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return null;
    }

    const cbKey: UINT32 = @as(UINT32, @intCast(@sizeOf(SYMCRYPT_MLKEMKEY))) + internalParams.cbMatrix + (2 * internalParams.cbVector);
    const pbKey = SymCryptCallbackAlloc(cbKey) orelse return null;

    const pKey = SymCryptMlKemkeyInitialize(&internalParams, pbKey, cbKey) orelse {
        SymCryptCallbackFree(pbKey);
        return null;
    };

    return pKey;
}

pub export fn SymCryptMlKemkeyFree(
    pkMlKemkey: PSYMCRYPT_MLKEMKEY,
) callconv(SYMCRYPT_CALL) void {
    macros.CHECK_MAGIC(pkMlKemkey);
    hash.SymCryptWipe(@ptrCast(pkMlKemkey), pkMlKemkey.cbTotalSize);
    SymCryptCallbackFree(@ptrCast(pkMlKemkey));
}

pub export fn SymCryptMlKemSizeofKeyFormatFromParams(
    params: SYMCRYPT_MLKEM_PARAMS,
    mlKemkeyFormat: SYMCRYPT_MLKEMKEY_FORMAT,
    pcbKeyFormat: *SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    if (mlKemkeyFormat == .NULL) {
        return .SYMCRYPT_INCOMPATIBLE_FORMAT;
    }

    var internalParams: SYMCRYPT_MLKEM_INTERNAL_PARAMS = undefined;
    const scError = SymCryptMlKemkeyGetInternalParamsFromParams(params, &internalParams);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    switch (mlKemkeyFormat) {
        .PRIVATE_SEED => pcbKeyFormat.* = SYMCRYPT_MLKEM_PRIVATE_SEED_SIZE,
        .DECAPSULATION_KEY => pcbKeyFormat.* = sizeofFormatDecapsulationKey(internalParams.nRows),
        .ENCAPSULATION_KEY => pcbKeyFormat.* = sizeofFormatEncapsulationKey(internalParams.nRows),
        else => return .SYMCRYPT_INVALID_ARGUMENT,
    }

    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptMlKemSizeofCiphertextFromParams(
    params: SYMCRYPT_MLKEM_PARAMS,
    pcbCiphertext: *SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var internalParams: SYMCRYPT_MLKEM_INTERNAL_PARAMS = undefined;
    const scError = SymCryptMlKemkeyGetInternalParamsFromParams(params, &internalParams);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    const cbU: SIZE_T = @as(SIZE_T, internalParams.nRows) * @as(SIZE_T, internalParams.nBitsOfU) * (SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS / 8);
    const cbV: SIZE_T = @as(SIZE_T, internalParams.nBitsOfV) * (SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS / 8);
    pcbCiphertext.* = cbU + cbV;

    macros.ASSERT((internalParams.params != @backingInt(SYMCRYPT_MLKEM_PARAMS.MLKEM512)) or ((cbU + cbV) == prim.SYMCRYPT_MLKEM_CIPHERTEXT_SIZE_MLKEM512));
    macros.ASSERT((internalParams.params != @backingInt(SYMCRYPT_MLKEM_PARAMS.MLKEM768)) or ((cbU + cbV) == prim.SYMCRYPT_MLKEM_CIPHERTEXT_SIZE_MLKEM768));
    macros.ASSERT((internalParams.params != @backingInt(SYMCRYPT_MLKEM_PARAMS.MLKEM1024)) or ((cbU + cbV) == prim.SYMCRYPT_MLKEM_CIPHERTEXT_SIZE_MLKEM1024));

    return .SYMCRYPT_NO_ERROR;
}

fn SymCryptMlKemkeyExpandPublicMatrixFromPublicSeed(
    pkMlKemkey: PSYMCRYPT_MLKEMKEY,
    pCompTemps: PSYMCRYPT_MLKEM_INTERNAL_COMPUTATION_TEMPORARIES,
) void {
    var coordinates: [2]BYTE = undefined;
    const pShakeStateBase: shake.PSYMCRYPT_SHAKE128_STATE = &pCompTemps.hashState0.shake128State;
    const pShakeStateWork: shake.PSYMCRYPT_SHAKE128_STATE = &pCompTemps.hashState1.shake128State;
    const nRows: usize = pkMlKemkey.params.nRows;

    shake.SymCryptShake128Init(pShakeStateBase);
    shake.SymCryptShake128Append(pShakeStateBase, &pkMlKemkey.publicSeed, pkMlKemkey.publicSeed.len);

    var i: usize = 0;
    while (i < nRows) : (i += 1) {
        coordinates[1] = @truncate(i);
        var j: usize = 0;
        while (j < nRows) : (j += 1) {
            coordinates[0] = @truncate(j);
            shake.SymCryptShake128StateCopy(pShakeStateBase, pShakeStateWork);
            shake.SymCryptShake128Append(pShakeStateWork, &coordinates, coordinates.len);

            prim.SymCryptMlKemPolyElementSampleNTTFromShake128(
                pShakeStateWork,
                pkMlKemkey.pmAtranspose.apPolyElements[(i * nRows) + j],
            );
        }
    }
}

fn SymCryptMlKemkeyComputeEncapsulationKeyHash(
    pkMlKemkey: PSYMCRYPT_MLKEMKEY,
    pCompTemps: PSYMCRYPT_MLKEM_INTERNAL_COMPUTATION_TEMPORARIES,
    cbEncodedVector: SIZE_T,
) void {
    const pState: sha3.PSYMCRYPT_SHA3_256_STATE = &pCompTemps.hashState0.sha3_256State;

    sha3.SymCryptSha3_256Init(pState);
    sha3.SymCryptSha3_256Append(pState, &pkMlKemkey.encodedT, cbEncodedVector);
    sha3.SymCryptSha3_256Append(pState, &pkMlKemkey.publicSeed, pkMlKemkey.publicSeed.len);
    sha3.SymCryptSha3_256Result(pState, &pkMlKemkey.encapsKeyHash);
}

fn SymCryptMlKemkeyExpandFromPrivateSeed(
    pkMlKemkey: PSYMCRYPT_MLKEMKEY,
    pCompTemps: PSYMCRYPT_MLKEM_INTERNAL_COMPUTATION_TEMPORARIES,
) void {
    var privateSeedHash: [sha3.SYMCRYPT_SHA3_512_RESULT_SIZE]BYTE = undefined;
    var CBDSampleBuffer: [3 * 64 + 1]BYTE = undefined;
    const pShakeStateBase: shake.PSYMCRYPT_SHAKE256_STATE = &pCompTemps.hashState0.shake256State;
    const pShakeStateWork: shake.PSYMCRYPT_SHAKE256_STATE = &pCompTemps.hashState1.shake256State;
    const nRows: UINT32 = pkMlKemkey.params.nRows;
    const nEta1: UINT32 = pkMlKemkey.params.nEta1;
    const cbEncodedVector: SIZE_T = sizeofEncodedUncompressedVector(nRows);
    const cbPolyElement: UINT32 = pkMlKemkey.params.cbPolyElement;
    const cbVector: UINT32 = pkMlKemkey.params.cbVector;

    macros.ASSERT(pkMlKemkey.hasPrivateSeed != 0);
    macros.ASSERT((nEta1 == 2) or (nEta1 == 3));
    macros.ASSERT(cbEncodedVector <= pkMlKemkey.encodedT.len);

    const pvTmp = prim.SymCryptMlKemVectorCreate(&pCompTemps.abVectorBuffer0, cbVector, nRows).?;
    const paTmp = prim.SymCryptMlKemPolyElementAccumulatorCreate(&pCompTemps.abPolyElementAccumulatorBuffer, 2 * cbPolyElement).?;

    @memcpy(CBDSampleBuffer[0..pkMlKemkey.privateSeed.len], &pkMlKemkey.privateSeed);
    CBDSampleBuffer[pkMlKemkey.privateSeed.len] = @truncate(nRows);
    sha3.SymCryptSha3_512(&CBDSampleBuffer, pkMlKemkey.privateSeed.len + 1, &privateSeedHash);

    @memcpy(&pkMlKemkey.publicSeed, privateSeedHash[0..pkMlKemkey.publicSeed.len]);

    SymCryptMlKemkeyExpandPublicMatrixFromPublicSeed(pkMlKemkey, pCompTemps);

    shake.SymCryptShake256Init(pShakeStateBase);
    shake.SymCryptShake256Append(pShakeStateBase, privateSeedHash[pkMlKemkey.publicSeed.len..].ptr, 32);

    var i: usize = 0;
    while (i < nRows) : (i += 1) {
        CBDSampleBuffer[0] = @truncate(i);
        shake.SymCryptShake256StateCopy(pShakeStateBase, pShakeStateWork);
        shake.SymCryptShake256Append(pShakeStateWork, &CBDSampleBuffer, 1);

        shake.SymCryptShake256Extract(pShakeStateWork, &CBDSampleBuffer, 64 * @as(usize, nEta1), 0);

        prim.SymCryptMlKemPolyElementSampleCBDFromBytes(&CBDSampleBuffer, nEta1, prim.vectorElement(pkMlKemkey.pvs, i));
    }

    i = 0;
    while (i < nRows) : (i += 1) {
        CBDSampleBuffer[0] = @truncate(@as(usize, nRows) + i);
        shake.SymCryptShake256StateCopy(pShakeStateBase, pShakeStateWork);
        shake.SymCryptShake256Append(pShakeStateWork, &CBDSampleBuffer, 1);

        shake.SymCryptShake256Extract(pShakeStateWork, &CBDSampleBuffer, 64 * @as(usize, nEta1), 0);

        prim.SymCryptMlKemPolyElementSampleCBDFromBytes(&CBDSampleBuffer, nEta1, prim.vectorElement(pkMlKemkey.pvt, i));
    }

    prim.SymCryptMlKemVectorNTT(pkMlKemkey.pvs);
    prim.SymCryptMlKemVectorNTT(pkMlKemkey.pvt);

    prim.SymCryptMlKemVectorMulR(pkMlKemkey.pvs, pvTmp);

    prim.SymCryptMlKemMatrixVectorMontMulAndAdd(pkMlKemkey.pmAtranspose, pvTmp, pkMlKemkey.pvt, paTmp);

    prim.SymCryptMlKemMatrixTranspose(pkMlKemkey.pmAtranspose);

    prim.SymCryptMlKemVectorCompressAndEncode(pkMlKemkey.pvt, 12, &pkMlKemkey.encodedT, cbEncodedVector);

    SymCryptMlKemkeyComputeEncapsulationKeyHash(pkMlKemkey, pCompTemps, cbEncodedVector);

    hash.SymCryptWipeKnownSize(&privateSeedHash, privateSeedHash.len);
    hash.SymCryptWipeKnownSize(&CBDSampleBuffer, CBDSampleBuffer.len);
}

pub export fn SymCryptMlKemkeySetValue(
    pbSrc: PCBYTE,
    cbSrc: SIZE_T,
    mlKemkeyFormat: SYMCRYPT_MLKEMKEY_FORMAT,
    flags: UINT32,
    pkMlKemkey: PSYMCRYPT_MLKEMKEY,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;
    var pbCurr: PCBYTE = pbSrc;
    var pCompTemps: ?PSYMCRYPT_MLKEM_INTERNAL_COMPUTATION_TEMPORARIES = null;
    const nRows: usize = pkMlKemkey.params.nRows;
    const cbEncodedVector: SIZE_T = sizeofEncodedUncompressedVector(nRows);

    const allowedFlags: UINT32 = SYMCRYPT_FLAG_KEY_NO_FIPS | SYMCRYPT_FLAG_KEY_MINIMAL_VALIDATION;

    if ((flags & ~allowedFlags) != 0) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    if (((flags & SYMCRYPT_FLAG_KEY_NO_FIPS) == 0) and
        ((flags & SYMCRYPT_FLAG_KEY_MINIMAL_VALIDATION) != 0))
    {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    if (mlKemkeyFormat == .NULL) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    if ((flags & SYMCRYPT_FLAG_KEY_NO_FIPS) == 0) {
        if ((@atomicLoad(UINT32, &g_SymCryptFipsSelftestsPerformed, .unordered) & SYMCRYPT_SELFTEST_ALGORITHM_MLKEM) == 0) {
            SymCryptMlKemSelftest();
            _ = @atomicRmw(UINT32, &g_SymCryptFipsSelftestsPerformed, .Or, SYMCRYPT_SELFTEST_ALGORITHM_MLKEM, .monotonic);
        }
    }

    const pbCompTemps = SymCryptCallbackAlloc(@sizeOf(SYMCRYPT_MLKEM_INTERNAL_COMPUTATION_TEMPORARIES)) orelse {
        return .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
    };
    const alignedCompTemps: [*]align(types.SYMCRYPT_ASYM_ALIGN_VALUE) BYTE = @alignCast(pbCompTemps);
    pCompTemps = @ptrCast(alignedCompTemps);
    defer {
        if (pCompTemps) |temps| {
            hash.SymCryptWipe(@ptrCast(temps), @sizeOf(SYMCRYPT_MLKEM_INTERNAL_COMPUTATION_TEMPORARIES));
            SymCryptCallbackFree(@ptrCast(temps));
        }
    }

    if (mlKemkeyFormat == .PRIVATE_SEED) {
        if (cbSrc != SYMCRYPT_MLKEM_PRIVATE_SEED_SIZE) {
            return .SYMCRYPT_WRONG_KEY_SIZE;
        }

        pkMlKemkey.hasPrivateSeed = 1;
        @memcpy(&pkMlKemkey.privateSeed, pbCurr[0..pkMlKemkey.privateSeed.len]);
        pbCurr += pkMlKemkey.privateSeed.len;

        pkMlKemkey.hasPrivateKey = 1;
        @memcpy(&pkMlKemkey.privateRandom, pbCurr[0..pkMlKemkey.privateRandom.len]);
        pbCurr += pkMlKemkey.privateRandom.len;

        SymCryptMlKemkeyExpandFromPrivateSeed(pkMlKemkey, pCompTemps.?);
    } else if (mlKemkeyFormat == .DECAPSULATION_KEY) {
        if (cbSrc != sizeofFormatDecapsulationKey(nRows)) {
            return .SYMCRYPT_WRONG_KEY_SIZE;
        }

        scError = prim.SymCryptMlKemVectorDecodeAndDecompress(pbCurr, cbEncodedVector, 12, pkMlKemkey.pvs);
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }
        pbCurr += cbEncodedVector;

        @memcpy(pkMlKemkey.encodedT[0..cbEncodedVector], pbCurr[0..cbEncodedVector]);
        pbCurr += cbEncodedVector;
        scError = prim.SymCryptMlKemVectorDecodeAndDecompress(&pkMlKemkey.encodedT, cbEncodedVector, 12, pkMlKemkey.pvt);
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }

        @memcpy(&pkMlKemkey.publicSeed, pbCurr[0..pkMlKemkey.publicSeed.len]);
        pbCurr += pkMlKemkey.publicSeed.len;
        SymCryptMlKemkeyExpandPublicMatrixFromPublicSeed(pkMlKemkey, pCompTemps.?);

        prim.SymCryptMlKemMatrixTranspose(pkMlKemkey.pmAtranspose);

        SymCryptMlKemkeyComputeEncapsulationKeyHash(pkMlKemkey, pCompTemps.?, cbEncodedVector);

        if (equal.SymCryptEqual(pbCurr, &pkMlKemkey.encapsKeyHash, pkMlKemkey.encapsKeyHash.len) == 0) {
            return .SYMCRYPT_INVALID_BLOB;
        }
        pbCurr += pkMlKemkey.encapsKeyHash.len;

        @memcpy(&pkMlKemkey.privateRandom, pbCurr[0..pkMlKemkey.privateRandom.len]);
        pbCurr += pkMlKemkey.privateRandom.len;

        pkMlKemkey.hasPrivateSeed = 0;
        pkMlKemkey.hasPrivateKey = 1;
    } else if (mlKemkeyFormat == .ENCAPSULATION_KEY) {
        if (cbSrc != sizeofFormatEncapsulationKey(nRows)) {
            return .SYMCRYPT_WRONG_KEY_SIZE;
        }

        @memcpy(pkMlKemkey.encodedT[0..cbEncodedVector], pbCurr[0..cbEncodedVector]);
        pbCurr += cbEncodedVector;
        scError = prim.SymCryptMlKemVectorDecodeAndDecompress(&pkMlKemkey.encodedT, cbEncodedVector, 12, pkMlKemkey.pvt);
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }

        @memcpy(&pkMlKemkey.publicSeed, pbCurr[0..pkMlKemkey.publicSeed.len]);
        pbCurr += pkMlKemkey.publicSeed.len;
        SymCryptMlKemkeyExpandPublicMatrixFromPublicSeed(pkMlKemkey, pCompTemps.?);

        prim.SymCryptMlKemMatrixTranspose(pkMlKemkey.pmAtranspose);

        SymCryptMlKemkeyComputeEncapsulationKeyHash(pkMlKemkey, pCompTemps.?, cbEncodedVector);

        pkMlKemkey.hasPrivateSeed = 0;
        pkMlKemkey.hasPrivateKey = 0;
    } else {
        return .SYMCRYPT_NOT_IMPLEMENTED;
    }

    macros.ASSERT(pbCurr == pbSrc + cbSrc);
    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptMlKemkeyGetValue(
    pkMlKemkey: PCSYMCRYPT_MLKEMKEY,
    pbDst: PBYTE,
    cbDst: SIZE_T,
    mlKemkeyFormat: SYMCRYPT_MLKEMKEY_FORMAT,
    flags: UINT32,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    _ = flags;
    var pbCurr: PBYTE = pbDst;
    const nRows: usize = pkMlKemkey.params.nRows;
    const cbEncodedVector: SIZE_T = sizeofEncodedUncompressedVector(nRows);

    if (mlKemkeyFormat == .NULL) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    if (mlKemkeyFormat == .PRIVATE_SEED) {
        if (cbDst != SYMCRYPT_MLKEM_PRIVATE_SEED_SIZE) {
            return .SYMCRYPT_WRONG_KEY_SIZE;
        }

        if (pkMlKemkey.hasPrivateSeed == 0) {
            return .SYMCRYPT_INCOMPATIBLE_FORMAT;
        }

        @memcpy(pbCurr[0..pkMlKemkey.privateSeed.len], &pkMlKemkey.privateSeed);
        pbCurr += pkMlKemkey.privateSeed.len;

        @memcpy(pbCurr[0..pkMlKemkey.privateRandom.len], &pkMlKemkey.privateRandom);
        pbCurr += pkMlKemkey.privateRandom.len;
    } else if (mlKemkeyFormat == .DECAPSULATION_KEY) {
        if (cbDst != sizeofFormatDecapsulationKey(nRows)) {
            return .SYMCRYPT_INVALID_ARGUMENT;
        }

        if (pkMlKemkey.hasPrivateKey == 0) {
            return .SYMCRYPT_INCOMPATIBLE_FORMAT;
        }

        prim.SymCryptMlKemVectorCompressAndEncode(pkMlKemkey.pvs, 12, pbCurr, cbEncodedVector);
        pbCurr += cbEncodedVector;

        @memcpy(pbCurr[0..cbEncodedVector], pkMlKemkey.encodedT[0..cbEncodedVector]);
        pbCurr += cbEncodedVector;

        @memcpy(pbCurr[0..pkMlKemkey.publicSeed.len], &pkMlKemkey.publicSeed);
        pbCurr += pkMlKemkey.publicSeed.len;

        @memcpy(pbCurr[0..pkMlKemkey.encapsKeyHash.len], &pkMlKemkey.encapsKeyHash);
        pbCurr += pkMlKemkey.encapsKeyHash.len;

        @memcpy(pbCurr[0..pkMlKemkey.privateRandom.len], &pkMlKemkey.privateRandom);
        pbCurr += pkMlKemkey.privateRandom.len;
    } else if (mlKemkeyFormat == .ENCAPSULATION_KEY) {
        if (cbDst != sizeofFormatEncapsulationKey(nRows)) {
            return .SYMCRYPT_INVALID_ARGUMENT;
        }

        @memcpy(pbCurr[0..cbEncodedVector], pkMlKemkey.encodedT[0..cbEncodedVector]);
        pbCurr += cbEncodedVector;

        @memcpy(pbCurr[0..pkMlKemkey.publicSeed.len], &pkMlKemkey.publicSeed);
        pbCurr += pkMlKemkey.publicSeed.len;
    } else {
        return .SYMCRYPT_NOT_IMPLEMENTED;
    }

    macros.ASSERT(pbCurr == pbDst + cbDst);
    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptMlKemkeyGenerate(
    pkMlKemkey: PSYMCRYPT_MLKEMKEY,
    flags: UINT32,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;
    var privateSeed: [SYMCRYPT_MLKEM_PRIVATE_SEED_SIZE]BYTE = undefined;
    var pbPctCipherText: ?PBYTE = null;
    var cbPctCipherText: SIZE_T = 0;

    defer {
        if (pbPctCipherText) |ptr| {
            hash.SymCryptWipe(ptr, cbPctCipherText);
            SymCryptCallbackFree(ptr);
        }
        hash.SymCryptWipeKnownSize(&privateSeed, privateSeed.len);
    }

    const allowedFlags: UINT32 = SYMCRYPT_FLAG_KEY_NO_FIPS;
    if ((flags & ~allowedFlags) != 0) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    scError = SymCryptCallbackRandom(&privateSeed, privateSeed.len);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    scError = SymCryptMlKemkeySetValue(&privateSeed, privateSeed.len, .PRIVATE_SEED, flags, pkMlKemkey);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    if ((flags & SYMCRYPT_FLAG_KEY_NO_FIPS) == 0) {
        const nRows: SIZE_T = pkMlKemkey.params.nRows;
        const nBitsOfU: SIZE_T = pkMlKemkey.params.nBitsOfU;
        const nBitsOfV: SIZE_T = pkMlKemkey.params.nBitsOfV;

        const cbU: SIZE_T = nRows * nBitsOfU * (SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS / 8);
        const cbV: SIZE_T = nBitsOfV * (SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS / 8);
        cbPctCipherText = cbU + cbV;

        pbPctCipherText = SymCryptCallbackAlloc(cbPctCipherText) orelse {
            return .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
        };

        scError = SymCryptMlKemEncapsulate(
            pkMlKemkey,
            privateSeed[0..SYMCRYPT_MLKEM_SIZEOF_AGREED_SECRET].ptr,
            SYMCRYPT_MLKEM_SIZEOF_AGREED_SECRET,
            pbPctCipherText.?,
            cbPctCipherText,
        );
        if (scError != .SYMCRYPT_NO_ERROR) {
            return .SYMCRYPT_FIPS_FAILURE;
        }

        scError = SymCryptMlKemDecapsulate(
            pkMlKemkey,
            pbPctCipherText.?,
            cbPctCipherText,
            privateSeed[SYMCRYPT_MLKEM_SIZEOF_AGREED_SECRET..].ptr,
            SYMCRYPT_MLKEM_SIZEOF_AGREED_SECRET,
        );
        if (scError != .SYMCRYPT_NO_ERROR) {
            return .SYMCRYPT_FIPS_FAILURE;
        }

        if (equal.SymCryptEqual(
            privateSeed[0..SYMCRYPT_MLKEM_SIZEOF_AGREED_SECRET].ptr,
            privateSeed[SYMCRYPT_MLKEM_SIZEOF_AGREED_SECRET..].ptr,
            SYMCRYPT_MLKEM_SIZEOF_AGREED_SECRET,
        ) == 0) {
            return .SYMCRYPT_FIPS_FAILURE;
        }
    }

    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptMlKemEncapsulateInternal(
    pkMlKemkey: PCSYMCRYPT_MLKEMKEY,
    pbAgreedSecret: PBYTE,
    cbAgreedSecret: SIZE_T,
    pbCiphertext: PBYTE,
    cbCiphertext: SIZE_T,
    pbRandom: PCBYTE,
    pCompTemps: PSYMCRYPT_MLKEM_INTERNAL_COMPUTATION_TEMPORARIES,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var CBDSampleBuffer: [3 * 64 + 1]BYTE = undefined;
    defer hash.SymCryptWipeKnownSize(&CBDSampleBuffer, CBDSampleBuffer.len);

    const pHashState: sha3.PSYMCRYPT_SHA3_512_STATE = &pCompTemps.hashState0.sha3_512State;
    const pShakeBaseState: shake.PSYMCRYPT_SHAKE256_STATE = &pCompTemps.hashState0.shake256State;
    const pShakeWorkState: shake.PSYMCRYPT_SHAKE256_STATE = &pCompTemps.hashState1.shake256State;
    const nRows: UINT32 = pkMlKemkey.params.nRows;
    const nBitsOfU: UINT32 = pkMlKemkey.params.nBitsOfU;
    const nBitsOfV: UINT32 = pkMlKemkey.params.nBitsOfV;
    const nEta1: UINT32 = pkMlKemkey.params.nEta1;
    const nEta2: UINT32 = pkMlKemkey.params.nEta2;
    const cbPolyElement: UINT32 = pkMlKemkey.params.cbPolyElement;
    const cbVector: UINT32 = pkMlKemkey.params.cbVector;

    const cbU: SIZE_T = @as(SIZE_T, nRows) * @as(SIZE_T, nBitsOfU) * (SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS / 8);
    const cbV: SIZE_T = @as(SIZE_T, nBitsOfV) * (SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS / 8);

    if ((cbAgreedSecret != SYMCRYPT_MLKEM_SIZEOF_AGREED_SECRET) or
        (cbCiphertext != cbU + cbV))
    {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    const pvrInner = prim.SymCryptMlKemVectorCreate(&pCompTemps.abVectorBuffer0, cbVector, nRows).?;
    const pvTmp = prim.SymCryptMlKemVectorCreate(&pCompTemps.abVectorBuffer1, cbVector, nRows).?;
    const peTmp0 = prim.SymCryptMlKemPolyElementCreate(&pCompTemps.abPolyElementBuffer0, cbPolyElement).?;
    const peTmp1 = prim.SymCryptMlKemPolyElementCreate(&pCompTemps.abPolyElementBuffer1, cbPolyElement).?;
    const paTmp = prim.SymCryptMlKemPolyElementAccumulatorCreate(&pCompTemps.abPolyElementAccumulatorBuffer, 2 * cbPolyElement).?;

    sha3.SymCryptSha3_512Init(pHashState);
    sha3.SymCryptSha3_512Append(pHashState, pbRandom, SYMCRYPT_MLKEM_SIZEOF_ENCAPS_RANDOM);
    sha3.SymCryptSha3_512Append(pHashState, &pkMlKemkey.encapsKeyHash, pkMlKemkey.encapsKeyHash.len);
    sha3.SymCryptSha3_512Result(pHashState, &CBDSampleBuffer);

    @memcpy(pbAgreedSecret[0..SYMCRYPT_MLKEM_SIZEOF_AGREED_SECRET], CBDSampleBuffer[0..SYMCRYPT_MLKEM_SIZEOF_AGREED_SECRET]);

    shake.SymCryptShake256Init(pShakeBaseState);
    shake.SymCryptShake256Append(pShakeBaseState, CBDSampleBuffer[cbAgreedSecret..].ptr, 32);

    macros.ASSERT(nRows >= 2 and nRows <= 4);

    var i: usize = 0;
    while (i < nRows) : (i += 1) {
        CBDSampleBuffer[0] = @truncate(i);
        shake.SymCryptShake256StateCopy(pShakeBaseState, pShakeWorkState);
        shake.SymCryptShake256Append(pShakeWorkState, &CBDSampleBuffer, 1);

        shake.SymCryptShake256Extract(pShakeWorkState, &CBDSampleBuffer, 64 * @as(usize, nEta1), 0);

        prim.SymCryptMlKemPolyElementSampleCBDFromBytes(&CBDSampleBuffer, nEta1, prim.vectorElement(pvrInner, i));
    }

    prim.SymCryptMlKemVectorNTT(pvrInner);

    prim.SymCryptMlKemVectorSetZero(pvTmp);

    prim.SymCryptMlKemMatrixVectorMontMulAndAdd(pkMlKemkey.pmAtranspose, pvrInner, pvTmp, paTmp);

    prim.SymCryptMlKemVectorINTTAndMulR(pvTmp);

    i = 0;
    while (i < nRows) : (i += 1) {
        CBDSampleBuffer[0] = @truncate(@as(usize, nRows) + i);
        shake.SymCryptShake256StateCopy(pShakeBaseState, pShakeWorkState);
        shake.SymCryptShake256Append(pShakeWorkState, &CBDSampleBuffer, 1);

        shake.SymCryptShake256Extract(pShakeWorkState, &CBDSampleBuffer, 64 * @as(usize, nEta2), 0);

        prim.SymCryptMlKemPolyElementSampleCBDFromBytes(&CBDSampleBuffer, nEta2, peTmp0);

        prim.SymCryptMlKemPolyElementAdd(prim.vectorElement(pvTmp, i), peTmp0, prim.vectorElement(pvTmp, i));
    }

    prim.SymCryptMlKemVectorCompressAndEncode(pvTmp, nBitsOfU, pbCiphertext, cbU);

    prim.SymCryptMlKemVectorMontDotProduct(pkMlKemkey.pvt, pvrInner, peTmp0, paTmp);

    prim.SymCryptMlKemPolyElementINTTAndMulR(peTmp0);

    CBDSampleBuffer[0] = @truncate(2 * @as(usize, nRows));
    shake.SymCryptShake256StateCopy(pShakeBaseState, pShakeWorkState);
    shake.SymCryptShake256Append(pShakeWorkState, &CBDSampleBuffer, 1);

    shake.SymCryptShake256Extract(pShakeWorkState, &CBDSampleBuffer, 64 * @as(usize, nEta2), 0);

    prim.SymCryptMlKemPolyElementSampleCBDFromBytes(&CBDSampleBuffer, nEta2, peTmp1);

    prim.SymCryptMlKemPolyElementAdd(peTmp0, peTmp1, peTmp0);

    _ = prim.SymCryptMlKemPolyElementDecodeAndDecompress(pbRandom, 1, peTmp1);

    prim.SymCryptMlKemPolyElementAdd(peTmp0, peTmp1, peTmp0);

    prim.SymCryptMlKemPolyElementCompressAndEncode(peTmp0, nBitsOfV, pbCiphertext + cbU);

    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptMlKemEncapsulateEx(
    pkMlKemkey: PCSYMCRYPT_MLKEMKEY,
    pbRandom: PCBYTE,
    cbRandom: SIZE_T,
    pbAgreedSecret: PBYTE,
    cbAgreedSecret: SIZE_T,
    pbCiphertext: PBYTE,
    cbCiphertext: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    if (cbRandom != SYMCRYPT_MLKEM_SIZEOF_ENCAPS_RANDOM) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    const pbCompTemps = SymCryptCallbackAlloc(@sizeOf(SYMCRYPT_MLKEM_INTERNAL_COMPUTATION_TEMPORARIES)) orelse {
        return .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
    };
    const alignedCompTemps: [*]align(types.SYMCRYPT_ASYM_ALIGN_VALUE) BYTE = @alignCast(pbCompTemps);
    const pCompTemps: PSYMCRYPT_MLKEM_INTERNAL_COMPUTATION_TEMPORARIES = @ptrCast(alignedCompTemps);
    defer {
        hash.SymCryptWipe(@ptrCast(pCompTemps), @sizeOf(SYMCRYPT_MLKEM_INTERNAL_COMPUTATION_TEMPORARIES));
        SymCryptCallbackFree(@ptrCast(pCompTemps));
    }

    return SymCryptMlKemEncapsulateInternal(
        pkMlKemkey,
        pbAgreedSecret,
        cbAgreedSecret,
        pbCiphertext,
        cbCiphertext,
        pbRandom,
        pCompTemps,
    );
}

pub export fn SymCryptMlKemEncapsulate(
    pkMlKemkey: PCSYMCRYPT_MLKEMKEY,
    pbAgreedSecret: PBYTE,
    cbAgreedSecret: SIZE_T,
    pbCiphertext: PBYTE,
    cbCiphertext: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var pbm: [SYMCRYPT_MLKEM_SIZEOF_ENCAPS_RANDOM]BYTE = undefined;
    defer hash.SymCryptWipeKnownSize(&pbm, pbm.len);

    const scError = SymCryptCallbackRandom(&pbm, pbm.len);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    return SymCryptMlKemEncapsulateEx(
        pkMlKemkey,
        &pbm,
        pbm.len,
        pbAgreedSecret,
        cbAgreedSecret,
        pbCiphertext,
        cbCiphertext,
    );
}

pub export fn SymCryptMlKemDecapsulate(
    pkMlKemkey: PCSYMCRYPT_MLKEMKEY,
    pbCiphertext: PCBYTE,
    cbCiphertext: SIZE_T,
    pbAgreedSecret: PBYTE,
    cbAgreedSecret: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var pbDecryptedRandom: [SYMCRYPT_MLKEM_SIZEOF_ENCAPS_RANDOM]BYTE = undefined;
    var pbDecapsulatedSecret: [SYMCRYPT_MLKEM_SIZEOF_AGREED_SECRET]BYTE = undefined;
    var pbImplicitRejectionSecret: [SYMCRYPT_MLKEM_SIZEOF_AGREED_SECRET]BYTE = undefined;
    defer {
        hash.SymCryptWipeKnownSize(&pbDecryptedRandom, pbDecryptedRandom.len);
        hash.SymCryptWipeKnownSize(&pbDecapsulatedSecret, pbDecapsulatedSecret.len);
        hash.SymCryptWipeKnownSize(&pbImplicitRejectionSecret, pbImplicitRejectionSecret.len);
    }

    const nRows: UINT32 = pkMlKemkey.params.nRows;
    const nBitsOfU: UINT32 = pkMlKemkey.params.nBitsOfU;
    const nBitsOfV: UINT32 = pkMlKemkey.params.nBitsOfV;
    const cbPolyElement: UINT32 = pkMlKemkey.params.cbPolyElement;
    const cbVector: UINT32 = pkMlKemkey.params.cbVector;

    const cbU: SIZE_T = @as(SIZE_T, nRows) * @as(SIZE_T, nBitsOfU) * (SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS / 8);
    const cbV: SIZE_T = @as(SIZE_T, nBitsOfV) * (SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS / 8);

    if ((cbAgreedSecret != SYMCRYPT_MLKEM_SIZEOF_AGREED_SECRET) or
        (cbCiphertext != cbU + cbV) or
        (pkMlKemkey.hasPrivateKey == 0))
    {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    const cbAlloc: SIZE_T = @sizeOf(SYMCRYPT_MLKEM_INTERNAL_COMPUTATION_TEMPORARIES) + (2 * cbCiphertext);
    const pbAlloc = SymCryptCallbackAlloc(cbAlloc) orelse {
        return .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
    };
    defer {
        hash.SymCryptWipe(pbAlloc, cbAlloc);
        SymCryptCallbackFree(pbAlloc);
    }

    var pbCurr: PBYTE = pbAlloc;
    const alignedCompTemps: [*]align(types.SYMCRYPT_ASYM_ALIGN_VALUE) BYTE = @alignCast(pbCurr);
    const pCompTemps: PSYMCRYPT_MLKEM_INTERNAL_COMPUTATION_TEMPORARIES = @ptrCast(alignedCompTemps);
    pbCurr += @sizeOf(SYMCRYPT_MLKEM_INTERNAL_COMPUTATION_TEMPORARIES);

    const pbReadCiphertext: PBYTE = pbCurr;
    pbCurr += cbCiphertext;

    const pbReencapsulatedCiphertext: PBYTE = pbCurr;
    pbCurr += cbCiphertext;

    macros.ASSERT(pbCurr == (pbAlloc + cbAlloc));

    @memcpy(pbReadCiphertext[0..cbCiphertext], pbCiphertext[0..cbCiphertext]);

    const pvu = prim.SymCryptMlKemVectorCreate(&pCompTemps.abVectorBuffer0, cbVector, nRows).?;
    const peTmp0 = prim.SymCryptMlKemPolyElementCreate(&pCompTemps.abPolyElementBuffer0, cbPolyElement).?;
    const peTmp1 = prim.SymCryptMlKemPolyElementCreate(&pCompTemps.abPolyElementBuffer1, cbPolyElement).?;
    const paTmp = prim.SymCryptMlKemPolyElementAccumulatorCreate(&pCompTemps.abPolyElementAccumulatorBuffer, 2 * cbPolyElement).?;

    var scError = prim.SymCryptMlKemVectorDecodeAndDecompress(pbReadCiphertext, cbU, nBitsOfU, pvu);
    macros.ASSERT(scError == .SYMCRYPT_NO_ERROR);

    prim.SymCryptMlKemVectorNTT(pvu);

    prim.SymCryptMlKemVectorMontDotProduct(pkMlKemkey.pvs, pvu, peTmp0, paTmp);

    prim.SymCryptMlKemPolyElementINTTAndMulR(peTmp0);

    scError = prim.SymCryptMlKemPolyElementDecodeAndDecompress(pbReadCiphertext + cbU, nBitsOfV, peTmp1);
    macros.ASSERT(scError == .SYMCRYPT_NO_ERROR);

    prim.SymCryptMlKemPolyElementSub(peTmp1, peTmp0, peTmp0);

    prim.SymCryptMlKemPolyElementCompressAndEncode(peTmp0, 1, &pbDecryptedRandom);

    scError = SymCryptMlKemEncapsulateInternal(
        pkMlKemkey,
        &pbDecapsulatedSecret,
        pbDecapsulatedSecret.len,
        pbReencapsulatedCiphertext,
        cbCiphertext,
        &pbDecryptedRandom,
        pCompTemps,
    );
    macros.ASSERT(scError == .SYMCRYPT_NO_ERROR);

    const pShakeState: shake.PSYMCRYPT_SHAKE256_STATE = &pCompTemps.hashState0.shake256State;
    shake.SymCryptShake256Init(pShakeState);
    shake.SymCryptShake256Append(pShakeState, &pkMlKemkey.privateRandom, pkMlKemkey.privateRandom.len);
    shake.SymCryptShake256Append(pShakeState, pbReadCiphertext, cbCiphertext);
    shake.SymCryptShake256Extract(pShakeState, &pbImplicitRejectionSecret, pbImplicitRejectionSecret.len, 0);

    const successfulReencrypt: BOOLEAN = equal.SymCryptEqual(pbReencapsulatedCiphertext, pbReadCiphertext, cbCiphertext);

    const cbCopy: SIZE_T = (@as(SIZE_T, successfulReencrypt) -% 1) & SYMCRYPT_MLKEM_SIZEOF_AGREED_SECRET;
    scs_tools.SymCryptScsCopy(&pbImplicitRejectionSecret, cbCopy, &pbDecapsulatedSecret, SYMCRYPT_MLKEM_SIZEOF_AGREED_SECRET);

    @memcpy(pbAgreedSecret[0..SYMCRYPT_MLKEM_SIZEOF_AGREED_SECRET], &pbDecapsulatedSecret);

    return .SYMCRYPT_NO_ERROR;
}
