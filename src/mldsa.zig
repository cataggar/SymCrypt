//
// mldsa.zig   ML-DSA related functionality
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

const std = @import("std");
const types = @import("types.zig");
const macros = @import("macros.zig");
const equal = @import("equal.zig");
const libmain = @import("libmain.zig");
const shake = @import("shake.zig");
const prim = @import("mldsa_primitives.zig");

const BYTE = types.BYTE;
const PBYTE = types.PBYTE;
const PCBYTE = types.PCBYTE;
const UINT8 = types.UINT8;
const UINT16 = types.UINT16;
const UINT32 = types.UINT32;
const SIZE_T = types.SIZE_T;
const BOOLEAN = types.BOOLEAN;
const SYMCRYPT_ERROR = types.SYMCRYPT_ERROR;
const SYMCRYPT_CALL = types.SYMCRYPT_CALL;
const PCSYMCRYPT_OID = types.PCSYMCRYPT_OID;
const SYMCRYPT_PQDSA_HASH_ID = types.SYMCRYPT_PQDSA_HASH_ID;
const SYMCRYPT_MLDSA_PARAMS = types.SYMCRYPT_MLDSA_PARAMS;
const SYMCRYPT_MLDSAKEY_FORMAT = types.SYMCRYPT_MLDSAKEY_FORMAT;

const PSYMCRYPT_MLDSAKEY = prim.PSYMCRYPT_MLDSAKEY;
const PCSYMCRYPT_MLDSAKEY = prim.PCSYMCRYPT_MLDSAKEY;
const PCSYMCRYPT_MLDSA_INTERNAL_PARAMS = prim.PCSYMCRYPT_MLDSA_INTERNAL_PARAMS;
const PSYMCRYPT_MLDSA_VECTOR = prim.PSYMCRYPT_MLDSA_VECTOR;
const PSYMCRYPT_MLDSA_POLYELEMENT = prim.PSYMCRYPT_MLDSA_POLYELEMENT;

extern fn SymCryptCallbackAlloc(cb: SIZE_T) callconv(SYMCRYPT_CALL) ?*anyopaque;
extern fn SymCryptCallbackFree(p: *anyopaque) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptCallbackRandom(pbBuffer: PBYTE, cbBuffer: SIZE_T) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;

extern var g_SymCryptFipsSelftestsPerformed: UINT32;
extern fn SymCryptMlDsaSelftest() callconv(SYMCRYPT_CALL) void;

pub const SYMCRYPT_FLAG_KEY_NO_FIPS: UINT32 = 0x00000100;
const SYMCRYPT_SELFTEST_ALGORITHM_MLDSA: UINT32 = 0x200;

inline fn runMlDsaSelftestOnce() void {
    if (types.DO_FIPS_SELFTESTS) {
        if ((g_SymCryptFipsSelftestsPerformed & SYMCRYPT_SELFTEST_ALGORITHM_MLDSA) == 0) {
            SymCryptMlDsaSelftest();
            _ = @atomicRmw(UINT32, &g_SymCryptFipsSelftestsPerformed, .Or, SYMCRYPT_SELFTEST_ALGORITHM_MLDSA, .monotonic);
        }
    }
}

pub export fn SymCryptMlDsakeyAllocate(
    params: SYMCRYPT_MLDSA_PARAMS,
) callconv(SYMCRYPT_CALL) ?PSYMCRYPT_MLDSAKEY {
    var pInternalParams: PCSYMCRYPT_MLDSA_INTERNAL_PARAMS = undefined;
    const scError = prim.SymCryptMlDsaGetInternalParamsFromParams(params, &pInternalParams);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return null;
    }

    const cbKey: UINT32 = prim.SYMCRYPT_INTERNAL_MLDSA_SIZEOF_KEY(pInternalParams.nRows, pInternalParams.nCols);
    const rawPtr = SymCryptCallbackAlloc(cbKey) orelse return null;
    const pbKey: PBYTE = @ptrCast(rawPtr);

    const pkMlDsakey = prim.SymCryptMlDsakeyInitialize(pInternalParams, pbKey, cbKey);
    if (pkMlDsakey == null) {
        SymCryptCallbackFree(rawPtr);
        return null;
    }

    return pkMlDsakey;
}

pub export fn SymCryptMlDsakeyFree(
    pkMlDsakey: PSYMCRYPT_MLDSAKEY,
) callconv(SYMCRYPT_CALL) void {
    macros.CHECK_MAGIC(pkMlDsakey);

    const cbTotalSize = pkMlDsakey.cbTotalSize;
    libmain.SymCryptWipe(@ptrCast(pkMlDsakey), cbTotalSize);
    SymCryptCallbackFree(@ptrCast(pkMlDsakey));
}

pub export fn SymCryptMlDsaKeyGenerateEx(
    pkMlDsakey: PSYMCRYPT_MLDSAKEY,
    pbRootSeed: PCBYTE,
    cbRootSeed: SIZE_T,
    flags: UINT32,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    _ = flags;
    macros.ASSERT(cbRootSeed == prim.SYMCRYPT_MLDSA_PRIVATE_SEED_SIZE);

    const pParams = pkMlDsakey.pParams;
    var privateVectorSeed: [prim.SYMCRYPT_MLDSA_PRIVATE_VECTOR_SEED_SIZE]BYTE = undefined;
    defer libmain.SymCryptWipe(@ptrCast(&privateVectorSeed), privateVectorSeed.len);

    const pTemps = prim.SymCryptMlDsaTemporariesAllocateAndInitialize(
        pParams,
        1,
        0,
        1,
        pParams.cbEncodedPublicKey,
    ) orelse return .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
    defer prim.SymCryptMlDsaTemporariesFree(pTemps);

    @memcpy(&pkMlDsakey.rootSeed, pbRootSeed[0..prim.SYMCRYPT_MLDSA_PRIVATE_SEED_SIZE]);

    {
        const pShakeState = &pTemps.shake256State;
        const nRowsArr = [1]BYTE{pParams.nRows};
        const nColsArr = [1]BYTE{pParams.nCols};

        shake.SymCryptShake256Init(pShakeState);
        shake.SymCryptShake256Append(pShakeState, &pkMlDsakey.rootSeed, cbRootSeed);
        shake.SymCryptShake256Append(pShakeState, &nRowsArr, 1);
        shake.SymCryptShake256Append(pShakeState, &nColsArr, 1);

        shake.SymCryptShake256Extract(pShakeState, &pkMlDsakey.publicSeed, pkMlDsakey.publicSeed.len, types.FALSE);
        shake.SymCryptShake256Extract(pShakeState, &privateVectorSeed, privateVectorSeed.len, types.FALSE);
        shake.SymCryptShake256Extract(pShakeState, &pkMlDsakey.privateSigningSeed, pkMlDsakey.privateSigningSeed.len, types.FALSE);
    }

    var scError = prim.SymCryptMlDsaExpandA(&pkMlDsakey.publicSeed, pkMlDsakey.publicSeed.len, pkMlDsakey.pmA);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    scError = prim.SymCryptMlDsaExpandS(
        pkMlDsakey.pParams,
        &privateVectorSeed,
        privateVectorSeed.len,
        pkMlDsakey.pvs1,
        pkMlDsakey.pvs2,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    prim.SymCryptMlDsaVectorNTT(pkMlDsakey.pvs1);
    prim.SymCryptMlDsaVectorNTT(pkMlDsakey.pvs2);

    prim.SymCryptMlDsakeyComputeT(
        pkMlDsakey.pmA,
        pkMlDsakey.pvs1,
        pkMlDsakey.pvs2,
        pkMlDsakey.pvt0,
        pkMlDsakey.pvt1,
        pTemps.pvRowVectors.?[0],
        pTemps.pePolyElements.?[0],
    );

    prim.SymCryptMlDsaVectorNTT(pkMlDsakey.pvt0);
    prim.SymCryptMlDsaVectorNTT(pkMlDsakey.pvt1);

    const pbScratch = pTemps.pbScratch.?;
    scError = prim.SymCryptMlDsaPkEncode(pkMlDsakey, pbScratch, pParams.cbEncodedPublicKey);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    shake.SymCryptShake256(
        pbScratch,
        pParams.cbEncodedPublicKey,
        &pkMlDsakey.publicKeyHash,
        pkMlDsakey.publicKeyHash.len,
    );

    pkMlDsakey.hasRootSeed = types.TRUE;
    pkMlDsakey.hasPrivateKey = types.TRUE;

    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptMlDsakeyGenerate(
    pkMlDsakey: PSYMCRYPT_MLDSAKEY,
    flags: UINT32,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var random: [prim.SYMCRYPT_MLDSA_PRIVATE_SEED_SIZE]BYTE = undefined;
    defer libmain.SymCryptWipe(@ptrCast(&random), random.len);

    const allowedFlags: UINT32 = SYMCRYPT_FLAG_KEY_NO_FIPS;
    if ((flags & ~allowedFlags) != 0) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    var scError = SymCryptCallbackRandom(&random, random.len);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    scError = SymCryptMlDsakeySetValue(
        &random,
        random.len,
        .SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_SEED,
        flags,
        pkMlDsakey,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    if ((flags & SYMCRYPT_FLAG_KEY_NO_FIPS) == 0) {
        const cbPctSignature: SIZE_T = pkMlDsakey.pParams.cbEncodedSignature;
        const rawSig = SymCryptCallbackAlloc(cbPctSignature) orelse return .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
        const pbPctSignature: PBYTE = @ptrCast(rawSig);
        defer {
            libmain.SymCryptWipe(@ptrCast(pbPctSignature), cbPctSignature);
            SymCryptCallbackFree(rawSig);
        }

        scError = SymCryptMlDsaSign(
            pkMlDsakey,
            null,
            0,
            null,
            0,
            0,
            pbPctSignature,
            cbPctSignature,
        );
        if (scError != .SYMCRYPT_NO_ERROR) {
            return .SYMCRYPT_FIPS_FAILURE;
        }

        scError = SymCryptMlDsaVerify(
            pkMlDsakey,
            null,
            0,
            null,
            0,
            pbPctSignature,
            cbPctSignature,
            0,
        );
        if (scError != .SYMCRYPT_NO_ERROR) {
            return .SYMCRYPT_FIPS_FAILURE;
        }
    }

    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptMlDsakeySetValue(
    pbSrc: PCBYTE,
    cbSrc: SIZE_T,
    mlDsakeyFormat: SYMCRYPT_MLDSAKEY_FORMAT,
    flags: UINT32,
    pkMlDsakey: PSYMCRYPT_MLDSAKEY,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    const allowedFlags: UINT32 = SYMCRYPT_FLAG_KEY_NO_FIPS;
    if ((flags & ~allowedFlags) != 0) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    if ((flags & SYMCRYPT_FLAG_KEY_NO_FIPS) == 0) {
        runMlDsaSelftestOnce();
    }

    switch (mlDsakeyFormat) {
        .SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_SEED => {
            if (cbSrc != prim.SYMCRYPT_MLDSA_PRIVATE_SEED_SIZE) {
                return .SYMCRYPT_WRONG_KEY_SIZE;
            }
            return SymCryptMlDsaKeyGenerateEx(pkMlDsakey, pbSrc, cbSrc, flags);
        },
        .SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_KEY => {
            return prim.SymCryptMlDsaSkDecode(pbSrc, cbSrc, flags, pkMlDsakey);
        },
        .SYMCRYPT_MLDSAKEY_FORMAT_PUBLIC_KEY => {
            return prim.SymCryptMlDsaPkDecode(pbSrc, cbSrc, flags, pkMlDsakey);
        },
        else => return .SYMCRYPT_INVALID_ARGUMENT,
    }
}

pub export fn SymCryptMlDsakeyGetValue(
    pkMlDsakey: PCSYMCRYPT_MLDSAKEY,
    pbDst: PBYTE,
    cbDst: SIZE_T,
    mlDsakeyFormat: SYMCRYPT_MLDSAKEY_FORMAT,
    flags: UINT32,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    if (flags != 0) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    switch (mlDsakeyFormat) {
        .SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_KEY => {
            return prim.SymCryptMlDsaSkEncode(pkMlDsakey, pbDst, cbDst);
        },
        .SYMCRYPT_MLDSAKEY_FORMAT_PUBLIC_KEY => {
            return prim.SymCryptMlDsaPkEncode(pkMlDsakey, pbDst, cbDst);
        },
        .SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_SEED => {
            if (cbDst < prim.SYMCRYPT_MLDSA_PRIVATE_SEED_SIZE) {
                return .SYMCRYPT_BUFFER_TOO_SMALL;
            }
            if (pkMlDsakey.hasRootSeed == types.FALSE) {
                return .SYMCRYPT_INCOMPATIBLE_FORMAT;
            }
            @memcpy(pbDst[0..prim.SYMCRYPT_MLDSA_PRIVATE_SEED_SIZE], &pkMlDsakey.rootSeed);
            return .SYMCRYPT_NO_ERROR;
        },
        else => return .SYMCRYPT_INVALID_ARGUMENT,
    }
}

pub export fn SymCryptMlDsaSignEx(
    pkMlDsakey: PCSYMCRYPT_MLDSAKEY,
    pbInput: ?PCBYTE,
    cbInput: SIZE_T,
    pbContext: ?PCBYTE,
    cbContext: SIZE_T,
    pbHashOid: ?PCBYTE,
    cbHashOid: SIZE_T,
    pbRandom: PCBYTE,
    cbRandom: SIZE_T,
    flags: UINT32,
    pbSignature: PBYTE,
    cbSignature: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    macros.ASSERT(pkMlDsakey.hasPrivateKey == types.TRUE);
    macros.ASSERT(cbContext <= prim.SYMCRYPT_MLDSA_CONTEXT_MAX_LENGTH);
    macros.ASSERT(cbRandom == prim.SYMCRYPT_MLDSA_SIGNING_RANDOM_SIZE);
    macros.ASSERT(pbHashOid != null or cbHashOid == 0);
    macros.ASSERT(pbContext != null or cbContext == 0);
    macros.ASSERT(cbSignature == pkMlDsakey.pParams.cbEncodedSignature);
    macros.ASSERT((flags & ~prim.SYMCRYPT_FLAG_MLDSA_EXTERNALMU) == 0);
    macros.ASSERT(((flags & prim.SYMCRYPT_FLAG_MLDSA_EXTERNALMU) == 0) or (pbContext == null and pbHashOid == null));

    const pParams = pkMlDsakey.pParams;
    const beta: UINT32 = @as(UINT32, pParams.nChallengeNonZeroCoeffs) * @as(UINT32, pParams.privateKeyRange);

    const bExternalMu: bool = (flags & prim.SYMCRYPT_FLAG_MLDSA_EXTERNALMU) != 0;
    const modeIdArr = [1]UINT8{if (pbHashOid == null) 0 else 1};
    const cbContextByteArr = [1]UINT8{@intCast(cbContext)};
    var messageRepresentative: [shake.SYMCRYPT_SHAKE256_RESULT_SIZE]BYTE = undefined;
    var privateRandom: [shake.SYMCRYPT_SHAKE256_RESULT_SIZE]BYTE = undefined;
    defer {
        libmain.SymCryptWipeKnownSize(&privateRandom, @sizeOf(@TypeOf(privateRandom)));
        libmain.SymCryptWipeKnownSize(&messageRepresentative, @sizeOf(@TypeOf(messageRepresentative)));
    }
    var commitmentHash: [64]BYTE = undefined;

    const cbw1Encoded: UINT32 = @as(UINT32, pParams.nRows) * pParams.w1EncodeCoefficientBitLength *
        (prim.SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS / 8);

    const pTemps = prim.SymCryptMlDsaTemporariesAllocateAndInitialize(
        pParams,
        2,
        3,
        1,
        cbw1Encoded,
    ) orelse return .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
    defer prim.SymCryptMlDsaTemporariesFree(pTemps);

    const pShakeState = &pTemps.shake256State;
    shake.SymCryptShake256Init(pShakeState);

    if (bExternalMu) {
        macros.ASSERT(cbInput == shake.SYMCRYPT_SHAKE256_RESULT_SIZE);
        @memcpy(&messageRepresentative, pbInput.?[0..shake.SYMCRYPT_SHAKE256_RESULT_SIZE]);
    } else {
        shake.SymCryptShake256Append(pShakeState, &pkMlDsakey.publicKeyHash, pkMlDsakey.publicKeyHash.len);
        shake.SymCryptShake256Append(pShakeState, &modeIdArr, 1);
        shake.SymCryptShake256Append(pShakeState, &cbContextByteArr, 1);

        if (cbContext > 0) {
            shake.SymCryptShake256Append(pShakeState, pbContext.?, cbContext);
        }
        if (cbHashOid > 0) {
            shake.SymCryptShake256Append(pShakeState, pbHashOid.?, cbHashOid);
        }
        if (cbInput > 0) {
            shake.SymCryptShake256Append(pShakeState, pbInput.?, cbInput);
        }
        shake.SymCryptShake256Result(pShakeState, &messageRepresentative);
    }

    shake.SymCryptShake256Append(pShakeState, &pkMlDsakey.privateSigningSeed, pkMlDsakey.privateSigningSeed.len);
    shake.SymCryptShake256Append(pShakeState, pbRandom, cbRandom);
    shake.SymCryptShake256Append(pShakeState, &messageRepresentative, messageRepresentative.len);
    shake.SymCryptShake256Result(pShakeState, &privateRandom);

    const pvW: PSYMCRYPT_MLDSA_VECTOR = pTemps.pvRowVectors.?[0];
    var pvHint: ?PSYMCRYPT_MLDSA_VECTOR = null;

    const pvMask: PSYMCRYPT_MLDSA_VECTOR = pTemps.pvColVectors.?[0];
    const pvResponse: PSYMCRYPT_MLDSA_VECTOR = pTemps.pvColVectors.?[1];
    const pvcs1: PSYMCRYPT_MLDSA_VECTOR = pTemps.pvColVectors.?[2];

    const pbW1Encoded: PBYTE = pTemps.pbScratch.?;

    const kappaLimit: UINT32 = prim.SYMCRYPT_MLDSA_SIGN_INTERNAL_MAX_ITERATIONS * @as(UINT32, pParams.nCols);
    macros.ASSERT(kappaLimit <= std.math.maxInt(UINT16));

    const shiftMaskRange: u5 = @intCast(pParams.maskCoefficientRangeLog2);
    const zNormBound: UINT32 = (@as(UINT32, 1) << shiftMaskRange) - beta;
    const r0NormBound: UINT32 = pParams.commitmentRoundingRange - beta;

    var kappa: UINT16 = 0;
    while (kappa < @as(UINT16, @intCast(kappaLimit))) : (kappa += pParams.nCols) {
        prim.SymCryptMlDsaExpandMask(
            pParams,
            pShakeState,
            &privateRandom,
            privateRandom.len,
            kappa,
            pvMask,
        );

        prim.SymCryptMlDsaMatrixVectorMontMul(pkMlDsakey.pmA, pvMask, pvW, pTemps.pePolyElements.?[0]);

        for (0..pvW.nElems) |i| {
            prim.SymCryptMlDsaPolyElementMulR(prim.vectorElement(i, pvW));
        }

        prim.SymCryptMlDsaVectorINTT(pvW);

        {
            const pvW1: PSYMCRYPT_MLDSA_VECTOR = pTemps.pvRowVectors.?[1];
            prim.SymCryptMlDsaVectorHighBits(pParams, pvW, pvW1);
            prim.SymCryptMlDsaVectorEncode(pvW1, pParams.w1EncodeCoefficientBitLength, 0, pbW1Encoded);
        }

        shake.SymCryptShake256Append(pShakeState, &messageRepresentative, messageRepresentative.len);
        shake.SymCryptShake256Append(pShakeState, pbW1Encoded, cbw1Encoded);
        shake.SymCryptShake256Extract(pShakeState, &commitmentHash, pParams.cbCommitmentHash, types.TRUE);

        const peC: PSYMCRYPT_MLDSA_POLYELEMENT = pTemps.pePolyElements.?[0];
        const scError = prim.SymCryptMlDsaSampleInBall(pParams, &commitmentHash, pParams.cbCommitmentHash, peC);
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }

        prim.SymCryptMlDsaPolyElementNTT(peC);
        prim.SymCryptMlDsaPolyElementMulR(peC);

        {
            const pvcs2: PSYMCRYPT_MLDSA_VECTOR = pTemps.pvRowVectors.?[1];
            prim.SymCryptMlDsaVectorPolyElementMontMul(pkMlDsakey.pvs1, peC, pvcs1);
            prim.SymCryptMlDsaVectorPolyElementMontMul(pkMlDsakey.pvs2, peC, pvcs2);

            prim.SymCryptMlDsaVectorINTT(pvcs1);
            prim.SymCryptMlDsaVectorINTT(pvcs2);

            prim.SymCryptMlDsaVectorINTT(pvMask);
            prim.SymCryptMlDsaVectorAdd(pvMask, pvcs1, pvResponse);

            prim.SymCryptMlDsaVectorSub(pvW, pvcs2, pvW);
        }

        {
            const pvr0: PSYMCRYPT_MLDSA_VECTOR = pTemps.pvRowVectors.?[1];
            prim.SymCryptMlDsaVectorLowBits(pParams, pvW, pvr0);

            const zInfinityNorm = prim.SymCryptMlDsaVectorInfinityNorm(pvResponse);
            const r0InfinityNorm = prim.SymCryptMlDsaVectorInfinityNorm(pvr0);

            if (zInfinityNorm >= zNormBound or r0InfinityNorm >= r0NormBound) {
                continue;
            }
        }

        {
            const pvct0: PSYMCRYPT_MLDSA_VECTOR = pTemps.pvRowVectors.?[1];

            prim.SymCryptMlDsaVectorPolyElementMontMul(pkMlDsakey.pvt0, peC, pvct0);
            prim.SymCryptMlDsaVectorINTT(pvct0);

            const ct0InfinityNorm = prim.SymCryptMlDsaVectorInfinityNorm(pvct0);
            if (ct0InfinityNorm >= pParams.commitmentRoundingRange) {
                continue;
            }

            prim.SymCryptMlDsaVectorAdd(pvct0, pvW, pvct0);

            var nHintBitsSet: UINT32 = 0;
            prim.SymCryptMlDsaMakeHint(pParams, pvW, pvct0, pvct0, &nHintBitsSet);

            if (nHintBitsSet > pParams.nHintNonZeroCoeffs) {
                continue;
            }
        }

        pvHint = pTemps.pvRowVectors.?[1];
        break;
    }

    if (pvHint == null) {
        return .SYMCRYPT_EXTERNAL_FAILURE;
    }

    prim.SymCryptMlDsaSigEncode(
        pParams,
        &commitmentHash,
        pParams.cbCommitmentHash,
        pvResponse,
        pvHint.?,
        pbSignature,
        cbSignature,
    );

    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptMlDsaSign(
    pkMlDsakey: PCSYMCRYPT_MLDSAKEY,
    pbMessage: ?PCBYTE,
    cbMessage: SIZE_T,
    pbContext: ?PCBYTE,
    cbContext: SIZE_T,
    flags: UINT32,
    pbSignature: PBYTE,
    cbSignature: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    if (flags != 0 or
        cbContext > prim.SYMCRYPT_MLDSA_CONTEXT_MAX_LENGTH or
        pkMlDsakey.hasPrivateKey == types.FALSE or
        cbSignature != pkMlDsakey.pParams.cbEncodedSignature)
    {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    var random: [prim.SYMCRYPT_MLDSA_SIGNING_RANDOM_SIZE]BYTE = undefined;
    defer libmain.SymCryptWipe(@ptrCast(&random), random.len);

    const scError = SymCryptCallbackRandom(&random, random.len);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    return SymCryptMlDsaSignEx(
        pkMlDsakey,
        pbMessage,
        cbMessage,
        pbContext,
        cbContext,
        null,
        0,
        &random,
        random.len,
        flags,
        pbSignature,
        cbSignature,
    );
}

pub export fn SymCryptExternalMuMlDsaSign(
    pkMlDsakey: PCSYMCRYPT_MLDSAKEY,
    pbMu: ?PCBYTE,
    cbMu: SIZE_T,
    flags: UINT32,
    pbSignature: PBYTE,
    cbSignature: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    if (flags != 0 or
        pkMlDsakey.hasPrivateKey == types.FALSE or
        cbMu != shake.SYMCRYPT_SHAKE256_RESULT_SIZE or
        cbSignature != pkMlDsakey.pParams.cbEncodedSignature)
    {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    var random: [prim.SYMCRYPT_MLDSA_SIGNING_RANDOM_SIZE]BYTE = undefined;
    defer libmain.SymCryptWipe(@ptrCast(&random), random.len);

    const scError = SymCryptCallbackRandom(&random, random.len);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    return SymCryptMlDsaSignEx(
        pkMlDsakey,
        pbMu,
        cbMu,
        null,
        0,
        null,
        0,
        &random,
        random.len,
        prim.SYMCRYPT_FLAG_MLDSA_EXTERNALMU,
        pbSignature,
        cbSignature,
    );
}

pub export fn SymCryptHashMlDsaSign(
    pkMlDsakey: PCSYMCRYPT_MLDSAKEY,
    hashAlg: SYMCRYPT_PQDSA_HASH_ID,
    pbHash: ?PCBYTE,
    cbHash: SIZE_T,
    pbContext: ?PCBYTE,
    cbContext: SIZE_T,
    flags: UINT32,
    pbSignature: PBYTE,
    cbSignature: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    if (flags != 0 or
        cbContext > prim.SYMCRYPT_MLDSA_CONTEXT_MAX_LENGTH or
        pkMlDsakey.hasPrivateKey == types.FALSE or
        cbSignature != pkMlDsakey.pParams.cbEncodedSignature)
    {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    var random: [prim.SYMCRYPT_MLDSA_SIGNING_RANDOM_SIZE]BYTE = undefined;
    defer libmain.SymCryptWipe(@ptrCast(&random), random.len);

    var scError = SymCryptCallbackRandom(&random, random.len);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    var pHashOid: PCSYMCRYPT_OID = undefined;
    scError = prim.SymCryptHashMlDsaValidateHashAlgAndGetOid(hashAlg, cbHash, &pHashOid);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    return SymCryptMlDsaSignEx(
        pkMlDsakey,
        pbHash,
        cbHash,
        pbContext,
        cbContext,
        pHashOid.pbOID,
        pHashOid.cbOID,
        &random,
        random.len,
        flags,
        pbSignature,
        cbSignature,
    );
}

pub export fn SymCryptMlDsaVerifyEx(
    pkMlDsakey: PCSYMCRYPT_MLDSAKEY,
    pbInput: ?PCBYTE,
    cbInput: SIZE_T,
    pbContext: ?PCBYTE,
    cbContext: SIZE_T,
    pbHashOid: ?PCBYTE,
    cbHashOid: SIZE_T,
    pbSignature: PCBYTE,
    cbSignature: SIZE_T,
    flags: UINT32,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    macros.ASSERT(cbContext <= prim.SYMCRYPT_MLDSA_CONTEXT_MAX_LENGTH);
    macros.ASSERT(pbHashOid != null or cbHashOid == 0);
    macros.ASSERT(pbContext != null or cbContext == 0);
    macros.ASSERT(cbSignature == pkMlDsakey.pParams.cbEncodedSignature);
    macros.ASSERT((flags & ~prim.SYMCRYPT_FLAG_MLDSA_EXTERNALMU) == 0);
    macros.ASSERT(((flags & prim.SYMCRYPT_FLAG_MLDSA_EXTERNALMU) == 0) or (pbContext == null and pbHashOid == null));

    const pParams = pkMlDsakey.pParams;
    const beta: UINT32 = @as(UINT32, pParams.nChallengeNonZeroCoeffs) * @as(UINT32, pParams.privateKeyRange);

    const bExternalMu: bool = (flags & prim.SYMCRYPT_FLAG_MLDSA_EXTERNALMU) != 0;
    const modeIdArr = [1]UINT8{if (pbHashOid == null) 0 else 1};
    const cbContextByteArr = [1]UINT8{@intCast(cbContext)};
    var messageRepresentative: [shake.SYMCRYPT_SHAKE256_RESULT_SIZE]BYTE = undefined;
    var commitmentHash: [64]BYTE = undefined;
    var recalculatedCommitmentHash: [64]BYTE = undefined;

    const cbw1Encoded: UINT32 = @as(UINT32, pParams.nRows) * pParams.w1EncodeCoefficientBitLength *
        (prim.SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS / 8);

    const pTemps = prim.SymCryptMlDsaTemporariesAllocateAndInitialize(
        pParams,
        4,
        1,
        2,
        cbw1Encoded,
    ) orelse return .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
    defer prim.SymCryptMlDsaTemporariesFree(pTemps);

    const pvHint: PSYMCRYPT_MLDSA_VECTOR = pTemps.pvRowVectors.?[0];
    const pvATimesNTTz: PSYMCRYPT_MLDSA_VECTOR = pTemps.pvRowVectors.?[1];
    const pvT1Times2D: PSYMCRYPT_MLDSA_VECTOR = pTemps.pvRowVectors.?[2];
    const pvCommitment: PSYMCRYPT_MLDSA_VECTOR = pTemps.pvRowVectors.?[3];

    const pvResponse: PSYMCRYPT_MLDSA_VECTOR = pTemps.pvColVectors.?[0];

    const peC: PSYMCRYPT_MLDSA_POLYELEMENT = pTemps.pePolyElements.?[0];
    const peTmp: PSYMCRYPT_MLDSA_POLYELEMENT = pTemps.pePolyElements.?[1];

    const pbw1Encoded: PBYTE = pTemps.pbScratch.?;

    var scError = prim.SymCryptMlDsaSigDecode(
        pParams,
        pbSignature,
        cbSignature,
        &commitmentHash,
        pParams.cbCommitmentHash,
        pvResponse,
        pvHint,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    const responseInfinityNorm = prim.SymCryptMlDsaVectorInfinityNorm(pvResponse);
    const shiftMaskRange: u5 = @intCast(pParams.maskCoefficientRangeLog2);
    if (responseInfinityNorm >= (@as(UINT32, 1) << shiftMaskRange) - beta) {
        return .SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE;
    }

    scError = prim.SymCryptMlDsaSampleInBall(
        pParams,
        &commitmentHash,
        pParams.cbCommitmentHash,
        peC,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    prim.SymCryptMlDsaVectorNTT(pvResponse);

    for (0..pvResponse.nElems) |i| {
        prim.SymCryptMlDsaPolyElementMulR(prim.vectorElement(i, pvResponse));
    }

    prim.SymCryptMlDsaMatrixVectorMontMul(
        pkMlDsakey.pmA,
        pvResponse,
        pvATimesNTTz,
        peTmp,
    );

    const pow2DTimesR: UINT32 = 4214781;
    for (0..pkMlDsakey.pvt1.nElems) |i| {
        const peSrc = prim.vectorElementConst(i, pkMlDsakey.pvt1);
        const peDst = prim.vectorElement(i, pvT1Times2D);
        for (0..prim.SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS) |j| {
            peDst.coeffs[j] = prim.SymCryptMlDsaMontMul(peSrc.coeffs[j], pow2DTimesR);
        }
    }

    prim.SymCryptMlDsaPolyElementNTT(peC);
    prim.SymCryptMlDsaPolyElementMulR(peC);

    prim.SymCryptMlDsaVectorPolyElementMontMul(pvT1Times2D, peC, pvT1Times2D);
    prim.SymCryptMlDsaVectorSub(pvATimesNTTz, pvT1Times2D, pvCommitment);
    prim.SymCryptMlDsaVectorINTT(pvCommitment);
    prim.SymCryptMlDsaUseHint(pParams, pvHint, pvCommitment);

    prim.SymCryptMlDsaVectorEncode(
        pvCommitment,
        pParams.w1EncodeCoefficientBitLength,
        0,
        pbw1Encoded,
    );

    const pShakeState = &pTemps.shake256State;
    shake.SymCryptShake256Init(pShakeState);

    if (bExternalMu) {
        macros.ASSERT(cbInput == shake.SYMCRYPT_SHAKE256_RESULT_SIZE);
        @memcpy(&messageRepresentative, pbInput.?[0..shake.SYMCRYPT_SHAKE256_RESULT_SIZE]);
    } else {
        shake.SymCryptShake256Append(pShakeState, &pkMlDsakey.publicKeyHash, pkMlDsakey.publicKeyHash.len);
        shake.SymCryptShake256Append(pShakeState, &modeIdArr, 1);
        shake.SymCryptShake256Append(pShakeState, &cbContextByteArr, 1);

        if (cbContext > 0) {
            shake.SymCryptShake256Append(pShakeState, pbContext.?, cbContext);
        }
        if (cbHashOid > 0) {
            shake.SymCryptShake256Append(pShakeState, pbHashOid.?, cbHashOid);
        }
        if (cbInput > 0) {
            shake.SymCryptShake256Append(pShakeState, pbInput.?, cbInput);
        }
        shake.SymCryptShake256Result(pShakeState, &messageRepresentative);
    }

    shake.SymCryptShake256Append(pShakeState, &messageRepresentative, messageRepresentative.len);
    shake.SymCryptShake256Append(pShakeState, pbw1Encoded, cbw1Encoded);
    shake.SymCryptShake256Extract(pShakeState, &recalculatedCommitmentHash, pParams.cbCommitmentHash, types.TRUE);

    if (equal.SymCryptEqual(&recalculatedCommitmentHash, &commitmentHash, pParams.cbCommitmentHash) == types.FALSE) {
        return .SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE;
    }

    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptMlDsaVerify(
    pkMlDsakey: PCSYMCRYPT_MLDSAKEY,
    pbMessage: ?PCBYTE,
    cbMessage: SIZE_T,
    pbContext: ?PCBYTE,
    cbContext: SIZE_T,
    pbSignature: PCBYTE,
    cbSignature: SIZE_T,
    flags: UINT32,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    if (flags != 0 or
        cbContext > prim.SYMCRYPT_MLDSA_CONTEXT_MAX_LENGTH or
        cbSignature != pkMlDsakey.pParams.cbEncodedSignature)
    {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    return SymCryptMlDsaVerifyEx(
        pkMlDsakey,
        pbMessage,
        cbMessage,
        pbContext,
        cbContext,
        null,
        0,
        pbSignature,
        cbSignature,
        flags,
    );
}

pub export fn SymCryptExternalMuMlDsaVerify(
    pkMlDsakey: PCSYMCRYPT_MLDSAKEY,
    pbMu: ?PCBYTE,
    cbMu: SIZE_T,
    pbSignature: PCBYTE,
    cbSignature: SIZE_T,
    flags: UINT32,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    if (flags != 0 or
        cbMu != shake.SYMCRYPT_SHAKE256_RESULT_SIZE or
        cbSignature != pkMlDsakey.pParams.cbEncodedSignature)
    {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    return SymCryptMlDsaVerifyEx(
        pkMlDsakey,
        pbMu,
        cbMu,
        null,
        0,
        null,
        0,
        pbSignature,
        cbSignature,
        prim.SYMCRYPT_FLAG_MLDSA_EXTERNALMU,
    );
}

pub export fn SymCryptHashMlDsaVerify(
    pkMlDsakey: PCSYMCRYPT_MLDSAKEY,
    hashAlg: SYMCRYPT_PQDSA_HASH_ID,
    pbHash: ?PCBYTE,
    cbHash: SIZE_T,
    pbContext: ?PCBYTE,
    cbContext: SIZE_T,
    pbSignature: PCBYTE,
    cbSignature: SIZE_T,
    flags: UINT32,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    if (flags != 0 or
        cbContext > prim.SYMCRYPT_MLDSA_CONTEXT_MAX_LENGTH or
        cbSignature != pkMlDsakey.pParams.cbEncodedSignature)
    {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    var pHashOid: PCSYMCRYPT_OID = undefined;
    const scError = prim.SymCryptHashMlDsaValidateHashAlgAndGetOid(hashAlg, cbHash, &pHashOid);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    return SymCryptMlDsaVerifyEx(
        pkMlDsakey,
        pbHash,
        cbHash,
        pbContext,
        cbContext,
        pHashOid.pbOID,
        pHashOid.cbOID,
        pbSignature,
        cbSignature,
        flags,
    );
}
