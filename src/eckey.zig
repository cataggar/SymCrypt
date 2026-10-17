//
// eckey.zig   Functions for the ECKEY object
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

const types = @import("types.zig");
const macros = @import("macros.zig");
const a_dispatch = @import("a_dispatch.zig");
const aes_ctr_drbg = @import("aes_ctr_drbg.zig");
const fips_selftest = @import("fips_selftest.zig");
const ecurve = @import("ecurve.zig");
const ecpoint = @import("ecpoint.zig");
const ec_dispatch = @import("ec_dispatch.zig");

extern fn SymCryptCallbackAlloc(cbData: SIZE_T) callconv(SYMCRYPT_CALL) ?PBYTE;
extern fn SymCryptCallbackFree(pMem: *anyopaque) callconv(SYMCRYPT_CALL) void;

const BYTE = types.BYTE;
const PBYTE = types.PBYTE;
const PCBYTE = types.PCBYTE;
const UINT32 = types.UINT32;
const INT32 = types.INT32;
const SIZE_T = types.SIZE_T;
const BOOLEAN = types.BOOLEAN;
const SYMCRYPT_CALL = types.SYMCRYPT_CALL;
const SYMCRYPT_ERROR = types.SYMCRYPT_ERROR;
const SYMCRYPT_NUMBER_FORMAT = types.SYMCRYPT_NUMBER_FORMAT;
const SYMCRYPT_ECPOINT_FORMAT = types.SYMCRYPT_ECPOINT_FORMAT;
const SYMCRYPT_ECURVE = types.SYMCRYPT_ECURVE;
const PCSYMCRYPT_ECURVE = types.PCSYMCRYPT_ECURVE;
const SYMCRYPT_ECPOINT = types.SYMCRYPT_ECPOINT;
const PSYMCRYPT_ECPOINT = types.PSYMCRYPT_ECPOINT;
const SYMCRYPT_ECKEY = types.SYMCRYPT_ECKEY;
const PSYMCRYPT_ECKEY = types.PSYMCRYPT_ECKEY;
const PCSYMCRYPT_ECKEY = types.PCSYMCRYPT_ECKEY;
const PSYMCRYPT_INT = types.PSYMCRYPT_INT;
const PSYMCRYPT_MODELEMENT = types.PSYMCRYPT_MODELEMENT;
const SYMCRYPT_RNG_AES_STATE = types.SYMCRYPT_RNG_AES_STATE;

const SYMCRYPT_FLAG_ECKEY_PUBLIC_KEY_ORDER_VALIDATION: UINT32 = 0x1;
const SYMCRYPT_ECPOINT_SET_RANDOM_MAX_TRIES: INT32 = 1000;
const SYMCRYPT_ECKEY_DERIVE_MAX_TRIES: UINT32 = 256;
const SYMCRYPT_ECKEY_DERIVE_P521_SCALAR_SIZE: UINT32 = 66;
const SYMCRYPT_ECKEY_DERIVE_MAX_PRIVATE_KEY_SIZE: usize = SYMCRYPT_ECKEY_DERIVE_P521_SCALAR_SIZE;

pub export fn SymCryptEckeyAllocate(pCurve: PCSYMCRYPT_ECURVE) callconv(SYMCRYPT_CALL) ?PSYMCRYPT_ECKEY {
    @setRuntimeSafety(false);
    const cb: SIZE_T = SymCryptSizeofEckeyFromCurve(pCurve);
    const p = SymCryptCallbackAlloc(cb) orelse return null;
    return SymCryptEckeyCreate(@ptrCast(p), cb, pCurve);
}

pub export fn SymCryptEckeyFree(pkObj: PSYMCRYPT_ECKEY) callconv(SYMCRYPT_CALL) void {
    @setRuntimeSafety(false);
    macros.SYMCRYPT_CHECK_MAGIC(pkObj);
    SymCryptEckeyWipe(pkObj);
    SymCryptCallbackFree(pkObj);
}

pub export fn SymCryptSizeofEckeyFromCurve(pCurve: PCSYMCRYPT_ECURVE) callconv(SYMCRYPT_CALL) UINT32 {
    @setRuntimeSafety(false);
    return @as(UINT32, @sizeOf(SYMCRYPT_ECKEY)) +
        ecpoint.SymCryptSizeofEcpointFromCurve(pCurve) +
        a_dispatch.SymCryptSizeofIntFromDigits(ecurve.SymCryptEcurveDigitsofScalarMultiplier(pCurve));
}

pub export fn SymCryptEckeyCreate(
    pbBuffer: PBYTE,
    cbBuffer: SIZE_T,
    pCurve: PCSYMCRYPT_ECURVE,
) callconv(SYMCRYPT_CALL) ?PSYMCRYPT_ECKEY {
    @setRuntimeSafety(false);
    const privateKeyDigits: UINT32 = ecurve.SymCryptEcurveDigitsofScalarMultiplier(pCurve);
    const cbPublicKey: SIZE_T = ecpoint.SymCryptSizeofEcpointFromCurve(pCurve);
    const cbPrivateKey: SIZE_T = a_dispatch.SymCryptSizeofIntFromDigits(privateKeyDigits);

    macros.SYMCRYPT_ASSERT(cbBuffer >= SymCryptSizeofEckeyFromCurve(pCurve));
    macros.SYMCRYPT_ASSERT(cbBuffer >= @sizeOf(SYMCRYPT_ECKEY) + cbPublicKey + cbPrivateKey);
    macros.SYMCRYPT_ASSERT_ASYM_ALIGNED(pbBuffer);

    const pkObj: PSYMCRYPT_ECKEY = @ptrCast(@alignCast(pbBuffer));

    pkObj.fAlgorithmInfo = 0;
    pkObj.hasPrivateKey = types.FALSE;
    pkObj.pCurve = pCurve;

    pkObj.poPublicKey = ecpoint.SymCryptEcpointCreate(
        pbBuffer + @sizeOf(SYMCRYPT_ECKEY),
        cbPublicKey,
        pCurve,
    ).?;

    pkObj.piPrivateKey = a_dispatch.SymCryptIntCreate(
        pbBuffer + @sizeOf(SYMCRYPT_ECKEY) + cbPublicKey,
        cbPrivateKey,
        privateKeyDigits,
    ).?;

    macros.SYMCRYPT_SET_MAGIC(pkObj);

    return pkObj;
}

pub export fn SymCryptEckeyWipePrivateState(pkEckey: PSYMCRYPT_ECKEY) callconv(SYMCRYPT_CALL) void {
    @setRuntimeSafety(false);
    a_dispatch.SymCryptIntSetValueUint32(0, pkEckey.piPrivateKey);
    pkEckey.hasPrivateKey = types.FALSE;
}

pub export fn SymCryptEckeyWipe(pkDst: PSYMCRYPT_ECKEY) callconv(SYMCRYPT_CALL) void {
    @setRuntimeSafety(false);
    macros.SymCryptWipe(pkDst, SymCryptSizeofEckeyFromCurve(pkDst.pCurve));
}

pub export fn SymCryptEckeyCopy(
    pkSrc: PCSYMCRYPT_ECKEY,
    pkDst: PSYMCRYPT_ECKEY,
) callconv(.c) void {
    @setRuntimeSafety(false);
    if (@intFromPtr(pkSrc) != @intFromPtr(pkDst)) {
        pkDst.fAlgorithmInfo = pkSrc.fAlgorithmInfo;
        pkDst.hasPrivateKey = pkSrc.hasPrivateKey;
        ecpoint.SymCryptEcpointCopy(pkSrc.pCurve, pkSrc.poPublicKey, pkDst.poPublicKey);
        a_dispatch.SymCryptIntCopy(pkSrc.piPrivateKey, pkDst.piPrivateKey);
    }
}

pub export fn SymCryptEckeySizeofPublicKey(
    pkEckey: PCSYMCRYPT_ECKEY,
    ecPointFormat: SYMCRYPT_ECPOINT_FORMAT,
) callconv(SYMCRYPT_CALL) UINT32 {
    @setRuntimeSafety(false);
    const fmt_idx: usize = @intCast(@as(UINT32, @bitCast(@backingInt(ecPointFormat))));
    return ecpoint.SymCryptEcpointFormatNumberofElements[fmt_idx] *
        ecurve.SymCryptEcurveSizeofFieldElement(pkEckey.pCurve);
}

pub export fn SymCryptEckeySizeofPrivateKey(pkEckey: PCSYMCRYPT_ECKEY) callconv(SYMCRYPT_CALL) UINT32 {
    @setRuntimeSafety(false);
    return ecurve.SymCryptEcurveSizeofScalarMultiplier(pkEckey.pCurve);
}

pub export fn SymCryptEckeyHasPrivateKey(pkEckey: PCSYMCRYPT_ECKEY) callconv(SYMCRYPT_CALL) BOOLEAN {
    @setRuntimeSafety(false);
    return pkEckey.hasPrivateKey;
}

pub export fn SymCryptEckeyPerformPublicKeyValidation(
    pEckey: PCSYMCRYPT_ECKEY,
    flags: UINT32,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    @setRuntimeSafety(false);
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;
    const pCurve: PCSYMCRYPT_ECURVE = pEckey.pCurve;
    const cbNPub: UINT32 = ecpoint.SymCryptSizeofEcpointFromCurve(pCurve);

    var pbScratchCur: PBYTE = pbScratch;
    var cbScratchCur: SIZE_T = cbScratch;

    macros.SYMCRYPT_ASSERT(cbScratchCur >= types.SYMCRYPT_INTERNAL_SCRATCH_BYTES_FOR_ECKEY_ECURVE_OPERATIONS(pCurve));
    macros.SYMCRYPT_ASSERT(cbScratchCur >= cbNPub);

    if (ec_dispatch.SymCryptEcpointIsZero(pCurve, pEckey.poPublicKey, pbScratchCur, cbScratchCur) != 0) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    if (!types.SYMCRYPT_CURVE_IS_MONTGOMERY_TYPE(pCurve) and
        ec_dispatch.SymCryptEcpointOnCurve(pCurve, pEckey.poPublicKey, pbScratchCur, cbScratchCur) == 0)
    {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    if ((flags & SYMCRYPT_FLAG_ECKEY_PUBLIC_KEY_ORDER_VALIDATION) != 0) {
        if (a_dispatch.SymCryptIntIsEqualUint32(pCurve.H, 1) == 0) {
            const poNPub = ecpoint.SymCryptEcpointCreate(pbScratchCur, cbNPub, pCurve).?;
            pbScratchCur += cbNPub;
            cbScratchCur -= cbNPub;

            scError = ec_dispatch.SymCryptEcpointScalarMul(
                pCurve,
                a_dispatch.SymCryptIntFromModulus(pCurve.GOrd),
                pEckey.poPublicKey,
                0,
                poNPub,
                pbScratchCur,
                cbScratchCur,
            );
            if (scError != .SYMCRYPT_NO_ERROR) {
                return scError;
            }

            if (ec_dispatch.SymCryptEcpointIsZero(pCurve, poNPub, pbScratchCur, cbScratchCur) == 0) {
                return .SYMCRYPT_INVALID_ARGUMENT;
            }
        }
    }

    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptEckeySetValue(
    pbPrivateKey: ?PCBYTE,
    cbPrivateKey: SIZE_T,
    pbPublicKey: ?PCBYTE,
    cbPublicKey: SIZE_T,
    numFormat: SYMCRYPT_NUMBER_FORMAT,
    ecPointFormat: SYMCRYPT_ECPOINT_FORMAT,
    flags: UINT32,
    pEckey: PSYMCRYPT_ECKEY,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    @setRuntimeSafety(false);
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;
    var pbScratch: ?PBYTE = null;
    var cbScratch: UINT32 = 0;
    var pbScratchInternal: PBYTE = undefined;
    var cbScratchInternal: UINT32 = 0;

    const pCurve: PCSYMCRYPT_ECURVE = pEckey.pCurve;
    const cbTmpModElement: UINT32 = pCurve.cbModElement;
    const privateKeyDigits: UINT32 = ecurve.SymCryptEcurveDigitsofScalarMultiplier(pCurve);

    var fValidatePublicKeyOrder: UINT32 = SYMCRYPT_FLAG_ECKEY_PUBLIC_KEY_ORDER_VALIDATION;

    const algorithmFlags: UINT32 = types.SYMCRYPT_FLAG_ECKEY_ECDSA | types.SYMCRYPT_FLAG_ECKEY_ECDH;
    const allowedFlags: UINT32 = fips_selftest.SYMCRYPT_FLAG_KEY_NO_FIPS | fips_selftest.SYMCRYPT_FLAG_KEY_MINIMAL_VALIDATION | algorithmFlags;

    defer {
        if (pbScratch) |ptr| {
            macros.SymCryptWipe(ptr, cbScratch);
            SymCryptCallbackFree(@ptrCast(ptr));
        }
    }

    if (((flags & ~allowedFlags) != 0) or ((flags & algorithmFlags) == 0)) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    if (((flags & fips_selftest.SYMCRYPT_FLAG_KEY_NO_FIPS) == 0) and
        ((flags & fips_selftest.SYMCRYPT_FLAG_KEY_MINIMAL_VALIDATION) != 0))
    {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    if ((flags & fips_selftest.SYMCRYPT_FLAG_KEY_NO_FIPS) != 0) {
        fValidatePublicKeyOrder = 0;
    }

    if (((cbPrivateKey == 0) and (cbPublicKey == 0)) or
        ((cbPrivateKey != 0) and (cbPrivateKey != ecurve.SymCryptEcurveSizeofScalarMultiplier(pEckey.pCurve))) or
        ((cbPublicKey != 0) and (cbPublicKey != SymCryptEckeySizeofPublicKey(pEckey, ecPointFormat))))
    {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    cbScratch = types.SYMCRYPT_INTERNAL_SCRATCH_BYTES_FOR_ECKEY_ECURVE_OPERATIONS(pCurve);
    const allocPtr = SymCryptCallbackAlloc(cbScratch) orelse {
        return .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
    };
    pbScratch = @ptrCast(allocPtr);

    if (pbPrivateKey) |privKeyPtr| {
        pbScratchInternal = pbScratch.?;
        cbScratchInternal = cbScratch;

        const cbTmpInteger: UINT32 = a_dispatch.SymCryptSizeofIntFromDigits(privateKeyDigits);
        const piTmpInteger: PSYMCRYPT_INT = a_dispatch.SymCryptIntCreate(pbScratchInternal, cbTmpInteger, privateKeyDigits).?;
        pbScratchInternal += cbTmpInteger;
        cbScratchInternal -= cbTmpInteger;

        const peTmpModElement: PSYMCRYPT_MODELEMENT = a_dispatch.SymCryptModElementCreate(pbScratchInternal, cbTmpModElement, pCurve.GOrd).?;
        pbScratchInternal += cbTmpModElement;
        cbScratchInternal -= cbTmpModElement;

        scError = a_dispatch.SymCryptIntSetValue(privKeyPtr, cbPrivateKey, numFormat, piTmpInteger);
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }

        if ((flags & fips_selftest.SYMCRYPT_FLAG_KEY_MINIMAL_VALIDATION) == 0) {
            if (pCurve.PrivateKeyDefaultFormat == types.SYMCRYPT_ECKEY_PRIVATE_FORMAT_CANONICAL) {
                if (a_dispatch.SymCryptIntIsLessThan(piTmpInteger, a_dispatch.SymCryptIntFromModulus(pCurve.GOrd)) == 0) {
                    return .SYMCRYPT_INVALID_ARGUMENT;
                }
            }

            if ((pCurve.coFactorPower > 0) and
                (pCurve.PrivateKeyDefaultFormat == types.SYMCRYPT_ECKEY_PRIVATE_FORMAT_DIVH_TIMESH) and
                (a_dispatch.SymCryptIntGetBits(piTmpInteger, 0, pCurve.coFactorPower) != 0))
            {
                return .SYMCRYPT_INVALID_ARGUMENT;
            }

            if ((pCurve.HighBitRestrictionNumOfBits > 0) and
                (a_dispatch.SymCryptIntGetBits(
                    piTmpInteger,
                    pCurve.HighBitRestrictionPosition,
                    pCurve.HighBitRestrictionNumOfBits,
                ) != pCurve.HighBitRestrictionValue))
            {
                return .SYMCRYPT_INVALID_ARGUMENT;
            }
        }

        if (pCurve.coFactorPower > 0) {
            if (pCurve.PrivateKeyDefaultFormat == types.SYMCRYPT_ECKEY_PRIVATE_FORMAT_DIVH_TIMESH) {
                a_dispatch.SymCryptIntDivPow2(piTmpInteger, pCurve.coFactorPower, piTmpInteger);
            }

            if (pCurve.PrivateKeyDefaultFormat == types.SYMCRYPT_ECKEY_PRIVATE_FORMAT_CANONICAL) {
                a_dispatch.SymCryptIntToModElement(piTmpInteger, pCurve.GOrd, peTmpModElement, pbScratchInternal, cbScratchInternal);
                a_dispatch.SymCryptModDivPow2(pCurve.GOrd, peTmpModElement, pCurve.coFactorPower, peTmpModElement, pbScratchInternal, cbScratchInternal);
                a_dispatch.SymCryptModElementToInt(pCurve.GOrd, peTmpModElement, piTmpInteger, pbScratchInternal, cbScratchInternal);
            }
        }

        a_dispatch.SymCryptIntDivMod(
            piTmpInteger,
            a_dispatch.SymCryptDivisorFromModulus(pCurve.GOrd),
            null,
            piTmpInteger,
            pbScratchInternal,
            cbScratchInternal,
        );

        if (a_dispatch.SymCryptIntIsEqualUint32(piTmpInteger, 0) != 0) {
            return .SYMCRYPT_INVALID_ARGUMENT;
        }

        a_dispatch.SymCryptIntCopy(piTmpInteger, pEckey.piPrivateKey);
        pEckey.hasPrivateKey = types.TRUE;
    }

    if (pbPublicKey) |pubKeyPtr| {
        scError = ecpoint.SymCryptEcpointSetValue(
            pCurve,
            pubKeyPtr,
            cbPublicKey,
            numFormat,
            ecPointFormat,
            pEckey.poPublicKey,
            types.SYMCRYPT_FLAG_DATA_PUBLIC,
            pbScratch.?,
            cbScratch,
        );
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }

        if ((flags & fips_selftest.SYMCRYPT_FLAG_KEY_MINIMAL_VALIDATION) == 0) {
            scError = SymCryptEckeyPerformPublicKeyValidation(
                pEckey,
                fValidatePublicKeyOrder,
                pbScratch.?,
                cbScratch,
            );
            if (scError != .SYMCRYPT_NO_ERROR) {
                return scError;
            }
        }
    }

    if ((pbPublicKey == null) or
        (((flags & fips_selftest.SYMCRYPT_FLAG_KEY_NO_FIPS) == 0) and
            (pbPrivateKey != null) and (pbPublicKey != null)))
    {
        pbScratchInternal = pbScratch.?;
        cbScratchInternal = cbScratch;

        var poTmp: PSYMCRYPT_ECPOINT = pEckey.poPublicKey;

        if (pbPublicKey != null) {
            const cbTmp: UINT32 = ecpoint.SymCryptSizeofEcpointFromCurve(pCurve);
            poTmp = ecpoint.SymCryptEcpointCreate(pbScratchInternal, cbTmp, pCurve).?;
            pbScratchInternal += cbTmp;
            cbScratchInternal -= cbTmp;
        }

        scError = ec_dispatch.SymCryptEcpointScalarMul(
            pCurve,
            pEckey.piPrivateKey,
            null,
            types.SYMCRYPT_FLAG_ECC_LL_COFACTOR_MUL,
            poTmp,
            pbScratchInternal,
            cbScratchInternal,
        );
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }

        if (pbPublicKey != null) {
            if (ec_dispatch.SymCryptEcpointIsEqual(pCurve, poTmp, pEckey.poPublicKey, 0, pbScratchInternal, cbScratchInternal) == 0) {
                return .SYMCRYPT_INVALID_ARGUMENT;
            }
        } else if ((flags & fips_selftest.SYMCRYPT_FLAG_KEY_MINIMAL_VALIDATION) == 0) {
            scError = SymCryptEckeyPerformPublicKeyValidation(
                pEckey,
                fValidatePublicKeyOrder,
                pbScratch.?,
                cbScratch,
            );
            if (scError != .SYMCRYPT_NO_ERROR) {
                return scError;
            }
        }
    }

    pEckey.fAlgorithmInfo = flags;

    if ((flags & fips_selftest.SYMCRYPT_FLAG_KEY_NO_FIPS) == 0) {
        if ((flags & types.SYMCRYPT_FLAG_ECKEY_ECDSA) != 0) {
            fips_selftest.SYMCRYPT_RUN_SELFTEST_ONCE(
                fips_selftest.SymCryptEcDsaSelftest,
                fips_selftest.SYMCRYPT_SELFTEST_ALGORITHM_ECDSA,
            );
            pEckey.fAlgorithmInfo |= fips_selftest.SYMCRYPT_PCT_ECDSA;
        }

        if ((flags & types.SYMCRYPT_FLAG_ECKEY_ECDH) != 0) {
            fips_selftest.SYMCRYPT_RUN_SELFTEST_ONCE(
                fips_selftest.SymCryptEcDhSecretAgreementSelftest,
                fips_selftest.SYMCRYPT_SELFTEST_ALGORITHM_ECDH,
            );
        }
    }

    return scError;
}

pub export fn SymCryptEckeyGetValue(
    pEckey: PCSYMCRYPT_ECKEY,
    pbPrivateKey: ?PBYTE,
    cbPrivateKey: SIZE_T,
    pbPublicKey: ?PBYTE,
    cbPublicKey: SIZE_T,
    numFormat: SYMCRYPT_NUMBER_FORMAT,
    ecPointFormat: SYMCRYPT_ECPOINT_FORMAT,
    flags: UINT32,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    @setRuntimeSafety(false);
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;
    var pbScratch: ?PBYTE = null;
    var cbScratch: UINT32 = 0;

    const pCurve: PCSYMCRYPT_ECURVE = pEckey.pCurve;
    const cbTmpModElement: UINT32 = pCurve.cbModElement;
    const privateKeyDigits: UINT32 = ecurve.SymCryptEcurveDigitsofScalarMultiplier(pCurve);

    macros.SYMCRYPT_ASSERT((cbPrivateKey == 0) or (cbPrivateKey == ecurve.SymCryptEcurveSizeofScalarMultiplier(pEckey.pCurve)));
    macros.SYMCRYPT_ASSERT((cbPublicKey == 0) or (cbPublicKey == SymCryptEckeySizeofPublicKey(pEckey, ecPointFormat)));

    defer {
        if (pbScratch) |ptr| {
            macros.SymCryptWipe(ptr, cbScratch);
            SymCryptCallbackFree(@ptrCast(ptr));
        }
    }

    if (flags != 0) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    cbScratch = types.SYMCRYPT_INTERNAL_SCRATCH_BYTES_FOR_ECKEY_ECURVE_OPERATIONS(pCurve);
    const allocPtr = SymCryptCallbackAlloc(cbScratch) orelse {
        return .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
    };
    pbScratch = @ptrCast(allocPtr);

    var pbScratchInternal: PBYTE = pbScratch.?;
    var cbScratchInternal: UINT32 = cbScratch;

    const cbTmpInteger: UINT32 = a_dispatch.SymCryptSizeofIntFromDigits(privateKeyDigits);
    const piTmpInteger: PSYMCRYPT_INT = a_dispatch.SymCryptIntCreate(pbScratchInternal, cbTmpInteger, privateKeyDigits).?;
    pbScratchInternal += cbTmpInteger;
    cbScratchInternal -= cbTmpInteger;

    _ = a_dispatch.SymCryptModElementCreate(pbScratchInternal, cbTmpModElement, pCurve.GOrd).?;
    pbScratchInternal += cbTmpModElement;
    cbScratchInternal -= cbTmpModElement;

    if ((cbPrivateKey == 0) and (cbPublicKey == 0)) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    if (cbPrivateKey != 0) {
        if (pEckey.hasPrivateKey == types.FALSE) {
            return .SYMCRYPT_INVALID_BLOB;
        }

        if (((pEckey.fAlgorithmInfo & types.SYMCRYPT_FLAG_ECKEY_ECDSA) != 0) and
            ((pEckey.fAlgorithmInfo & fips_selftest.SYMCRYPT_FLAG_KEY_NO_FIPS) == 0))
        {
            if ((pEckey.fAlgorithmInfo & (fips_selftest.SYMCRYPT_PCT_ECDSA | fips_selftest.SYMCRYPT_FLAG_KEY_NO_FIPS)) == 0) {
                fips_selftest.SYMCRYPT_FIPS_ASSERT(fips_selftest.SymCryptEcDsaPct(@ptrCast(pEckey)) == .SYMCRYPT_NO_ERROR);
                _ = @atomicRmw(UINT32, &@constCast(pEckey).fAlgorithmInfo, .Or, fips_selftest.SYMCRYPT_PCT_ECDSA, .monotonic);
            }
        }

        a_dispatch.SymCryptIntCopy(pEckey.piPrivateKey, piTmpInteger);

        if (pCurve.coFactorPower > 0) {
            if (pCurve.PrivateKeyDefaultFormat == types.SYMCRYPT_ECKEY_PRIVATE_FORMAT_CANONICAL) {
                a_dispatch.SymCryptIntMulPow2(piTmpInteger, pCurve.coFactorPower, piTmpInteger);
                a_dispatch.SymCryptIntDivMod(
                    piTmpInteger,
                    a_dispatch.SymCryptDivisorFromModulus(pCurve.GOrd),
                    null,
                    piTmpInteger,
                    pbScratchInternal,
                    cbScratchInternal,
                );
            }

            if (pCurve.PrivateKeyDefaultFormat == types.SYMCRYPT_ECKEY_PRIVATE_FORMAT_DIVH_TIMESH) {
                a_dispatch.SymCryptIntMulPow2(piTmpInteger, pCurve.coFactorPower, piTmpInteger);
            }
        }

        scError = a_dispatch.SymCryptIntGetValue(piTmpInteger, pbPrivateKey.?, cbPrivateKey, numFormat);
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }
    }

    if (cbPublicKey != 0) {
        scError = ecpoint.SymCryptEcpointGetValue(
            pCurve,
            pEckey.poPublicKey,
            numFormat,
            ecPointFormat,
            pbPublicKey.?,
            cbPublicKey,
            types.SYMCRYPT_FLAG_DATA_PUBLIC,
            pbScratch.?,
            cbScratch,
        );
    }

    return scError;
}

pub export fn SymCryptEckeySetRandom(
    flags: UINT32,
    pEckey: PSYMCRYPT_ECKEY,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    @setRuntimeSafety(false);
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;
    var pbScratch: ?PBYTE = null;
    var cbScratch: UINT32 = 0;

    const pCurve: PCSYMCRYPT_ECURVE = pEckey.pCurve;
    var cntr: INT32 = SYMCRYPT_ECPOINT_SET_RANDOM_MAX_TRIES;
    var highBitRestrictionPosition: UINT32 = pCurve.HighBitRestrictionPosition;

    const algorithmFlags: UINT32 = types.SYMCRYPT_FLAG_ECKEY_ECDSA | types.SYMCRYPT_FLAG_ECKEY_ECDH;
    const allowedFlags: UINT32 = fips_selftest.SYMCRYPT_FLAG_KEY_NO_FIPS | algorithmFlags;

    defer {
        if (pbScratch) |ptr| {
            macros.SymCryptWipe(ptr, cbScratch);
            SymCryptCallbackFree(@ptrCast(ptr));
        }
    }

    if (((flags & ~allowedFlags) != 0) or ((flags & algorithmFlags) == 0)) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    cbScratch = types.SYMCRYPT_INTERNAL_SCRATCH_BYTES_FOR_ECKEY_ECURVE_OPERATIONS(pCurve);
    const allocPtr = SymCryptCallbackAlloc(cbScratch) orelse {
        return .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
    };
    pbScratch = @ptrCast(allocPtr);

    var pbScratchInternal: PBYTE = pbScratch.?;
    var cbScratchInternal: UINT32 = cbScratch;

    const peScalar: PSYMCRYPT_MODELEMENT = a_dispatch.SymCryptModElementCreate(pbScratchInternal, pCurve.cbModElement, pCurve.GOrd).?;
    pbScratchInternal += pCurve.cbModElement;
    cbScratchInternal -= pCurve.cbModElement;

    const cbScalar: UINT32 = a_dispatch.SymCryptSizeofIntFromDigits(ecurve.SymCryptEcurveDigitsofScalarMultiplier(pCurve));
    const piScalar: PSYMCRYPT_INT = a_dispatch.SymCryptIntCreate(pbScratchInternal, cbScalar, ecurve.SymCryptEcurveDigitsofScalarMultiplier(pCurve)).?;
    pbScratchInternal += cbScalar;
    cbScratchInternal -= cbScalar;

    if (pCurve.PrivateKeyDefaultFormat == types.SYMCRYPT_ECKEY_PRIVATE_FORMAT_DIVH_TIMESH) {
        highBitRestrictionPosition -= pCurve.coFactorPower;
    }

    while (true) {
        a_dispatch.SymCryptModSetRandom(
            pCurve.GOrd,
            peScalar,
            types.SYMCRYPT_FLAG_MODRANDOM_ALLOW_ONE | types.SYMCRYPT_FLAG_MODRANDOM_ALLOW_MINUSONE,
            pbScratchInternal,
            cbScratchInternal,
        );

        if (pCurve.PrivateKeyDefaultFormat == types.SYMCRYPT_ECKEY_PRIVATE_FORMAT_CANONICAL) {
            var i: UINT32 = 0;
            while (i < pCurve.coFactorPower) : (i += 1) {
                a_dispatch.SymCryptModAdd(pCurve.GOrd, peScalar, peScalar, peScalar, pbScratchInternal, cbScratchInternal);
            }
        }

        a_dispatch.SymCryptModElementToInt(pCurve.GOrd, peScalar, piScalar, pbScratchInternal, cbScratchInternal);

        if (pCurve.HighBitRestrictionNumOfBits > 0) {
            a_dispatch.SymCryptIntSetBits(
                piScalar,
                pCurve.HighBitRestrictionValue,
                highBitRestrictionPosition,
                pCurve.HighBitRestrictionNumOfBits,
            );

            if (a_dispatch.SymCryptIntIsLessThan(
                piScalar,
                a_dispatch.SymCryptIntFromModulus(pCurve.GOrd),
            ) != 0) {
                break;
            }
        } else {
            break;
        }

        cntr -= 1;
        if (cntr <= 0) {
            break;
        }
    }

    if (cntr <= 0) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    a_dispatch.SymCryptIntToModElement(piScalar, pCurve.GOrd, peScalar, pbScratchInternal, cbScratchInternal);

    if (pCurve.PrivateKeyDefaultFormat == types.SYMCRYPT_ECKEY_PRIVATE_FORMAT_CANONICAL) {
        a_dispatch.SymCryptModDivPow2(pCurve.GOrd, peScalar, pCurve.coFactorPower, peScalar, pbScratchInternal, cbScratchInternal);
    }

    a_dispatch.SymCryptModElementToInt(pCurve.GOrd, peScalar, pEckey.piPrivateKey, pbScratchInternal, cbScratchInternal);

    scError = ec_dispatch.SymCryptEcpointScalarMul(
        pCurve,
        pEckey.piPrivateKey,
        null,
        types.SYMCRYPT_FLAG_ECC_LL_COFACTOR_MUL,
        pEckey.poPublicKey,
        pbScratch.?,
        cbScratch,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    if ((flags & fips_selftest.SYMCRYPT_FLAG_KEY_NO_FIPS) == 0) {
        scError = SymCryptEckeyPerformPublicKeyValidation(
            pEckey,
            SYMCRYPT_FLAG_ECKEY_PUBLIC_KEY_ORDER_VALIDATION,
            pbScratch.?,
            cbScratch,
        );
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }
    }

    pEckey.hasPrivateKey = types.TRUE;
    pEckey.fAlgorithmInfo = flags;

    if ((flags & fips_selftest.SYMCRYPT_FLAG_KEY_NO_FIPS) == 0) {
        if ((flags & types.SYMCRYPT_FLAG_ECKEY_ECDSA) != 0) {
            fips_selftest.SYMCRYPT_RUN_SELFTEST_ONCE(
                fips_selftest.SymCryptEcDsaSelftest,
                fips_selftest.SYMCRYPT_SELFTEST_ALGORITHM_ECDSA,
            );
        }

        if ((flags & types.SYMCRYPT_FLAG_ECKEY_ECDH) != 0) {
            fips_selftest.SYMCRYPT_RUN_SELFTEST_ONCE(
                fips_selftest.SymCryptEcDhSecretAgreementSelftest,
                fips_selftest.SYMCRYPT_SELFTEST_ALGORITHM_ECDH,
            );

            pbScratchInternal = pbScratch.?;
            cbScratchInternal = cbScratch;

            const cbTmp: UINT32 = ecpoint.SymCryptSizeofEcpointFromCurve(pCurve);
            const poTmp: PSYMCRYPT_ECPOINT = ecpoint.SymCryptEcpointCreate(pbScratchInternal, cbTmp, pCurve).?;
            pbScratchInternal += cbTmp;
            cbScratchInternal -= cbTmp;

            scError = ec_dispatch.SymCryptEcpointScalarMul(
                pCurve,
                pEckey.piPrivateKey,
                null,
                types.SYMCRYPT_FLAG_ECC_LL_COFACTOR_MUL,
                poTmp,
                pbScratchInternal,
                cbScratchInternal,
            );
            if (scError != .SYMCRYPT_NO_ERROR) {
                return scError;
            }

            fips_selftest.SYMCRYPT_FIPS_ASSERT(
                ec_dispatch.SymCryptEcpointIsEqual(pCurve, poTmp, pEckey.poPublicKey, 0, pbScratchInternal, cbScratchInternal) != 0,
            );
        }
    }

    return scError;
}

pub export fn SymCryptEckeyDerive(
    pEckey: PSYMCRYPT_ECKEY,
    pbSeed: ?PCBYTE,
    cbSeed: SIZE_T,
    flags: UINT32,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    @setRuntimeSafety(false);
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;
    const pCurve: PCSYMCRYPT_ECURVE = pEckey.pCurve;
    var rngState: SYMCRYPT_RNG_AES_STATE = undefined;

    const cbScalarSize: UINT32 = ecurve.SymCryptEcurveSizeofScalarMultiplier(pCurve);

    const algorithmFlags: UINT32 = types.SYMCRYPT_FLAG_ECKEY_ECDSA | types.SYMCRYPT_FLAG_ECKEY_ECDH;
    const allowedFlags: UINT32 = fips_selftest.SYMCRYPT_FLAG_KEY_NO_FIPS | algorithmFlags;

    var abCandidate: [SYMCRYPT_ECKEY_DERIVE_MAX_PRIVATE_KEY_SIZE]BYTE = undefined;
    var fFoundValidScalar: BOOLEAN = types.FALSE;

    if ((pbSeed == null) or (cbSeed == 0)) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    if (((flags & ~allowedFlags) != 0) or ((flags & algorithmFlags) == 0)) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    if (pCurve.PrivateKeyDefaultFormat != types.SYMCRYPT_ECKEY_PRIVATE_FORMAT_CANONICAL) {
        return .SYMCRYPT_NOT_IMPLEMENTED;
    }

    if (cbScalarSize > abCandidate.len) {
        return .SYMCRYPT_NOT_IMPLEMENTED;
    }

    defer {
        aes_ctr_drbg.SymCryptRngAesUninstantiate(&rngState);
        macros.SymCryptWipeKnownSize(&abCandidate, @sizeOf(@TypeOf(abCandidate)));
    }

    scError = aes_ctr_drbg.SymCryptRngAesInstantiate(&rngState, pbSeed, cbSeed);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    var counter: UINT32 = 0;
    while (counter < SYMCRYPT_ECKEY_DERIVE_MAX_TRIES) : (counter += 1) {
        aes_ctr_drbg.SymCryptRngAesGenerate(&rngState, &abCandidate, cbScalarSize);

        if (cbScalarSize == SYMCRYPT_ECKEY_DERIVE_P521_SCALAR_SIZE) {
            abCandidate[0] &= 0x01;
        }

        scError = SymCryptEckeySetValue(
            &abCandidate,
            cbScalarSize,
            null,
            0,
            .SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            .SYMCRYPT_ECPOINT_FORMAT_XY,
            flags,
            pEckey,
        );
        if (scError == .SYMCRYPT_NO_ERROR) {
            fFoundValidScalar = types.TRUE;
            break;
        }

        macros.SYMCRYPT_ASSERT(scError == .SYMCRYPT_INVALID_ARGUMENT);
        if (scError != .SYMCRYPT_INVALID_ARGUMENT) {
            return scError;
        }
    }

    if (fFoundValidScalar == types.FALSE) {
        scError = .SYMCRYPT_INVALID_ARGUMENT;
    }

    return scError;
}

pub export fn SymCryptEckeyExtendKeyUsage(
    pEckey: PSYMCRYPT_ECKEY,
    flags: UINT32,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    @setRuntimeSafety(false);
    const algorithmFlags: UINT32 = types.SYMCRYPT_FLAG_ECKEY_ECDSA | types.SYMCRYPT_FLAG_ECKEY_ECDH;

    if (((flags & ~algorithmFlags) != 0) or ((flags & algorithmFlags) == 0)) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    pEckey.fAlgorithmInfo |= flags;

    return .SYMCRYPT_NO_ERROR;
}
