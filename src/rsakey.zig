//
// rsakey.zig   RSA keys' related algorithms
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

const std = @import("std");
const types = @import("types.zig");
const macros = @import("macros.zig");
const a_dispatch = @import("a_dispatch.zig");
const gen_int = @import("gen_int.zig");
const crt = @import("crt.zig");
const primes = @import("primes.zig");
const libmain = @import("libmain.zig");
const aes_ctr_drbg = @import("aes_ctr_drbg.zig");
const fips_selftest = @import("fips_selftest.zig");

const SYMCRYPT_CALL = types.SYMCRYPT_CALL;
const BYTE = types.BYTE;
const PBYTE = types.PBYTE;
const PCBYTE = types.PCBYTE;
const UINT32 = types.UINT32;
const UINT64 = types.UINT64;
const SIZE_T = types.SIZE_T;
const BOOLEAN = types.BOOLEAN;
const SYMCRYPT_ERROR = types.SYMCRYPT_ERROR;
const SYMCRYPT_NUMBER_FORMAT = types.SYMCRYPT_NUMBER_FORMAT;
const SYMCRYPT_RSA_PARAMS = types.SYMCRYPT_RSA_PARAMS;
const PCSYMCRYPT_RSA_PARAMS = types.PCSYMCRYPT_RSA_PARAMS;
const SYMCRYPT_RSAKEY = types.SYMCRYPT_RSAKEY;
const PSYMCRYPT_RSAKEY = types.PSYMCRYPT_RSAKEY;
const PCSYMCRYPT_RSAKEY = types.PCSYMCRYPT_RSAKEY;
const PSYMCRYPT_INT = types.PSYMCRYPT_INT;
const PSYMCRYPT_DIVISOR = types.PSYMCRYPT_DIVISOR;
const PSYMCRYPT_MODELEMENT = types.PSYMCRYPT_MODELEMENT;
const SYMCRYPT_RNG_AES_STATE = types.SYMCRYPT_RNG_AES_STATE;
const PSYMCRYPT_RNG_AES_STATE = types.PSYMCRYPT_RNG_AES_STATE;

extern fn SymCryptCallbackAlloc(cbBytes: SIZE_T) callconv(SYMCRYPT_CALL) ?PBYTE;
extern fn SymCryptCallbackFree(pMem: ?*anyopaque) callconv(SYMCRYPT_CALL) void;

const RSA_DEFAULT_PUBLIC_EXPONENT: UINT64 = 65537;
const SYMCRYPT_MAX_PRIME_RECOVERY_ITERATIONS: UINT32 = 100;

inline fn SYMCRYPT_SCRATCH_BYTES_FOR_PRIME_RECOVERY(ndMod: UINT32, ndPubExp: UINT32, nBitsMod: UINT32) UINT32 {
    return a_dispatch.SymCryptSizeofIntFromDigits(ndMod) +
        a_dispatch.SymCryptSizeofIntFromDigits(ndPubExp) +
        a_dispatch.SymCryptSizeofIntFromDigits(ndMod + ndPubExp) +
        (4 * types.SYMCRYPT_INTERNAL_SIZEOF_MODELEMENT_FROM_BITS(nBitsMod)) +
        @max(
            types.SYMCRYPT_SCRATCH_BYTES_FOR_INT_MUL(ndMod + ndPubExp),
            @max(
                types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(ndMod),
                @max(
                    types.SYMCRYPT_SCRATCH_BYTES_FOR_MODEXP(ndMod),
                    @max(
                        types.SYMCRYPT_SCRATCH_BYTES_FOR_EXTENDED_GCD(ndMod),
                        @max(
                            types.SYMCRYPT_SCRATCH_BYTES_FOR_INT_TO_MODULUS(ndMod),
                            types.SYMCRYPT_SCRATCH_BYTES_FOR_INT_DIVMOD(ndMod, ndMod),
                        ),
                    ),
                ),
            ),
        );
}

pub export fn SymCryptRsakeyAllocate(
    pParams: PCSYMCRYPT_RSA_PARAMS,
    flags: UINT32,
) callconv(SYMCRYPT_CALL) ?PSYMCRYPT_RSAKEY {
    _ = flags;

    const cb: SIZE_T = SymCryptSizeofRsakeyFromParams(pParams);
    const p = SymCryptCallbackAlloc(cb) orelse return null;

    return SymCryptRsakeyCreate(p, cb, pParams);
}

pub export fn SymCryptRsakeyFree(pkObj: PSYMCRYPT_RSAKEY) callconv(SYMCRYPT_CALL) void {
    macros.SYMCRYPT_CHECK_MAGIC(pkObj);
    SymCryptRsakeyWipe(pkObj);
    SymCryptCallbackFree(@ptrCast(pkObj));
}

pub export fn SymCryptSizeofRsakeyFromParams(pParams: PCSYMCRYPT_RSA_PARAMS) callconv(SYMCRYPT_CALL) UINT32 {
    const nModulusDigits: UINT32 = a_dispatch.SymCryptDigitsFromBits(pParams.nBitsOfModulus);

    const res: UINT32 = @sizeOf(SYMCRYPT_RSAKEY) +
        a_dispatch.SymCryptSizeofModulusFromDigits(nModulusDigits) +
        pParams.nPrimes * a_dispatch.SymCryptSizeofModulusFromDigits(nModulusDigits) +
        pParams.nPrimes * types.SYMCRYPT_INTERNAL_SIZEOF_MODELEMENT_FROM_BITS(pParams.nBitsOfModulus) +
        pParams.nPubExp * a_dispatch.SymCryptSizeofIntFromDigits(nModulusDigits) +
        pParams.nPubExp * pParams.nPrimes * a_dispatch.SymCryptSizeofIntFromDigits(nModulusDigits);

    macros.SYMCRYPT_ASSERT(
        res <= types.SYMCRYPT_SIZEOF_RSAKEY_FROM_PARAMS(pParams.nBitsOfModulus, pParams.nPrimes, pParams.nPubExp),
    );

    return res;
}

pub export fn SymCryptRsakeyCreate(
    pbBuffer: PBYTE,
    cbBuffer: SIZE_T,
    pParams: PCSYMCRYPT_RSA_PARAMS,
) callconv(SYMCRYPT_CALL) ?PSYMCRYPT_RSAKEY {
    var pbCurr: PBYTE = pbBuffer;
    const cbNeeded: SIZE_T = SymCryptSizeofRsakeyFromParams(pParams);

    macros.SYMCRYPT_ASSERT((@intFromPtr(pbCurr) & (types.SYMCRYPT_ASYM_ALIGN_VALUE - 1)) == 0);

    if ((cbBuffer < cbNeeded) or
        (pParams.nBitsOfModulus < types.SYMCRYPT_RSAKEY_MIN_BITSIZE_MODULUS) or
        (pParams.nBitsOfModulus > types.SYMCRYPT_RSAKEY_MAX_BITSIZE_MODULUS) or
        (pParams.nPubExp < 1) or
        (pParams.nPubExp > types.SYMCRYPT_RSAKEY_MAX_NUMOF_PUBEXPS) or
        (pParams.nPrimes == 1) or
        (pParams.nPrimes > types.SYMCRYPT_RSAKEY_MAX_NUMOF_PRIMES))
    {
        return null;
    }
    macros.SYMCRYPT_ASSERT(cbBuffer >= @sizeOf(SYMCRYPT_RSAKEY));

    const pkObj: PSYMCRYPT_RSAKEY = @ptrCast(@alignCast(pbCurr));

    macros.SymCryptWipe(@ptrCast(pbBuffer), cbBuffer);

    pkObj.cbTotalSize = @intCast(cbNeeded);
    macros.SYMCRYPT_ASSERT(pkObj.cbTotalSize == cbNeeded);

    pkObj.hasPrivateKey = 0;

    pkObj.nSetBitsOfModulus = pParams.nBitsOfModulus;
    pkObj.nDigitsOfModulus = a_dispatch.SymCryptDigitsFromBits(pkObj.nSetBitsOfModulus);

    pkObj.nPrimes = pParams.nPrimes;
    pkObj.nPubExp = pParams.nPubExp;

    pbCurr += @sizeOf(SYMCRYPT_RSAKEY);

    const itemSize: SIZE_T = a_dispatch.SymCryptSizeofModulusFromDigits(pkObj.nDigitsOfModulus);
    macros.SYMCRYPT_ASSERT(
        cbBuffer >= @sizeOf(SYMCRYPT_RSAKEY) + itemSize +
            (pkObj.nPrimes * a_dispatch.SymCryptSizeofModulusFromDigits(pkObj.nDigitsOfModulus)) +
            (pkObj.nPrimes * types.SYMCRYPT_INTERNAL_SIZEOF_MODELEMENT_FROM_BITS(pParams.nBitsOfModulus)) +
            (pkObj.nPubExp * a_dispatch.SymCryptSizeofIntFromDigits(pkObj.nDigitsOfModulus)) +
            (pkObj.nPubExp * pkObj.nPrimes * a_dispatch.SymCryptSizeofIntFromDigits(pkObj.nDigitsOfModulus)),
    );
    pkObj.pmModulus = a_dispatch.SymCryptModulusCreate(
        pbCurr,
        itemSize,
        pkObj.nDigitsOfModulus,
    );
    macros.SYMCRYPT_ASSERT(pkObj.pmModulus != null);
    pbCurr += itemSize;

    var i: UINT32 = 0;
    while (i < pkObj.nPrimes) : (i += 1) {
        pkObj.pbPrimes[i] = pbCurr;
        pbCurr += a_dispatch.SymCryptSizeofModulusFromDigits(pkObj.nDigitsOfModulus);
    }

    i = 0;
    while (i < pkObj.nPrimes) : (i += 1) {
        pkObj.pbCrtInverses[i] = pbCurr;
        pbCurr += types.SYMCRYPT_INTERNAL_SIZEOF_MODELEMENT_FROM_BITS(pParams.nBitsOfModulus);
    }

    i = 0;
    while (i < pkObj.nPubExp) : (i += 1) {
        pkObj.pbPrivExps[i] = pbCurr;
        pbCurr += a_dispatch.SymCryptSizeofIntFromDigits(pkObj.nDigitsOfModulus);
    }

    i = 0;
    while (i < pkObj.nPubExp * pkObj.nPrimes) : (i += 1) {
        pkObj.pbCrtPrivExps[i] = pbCurr;
        pbCurr += a_dispatch.SymCryptSizeofIntFromDigits(pkObj.nDigitsOfModulus);
    }

    macros.SYMCRYPT_SET_MAGIC(pkObj);

    return pkObj;
}

pub export fn SymCryptRsakeyWipe(pkDst: PSYMCRYPT_RSAKEY) callconv(SYMCRYPT_CALL) void {
    macros.SymCryptWipe(@ptrCast(pkDst), pkDst.cbTotalSize);
}

pub export fn SymCryptRsakeyHasPrivateKey(pkRsakey: PCSYMCRYPT_RSAKEY) callconv(SYMCRYPT_CALL) BOOLEAN {
    return pkRsakey.hasPrivateKey;
}

pub export fn SymCryptRsakeySizeofModulus(pkRsakey: PCSYMCRYPT_RSAKEY) callconv(SYMCRYPT_CALL) UINT32 {
    return (pkRsakey.nBitsOfModulus + 7) / 8;
}

pub export fn SymCryptRsakeyModulusBits(pkRsakey: PCSYMCRYPT_RSAKEY) callconv(SYMCRYPT_CALL) UINT32 {
    return pkRsakey.nBitsOfModulus;
}

pub export fn SymCryptRsakeySizeofPublicExponent(
    pRsakey: PCSYMCRYPT_RSAKEY,
    index: UINT32,
) callconv(SYMCRYPT_CALL) UINT32 {
    macros.SYMCRYPT_ASSERT(index == 0);
    return libmain.SymCryptUint64Bytesize(pRsakey.au64PubExp[0]);
}

pub export fn SymCryptRsakeySizeofPrime(
    pkRsakey: PCSYMCRYPT_RSAKEY,
    index: UINT32,
) callconv(SYMCRYPT_CALL) UINT32 {
    return (pkRsakey.nBitsOfPrimes[index] + 7) / 8;
}

pub export fn SymCryptRsakeyGetNumberOfPublicExponents(pkRsakey: PCSYMCRYPT_RSAKEY) callconv(SYMCRYPT_CALL) UINT32 {
    return pkRsakey.nPubExp;
}

pub export fn SymCryptRsakeyGetNumberOfPrimes(pkRsakey: PCSYMCRYPT_RSAKEY) callconv(SYMCRYPT_CALL) UINT32 {
    return pkRsakey.nPrimes;
}

pub export fn SymCryptRsakeyCreateAllObjects(pkRsakey: PSYMCRYPT_RSAKEY) callconv(SYMCRYPT_CALL) void {
    var i: UINT32 = 0;
    while (i < pkRsakey.nPrimes) : (i += 1) {
        pkRsakey.pmPrimes[i] = a_dispatch.SymCryptModulusCreate(
            pkRsakey.pbPrimes[i].?,
            a_dispatch.SymCryptSizeofModulusFromDigits(pkRsakey.nDigitsOfPrimes[i]),
            pkRsakey.nDigitsOfPrimes[i],
        );
        macros.SYMCRYPT_ASSERT(pkRsakey.pmPrimes[i] != null);
    }

    i = 0;
    while (i < pkRsakey.nPrimes) : (i += 1) {
        pkRsakey.peCrtInverses[i] = a_dispatch.SymCryptModElementCreate(
            pkRsakey.pbCrtInverses[i].?,
            a_dispatch.SymCryptSizeofModElementFromModulus(pkRsakey.pmPrimes[i].?),
            pkRsakey.pmPrimes[i].?,
        );
        macros.SYMCRYPT_ASSERT(pkRsakey.peCrtInverses[i] != null);
    }

    i = 0;
    while (i < pkRsakey.nPubExp) : (i += 1) {
        pkRsakey.piPrivExps[i] = a_dispatch.SymCryptIntCreate(
            pkRsakey.pbPrivExps[i].?,
            a_dispatch.SymCryptSizeofIntFromDigits(pkRsakey.nDigitsOfModulus),
            pkRsakey.nDigitsOfModulus,
        );
        macros.SYMCRYPT_ASSERT(pkRsakey.piPrivExps[i] != null);
    }

    i = 0;
    while (i < pkRsakey.nPubExp * pkRsakey.nPrimes) : (i += 1) {
        pkRsakey.piCrtPrivExps[i] = a_dispatch.SymCryptIntCreate(
            pkRsakey.pbCrtPrivExps[i].?,
            a_dispatch.SymCryptSizeofIntFromDigits(pkRsakey.nDigitsOfPrimes[i]),
            pkRsakey.nDigitsOfPrimes[i],
        );
        macros.SYMCRYPT_ASSERT(pkRsakey.piCrtPrivExps[i] != null);
    }
}

pub export fn SymCryptRsakeyCalculatePrivateFields(
    pkRsakey: PSYMCRYPT_RSAKEY,
    pdTmp: PSYMCRYPT_DIVISOR,
    piPhi: PSYMCRYPT_INT,
    piAcc: PSYMCRYPT_INT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
    flags: UINT32,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;
    var tmpGcdBuf: [types.SYMCRYPT_INTERNAL_SIZEOF_INT_FROM_BITS(64)]BYTE align(types.SYMCRYPT_ASYM_ALIGN_VALUE) = undefined;
    defer libmain.SymCryptWipeKnownSize(&tmpGcdBuf, @sizeOf(@TypeOf(tmpGcdBuf)));

    const piScr: PSYMCRYPT_INT = a_dispatch.SymCryptIntFromDivisor(pdTmp);
    const allowedFlags: UINT32 = types.SYMCRYPT_FLAG_KEY_MINIMAL_VALIDATION;

    if ((flags & ~allowedFlags) != 0) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    const piTmpGcd = a_dispatch.SymCryptIntCreate(
        &tmpGcdBuf,
        tmpGcdBuf.len,
        a_dispatch.SymCryptDigitsFromBits(64),
    ).?;

    scError = crt.SymCryptCrtGenerateInverses(
        pkRsakey.nPrimes,
        @ptrCast(&pkRsakey.pmPrimes[0]),
        0,
        @ptrCast(&pkRsakey.peCrtInverses[0]),
        pbScratch,
        cbScratch,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    a_dispatch.SymCryptIntSetValueUint32(1, piPhi);
    var i: UINT32 = 0;
    while (i < pkRsakey.nPrimes) : (i += 1) {
        scError = a_dispatch.SymCryptIntCopyMixedSize(a_dispatch.SymCryptIntFromModulus(pkRsakey.pmPrimes[i].?), piScr);
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }
        _ = a_dispatch.SymCryptIntSubUint32(piScr, 1, piScr);
        a_dispatch.SymCryptIntMulMixedSize(piScr, piPhi, piAcc, pbScratch, cbScratch);
        scError = a_dispatch.SymCryptIntCopyMixedSize(piAcc, piPhi);
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }
    }

    i = 0;
    while (i < pkRsakey.nPubExp) : (i += 1) {
        if (pkRsakey.au64PubExp[i] == 1 or (pkRsakey.au64PubExp[i] & 1) != 1) {
            return .SYMCRYPT_INVALID_ARGUMENT;
        }

        a_dispatch.SymCryptIntSetValueUint64(pkRsakey.au64PubExp[i], piScr);

        gen_int.SymCryptIntExtendedGcd(
            piPhi,
            piScr,
            types.SYMCRYPT_FLAG_GCD_INPUTS_NOT_BOTH_EVEN,
            piTmpGcd,
            null,
            null,
            pkRsakey.piPrivExps[i].?,
            pbScratch,
            cbScratch,
        );

        if (a_dispatch.SymCryptIntIsEqualUint32(piTmpGcd, 1) == 0) {
            return .SYMCRYPT_INVALID_ARGUMENT;
        }
    }

    i = 0;
    while (i < pkRsakey.nPrimes) : (i += 1) {
        scError = a_dispatch.SymCryptIntCopyMixedSize(
            a_dispatch.SymCryptIntFromModulus(pkRsakey.pmPrimes[i].?),
            a_dispatch.SymCryptIntFromDivisor(pdTmp),
        );
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }

        _ = a_dispatch.SymCryptIntSubUint32(a_dispatch.SymCryptIntFromDivisor(pdTmp), 1, a_dispatch.SymCryptIntFromDivisor(pdTmp));
        a_dispatch.SymCryptIntToDivisor(
            a_dispatch.SymCryptIntFromDivisor(pdTmp),
            pdTmp,
            pkRsakey.nPubExp,
            0,
            pbScratch,
            cbScratch,
        );

        var j: UINT32 = 0;
        while (j < pkRsakey.nPubExp) : (j += 1) {
            a_dispatch.SymCryptIntDivMod(
                pkRsakey.piPrivExps[j].?,
                pdTmp,
                null,
                piPhi,
                pbScratch,
                cbScratch,
            );

            scError = a_dispatch.SymCryptIntCopyMixedSize(piPhi, pkRsakey.piCrtPrivExps[j * pkRsakey.nPrimes + i].?);
            if (scError != .SYMCRYPT_NO_ERROR) {
                return scError;
            }
        }
    }

    if ((flags & types.SYMCRYPT_FLAG_KEY_MINIMAL_VALIDATION) == 0) {
        if (pkRsakey.nPrimes != 2) {
            return .SYMCRYPT_INVALID_ARGUMENT;
        }

        a_dispatch.SymCryptIntMulMixedSize(
            a_dispatch.SymCryptIntFromModulus(pkRsakey.pmPrimes[0].?),
            a_dispatch.SymCryptIntFromModulus(pkRsakey.pmPrimes[1].?),
            piAcc,
            pbScratch,
            cbScratch,
        );

        if (a_dispatch.SymCryptIntIsEqual(piAcc, a_dispatch.SymCryptIntFromModulus(pkRsakey.pmModulus.?)) == 0) {
            return .SYMCRYPT_INVALID_ARGUMENT;
        }
    }

    return scError;
}

fn SymCryptRsakeyGenerateInternal(
    pkRsakey: PSYMCRYPT_RSAKEY,
    pu64PubExp_in: ?[*]const UINT64,
    nPubExp_in: UINT32,
    pRngState: ?PSYMCRYPT_RNG_AES_STATE,
    flags: UINT32,
) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;
    var pu64PubExp = pu64PubExp_in;
    var nPubExp = nPubExp_in;

    const ndMod: UINT32 = pkRsakey.nDigitsOfModulus;
    const defaultExponent: [1]UINT64 = .{RSA_DEFAULT_PUBLIC_EXPONENT};

    const algorithmFlags: UINT32 = types.SYMCRYPT_FLAG_RSAKEY_SIGN | types.SYMCRYPT_FLAG_RSAKEY_ENCRYPT;
    const allowedFlags: UINT32 = types.SYMCRYPT_FLAG_KEY_NO_FIPS | algorithmFlags;

    if (((flags & ~allowedFlags) != 0) or ((flags & algorithmFlags) == 0)) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    if (((flags & types.SYMCRYPT_FLAG_KEY_NO_FIPS) == 0) and
        (pkRsakey.nSetBitsOfModulus < types.SYMCRYPT_RSAKEY_FIPS_MIN_BITSIZE_MODULUS))
    {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    if (pu64PubExp == null and nPubExp == 0) {
        pu64PubExp = &defaultExponent;
        nPubExp = 1;
    }

    if (pkRsakey.nPrimes != 2 or nPubExp != pkRsakey.nPubExp or nPubExp != 1 or pu64PubExp == null) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    pkRsakey.au64PubExp[0] = pu64PubExp.?[0];

    pkRsakey.nBitsOfModulus = pkRsakey.nSetBitsOfModulus;

    pkRsakey.nBitsOfPrimes[0] = (pkRsakey.nBitsOfModulus + 1) / 2;
    pkRsakey.nBitsOfPrimes[1] = pkRsakey.nBitsOfModulus / 2;

    pkRsakey.nDigitsOfPrimes[0] = a_dispatch.SymCryptDigitsFromBits(pkRsakey.nBitsOfPrimes[0]);
    pkRsakey.nDigitsOfPrimes[1] = a_dispatch.SymCryptDigitsFromBits(pkRsakey.nBitsOfPrimes[1]);

    pkRsakey.nMaxDigitsOfPrimes = @max(pkRsakey.nDigitsOfPrimes[0], pkRsakey.nDigitsOfPrimes[1]);

    const ndPrimes: UINT32 = pkRsakey.nMaxDigitsOfPrimes;
    const ndLarge: UINT32 = ndPrimes + ndMod;

    const primeBits: UINT32 = @max(pkRsakey.nBitsOfPrimes[0], pkRsakey.nBitsOfPrimes[1]);
    const maxTries: UINT32 = 100 * primeBits;

    SymCryptRsakeyCreateAllObjects(pkRsakey);

    const cbPrimes: UINT32 = a_dispatch.SymCryptSizeofIntFromDigits(ndPrimes);
    const cbMod: UINT32 = a_dispatch.SymCryptSizeofIntFromDigits(ndMod);
    const cbLarge: UINT32 = a_dispatch.SymCryptSizeofIntFromDigits(ndLarge);
    const cbDivisor: UINT32 = a_dispatch.SymCryptSizeofDivisorFromDigits(ndPrimes);

    const cbScratch: UINT32 = 2 * cbPrimes + cbMod + cbLarge + cbDivisor +
        @max(
            types.SYMCRYPT_SCRATCH_BYTES_FOR_INT_PRIME_GEN(ndPrimes),
            @max(
                types.SYMCRYPT_SCRATCH_BYTES_FOR_INT_TO_MODULUS(ndMod),
                @max(
                    types.SYMCRYPT_SCRATCH_BYTES_FOR_INT_MUL(ndMod),
                    @max(
                        types.SYMCRYPT_SCRATCH_BYTES_FOR_CRT_GENERATION(ndPrimes),
                        @max(
                            types.SYMCRYPT_SCRATCH_BYTES_FOR_EXTENDED_GCD(ndMod),
                            @max(
                                types.SYMCRYPT_SCRATCH_BYTES_FOR_INT_TO_DIVISOR(ndPrimes),
                                types.SYMCRYPT_SCRATCH_BYTES_FOR_INT_DIVMOD(ndMod, ndPrimes),
                            ),
                        ),
                    ),
                ),
            ),
        );

    const pbScratch = SymCryptCallbackAlloc(cbScratch) orelse {
        return .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
    };
    defer {
        macros.SymCryptWipe(@ptrCast(pbScratch), cbScratch);
        SymCryptCallbackFree(@ptrCast(pbScratch));
    }

    var pbFnScratch: PBYTE = pbScratch;
    var cbFnScratch: UINT32 = cbScratch;

    const piLow = a_dispatch.SymCryptIntCreate(pbFnScratch, cbPrimes, ndPrimes).?;
    pbFnScratch += cbPrimes;
    cbFnScratch -= cbPrimes;
    const piHigh = a_dispatch.SymCryptIntCreate(pbFnScratch, cbPrimes, ndPrimes).?;
    pbFnScratch += cbPrimes;
    cbFnScratch -= cbPrimes;

    const piPhi = a_dispatch.SymCryptIntCreate(pbFnScratch, cbMod, ndMod).?;
    pbFnScratch += cbMod;
    cbFnScratch -= cbMod;

    const piAcc = a_dispatch.SymCryptIntCreate(pbFnScratch, cbLarge, ndLarge).?;
    pbFnScratch += cbLarge;
    cbFnScratch -= cbLarge;

    const pdTmp = a_dispatch.SymCryptDivisorCreate(pbFnScratch, cbDivisor, ndPrimes).?;
    pbFnScratch += cbDivisor;
    cbFnScratch -= cbDivisor;

    a_dispatch.SymCryptIntSetValueUint32(3, piLow);
    a_dispatch.SymCryptIntMulPow2(piLow, primeBits - 2, piLow);

    a_dispatch.SymCryptIntSetValueUint32(1, piHigh);
    a_dispatch.SymCryptIntMulPow2(piHigh, primeBits, piHigh);
    _ = a_dispatch.SymCryptIntSubUint32(piHigh, 1, piHigh);

    a_dispatch.SymCryptIntSetValueUint32(1, piPhi);
    var i: UINT32 = 0;
    while (i < pkRsakey.nPrimes) : (i += 1) {
        if (((pkRsakey.nBitsOfModulus % 2) == 1) and (i > 0)) {
            a_dispatch.SymCryptIntDivPow2(piLow, 1, piLow);
            a_dispatch.SymCryptIntDivPow2(piHigh, 1, piHigh);
        }

        scError = primes.SymCryptIntGenerateRandomPrimeEx(
            piLow,
            piHigh,
            pu64PubExp,
            nPubExp,
            maxTries,
            0,
            @ptrCast(pRngState),
            a_dispatch.SymCryptIntFromModulus(pkRsakey.pmPrimes[i].?),
            pbFnScratch,
            cbFnScratch,
        );
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }

        a_dispatch.SymCryptIntToModulus(
            a_dispatch.SymCryptIntFromModulus(pkRsakey.pmPrimes[i].?),
            pkRsakey.pmPrimes[i].?,
            pkRsakey.nBitsOfModulus,
            types.SYMCRYPT_FLAG_MODULUS_PARITY_PUBLIC | types.SYMCRYPT_FLAG_MODULUS_PRIME,
            pbFnScratch,
            cbFnScratch,
        );

        a_dispatch.SymCryptIntMulMixedSize(
            a_dispatch.SymCryptIntFromModulus(pkRsakey.pmPrimes[i].?),
            piPhi,
            piAcc,
            pbFnScratch,
            cbFnScratch,
        );
        scError = a_dispatch.SymCryptIntCopyMixedSize(piAcc, piPhi);
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }
    }

    a_dispatch.SymCryptIntCopy(piPhi, a_dispatch.SymCryptIntFromModulus(pkRsakey.pmModulus.?));
    a_dispatch.SymCryptIntToModulus(
        a_dispatch.SymCryptIntFromModulus(pkRsakey.pmModulus.?),
        pkRsakey.pmModulus.?,
        pkRsakey.nBitsOfModulus,
        types.SYMCRYPT_FLAG_DATA_PUBLIC,
        pbFnScratch,
        cbFnScratch,
    );

    if (a_dispatch.SymCryptIntBitsizeOfValue(piPhi) != pkRsakey.nBitsOfModulus) {
        return .SYMCRYPT_EXTERNAL_FAILURE;
    }

    scError = SymCryptRsakeyCalculatePrivateFields(pkRsakey, pdTmp, piPhi, piAcc, pbFnScratch, cbFnScratch, 0);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    pkRsakey.hasPrivateKey = 1;
    pkRsakey.fAlgorithmInfo = flags;

    if ((flags & types.SYMCRYPT_FLAG_KEY_NO_FIPS) == 0) {
        fips_selftest.SYMCRYPT_RUN_SELFTEST_ONCE(
            fips_selftest.SymCryptRsaSelftest,
            fips_selftest.SYMCRYPT_SELFTEST_ALGORITHM_RSA,
        );

        pkRsakey.fAlgorithmInfo |= types.SYMCRYPT_FLAG_RSAKEY_SIGN;

        fips_selftest.SYMCRYPT_RUN_KEY_GEN_PCT(
            fips_selftest.SymCryptRsaSignVerifyPct,
            pkRsakey,
            fips_selftest.SYMCRYPT_PCT_RSA_SIGN,
        );

        if ((flags & types.SYMCRYPT_FLAG_RSAKEY_SIGN) == 0) {
            pkRsakey.fAlgorithmInfo ^= types.SYMCRYPT_FLAG_RSAKEY_SIGN;
        }
    }

    return scError;
}

pub export fn SymCryptRsakeyDerive(
    pkRsakey: PSYMCRYPT_RSAKEY,
    pbSeed: PCBYTE,
    cbSeed: SIZE_T,
    flags: UINT32,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;
    var rngState: SYMCRYPT_RNG_AES_STATE = undefined;
    defer aes_ctr_drbg.SymCryptRngAesUninstantiate(&rngState);

    scError = aes_ctr_drbg.SymCryptRngAesInstantiate(&rngState, pbSeed, cbSeed);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    scError = SymCryptRsakeyGenerateInternal(
        pkRsakey,
        null,
        0,
        &rngState,
        flags,
    );

    return scError;
}

pub export fn SymCryptRsakeyGenerate(
    pkRsakey: PSYMCRYPT_RSAKEY,
    pu64PubExp: ?[*]const UINT64,
    nPubExp: UINT32,
    flags: UINT32,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    return SymCryptRsakeyGenerateInternal(
        pkRsakey,
        pu64PubExp,
        nPubExp,
        null,
        flags,
    );
}

fn SymCryptRsakeyCalculatePrimesFromPrivateExponent(
    pkRsakey: PSYMCRYPT_RSAKEY,
    pbPrivateExponent: PCBYTE,
    cbPrivateExponent: SIZE_T,
    numFormat: SYMCRYPT_NUMBER_FORMAT,
    pbScratch: PBYTE,
    cbScratch: UINT32,
) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;

    const ndMod: UINT32 = pkRsakey.nDigitsOfModulus;
    const cbMod: UINT32 = a_dispatch.SymCryptSizeofIntFromDigits(ndMod);

    const ndPubExp: UINT32 = a_dispatch.SymCryptDigitsFromBits(64);
    const cbPubExp: UINT32 = a_dispatch.SymCryptSizeofIntFromDigits(ndPubExp);

    var nBitsExpProd: UINT32 = 0;
    const ndExpProd: UINT32 = ndMod + ndPubExp;
    const cbExpProd: UINT32 = a_dispatch.SymCryptSizeofIntFromDigits(ndExpProd);

    const cbModElement: UINT32 = types.SYMCRYPT_INTERNAL_SIZEOF_MODELEMENT_FROM_BITS(pkRsakey.nBitsOfModulus);

    var pbFnScratch: PBYTE = pbScratch;
    var cbFnScratch: UINT32 = cbScratch;

    var bFoundNonTrivialRoot: bool = false;

    macros.SYMCRYPT_ASSERT(pkRsakey.nPrimes == 2);
    macros.SYMCRYPT_ASSERT(cbScratch >= SYMCRYPT_SCRATCH_BYTES_FOR_PRIME_RECOVERY(ndMod, ndPubExp, pkRsakey.nBitsOfModulus));

    const piPrivExp = a_dispatch.SymCryptIntCreate(pbFnScratch, cbMod, ndMod).?;
    pbFnScratch += cbMod;
    cbFnScratch -= cbMod;
    const piPubExp = a_dispatch.SymCryptIntCreate(pbFnScratch, cbPubExp, ndPubExp).?;
    pbFnScratch += cbPubExp;
    cbFnScratch -= cbPubExp;
    const piExpProd = a_dispatch.SymCryptIntCreate(pbFnScratch, cbExpProd, ndExpProd).?;
    pbFnScratch += cbExpProd;
    cbFnScratch -= cbExpProd;

    var peTmpY: PSYMCRYPT_MODELEMENT = a_dispatch.SymCryptModElementCreate(pbFnScratch, cbModElement, pkRsakey.pmModulus.?).?;
    pbFnScratch += cbModElement;
    cbFnScratch -= cbModElement;
    var peTmpX: PSYMCRYPT_MODELEMENT = a_dispatch.SymCryptModElementCreate(pbFnScratch, cbModElement, pkRsakey.pmModulus.?).?;
    pbFnScratch += cbModElement;
    cbFnScratch -= cbModElement;
    const peOne = a_dispatch.SymCryptModElementCreate(pbFnScratch, cbModElement, pkRsakey.pmModulus.?).?;
    pbFnScratch += cbModElement;
    cbFnScratch -= cbModElement;
    const peNegOne = a_dispatch.SymCryptModElementCreate(pbFnScratch, cbModElement, pkRsakey.pmModulus.?).?;
    pbFnScratch += cbModElement;
    cbFnScratch -= cbModElement;

    if ((a_dispatch.SymCryptIntGetValueLsbits32(a_dispatch.SymCryptIntFromModulus(pkRsakey.pmModulus.?)) & 1) == 0) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    scError = a_dispatch.SymCryptIntSetValue(pbPrivateExponent, cbPrivateExponent, numFormat, piPrivExp);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    if (a_dispatch.SymCryptIntIsLessThan(piPrivExp, a_dispatch.SymCryptIntFromModulus(pkRsakey.pmModulus.?)) == 0) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    a_dispatch.SymCryptIntSetValueUint64(pkRsakey.au64PubExp[0], piPubExp);

    nBitsExpProd = pkRsakey.nBitsOfModulus + a_dispatch.SymCryptIntBitsizeOfValue(piPubExp);

    a_dispatch.SymCryptIntMulMixedSize(piPrivExp, piPubExp, piExpProd, pbFnScratch, cbFnScratch);

    const low64ExpProd: UINT64 = a_dispatch.SymCryptIntGetValueLsbits64(piExpProd);

    if ((low64ExpProd & 1) == 0) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    const trailingZeros: UINT32 = macros.SymCryptCountTrailingZeros64(low64ExpProd - 1);

    if (trailingZeros == 64) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    a_dispatch.SymCryptIntDivPow2(piExpProd, trailingZeros, piExpProd);
    a_dispatch.SymCryptModElementSetValueUint32(1, pkRsakey.pmModulus.?, peOne, pbFnScratch, cbFnScratch);
    a_dispatch.SymCryptModElementSetValueNegUint32(1, pkRsakey.pmModulus.?, peNegOne, pbFnScratch, cbFnScratch);

    var i: UINT32 = 0;
    while (i < SYMCRYPT_MAX_PRIME_RECOVERY_ITERATIONS) : (i += 1) {
        a_dispatch.SymCryptModSetRandom(pkRsakey.pmModulus.?, peTmpY, 0, pbFnScratch, cbFnScratch);

        a_dispatch.SymCryptModExp(
            pkRsakey.pmModulus.?,
            peTmpY,
            piExpProd,
            nBitsExpProd - 1,
            0,
            peTmpY,
            pbFnScratch,
            cbFnScratch,
        );

        if (a_dispatch.SymCryptModElementIsEqual(pkRsakey.pmModulus.?, peTmpY, peOne) != 0 or
            a_dispatch.SymCryptModElementIsEqual(pkRsakey.pmModulus.?, peTmpY, peNegOne) != 0)
        {
            continue;
        }

        var j: UINT32 = 1;
        while (j <= trailingZeros) : (j += 1) {
            a_dispatch.SymCryptModSquare(pkRsakey.pmModulus.?, peTmpY, peTmpX, pbFnScratch, cbFnScratch);

            if (a_dispatch.SymCryptModElementIsEqual(pkRsakey.pmModulus.?, peTmpX, peOne) != 0) {
                bFoundNonTrivialRoot = true;
                break;
            }

            if (a_dispatch.SymCryptModElementIsEqual(pkRsakey.pmModulus.?, peTmpX, peNegOne) != 0) {
                break;
            }

            const peTmpPtr = peTmpY;
            peTmpY = peTmpX;
            peTmpX = peTmpPtr;
        }
        if (bFoundNonTrivialRoot) {
            break;
        }
    }

    if (!bFoundNonTrivialRoot) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    a_dispatch.SymCryptModElementToInt(pkRsakey.pmModulus.?, peTmpY, piPrivExp, pbFnScratch, cbFnScratch);
    _ = a_dispatch.SymCryptIntSubUint32(piPrivExp, 1, piPrivExp);

    gen_int.SymCryptIntExtendedGcd(
        piPrivExp,
        a_dispatch.SymCryptIntFromModulus(pkRsakey.pmModulus.?),
        types.SYMCRYPT_FLAG_GCD_INPUTS_NOT_BOTH_EVEN,
        piPrivExp,
        null,
        null,
        null,
        pbFnScratch,
        cbFnScratch,
    );

    pkRsakey.nBitsOfPrimes[0] = a_dispatch.SymCryptIntBitsizeOfValue(piPrivExp);
    pkRsakey.nBitsOfPrimes[1] = pkRsakey.nBitsOfModulus - pkRsakey.nBitsOfPrimes[0];
    i = 0;
    while (i < 2) : (i += 1) {
        pkRsakey.nDigitsOfPrimes[i] = a_dispatch.SymCryptDigitsFromBits(pkRsakey.nBitsOfPrimes[i]);
        if (pkRsakey.nBitsOfPrimes[i] < types.SYMCRYPT_RSAKEY_MIN_BITSIZE_PRIME) {
            return .SYMCRYPT_WRONG_KEY_SIZE;
        }
    }
    pkRsakey.nMaxDigitsOfPrimes = @max(pkRsakey.nDigitsOfPrimes[0], pkRsakey.nDigitsOfPrimes[1]);

    SymCryptRsakeyCreateAllObjects(pkRsakey);

    scError = a_dispatch.SymCryptIntCopyMixedSize(piPrivExp, a_dispatch.SymCryptIntFromModulus(pkRsakey.pmPrimes[0].?));
    if (scError != .SYMCRYPT_NO_ERROR) {
        return .SYMCRYPT_HARDWARE_FAILURE;
    }

    a_dispatch.SymCryptIntToModulus(
        a_dispatch.SymCryptIntFromModulus(pkRsakey.pmPrimes[0].?),
        pkRsakey.pmPrimes[0].?,
        pkRsakey.nBitsOfModulus,
        types.SYMCRYPT_FLAG_MODULUS_PARITY_PUBLIC | types.SYMCRYPT_FLAG_MODULUS_PRIME,
        pbFnScratch,
        cbFnScratch,
    );

    a_dispatch.SymCryptIntDivMod(
        a_dispatch.SymCryptIntFromModulus(pkRsakey.pmModulus.?),
        a_dispatch.SymCryptDivisorFromModulus(pkRsakey.pmPrimes[0].?),
        piExpProd,
        piPrivExp,
        pbFnScratch,
        cbFnScratch,
    );

    if (a_dispatch.SymCryptIntIsEqualUint32(piPrivExp, 0) == 0) {
        return .SYMCRYPT_HARDWARE_FAILURE;
    }

    scError = a_dispatch.SymCryptIntCopyMixedSize(piExpProd, a_dispatch.SymCryptIntFromModulus(pkRsakey.pmPrimes[1].?));
    if (scError != .SYMCRYPT_NO_ERROR) {
        return .SYMCRYPT_HARDWARE_FAILURE;
    }

    a_dispatch.SymCryptIntToModulus(
        a_dispatch.SymCryptIntFromModulus(pkRsakey.pmPrimes[1].?),
        pkRsakey.pmPrimes[1].?,
        pkRsakey.nBitsOfModulus,
        types.SYMCRYPT_FLAG_MODULUS_PARITY_PUBLIC | types.SYMCRYPT_FLAG_MODULUS_PRIME,
        pbFnScratch,
        cbFnScratch,
    );

    return scError;
}

pub export fn SymCryptRsakeySetValueInternal(
    pbModulus: ?PCBYTE,
    cbModulus: SIZE_T,
    pu64PubExp: ?[*]const UINT64,
    nPubExp: UINT32,
    pbPrivateExponent: ?PCBYTE,
    cbPrivateExponent: SIZE_T,
    ppPrimes: ?[*]const ?PCBYTE,
    pcbPrimes: ?[*]const SIZE_T,
    nPrimes: UINT32,
    numFormat: SYMCRYPT_NUMBER_FORMAT,
    flags: UINT32,
    pkRsakey: PSYMCRYPT_RSAKEY,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;

    var cbDivisor: UINT32 = 0;
    var cbMod: UINT32 = 0;
    var piPhi: ?PSYMCRYPT_INT = null;
    var cbLarge: UINT32 = 0;
    var cbScratch: UINT32 = 0;
    var pbFnScratch: PBYTE = undefined;
    var cbFnScratch: UINT32 = 0;

    const algorithmFlags: UINT32 = types.SYMCRYPT_FLAG_RSAKEY_SIGN | types.SYMCRYPT_FLAG_RSAKEY_ENCRYPT;
    const allowedFlags: UINT32 = types.SYMCRYPT_FLAG_KEY_NO_FIPS | types.SYMCRYPT_FLAG_KEY_MINIMAL_VALIDATION | algorithmFlags;

    if (((flags & ~allowedFlags) != 0) or ((flags & algorithmFlags) == 0)) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    if (((flags & types.SYMCRYPT_FLAG_KEY_NO_FIPS) == 0) and
        ((flags & types.SYMCRYPT_FLAG_KEY_MINIMAL_VALIDATION) != 0))
    {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    macros.SYMCRYPT_ASSERT((nPrimes == 0) or (pbPrivateExponent == null));

    if ((pbModulus == null) or (cbModulus == 0) or
        (nPubExp != 1) or (pu64PubExp == null) or
        ((nPrimes != 2) and (nPrimes != 0)) or
        ((nPrimes == 2) and ((ppPrimes == null) or (pcbPrimes == null) or
            (ppPrimes.?[0] == null) or (ppPrimes.?[1] == null) or
            (pcbPrimes.?[0] == 0) or (pcbPrimes.?[1] == 0))))
    {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    const ndMod: UINT32 = pkRsakey.nDigitsOfModulus;

    if ((pbPrivateExponent != null) or (nPrimes > 0)) {
        if (pkRsakey.nPrimes != 2) {
            return .SYMCRYPT_INVALID_ARGUMENT;
        }

        cbMod = a_dispatch.SymCryptSizeofIntFromDigits(ndMod);
        cbLarge = a_dispatch.SymCryptSizeofIntFromDigits(2 * ndMod);
        cbDivisor = a_dispatch.SymCryptSizeofDivisorFromDigits(ndMod);

        cbScratch = cbMod + cbLarge + cbDivisor +
            @max(
                types.SYMCRYPT_SCRATCH_BYTES_FOR_INT_TO_MODULUS(ndMod),
                @max(
                    types.SYMCRYPT_SCRATCH_BYTES_FOR_CRT_GENERATION(ndMod),
                    @max(
                        types.SYMCRYPT_SCRATCH_BYTES_FOR_EXTENDED_GCD(ndMod),
                        @max(
                            types.SYMCRYPT_SCRATCH_BYTES_FOR_INT_TO_DIVISOR(ndMod),
                            types.SYMCRYPT_SCRATCH_BYTES_FOR_INT_DIVMOD(ndMod, ndMod),
                        ),
                    ),
                ),
            );

        if (pbPrivateExponent != null) {
            macros.SYMCRYPT_ASSERT(a_dispatch.SymCryptDigitsFromBits(64) == 1);

            cbScratch = @max(
                cbScratch,
                SYMCRYPT_SCRATCH_BYTES_FOR_PRIME_RECOVERY(ndMod, 1, pkRsakey.nSetBitsOfModulus),
            );
        }
    } else {
        cbScratch = types.SYMCRYPT_SCRATCH_BYTES_FOR_INT_TO_MODULUS(ndMod);
    }

    const pbScratch = SymCryptCallbackAlloc(cbScratch) orelse {
        return .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
    };
    defer {
        macros.SymCryptWipe(@ptrCast(pbScratch), cbScratch);
        SymCryptCallbackFree(@ptrCast(pbScratch));
    }

    scError = a_dispatch.SymCryptIntSetValue(
        pbModulus.?,
        cbModulus,
        numFormat,
        a_dispatch.SymCryptIntFromModulus(pkRsakey.pmModulus.?),
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    pkRsakey.nBitsOfModulus = a_dispatch.SymCryptIntBitsizeOfValue(
        a_dispatch.SymCryptIntFromModulus(pkRsakey.pmModulus.?),
    );
    if (pkRsakey.nBitsOfModulus > pkRsakey.nSetBitsOfModulus) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    if (pkRsakey.nBitsOfModulus < types.SYMCRYPT_RSAKEY_MIN_BITSIZE_MODULUS) {
        return .SYMCRYPT_WRONG_KEY_SIZE;
    }

    a_dispatch.SymCryptIntToModulus(
        a_dispatch.SymCryptIntFromModulus(pkRsakey.pmModulus.?),
        pkRsakey.pmModulus.?,
        pkRsakey.nBitsOfModulus,
        types.SYMCRYPT_FLAG_DATA_PUBLIC,
        pbScratch,
        cbScratch,
    );

    pkRsakey.nPubExp = nPubExp;
    var i: UINT32 = 0;
    while (i < pkRsakey.nPubExp) : (i += 1) {
        pkRsakey.au64PubExp[i] = pu64PubExp.?[i];
    }

    if ((pbPrivateExponent != null) or (nPrimes > 0)) {
        if (pbPrivateExponent != null) {
            scError = SymCryptRsakeyCalculatePrimesFromPrivateExponent(
                pkRsakey,
                pbPrivateExponent.?,
                cbPrivateExponent,
                numFormat,
                pbScratch,
                cbScratch,
            );
            if (scError != .SYMCRYPT_NO_ERROR) {
                return scError;
            }

            pbFnScratch = pbScratch;
            cbFnScratch = cbScratch;

            piPhi = a_dispatch.SymCryptIntCreate(pbFnScratch, cbMod, ndMod);
            pbFnScratch += cbMod;
            cbFnScratch -= cbMod;
        } else {
            pbFnScratch = pbScratch;
            cbFnScratch = cbScratch;

            piPhi = a_dispatch.SymCryptIntCreate(pbFnScratch, cbMod, ndMod);
            pbFnScratch += cbMod;
            cbFnScratch -= cbMod;

            pkRsakey.nMaxDigitsOfPrimes = 0;
            i = 0;
            while (i < pkRsakey.nPrimes) : (i += 1) {
                scError = a_dispatch.SymCryptIntSetValue(
                    ppPrimes.?[i].?,
                    pcbPrimes.?[i],
                    numFormat,
                    piPhi.?,
                );
                if (scError != .SYMCRYPT_NO_ERROR) {
                    return scError;
                }

                pkRsakey.nBitsOfPrimes[i] = a_dispatch.SymCryptIntBitsizeOfValue(piPhi.?);
                pkRsakey.nDigitsOfPrimes[i] = a_dispatch.SymCryptDigitsFromBits(pkRsakey.nBitsOfPrimes[i]);

                pkRsakey.nMaxDigitsOfPrimes = @max(pkRsakey.nMaxDigitsOfPrimes, pkRsakey.nDigitsOfPrimes[i]);

                if (pkRsakey.nBitsOfPrimes[i] < types.SYMCRYPT_RSAKEY_MIN_BITSIZE_PRIME) {
                    return .SYMCRYPT_WRONG_KEY_SIZE;
                }
            }

            SymCryptRsakeyCreateAllObjects(pkRsakey);

            i = 0;
            while (i < pkRsakey.nPrimes) : (i += 1) {
                scError = a_dispatch.SymCryptIntSetValue(
                    ppPrimes.?[i].?,
                    pcbPrimes.?[i],
                    numFormat,
                    a_dispatch.SymCryptIntFromModulus(pkRsakey.pmPrimes[i].?),
                );
                if (scError != .SYMCRYPT_NO_ERROR) {
                    return scError;
                }

                if ((a_dispatch.SymCryptIntGetValueLsbits32(a_dispatch.SymCryptIntFromModulus(pkRsakey.pmPrimes[i].?)) & 1) == 0) {
                    return .SYMCRYPT_INVALID_ARGUMENT;
                }

                a_dispatch.SymCryptIntToModulus(
                    a_dispatch.SymCryptIntFromModulus(pkRsakey.pmPrimes[i].?),
                    pkRsakey.pmPrimes[i].?,
                    pkRsakey.nBitsOfModulus,
                    types.SYMCRYPT_FLAG_MODULUS_PARITY_PUBLIC | types.SYMCRYPT_FLAG_MODULUS_PRIME,
                    pbFnScratch,
                    cbFnScratch,
                );
            }
        }

        const piAcc = a_dispatch.SymCryptIntCreate(pbFnScratch, cbLarge, 2 * ndMod).?;
        pbFnScratch += cbLarge;
        cbFnScratch -= cbLarge;
        const pdTmp = a_dispatch.SymCryptDivisorCreate(pbFnScratch, cbDivisor, ndMod).?;
        pbFnScratch += cbDivisor;
        cbFnScratch -= cbDivisor;

        scError = SymCryptRsakeyCalculatePrivateFields(
            pkRsakey,
            pdTmp,
            piPhi.?,
            piAcc,
            pbFnScratch,
            cbFnScratch,
            flags & types.SYMCRYPT_FLAG_KEY_MINIMAL_VALIDATION,
        );
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }

        pkRsakey.hasPrivateKey = 1;
    }

    pkRsakey.fAlgorithmInfo = flags;

    if ((flags & types.SYMCRYPT_FLAG_KEY_NO_FIPS) == 0) {
        fips_selftest.SYMCRYPT_RUN_SELFTEST_ONCE(
            fips_selftest.SymCryptRsaSelftest,
            fips_selftest.SYMCRYPT_SELFTEST_ALGORITHM_RSA,
        );

        pkRsakey.fAlgorithmInfo |= fips_selftest.SYMCRYPT_PCT_RSA_SIGN;
    }

    return scError;
}

pub export fn SymCryptRsakeySetValue(
    pbModulus: ?PCBYTE,
    cbModulus: SIZE_T,
    pu64PubExp: ?[*]const UINT64,
    nPubExp: UINT32,
    ppPrimes: ?[*]const ?PCBYTE,
    pcbPrimes: ?[*]const SIZE_T,
    nPrimes: UINT32,
    numFormat: SYMCRYPT_NUMBER_FORMAT,
    flags: UINT32,
    pkRsakey: PSYMCRYPT_RSAKEY,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    return SymCryptRsakeySetValueInternal(
        pbModulus,
        cbModulus,
        pu64PubExp,
        nPubExp,
        null,
        0,
        ppPrimes,
        pcbPrimes,
        nPrimes,
        numFormat,
        flags,
        pkRsakey,
    );
}

pub export fn SymCryptRsakeySetValueFromPrivateExponent(
    pbModulus: ?PCBYTE,
    cbModulus: SIZE_T,
    u64PubExp: UINT64,
    pbPrivateExponent: ?PCBYTE,
    cbPrivateExponent: SIZE_T,
    numFormat: SYMCRYPT_NUMBER_FORMAT,
    flags: UINT32,
    pkRsakey: PSYMCRYPT_RSAKEY,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    const pubExpArr: [1]UINT64 = .{u64PubExp};
    return SymCryptRsakeySetValueInternal(
        pbModulus,
        cbModulus,
        &pubExpArr,
        1,
        pbPrivateExponent,
        cbPrivateExponent,
        null,
        null,
        0,
        numFormat,
        flags,
        pkRsakey,
    );
}

pub export fn SymCryptRsakeyGetValue(
    pkRsakey: PCSYMCRYPT_RSAKEY,
    pbModulus: ?PBYTE,
    cbModulus: SIZE_T,
    pu64PubExp: ?[*]UINT64,
    nPubExp: UINT32,
    ppPrimes: ?[*]const ?PBYTE,
    pcbPrimes: ?[*]const SIZE_T,
    nPrimes: UINT32,
    numFormat: SYMCRYPT_NUMBER_FORMAT,
    flags: UINT32,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;

    _ = flags;

    if ((nPrimes != 0) and (pkRsakey.hasPrivateKey == 0)) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    if (pbModulus) |pbMod| {
        scError = a_dispatch.SymCryptIntGetValue(
            a_dispatch.SymCryptIntFromModulus(pkRsakey.pmModulus.?),
            pbMod,
            cbModulus,
            numFormat,
        );
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }
    }

    if (pu64PubExp) |pu64| {
        if (nPubExp != 1) {
            return .SYMCRYPT_INVALID_ARGUMENT;
        }
        pu64[0] = pkRsakey.au64PubExp[0];
    }

    if (nPrimes != 0) {
        if (nPrimes != 2 or ppPrimes == null or pcbPrimes == null) {
            return .SYMCRYPT_INVALID_ARGUMENT;
        }

        var i: UINT32 = 0;
        while (i < nPrimes) : (i += 1) {
            if (ppPrimes.?[i]) |pbPrime| {
                scError = a_dispatch.SymCryptIntGetValue(
                    a_dispatch.SymCryptIntFromModulus(pkRsakey.pmPrimes[i].?),
                    pbPrime,
                    pcbPrimes.?[i],
                    numFormat,
                );
                if (scError != .SYMCRYPT_NO_ERROR) {
                    return scError;
                }
            }
        }
    }

    return scError;
}

pub export fn SymCryptRsakeyGetCrtValue(
    pkRsakey: PCSYMCRYPT_RSAKEY,
    ppCrtExponents: ?[*]const ?PBYTE,
    pcbCrtExponents: ?[*]const SIZE_T,
    nCrtExponents: UINT32,
    pbCrtCoefficient: ?PBYTE,
    cbCrtCoefficient: SIZE_T,
    pbPrivateExponent: ?PBYTE,
    cbPrivateExponent: SIZE_T,
    numFormat: SYMCRYPT_NUMBER_FORMAT,
    flags: UINT32,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;

    _ = flags;

    if (((ppCrtExponents == null) and (nCrtExponents != 0)) or
        (nCrtExponents != 0 and nCrtExponents != 2))
    {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    if (pkRsakey.hasPrivateKey == 0) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    var i: UINT32 = 0;
    while (i < nCrtExponents) : (i += 1) {
        if (ppCrtExponents.?[i]) |pbCrtExp| {
            scError = a_dispatch.SymCryptIntGetValue(
                pkRsakey.piCrtPrivExps[i].?,
                pbCrtExp,
                pcbCrtExponents.?[i],
                numFormat,
            );
            if (scError != .SYMCRYPT_NO_ERROR) {
                return scError;
            }
        }
    }

    if (pbCrtCoefficient) |pbCoeff| {
        const cbScratch: SIZE_T = types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(pkRsakey.nDigitsOfModulus);
        const pbScratch = SymCryptCallbackAlloc(cbScratch) orelse {
            return .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
        };
        defer {
            macros.SymCryptWipe(@ptrCast(pbScratch), cbScratch);
            SymCryptCallbackFree(@ptrCast(pbScratch));
        }

        scError = a_dispatch.SymCryptModElementGetValue(
            pkRsakey.pmPrimes[0].?,
            pkRsakey.peCrtInverses[0].?,
            pbCoeff,
            cbCrtCoefficient,
            numFormat,
            pbScratch,
            cbScratch,
        );
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }
    }

    if (pbPrivateExponent) |pbPrivExp| {
        scError = a_dispatch.SymCryptIntGetValue(
            pkRsakey.piPrivExps[0].?,
            pbPrivExp,
            cbPrivateExponent,
            numFormat,
        );
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }
    }

    return scError;
}

pub export fn SymCryptRsakeyExtendKeyUsage(
    pkRsakey: PSYMCRYPT_RSAKEY,
    flags: UINT32,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    const algorithmFlags: UINT32 = types.SYMCRYPT_FLAG_RSAKEY_SIGN | types.SYMCRYPT_FLAG_RSAKEY_ENCRYPT;

    if (((flags & ~algorithmFlags) != 0) or ((flags & algorithmFlags) == 0)) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    pkRsakey.fAlgorithmInfo |= flags;

    return .SYMCRYPT_NO_ERROR;
}
