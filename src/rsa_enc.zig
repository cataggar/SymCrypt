//
// rsa_enc.zig   RSA related algorithms
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

const std = @import("std");
const types = @import("types.zig");
const macros = @import("macros.zig");
const a_dispatch = @import("a_dispatch.zig");
const crt = @import("crt.zig");
const scs_tools = @import("scs_tools.zig");
const rsakey = @import("rsakey.zig");
const rsa_padding = @import("rsa_padding.zig");

const SYMCRYPT_CALL = types.SYMCRYPT_CALL;
const BYTE = types.BYTE;
const PBYTE = types.PBYTE;
const PCBYTE = types.PCBYTE;
const UINT32 = types.UINT32;
const SIZE_T = types.SIZE_T;
const SYMCRYPT_ERROR = types.SYMCRYPT_ERROR;
const SYMCRYPT_NUMBER_FORMAT = types.SYMCRYPT_NUMBER_FORMAT;
const PCSYMCRYPT_RSAKEY = types.PCSYMCRYPT_RSAKEY;
const PSYMCRYPT_MODELEMENT = types.PSYMCRYPT_MODELEMENT;
const PCSYMCRYPT_HASH = types.PCSYMCRYPT_HASH;
const SYMCRYPT_OID = types.SYMCRYPT_OID;
const PCSYMCRYPT_OID = types.PCSYMCRYPT_OID;

extern fn SymCryptCallbackAlloc(cbBytes: SIZE_T) callconv(SYMCRYPT_CALL) ?PBYTE;
extern fn SymCryptCallbackFree(pMem: ?*anyopaque) callconv(SYMCRYPT_CALL) void;

pub export fn SymCryptRsaCoreEncScratchSpace(pkRsakey: PCSYMCRYPT_RSAKEY) callconv(SYMCRYPT_CALL) UINT32 {
    return a_dispatch.SymCryptSizeofModElementFromModulus(pkRsakey.pmModulus.?) +
        @max(
            types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(pkRsakey.nDigitsOfModulus),
            types.SYMCRYPT_SCRATCH_BYTES_FOR_MODEXP(pkRsakey.nDigitsOfModulus),
        );
}

pub export fn SymCryptRsaCoreVerifyInput(
    pkRsakey: PCSYMCRYPT_RSAKEY,
    pbSrc: PCBYTE,
    cbSrc: SIZE_T,
    numFormat: SYMCRYPT_NUMBER_FORMAT,
    cbDst: SIZE_T,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;

    if (cbSrc > rsakey.SymCryptRsakeySizeofModulus(pkRsakey) or
        cbDst < rsakey.SymCryptRsakeySizeofModulus(pkRsakey))
    {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    if (cbSrc == rsakey.SymCryptRsakeySizeofModulus(pkRsakey)) {
        const cbTmpInteger: UINT32 = a_dispatch.SymCryptSizeofIntFromDigits(pkRsakey.nDigitsOfModulus);
        macros.SYMCRYPT_ASSERT(cbScratch >= cbTmpInteger);
        const piTmpInteger = a_dispatch.SymCryptIntCreate(pbScratch, cbTmpInteger, pkRsakey.nDigitsOfModulus).?;

        scError = a_dispatch.SymCryptIntSetValue(pbSrc, cbSrc, numFormat, piTmpInteger);
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }

        if (a_dispatch.SymCryptIntIsLessThan(piTmpInteger, a_dispatch.SymCryptIntFromModulus(pkRsakey.pmModulus.?)) == 0) {
            return .SYMCRYPT_INVALID_ARGUMENT;
        }
    }

    return scError;
}

pub export fn SymCryptRsaCoreEnc(
    pkRsakey: PCSYMCRYPT_RSAKEY,
    pbSrc: PCBYTE,
    cbSrc: SIZE_T,
    numFormat: SYMCRYPT_NUMBER_FORMAT,
    flags: UINT32,
    pbDst: PBYTE,
    cbDst: SIZE_T,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;

    var abExpIntBuffer: [types.SYMCRYPT_INTERNAL_SIZEOF_INT_FROM_BITS(64)]BYTE align(types.SYMCRYPT_ASYM_ALIGN_VALUE) = undefined;

    _ = flags;

    scError = SymCryptRsaCoreVerifyInput(pkRsakey, pbSrc, cbSrc, numFormat, cbDst, pbScratch, cbScratch);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    const cbModElement: UINT32 = a_dispatch.SymCryptSizeofModElementFromModulus(pkRsakey.pmModulus.?);

    macros.SYMCRYPT_ASSERT(
        cbScratch >= cbModElement +
            @max(
                types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(pkRsakey.nDigitsOfModulus),
                types.SYMCRYPT_SCRATCH_BYTES_FOR_MODEXP(pkRsakey.nDigitsOfModulus),
            ),
    );

    var pbFnScratch: PBYTE = pbScratch;
    var cbFnScratch: SIZE_T = cbScratch;

    const peRes = a_dispatch.SymCryptModElementCreate(pbScratch, cbModElement, pkRsakey.pmModulus.?).?;
    pbFnScratch += cbModElement;
    cbFnScratch -= cbModElement;

    scError = a_dispatch.SymCryptModElementSetValue(pbSrc, cbSrc, numFormat, pkRsakey.pmModulus.?, peRes, pbFnScratch, cbFnScratch);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    const piExp = a_dispatch.SymCryptIntCreate(&abExpIntBuffer, abExpIntBuffer.len, 1) orelse {
        return .SYMCRYPT_HARDWARE_FAILURE;
    };
    defer a_dispatch.SymCryptIntWipe(piExp);

    a_dispatch.SymCryptIntSetValueUint64(pkRsakey.au64PubExp[0], piExp);

    a_dispatch.SymCryptModExp(
        pkRsakey.pmModulus.?,
        peRes,
        piExp,
        a_dispatch.SymCryptIntBitsizeOfValue(piExp),
        types.SYMCRYPT_FLAG_DATA_PUBLIC,
        peRes,
        pbFnScratch,
        cbFnScratch,
    );

    scError = a_dispatch.SymCryptModElementGetValue(pkRsakey.pmModulus.?, peRes, pbDst, cbDst, numFormat, pbFnScratch, cbFnScratch);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    return scError;
}

pub export fn SymCryptRsaCoreDecCrtScratchSpace(pkRsakey: PCSYMCRYPT_RSAKEY) callconv(SYMCRYPT_CALL) UINT32 {
    var cbModElementTotal: UINT32 = 0;
    var nPrimes: UINT32 = pkRsakey.nPrimes;

    macros.SYMCRYPT_ASSERT(nPrimes <= types.SYMCRYPT_RSAKEY_MAX_NUMOF_PRIMES);
    nPrimes = @min(nPrimes, types.SYMCRYPT_RSAKEY_MAX_NUMOF_PRIMES);

    var i: UINT32 = 0;
    while (i < nPrimes) : (i += 1) {
        cbModElementTotal += types.SYMCRYPT_INTERNAL_SIZEOF_MODELEMENT_FROM_BITS(pkRsakey.nBitsOfPrimes[i]);
    }

    return 3 * a_dispatch.SymCryptSizeofIntFromDigits(pkRsakey.nDigitsOfModulus) +
        a_dispatch.SymCryptSizeofIntFromDigits(pkRsakey.nMaxDigitsOfPrimes) +
        cbModElementTotal +
        types.SYMCRYPT_INTERNAL_SIZEOF_MODELEMENT_FROM_BITS(pkRsakey.nBitsOfModulus) +
        @max(
            types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(pkRsakey.nDigitsOfModulus),
            @max(
                types.SYMCRYPT_SCRATCH_BYTES_FOR_MODEXP(pkRsakey.nDigitsOfModulus),
                @max(
                    types.SYMCRYPT_SCRATCH_BYTES_FOR_INT_DIVMOD(pkRsakey.nDigitsOfModulus, pkRsakey.nMaxDigitsOfPrimes),
                    types.SYMCRYPT_SCRATCH_BYTES_FOR_CRT_SOLUTION(pkRsakey.nMaxDigitsOfPrimes),
                ),
            ),
        );
}

pub export fn SymCryptRsaCoreDecScratchSpace(pkRsakey: PCSYMCRYPT_RSAKEY) callconv(SYMCRYPT_CALL) UINT32 {
    return a_dispatch.SymCryptSizeofModElementFromModulus(pkRsakey.pmModulus.?) +
        @max(
            types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(pkRsakey.nDigitsOfModulus),
            types.SYMCRYPT_SCRATCH_BYTES_FOR_MODEXP(pkRsakey.nDigitsOfModulus),
        );
}

pub export fn SymCryptRsaCoreDecCrt(
    pkRsakey: PCSYMCRYPT_RSAKEY,
    pbSrc: PCBYTE,
    cbSrc: SIZE_T,
    numFormat: SYMCRYPT_NUMBER_FORMAT,
    flags: UINT32,
    pbDst: PBYTE,
    cbDst: SIZE_T,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;

    var peCrtElements: [types.SYMCRYPT_RSAKEY_MAX_NUMOF_PRIMES]?PSYMCRYPT_MODELEMENT = .{ null, null };
    var cbModElements: [types.SYMCRYPT_RSAKEY_MAX_NUMOF_PRIMES]UINT32 = .{ 0, 0 };
    var cbModElementTotal: UINT32 = 0;

    _ = flags;

    if (pkRsakey.hasPrivateKey == 0) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    scError = SymCryptRsaCoreVerifyInput(pkRsakey, pbSrc, cbSrc, numFormat, cbDst, pbScratch, cbScratch);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    if (pkRsakey.nPrimes > types.SYMCRYPT_RSAKEY_MAX_NUMOF_PRIMES) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    const cbInt: UINT32 = a_dispatch.SymCryptSizeofIntFromDigits(pkRsakey.nDigitsOfModulus);
    const cbTmp: UINT32 = a_dispatch.SymCryptSizeofIntFromDigits(pkRsakey.nMaxDigitsOfPrimes);
    var i: UINT32 = 0;
    while (i < pkRsakey.nPrimes) : (i += 1) {
        cbModElements[i] = types.SYMCRYPT_INTERNAL_SIZEOF_MODELEMENT_FROM_BITS(pkRsakey.nBitsOfPrimes[i]);
        cbModElementTotal += cbModElements[i];
    }

    const cbModElementVerify: UINT32 = a_dispatch.SymCryptSizeofModElementFromModulus(pkRsakey.pmModulus.?);

    macros.SYMCRYPT_ASSERT(
        cbScratch >= 3 * cbInt + cbTmp + cbModElementTotal + cbModElementVerify +
            @max(
                types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(pkRsakey.nDigitsOfModulus),
                @max(
                    types.SYMCRYPT_SCRATCH_BYTES_FOR_MODEXP(pkRsakey.nDigitsOfModulus),
                    @max(
                        types.SYMCRYPT_SCRATCH_BYTES_FOR_INT_DIVMOD(pkRsakey.nDigitsOfModulus, pkRsakey.nMaxDigitsOfPrimes),
                        types.SYMCRYPT_SCRATCH_BYTES_FOR_CRT_SOLUTION(pkRsakey.nMaxDigitsOfPrimes),
                    ),
                ),
            ),
    );

    var pbFnScratch: PBYTE = pbScratch;
    var cbFnScratch: SIZE_T = cbScratch;

    const piPlaintext = a_dispatch.SymCryptIntCreate(pbFnScratch, cbFnScratch, pkRsakey.nDigitsOfModulus).?;
    pbFnScratch += cbInt;
    cbFnScratch -= cbInt;

    const piCiphertext = a_dispatch.SymCryptIntCreate(pbFnScratch, cbFnScratch, pkRsakey.nDigitsOfModulus).?;
    pbFnScratch += cbInt;
    cbFnScratch -= cbInt;

    const piTmp = a_dispatch.SymCryptIntCreate(pbFnScratch, cbFnScratch, pkRsakey.nMaxDigitsOfPrimes).?;
    pbFnScratch += cbTmp;
    cbFnScratch -= cbTmp;

    macros.SYMCRYPT_ASSERT(pkRsakey.nPrimes <= types.SYMCRYPT_RSAKEY_MAX_NUMOF_PRIMES);
    i = 0;
    while (i < pkRsakey.nPrimes) : (i += 1) {
        peCrtElements[i] = a_dispatch.SymCryptModElementCreate(pbFnScratch, cbFnScratch, pkRsakey.pmPrimes[i].?);
        macros.SYMCRYPT_ASSERT(peCrtElements[i] != null);
        pbFnScratch += cbModElements[i];
        cbFnScratch -= cbModElements[i];
    }

    const piVerify = a_dispatch.SymCryptIntCreate(pbFnScratch, cbFnScratch, pkRsakey.nDigitsOfModulus).?;
    pbFnScratch += cbInt;
    cbFnScratch -= cbInt;

    const peVerify = a_dispatch.SymCryptModElementCreate(pbFnScratch, cbFnScratch, pkRsakey.pmModulus.?).?;
    pbFnScratch += cbModElementVerify;
    cbFnScratch -= cbModElementVerify;

    scError = a_dispatch.SymCryptIntSetValue(pbSrc, cbSrc, numFormat, piCiphertext);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    i = 0;
    while (i < pkRsakey.nPrimes) : (i += 1) {
        a_dispatch.SymCryptIntDivMod(
            piCiphertext,
            a_dispatch.SymCryptDivisorFromModulus(pkRsakey.pmPrimes[i].?),
            null,
            piTmp,
            pbFnScratch,
            cbFnScratch,
        );

        a_dispatch.SymCryptIntToModElement(piTmp, pkRsakey.pmPrimes[i].?, peCrtElements[i].?, pbFnScratch, cbFnScratch);

        a_dispatch.SymCryptModExp(
            pkRsakey.pmPrimes[i].?,
            peCrtElements[i].?,
            pkRsakey.piCrtPrivExps[i].?,
            pkRsakey.nBitsOfPrimes[i],
            0,
            peCrtElements[i].?,
            pbFnScratch,
            cbFnScratch,
        );
    }

    scError = crt.SymCryptCrtSolve(
        pkRsakey.nPrimes,
        @ptrCast(&pkRsakey.pmPrimes[0]),
        @ptrCast(&pkRsakey.peCrtInverses[0]),
        @ptrCast(&peCrtElements[0]),
        0,
        piPlaintext,
        pbFnScratch,
        cbFnScratch,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    a_dispatch.SymCryptIntToModElement(piPlaintext, pkRsakey.pmModulus.?, peVerify, pbFnScratch, cbFnScratch);

    a_dispatch.SymCryptIntSetValueUint64(pkRsakey.au64PubExp[0], piTmp);

    a_dispatch.SymCryptModExp(
        pkRsakey.pmModulus.?,
        peVerify,
        piTmp,
        a_dispatch.SymCryptIntBitsizeOfValue(piTmp),
        types.SYMCRYPT_FLAG_DATA_PUBLIC,
        peVerify,
        pbFnScratch,
        cbFnScratch,
    );

    a_dispatch.SymCryptModElementToInt(pkRsakey.pmModulus.?, peVerify, piVerify, pbFnScratch, cbFnScratch);

    if (a_dispatch.SymCryptIntIsEqual(piCiphertext, piVerify) == 0) {
        return .SYMCRYPT_HARDWARE_FAILURE;
    }

    scError = a_dispatch.SymCryptIntGetValue(piPlaintext, pbDst, cbDst, numFormat);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    return scError;
}

pub export fn SymCryptRsaCoreDec(
    pkRsakey: PCSYMCRYPT_RSAKEY,
    pbSrc: PCBYTE,
    cbSrc: SIZE_T,
    numFormat: SYMCRYPT_NUMBER_FORMAT,
    flags: UINT32,
    pbDst: PBYTE,
    cbDst: SIZE_T,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;

    _ = flags;

    if ((cbSrc > rsakey.SymCryptRsakeySizeofModulus(pkRsakey)) or (pkRsakey.hasPrivateKey == 0)) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    const cbModElement: UINT32 = a_dispatch.SymCryptSizeofModElementFromModulus(pkRsakey.pmModulus.?);

    macros.SYMCRYPT_ASSERT(
        cbScratch >= cbModElement +
            @max(
                types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(pkRsakey.nDigitsOfModulus),
                types.SYMCRYPT_SCRATCH_BYTES_FOR_MODEXP(pkRsakey.nDigitsOfModulus),
            ),
    );

    var pbFnScratch: PBYTE = pbScratch;
    var cbFnScratch: SIZE_T = cbScratch;

    const peRes = a_dispatch.SymCryptModElementCreate(pbScratch, cbModElement, pkRsakey.pmModulus.?).?;
    pbFnScratch += cbModElement;
    cbFnScratch -= cbModElement;

    scError = a_dispatch.SymCryptModElementSetValue(pbSrc, cbSrc, numFormat, pkRsakey.pmModulus.?, peRes, pbFnScratch, cbFnScratch);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    a_dispatch.SymCryptModExp(
        pkRsakey.pmModulus.?,
        peRes,
        pkRsakey.piPrivExps[0].?,
        pkRsakey.nBitsOfModulus,
        0,
        peRes,
        pbFnScratch,
        cbFnScratch,
    );

    scError = a_dispatch.SymCryptModElementGetValue(pkRsakey.pmModulus.?, peRes, pbDst, cbDst, numFormat, pbFnScratch, cbFnScratch);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    return scError;
}

pub export fn SymCryptRsaRawEncrypt(
    pkRsakey: PCSYMCRYPT_RSAKEY,
    pbSrc: PCBYTE,
    cbSrc: SIZE_T,
    numFormat: SYMCRYPT_NUMBER_FORMAT,
    flags: UINT32,
    pbDst: PBYTE,
    cbDst: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    if ((pkRsakey.fAlgorithmInfo & types.SYMCRYPT_FLAG_RSAKEY_ENCRYPT) == 0) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    const cbScratch: UINT32 = SymCryptRsaCoreEncScratchSpace(pkRsakey);

    const pbScratch = SymCryptCallbackAlloc(cbScratch) orelse {
        return .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
    };
    defer {
        macros.SymCryptWipe(@ptrCast(pbScratch), cbScratch);
        SymCryptCallbackFree(@ptrCast(pbScratch));
    }

    return SymCryptRsaCoreEnc(pkRsakey, pbSrc, cbSrc, numFormat, flags, pbDst, cbDst, pbScratch, cbScratch);
}

pub export fn SymCryptRsaRawDecrypt(
    pkRsakey: PCSYMCRYPT_RSAKEY,
    pbSrc: PCBYTE,
    cbSrc: SIZE_T,
    numFormat: SYMCRYPT_NUMBER_FORMAT,
    flags: UINT32,
    pbDst: PBYTE,
    cbDst: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    if ((pkRsakey.fAlgorithmInfo & types.SYMCRYPT_FLAG_RSAKEY_ENCRYPT) == 0) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    if (pkRsakey.hasPrivateKey == 0) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    const cbScratch: UINT32 = SymCryptRsaCoreDecCrtScratchSpace(pkRsakey);

    const pbScratch = SymCryptCallbackAlloc(cbScratch) orelse {
        return .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
    };
    defer {
        macros.SymCryptWipe(@ptrCast(pbScratch), cbScratch);
        SymCryptCallbackFree(@ptrCast(pbScratch));
    }

    return SymCryptRsaCoreDecCrt(pkRsakey, pbSrc, cbSrc, numFormat, flags, pbDst, cbDst, pbScratch, cbScratch);
}

pub export fn SymCryptRsaPkcs1Encrypt(
    pkRsakey: PCSYMCRYPT_RSAKEY,
    pbSrc: ?PCBYTE,
    cbSrc: SIZE_T,
    flags: UINT32,
    nfDst: SYMCRYPT_NUMBER_FORMAT,
    pbDst: ?PBYTE,
    cbDst: SIZE_T,
    pcbDst: *SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;

    const cbTmp: SIZE_T = rsakey.SymCryptRsakeySizeofModulus(pkRsakey);
    const cbScratch: SIZE_T = cbTmp + SymCryptRsaCoreEncScratchSpace(pkRsakey);

    if ((pkRsakey.fAlgorithmInfo & types.SYMCRYPT_FLAG_RSAKEY_ENCRYPT) == 0) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    pcbDst.* = cbTmp;

    if (pbDst == null) {
        return .SYMCRYPT_NO_ERROR;
    }

    const pbScratch = SymCryptCallbackAlloc(cbScratch) orelse {
        return .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
    };
    defer {
        macros.SymCryptWipe(@ptrCast(pbScratch), cbScratch);
        SymCryptCallbackFree(@ptrCast(pbScratch));
    }

    const pbTmp: PBYTE = pbScratch + cbScratch - cbTmp;

    scError = rsa_padding.SymCryptRsaPkcs1ApplyEncryptionPadding(
        pbSrc,
        cbSrc,
        pbTmp,
        cbTmp,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    scError = SymCryptRsaCoreEnc(
        pkRsakey,
        pbTmp,
        cbTmp,
        .SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        flags,
        pbDst.?,
        cbDst,
        pbScratch,
        cbScratch - cbTmp,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    if (nfDst == .SYMCRYPT_NUMBER_FORMAT_LSB_FIRST) {
        return .SYMCRYPT_NOT_IMPLEMENTED;
    }

    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptRsaPkcs1Decrypt(
    pkRsakey: PCSYMCRYPT_RSAKEY,
    pbSrc: PCBYTE,
    cbSrc: SIZE_T,
    nfSrc: SYMCRYPT_NUMBER_FORMAT,
    flags: UINT32,
    pbDst: ?PBYTE,
    cbDst: SIZE_T,
    pcbDst: *SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;

    const cbModulus: SIZE_T = rsakey.SymCryptRsakeySizeofModulus(pkRsakey);
    const cbTmp: SIZE_T = scs_tools.SymCryptRoundUpPow2Sizet(cbModulus);

    if ((pkRsakey.fAlgorithmInfo & types.SYMCRYPT_FLAG_RSAKEY_ENCRYPT) == 0) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    if (pkRsakey.hasPrivateKey == 0) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    const cbScratch: SIZE_T = cbTmp + SymCryptRsaCoreDecCrtScratchSpace(pkRsakey);

    const pbScratch = SymCryptCallbackAlloc(cbScratch) orelse {
        return .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
    };
    defer {
        macros.SymCryptWipe(@ptrCast(pbScratch), cbScratch);
        SymCryptCallbackFree(@ptrCast(pbScratch));
    }

    const pbTmp: PBYTE = pbScratch + cbScratch - cbTmp;

    if (nfSrc == .SYMCRYPT_NUMBER_FORMAT_LSB_FIRST) {
        return .SYMCRYPT_NOT_IMPLEMENTED;
    }

    scError = SymCryptRsaCoreDecCrt(
        pkRsakey,
        pbSrc,
        cbSrc,
        .SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        flags,
        pbTmp,
        cbModulus,
        pbScratch,
        cbScratch - cbTmp,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    scError = rsa_padding.SymCryptRsaPkcs1RemoveEncryptionPadding(
        pbTmp,
        cbModulus,
        cbTmp,
        pbDst,
        cbDst,
        pcbDst,
    );

    return scError;
}

pub export fn SymCryptRsaOaepEncrypt(
    pkRsakey: PCSYMCRYPT_RSAKEY,
    pbSrc: ?PCBYTE,
    cbSrc: SIZE_T,
    hashAlgorithm: PCSYMCRYPT_HASH,
    pbLabel: ?PCBYTE,
    cbLabel: SIZE_T,
    flags: UINT32,
    nfDst: SYMCRYPT_NUMBER_FORMAT,
    pbDst: ?PBYTE,
    cbDst: SIZE_T,
    pcbDst: *SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;

    const cbTmp: SIZE_T = rsakey.SymCryptRsakeySizeofModulus(pkRsakey);

    if ((pkRsakey.fAlgorithmInfo & types.SYMCRYPT_FLAG_RSAKEY_ENCRYPT) == 0) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    pcbDst.* = cbTmp;

    if (pbDst == null) {
        return .SYMCRYPT_NO_ERROR;
    }

    const cbScratch: SIZE_T = cbTmp + @max(
        types.SYMCRYPT_INTERNAL_SCRATCH_BYTES_FOR_RSA_OAEP(hashAlgorithm, cbTmp),
        @as(SIZE_T, SymCryptRsaCoreEncScratchSpace(pkRsakey)),
    );
    const pbScratch = SymCryptCallbackAlloc(cbScratch) orelse {
        return .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
    };
    defer {
        macros.SymCryptWipe(@ptrCast(pbScratch), cbScratch);
        SymCryptCallbackFree(@ptrCast(pbScratch));
    }

    const pbTmp: PBYTE = pbScratch + cbScratch - cbTmp;

    scError = rsa_padding.SymCryptRsaOaepApplyEncryptionPadding(
        pbSrc,
        cbSrc,
        hashAlgorithm,
        pbLabel,
        cbLabel,
        null,
        0,
        pbTmp,
        cbTmp,
        pbScratch,
        cbScratch - cbTmp,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    scError = SymCryptRsaCoreEnc(
        pkRsakey,
        pbTmp,
        cbTmp,
        .SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        flags,
        pbDst.?,
        cbDst,
        pbScratch,
        cbScratch - cbTmp,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    if (nfDst == .SYMCRYPT_NUMBER_FORMAT_LSB_FIRST) {
        return .SYMCRYPT_NOT_IMPLEMENTED;
    }

    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptRsaOaepDecrypt(
    pkRsakey: PCSYMCRYPT_RSAKEY,
    pbSrc: PCBYTE,
    cbSrc: SIZE_T,
    nfSrc: SYMCRYPT_NUMBER_FORMAT,
    hashAlgorithm: PCSYMCRYPT_HASH,
    pbLabel: ?PCBYTE,
    cbLabel: SIZE_T,
    flags: UINT32,
    pbDst: ?PBYTE,
    cbDst: SIZE_T,
    pcbDst: *SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;
    var cbDstResult: SIZE_T = 0;
    defer pcbDst.* = cbDstResult;

    const cbTmp: SIZE_T = rsakey.SymCryptRsakeySizeofModulus(pkRsakey);

    if ((pkRsakey.fAlgorithmInfo & types.SYMCRYPT_FLAG_RSAKEY_ENCRYPT) == 0) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    if (cbSrc > cbTmp) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    if (pkRsakey.hasPrivateKey == 0) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    const cbScratch: SIZE_T = cbTmp + @max(
        types.SYMCRYPT_INTERNAL_SCRATCH_BYTES_FOR_RSA_OAEP(hashAlgorithm, cbSrc),
        @as(SIZE_T, SymCryptRsaCoreDecCrtScratchSpace(pkRsakey)),
    );

    const pbScratch = SymCryptCallbackAlloc(cbScratch) orelse {
        return .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
    };
    defer {
        macros.SymCryptWipe(@ptrCast(pbScratch), cbScratch);
        SymCryptCallbackFree(@ptrCast(pbScratch));
    }

    const pbTmp: PBYTE = pbScratch + cbScratch - cbTmp;

    if (nfSrc == .SYMCRYPT_NUMBER_FORMAT_LSB_FIRST) {
        return .SYMCRYPT_NOT_IMPLEMENTED;
    }

    scError = SymCryptRsaCoreDecCrt(
        pkRsakey,
        pbSrc,
        cbSrc,
        .SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        flags,
        pbTmp,
        cbTmp,
        pbScratch,
        cbScratch - cbTmp,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    scError = rsa_padding.SymCryptRsaOaepRemoveEncryptionPadding(
        pbTmp,
        cbTmp,
        hashAlgorithm,
        pbLabel,
        cbLabel,
        flags,
        pbDst,
        cbDst,
        &cbDstResult,
        pbScratch,
        cbScratch - cbTmp,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptRsaPkcs1Sign(
    pkRsakey: PCSYMCRYPT_RSAKEY,
    pbHashValue: ?PCBYTE,
    cbHashValue: SIZE_T,
    pHashOIDs: ?PCSYMCRYPT_OID,
    nOIDCount: SIZE_T,
    flags: UINT32,
    nfSignature: SYMCRYPT_NUMBER_FORMAT,
    pbSignature: ?PBYTE,
    cbSignature: SIZE_T,
    pcbSignature: *SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;

    const cbTmp: SIZE_T = rsakey.SymCryptRsakeySizeofModulus(pkRsakey);

    _ = nOIDCount;

    const pbOID: ?PCBYTE = if (pHashOIDs) |oid| oid.pbOID else null;
    const cbOID: SIZE_T = if (pHashOIDs) |oid| oid.cbOID else 0;

    if ((pkRsakey.fAlgorithmInfo & types.SYMCRYPT_FLAG_RSAKEY_SIGN) == 0) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    if (pkRsakey.hasPrivateKey == 0) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    pcbSignature.* = cbTmp;

    if (pbSignature == null) {
        return .SYMCRYPT_NO_ERROR;
    }

    const cbScratch: SIZE_T = cbTmp + SymCryptRsaCoreDecCrtScratchSpace(pkRsakey);

    const pbScratch = SymCryptCallbackAlloc(cbScratch) orelse {
        return .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
    };
    defer {
        macros.SymCryptWipe(@ptrCast(pbScratch), cbScratch);
        SymCryptCallbackFree(@ptrCast(pbScratch));
    }

    const pbTmp: PBYTE = pbScratch + cbScratch - cbTmp;

    scError = rsa_padding.SymCryptRsaPkcs1ApplySignaturePadding(
        pbHashValue,
        cbHashValue,
        pbOID,
        cbOID,
        flags,
        pbTmp,
        cbTmp,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    scError = SymCryptRsaCoreDecCrt(
        pkRsakey,
        pbTmp,
        cbTmp,
        .SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        flags,
        pbSignature.?,
        cbSignature,
        pbScratch,
        cbScratch - cbTmp,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    if (nfSignature == .SYMCRYPT_NUMBER_FORMAT_LSB_FIRST) {
        return .SYMCRYPT_NOT_IMPLEMENTED;
    }

    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptRsaPkcs1Verify(
    pkRsakey: PCSYMCRYPT_RSAKEY,
    pbHashValue: ?PCBYTE,
    cbHashValue: SIZE_T,
    pbSignature: PCBYTE,
    cbSignature: SIZE_T,
    nfSignature: SYMCRYPT_NUMBER_FORMAT,
    pHashOIDs: ?[*]const SYMCRYPT_OID,
    nOIDCount: SIZE_T,
    flags: UINT32,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;

    const cbTmp: SIZE_T = rsakey.SymCryptRsakeySizeofModulus(pkRsakey);

    if ((pkRsakey.fAlgorithmInfo & types.SYMCRYPT_FLAG_RSAKEY_SIGN) == 0) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    if (cbSignature > cbTmp) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    if (nfSignature == .SYMCRYPT_NUMBER_FORMAT_LSB_FIRST) {
        return .SYMCRYPT_NOT_IMPLEMENTED;
    }

    const cbScratch: SIZE_T = cbTmp +
        @max(
            @as(SIZE_T, SymCryptRsaCoreEncScratchSpace(pkRsakey)),
            types.SYMCRYPT_INTERNAL_SCRATCH_BYTES_FOR_RSA_PKCS1(cbTmp),
        );

    const pbScratch = SymCryptCallbackAlloc(cbScratch) orelse {
        return .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
    };
    defer {
        macros.SymCryptWipe(@ptrCast(pbScratch), cbScratch);
        SymCryptCallbackFree(@ptrCast(pbScratch));
    }

    const pbTmp: PBYTE = pbScratch + cbScratch - cbTmp;

    scError = SymCryptRsaCoreEnc(
        pkRsakey,
        pbSignature,
        cbSignature,
        .SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        flags,
        pbTmp,
        cbTmp,
        pbScratch,
        cbScratch - cbTmp,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    scError = rsa_padding.SymCryptRsaPkcs1VerifySignaturePadding(
        pbHashValue,
        cbHashValue,
        pHashOIDs,
        nOIDCount,
        pbTmp,
        cbTmp,
        flags,
        pbScratch,
        cbScratch - cbTmp,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptRsaPssSign(
    pkRsakey: PCSYMCRYPT_RSAKEY,
    pbHashValue: ?PCBYTE,
    cbHashValue: SIZE_T,
    hashAlgorithm: PCSYMCRYPT_HASH,
    cbSalt: SIZE_T,
    flags: UINT32,
    nfSignature: SYMCRYPT_NUMBER_FORMAT,
    pbSignature: ?PBYTE,
    cbSignature: SIZE_T,
    pcbSignature: *SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;

    const cbTmp: SIZE_T = rsakey.SymCryptRsakeySizeofModulus(pkRsakey);

    if ((pkRsakey.fAlgorithmInfo & types.SYMCRYPT_FLAG_RSAKEY_SIGN) == 0) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    if ((cbHashValue > cbTmp) or (cbSalt > cbTmp)) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    if (pkRsakey.hasPrivateKey == 0) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    pcbSignature.* = cbTmp;

    if (pbSignature == null) {
        return .SYMCRYPT_NO_ERROR;
    }

    const cbScratch: SIZE_T = cbTmp +
        @max(
            @as(SIZE_T, SymCryptRsaCoreDecCrtScratchSpace(pkRsakey)),
            types.SYMCRYPT_INTERNAL_SCRATCH_BYTES_FOR_RSA_PSS(hashAlgorithm, cbHashValue, cbTmp),
        );

    const pbScratch = SymCryptCallbackAlloc(cbScratch) orelse {
        return .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
    };
    defer {
        macros.SymCryptWipe(@ptrCast(pbScratch), cbScratch);
        SymCryptCallbackFree(@ptrCast(pbScratch));
    }

    const pbTmp: PBYTE = pbScratch + cbScratch - cbTmp;

    scError = rsa_padding.SymCryptRsaPssApplySignaturePadding(
        pbHashValue,
        cbHashValue,
        hashAlgorithm,
        null,
        cbSalt,
        pkRsakey.nBitsOfModulus,
        flags,
        pbTmp,
        cbTmp,
        pbScratch,
        cbScratch - cbTmp,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    scError = SymCryptRsaCoreDecCrt(
        pkRsakey,
        pbTmp,
        cbTmp,
        .SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        flags,
        pbSignature.?,
        cbSignature,
        pbScratch,
        cbScratch - cbTmp,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    if (nfSignature == .SYMCRYPT_NUMBER_FORMAT_LSB_FIRST) {
        return .SYMCRYPT_NOT_IMPLEMENTED;
    }

    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptRsaPssVerify(
    pkRsakey: PCSYMCRYPT_RSAKEY,
    pbHashValue: ?PCBYTE,
    cbHashValue: SIZE_T,
    pbSignature: PCBYTE,
    cbSignature: SIZE_T,
    nfSignature: SYMCRYPT_NUMBER_FORMAT,
    hashAlgorithm: PCSYMCRYPT_HASH,
    cbSalt: SIZE_T,
    flags: UINT32,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;

    const cbTmp: SIZE_T = rsakey.SymCryptRsakeySizeofModulus(pkRsakey);

    if ((pkRsakey.fAlgorithmInfo & types.SYMCRYPT_FLAG_RSAKEY_SIGN) == 0) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    if ((cbHashValue > cbTmp) or (cbSalt > cbTmp) or (cbSignature > cbTmp)) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    if (nfSignature == .SYMCRYPT_NUMBER_FORMAT_LSB_FIRST) {
        return .SYMCRYPT_NOT_IMPLEMENTED;
    }

    const cbScratch: SIZE_T = cbTmp +
        @max(
            @as(SIZE_T, SymCryptRsaCoreEncScratchSpace(pkRsakey)),
            types.SYMCRYPT_INTERNAL_SCRATCH_BYTES_FOR_RSA_PSS(hashAlgorithm, cbHashValue, cbTmp),
        );

    const pbScratch = SymCryptCallbackAlloc(cbScratch) orelse {
        return .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
    };
    defer {
        macros.SymCryptWipe(@ptrCast(pbScratch), cbScratch);
        SymCryptCallbackFree(@ptrCast(pbScratch));
    }

    const pbTmp: PBYTE = pbScratch + cbScratch - cbTmp;

    scError = SymCryptRsaCoreEnc(
        pkRsakey,
        pbSignature,
        cbSignature,
        .SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        flags,
        pbTmp,
        cbTmp,
        pbScratch,
        cbScratch - cbTmp,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    scError = rsa_padding.SymCryptRsaPssVerifySignaturePadding(
        pbHashValue,
        cbHashValue,
        hashAlgorithm,
        cbSalt,
        pbTmp,
        cbTmp,
        pkRsakey.nBitsOfModulus,
        flags,
        pbScratch,
        cbScratch - cbTmp,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    return .SYMCRYPT_NO_ERROR;
}
