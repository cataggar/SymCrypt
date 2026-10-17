//
// ec_dsa.zig   ECDSA functions
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

const types = @import("types.zig");
const macros = @import("macros.zig");
const a_dispatch = @import("a_dispatch.zig");
const fips_selftest = @import("fips_selftest.zig");
const ecurve = @import("ecurve.zig");
const ecpoint = @import("ecpoint.zig");
const ec_dispatch = @import("ec_dispatch.zig");

extern fn SymCryptCallbackAlloc(cbData: SIZE_T) callconv(SYMCRYPT_CALL) ?PBYTE;
extern fn SymCryptCallbackFree(pMem: *anyopaque) callconv(SYMCRYPT_CALL) void;

const PBYTE = types.PBYTE;
const PCBYTE = types.PCBYTE;
const UINT32 = types.UINT32;
const SIZE_T = types.SIZE_T;
const BOOLEAN = types.BOOLEAN;
const SYMCRYPT_CALL = types.SYMCRYPT_CALL;
const SYMCRYPT_ERROR = types.SYMCRYPT_ERROR;
const SYMCRYPT_NUMBER_FORMAT = types.SYMCRYPT_NUMBER_FORMAT;
const PCSYMCRYPT_ECURVE = types.PCSYMCRYPT_ECURVE;
const PSYMCRYPT_ECPOINT = types.PSYMCRYPT_ECPOINT;
const PCSYMCRYPT_ECPOINT = types.PCSYMCRYPT_ECPOINT;
const PCSYMCRYPT_ECKEY = types.PCSYMCRYPT_ECKEY;
const PSYMCRYPT_INT = types.PSYMCRYPT_INT;
const PCSYMCRYPT_INT = types.PCSYMCRYPT_INT;
const PSYMCRYPT_MODELEMENT = types.PSYMCRYPT_MODELEMENT;

const SYMCRYPT_MAX_ECDSA_SIGNATURE_COUNT: UINT32 = 100;

pub export fn SymCryptEcDsaTruncateHash(
    pCurve: PCSYMCRYPT_ECURVE,
    pbHashValue: PCBYTE,
    cbHashValue_in: SIZE_T,
    flags: UINT32,
    peMsghash: PSYMCRYPT_MODELEMENT,
    piTmp: PSYMCRYPT_INT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    @setRuntimeSafety(false);
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;
    var cbHashValue = cbHashValue_in;

    // Make sure that only the correct flags are set
    if ((flags & ~types.SYMCRYPT_FLAG_ECDSA_NO_TRUNCATION) != 0) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    // Get the bitsize of the group order
    const uiBitsizeOfGroup: UINT32 = ecurve.SymCryptEcurveBitsizeofGroupOrder(pCurve);

    // Truncate the last bytes of the hash
    if (cbHashValue * 8 > uiBitsizeOfGroup) {
        cbHashValue = (uiBitsizeOfGroup + 7) / 8;
    }

    // Get the value of msghash
    scError = a_dispatch.SymCryptIntSetValue(pbHashValue, cbHashValue, .SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, piTmp);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    // Get the bit size of the hash
    const uiBitsizeOfTmp: UINT32 = @as(UINT32, @truncate(cbHashValue)) * 8;

    // If SYMCRYPT_FLAG_ECDSA_NO_TRUNCATION is set, we don't do hash truncation.
    // The caller can do their own truncation before calling into Symcrypt.
    if ((flags & types.SYMCRYPT_FLAG_ECDSA_NO_TRUNCATION) == 0) {
        // ******** Standard truncation **************
        // Shift right if needed
        if (uiBitsizeOfTmp > uiBitsizeOfGroup) {
            a_dispatch.SymCryptIntDivPow2(piTmp, uiBitsizeOfTmp - uiBitsizeOfGroup, piTmp);
        }
    }

    a_dispatch.SymCryptIntToModElement(piTmp, pCurve.GOrd, peMsghash, pbScratch, cbScratch); // msghash mod r

    return scError;
}

pub export fn SymCryptEcDsaSignEx(
    pKey: PCSYMCRYPT_ECKEY,
    pbHashValue: PCBYTE,
    cbHashValue: SIZE_T,
    piK: ?PCSYMCRYPT_INT,
    format: SYMCRYPT_NUMBER_FORMAT,
    flags: UINT32,
    pbSignature: PBYTE,
    cbSignature: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    @setRuntimeSafety(false);
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;
    var pbScratch: ?PBYTE = null;
    var cbScratch: SIZE_T = 0;

    const pCurve: PCSYMCRYPT_ECURVE = pKey.pCurve;

    var signatureCount: UINT32 = 0;
    const allowedFlags: UINT32 = types.SYMCRYPT_FLAG_ECDSA_NO_TRUNCATION | types.SYMCRYPT_FLAG_DATA_PUBLIC;
    const publicFlag: UINT32 = flags & types.SYMCRYPT_FLAG_DATA_PUBLIC;
    const truncationFlag: UINT32 = flags & types.SYMCRYPT_FLAG_ECDSA_NO_TRUNCATION;

    defer {
        if (pbScratch) |ptr| {
            macros.SymCryptWipe(@ptrCast(ptr), cbScratch);
            SymCryptCallbackFree(@ptrCast(ptr));
        }
        if (scError != .SYMCRYPT_NO_ERROR) {
            macros.SymCryptWipe(@ptrCast(pbSignature), cbSignature);
        }
    }

    // Make sure that the key may be used in ECDSA
    if ((pKey.fAlgorithmInfo & types.SYMCRYPT_FLAG_ECKEY_ECDSA) == 0) {
        scError = .SYMCRYPT_INVALID_ARGUMENT;
        return scError;
    }

    // Make sure only allowed flags are specified and
    // there is a private key
    if (((flags & ~allowedFlags) != 0) or (pKey.hasPrivateKey == 0)) {
        scError = .SYMCRYPT_INVALID_ARGUMENT;
        return scError;
    }

    // Calculating the digits for the temporary integers
    const nDigitsInt: UINT32 = pCurve.GOrdDigits;
    const nDigitsMul: UINT32 = ecurve.SymCryptEcurveDigitsofScalarMultiplier(pCurve);

    // Objects and scratch space size calculation
    const cbInt: UINT32 = a_dispatch.SymCryptSizeofIntFromDigits(nDigitsInt);
    const cbMul: UINT32 = a_dispatch.SymCryptSizeofIntFromDigits(nDigitsMul);
    const cbKG: UINT32 = ecpoint.SymCryptSizeofEcpointFromCurve(pCurve);
    const cbRs: UINT32 = a_dispatch.SymCryptSizeofModElementFromModulus(pCurve.GOrd);
    const cbX: UINT32 = ecurve.SymCryptEcurveSizeofFieldElement(pCurve);

    var cbScratchInternal: SIZE_T = types.SYMCRYPT_SCRATCH_BYTES_FOR_SCALAR_ECURVE_OPERATIONS(pCurve, 1);
    cbScratchInternal = @max(cbScratchInternal, types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(pCurve.GOrdDigits));
    cbScratchInternal = @max(cbScratchInternal, types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(pCurve.FModDigits));
    cbScratchInternal = @max(cbScratchInternal, types.SYMCRYPT_SCRATCH_BYTES_FOR_MODINV(pCurve.GOrdDigits));
    cbScratchInternal = @max(cbScratchInternal, types.SYMCRYPT_SCRATCH_BYTES_FOR_GETSET_VALUE_ECURVE_OPERATIONS(pCurve));

    cbScratch = cbScratchInternal + cbInt + cbMul + cbKG + 4 * cbRs + cbX;

    // Scratch space allocation
    pbScratch = SymCryptCallbackAlloc(cbScratch) orelse {
        scError = .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
        return scError;
    };

    // Creating temporaries
    var pCurr: PBYTE = pbScratch.? + cbScratchInternal;
    const piTmp: PSYMCRYPT_INT = a_dispatch.SymCryptIntCreate(pCurr, cbInt, nDigitsInt).?;
    pCurr += cbInt;
    const piMul: PSYMCRYPT_INT = a_dispatch.SymCryptIntCreate(pCurr, cbMul, nDigitsMul).?;
    pCurr += cbMul;
    const poKG: PSYMCRYPT_ECPOINT = ecpoint.SymCryptEcpointCreate(pCurr, cbKG, pCurve).?;
    pCurr += cbKG;
    const peMsghash: PSYMCRYPT_MODELEMENT = a_dispatch.SymCryptModElementCreate(pCurr, cbRs, pCurve.GOrd).?;
    pCurr += cbRs;
    const peSigC: PSYMCRYPT_MODELEMENT = a_dispatch.SymCryptModElementCreate(pCurr, cbRs, pCurve.GOrd).?;
    pCurr += cbRs;
    const peSigD: PSYMCRYPT_MODELEMENT = a_dispatch.SymCryptModElementCreate(pCurr, cbRs, pCurve.GOrd).?;
    pCurr += cbRs;
    const peTmp: PSYMCRYPT_MODELEMENT = a_dispatch.SymCryptModElementCreate(pCurr, cbRs, pCurve.GOrd).?;
    pCurr += cbRs;
    const pbX: PBYTE = pCurr;

    // Truncate the message according to the flags
    scError = SymCryptEcDsaTruncateHash(
        pCurve,
        pbHashValue,
        cbHashValue,
        truncationFlag,
        peMsghash,
        piTmp,
        pbScratch.?,
        cbScratchInternal,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    //
    // Main loop: Stop when both c and d are not zero (unless a specific k is provided)
    //
    while (true) {
        if (piK == null) {
            ec_dispatch.SymCryptEcpointSetRandom(pCurve, piMul, poKG, pbScratch.?, cbScratchInternal);
            a_dispatch.SymCryptIntToModElement(piMul, pCurve.GOrd, peTmp, pbScratch.?, cbScratchInternal);
        } else {
            const k = piK.?;
            // Ensure that piK is in the range [1, GOrd-1]
            if (a_dispatch.SymCryptIntIsEqualUint32(k, 0) != 0 or
                a_dispatch.SymCryptIntIsLessThan(k, a_dispatch.SymCryptIntFromModulus(pCurve.GOrd)) == 0)
            {
                scError = .SYMCRYPT_INVALID_ARGUMENT;
                return scError;
            }

            a_dispatch.SymCryptIntCopy(k, piMul);
            a_dispatch.SymCryptIntToModElement(piMul, pCurve.GOrd, peTmp, pbScratch.?, cbScratchInternal);

            scError = ec_dispatch.SymCryptEcpointScalarMul(pCurve, piMul, null, 0, poKG, pbScratch.?, cbScratchInternal);
            if (scError != .SYMCRYPT_NO_ERROR) {
                return scError;
            }
        }

        scError = a_dispatch.SymCryptModInv(pCurve.GOrd, peTmp, peTmp, publicFlag, pbScratch.?, cbScratchInternal);
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }

        // Get the x coordinates from KG
        scError = ecpoint.SymCryptEcpointGetValue(
            pCurve,
            poKG,
            .SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            .SYMCRYPT_ECPOINT_FORMAT_X,
            pbX,
            cbX,
            publicFlag,
            pbScratch.?,
            cbScratchInternal,
        );
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }

        // Store c = x(KG) as an integer
        scError = a_dispatch.SymCryptModElementSetValue(
            pbX,
            cbX,
            .SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            pCurve.GOrd,
            peSigC,
            pbScratch.?,
            cbScratch,
        );
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }

        // Move the private key into peSigD
        a_dispatch.SymCryptIntToModElement(pKey.piPrivateKey, pCurve.GOrd, peSigD, pbScratch.?, cbScratchInternal);

        // Multiply the private key by h since its internal format is "DivH"
        var i: UINT32 = 0;
        while (i < pCurve.coFactorPower) : (i += 1) {
            a_dispatch.SymCryptModAdd(pCurve.GOrd, peSigD, peSigD, peSigD, pbScratch.?, cbScratchInternal);
        }

        a_dispatch.SymCryptModMul(pCurve.GOrd, peSigC, peSigD, peSigD, pbScratch.?, cbScratchInternal); // s * c
        a_dispatch.SymCryptModAdd(pCurve.GOrd, peMsghash, peSigD, peSigD, pbScratch.?, cbScratchInternal); // msghash + s*c
        a_dispatch.SymCryptModMul(pCurve.GOrd, peSigD, peTmp, peSigD, pbScratch.?, cbScratchInternal); // ( msghash + s*c ) / k

        if ((a_dispatch.SymCryptModElementIsZero(pCurve.GOrd, peSigC) |
            a_dispatch.SymCryptModElementIsZero(pCurve.GOrd, peSigD)) == 0)
        {
            break;
        }

        if (piK != null) {
            scError = .SYMCRYPT_INVALID_ARGUMENT;
            return scError;
        }

        signatureCount += 1;
        if (signatureCount >= SYMCRYPT_MAX_ECDSA_SIGNATURE_COUNT) {
            scError = .SYMCRYPT_INVALID_ARGUMENT;
            return scError;
        }
    }

    // Output c
    scError = a_dispatch.SymCryptModElementGetValue(
        pCurve.GOrd,
        peSigC,
        pbSignature,
        cbSignature / 2,
        format,
        pbScratch.?,
        cbScratchInternal,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    // Output d
    scError = a_dispatch.SymCryptModElementGetValue(
        pCurve.GOrd,
        peSigD,
        pbSignature + cbSignature / 2,
        cbSignature / 2,
        format,
        pbScratch.?,
        cbScratchInternal,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    return scError;
}

pub export fn SymCryptEcDsaSign(
    pKey: PCSYMCRYPT_ECKEY,
    pbHashValue: PCBYTE,
    cbHashValue: SIZE_T,
    format: SYMCRYPT_NUMBER_FORMAT,
    flags: UINT32,
    pbSignature: PBYTE,
    cbSignature: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    @setRuntimeSafety(false);
    // Make sure that only the correct flags are set
    if ((flags & ~types.SYMCRYPT_FLAG_ECDSA_NO_TRUNCATION) != 0) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    // We must have a private key to perform PCT or signature
    if (pKey.hasPrivateKey == 0 or (pKey.fAlgorithmInfo & types.SYMCRYPT_FLAG_ECKEY_ECDSA) == 0) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    // If the key was generated in SymCrypt and has not yet had a PCT performed - perform PCT before first use
    if ((pKey.fAlgorithmInfo & (fips_selftest.SYMCRYPT_PCT_ECDSA | fips_selftest.SYMCRYPT_FLAG_KEY_NO_FIPS)) == 0) {
        fips_selftest.SYMCRYPT_FIPS_ASSERT(fips_selftest.SymCryptEcDsaPct(@ptrCast(pKey)) == .SYMCRYPT_NO_ERROR);
        _ = @atomicRmw(UINT32, &@constCast(pKey).fAlgorithmInfo, .Or, fips_selftest.SYMCRYPT_PCT_ECDSA, .monotonic);
    }

    return SymCryptEcDsaSignEx(pKey, pbHashValue, cbHashValue, null, format, flags, pbSignature, cbSignature);
}

pub export fn SymCryptEcDsaVerify(
    pKey: PCSYMCRYPT_ECKEY,
    pbHashValue: PCBYTE,
    cbHashValue: SIZE_T,
    pbSignature: PCBYTE,
    cbSignature: SIZE_T,
    format: SYMCRYPT_NUMBER_FORMAT,
    flags: UINT32,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    @setRuntimeSafety(false);
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;
    var pbScratch: ?PBYTE = null;
    var cbScratch: SIZE_T = 0;
    var fValidSignature: BOOLEAN = types.FALSE;

    const pCurve: PCSYMCRYPT_ECURVE = pKey.pCurve;

    var poTable: [2]?PCSYMCRYPT_ECPOINT = .{ null, null };
    var piTable: [2]PCSYMCRYPT_INT = undefined;

    defer {
        if (pbScratch) |ptr| {
            macros.SymCryptWipe(@ptrCast(ptr), cbScratch);
            SymCryptCallbackFree(@ptrCast(ptr));
        }
    }

    // Make sure that the key may be used in ECDSA
    if ((pKey.fAlgorithmInfo & types.SYMCRYPT_FLAG_ECKEY_ECDSA) == 0) {
        return .SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE;
    }

    // Make sure that only the correct flags are set
    if ((flags & ~types.SYMCRYPT_FLAG_ECDSA_NO_TRUNCATION) != 0) {
        return .SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE;
    }

    // Calculating the digits for the temporary integer
    var nDigitsInt: UINT32 = @max(pCurve.FModDigits, pCurve.GOrdDigits);
    nDigitsInt = @max(nDigitsInt, a_dispatch.SymCryptDigitsFromBits(@as(UINT32, @truncate(cbSignature)) * 4));

    const nDigitsMul: UINT32 = ecurve.SymCryptEcurveDigitsofScalarMultiplier(pCurve);

    // Objects and scratch space size calculation
    const cbInt: UINT32 = a_dispatch.SymCryptSizeofIntFromDigits(nDigitsInt);
    const cbMul: UINT32 = a_dispatch.SymCryptSizeofIntFromDigits(nDigitsMul);
    const cbKG: UINT32 = ecpoint.SymCryptSizeofEcpointFromCurve(pCurve);
    const cbRs: UINT32 = a_dispatch.SymCryptSizeofModElementFromModulus(pCurve.GOrd);
    const cbX: UINT32 = ecurve.SymCryptEcurveSizeofFieldElement(pCurve);

    var cbScratchInternal: SIZE_T = types.SYMCRYPT_SCRATCH_BYTES_FOR_SCALAR_ECURVE_OPERATIONS(pCurve, 2);
    cbScratchInternal = @max(cbScratchInternal, types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(pCurve.GOrdDigits));
    cbScratchInternal = @max(cbScratchInternal, types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(pCurve.FModDigits));
    cbScratchInternal = @max(cbScratchInternal, types.SYMCRYPT_SCRATCH_BYTES_FOR_MODINV(pCurve.GOrdDigits));
    cbScratchInternal = @max(cbScratchInternal, types.SYMCRYPT_SCRATCH_BYTES_FOR_GETSET_VALUE_ECURVE_OPERATIONS(pCurve));
    cbScratchInternal = @max(cbScratchInternal, types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_ECURVE_OPERATIONS(pCurve));

    cbScratch = cbScratchInternal + cbInt + 2 * cbMul + 2 * cbKG + 4 * cbRs + cbX;

    // Scratch space allocation
    pbScratch = SymCryptCallbackAlloc(cbScratch) orelse {
        return .SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE;
    };

    // Creating temporaries
    var pCurr: PBYTE = pbScratch.? + cbScratchInternal;
    const piTmp: PSYMCRYPT_INT = a_dispatch.SymCryptIntCreate(pCurr, cbInt, nDigitsInt).?;
    pCurr += cbInt;
    const piMul1: PSYMCRYPT_INT = a_dispatch.SymCryptIntCreate(pCurr, cbMul, nDigitsMul).?;
    pCurr += cbMul;
    const piMul2: PSYMCRYPT_INT = a_dispatch.SymCryptIntCreate(pCurr, cbMul, nDigitsMul).?;
    pCurr += cbMul;
    const poQ1: PSYMCRYPT_ECPOINT = ecpoint.SymCryptEcpointCreate(pCurr, cbKG, pCurve).?;
    pCurr += cbKG;
    const poQ2: PSYMCRYPT_ECPOINT = ecpoint.SymCryptEcpointCreate(pCurr, cbKG, pCurve).?;
    _ = poQ2;
    pCurr += cbKG;
    const peMsghash: PSYMCRYPT_MODELEMENT = a_dispatch.SymCryptModElementCreate(pCurr, cbRs, pCurve.GOrd).?;
    pCurr += cbRs;
    const peSigC: PSYMCRYPT_MODELEMENT = a_dispatch.SymCryptModElementCreate(pCurr, cbRs, pCurve.GOrd).?;
    pCurr += cbRs;
    const peSigD: PSYMCRYPT_MODELEMENT = a_dispatch.SymCryptModElementCreate(pCurr, cbRs, pCurve.GOrd).?;
    pCurr += cbRs;
    const peTmp: PSYMCRYPT_MODELEMENT = a_dispatch.SymCryptModElementCreate(pCurr, cbRs, pCurve.GOrd).?;
    pCurr += cbRs;
    const pbX: PBYTE = pCurr;

    // Get c
    scError = a_dispatch.SymCryptIntSetValue(pbSignature, cbSignature / 2, format, piTmp);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return .SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE;
    }

    // Check if c is less than r
    if (a_dispatch.SymCryptIntIsLessThan(piTmp, a_dispatch.SymCryptIntFromModulus(pCurve.GOrd)) == 0) {
        return .SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE;
    }

    // c mod r
    a_dispatch.SymCryptIntToModElement(piTmp, pCurve.GOrd, peSigC, pbScratch.?, cbScratchInternal);

    // Check if c is zero
    if (a_dispatch.SymCryptModElementIsZero(pCurve.GOrd, peSigC) != 0) {
        return .SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE;
    }

    // Get d
    scError = a_dispatch.SymCryptIntSetValue(pbSignature + cbSignature / 2, cbSignature / 2, format, piTmp);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return .SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE;
    }

    // Check if d is less than r
    if (a_dispatch.SymCryptIntIsLessThan(piTmp, a_dispatch.SymCryptIntFromModulus(pCurve.GOrd)) == 0) {
        return .SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE;
    }

    // d mod r
    a_dispatch.SymCryptIntToModElement(piTmp, pCurve.GOrd, peSigD, pbScratch.?, cbScratchInternal);

    // Check if d is zero
    if (a_dispatch.SymCryptModElementIsZero(pCurve.GOrd, peSigD) != 0) {
        return .SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE;
    }

    // Calculate 1/d mod r
    scError = a_dispatch.SymCryptModInv(pCurve.GOrd, peSigD, peSigD, types.SYMCRYPT_FLAG_DATA_PUBLIC, pbScratch.?, cbScratchInternal);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return .SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE;
    }

    // Truncate the message according to the flags
    scError = SymCryptEcDsaTruncateHash(
        pCurve,
        pbHashValue,
        cbHashValue,
        flags,
        peMsghash,
        piTmp,
        pbScratch.?,
        cbScratchInternal,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return .SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE;
    }

    a_dispatch.SymCryptModMul(pCurve.GOrd, peMsghash, peSigD, peMsghash, pbScratch.?, cbScratchInternal); // msghash / d = h1
    a_dispatch.SymCryptModMul(pCurve.GOrd, peSigC, peSigD, peTmp, pbScratch.?, cbScratchInternal); // c / d = h2

    a_dispatch.SymCryptModElementToInt(pCurve.GOrd, peMsghash, piMul1, pbScratch.?, cbScratchInternal);
    a_dispatch.SymCryptModElementToInt(pCurve.GOrd, peTmp, piMul2, pbScratch.?, cbScratchInternal);

    // h1*G + h2*W
    piTable[0] = piMul1;
    piTable[1] = piMul2;

    poTable[0] = null; // The first base point is the generator G of the group
    poTable[1] = pKey.poPublicKey;

    scError = ec_dispatch.SymCryptEcpointMultiScalarMul(
        pCurve,
        &piTable,
        &poTable,
        2,
        types.SYMCRYPT_FLAG_DATA_PUBLIC,
        poQ1,
        pbScratch.?,
        cbScratchInternal,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return .SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE;
    }

    // Check for point at infinity
    if (ec_dispatch.SymCryptEcpointIsZero(pCurve, poQ1, pbScratch.?, cbScratchInternal) != 0) {
        return .SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE;
    }

    // Get the x from poQ1
    scError = ecpoint.SymCryptEcpointGetValue(
        pCurve,
        poQ1,
        .SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        .SYMCRYPT_ECPOINT_FORMAT_X,
        pbX,
        cbX,
        types.SYMCRYPT_FLAG_DATA_PUBLIC,
        pbScratch.?,
        cbScratchInternal,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return .SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE;
    }

    // Store it in a big enough INT
    scError = a_dispatch.SymCryptIntSetValue(pbX, cbX, .SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, piTmp);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return .SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE;
    }

    a_dispatch.SymCryptIntToModElement(piTmp, pCurve.GOrd, peTmp, pbScratch.?, cbScratchInternal); // x mod r

    // Comparison c = x
    if (a_dispatch.SymCryptModElementIsEqual(pCurve.GOrd, peSigC, peTmp) != 0) {
        fValidSignature = types.TRUE;
    }

    if (fValidSignature == 0) {
        scError = .SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE;
    }

    return scError;
}
