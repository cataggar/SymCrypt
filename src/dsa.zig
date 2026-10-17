//
// dsa.zig   DSA algorithms (FIPS 186-3)
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

const types = @import("types.zig");
const macros = @import("macros.zig");
const fips_selftest = @import("fips_selftest.zig");
const a_dispatch = @import("a_dispatch.zig");

const SYMCRYPT_CALL = types.SYMCRYPT_CALL;
const SYMCRYPT_ERROR = types.SYMCRYPT_ERROR;
const SYMCRYPT_NUMBER_FORMAT = types.SYMCRYPT_NUMBER_FORMAT;
const PBYTE = types.PBYTE;
const PCBYTE = types.PCBYTE;
const UINT32 = types.UINT32;
const SIZE_T = types.SIZE_T;
const PVOID = types.PVOID;
const BOOLEAN = types.BOOLEAN;
const PSYMCRYPT_INT = types.PSYMCRYPT_INT;
const PCSYMCRYPT_INT = types.PCSYMCRYPT_INT;
const PSYMCRYPT_MODELEMENT = types.PSYMCRYPT_MODELEMENT;
const PCSYMCRYPT_MODELEMENT = types.PCSYMCRYPT_MODELEMENT;
const PCSYMCRYPT_DLGROUP = types.PCSYMCRYPT_DLGROUP;
const PCSYMCRYPT_DLKEY = types.PCSYMCRYPT_DLKEY;

extern fn SymCryptCallbackAlloc(nBytes: SIZE_T) callconv(SYMCRYPT_CALL) ?PBYTE;
extern fn SymCryptCallbackFree(pMem: PVOID) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptWipe(pbData: PVOID, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void;

pub const SymCryptDsaSelftest = fips_selftest.SymCryptDsaSelftest;
pub const SymCryptDsaPct = fips_selftest.SymCryptDsaPct;

// The following sets an upper bound for the count of numbers tried during
// DSA signature calculation. Note that 0 is not allowed.
const SYMCRYPT_MAX_DSA_SIGNATURE_COUNT: UINT32 = 100;

pub export fn SymCryptDsaTruncateHash(
    pDlgroup: PCSYMCRYPT_DLGROUP,
    pbHashValue: PCBYTE,
    cbHashValue: SIZE_T,
    flags: UINT32,
    peMsghash: PSYMCRYPT_MODELEMENT,
    piIntLarge: PSYMCRYPT_INT,
    piIntQ: PSYMCRYPT_INT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    _ = flags;
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;
    const pmQ = pDlgroup.pmQ.?;

    // Get the value of msghash into piIntLarge
    scError = a_dispatch.SymCryptIntSetValue(
        pbHashValue,
        cbHashValue,
        .SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        piIntLarge,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    // Truncate the rightmost bits if the value exceeds the size of the modulus Q
    if (a_dispatch.SymCryptIntBitsizeOfValue(piIntLarge) > pDlgroup.nBitsOfQ) {
        a_dispatch.SymCryptIntDivPow2(
            piIntLarge,
            a_dispatch.SymCryptIntBitsizeOfValue(piIntLarge) - pDlgroup.nBitsOfQ,
            piIntLarge,
        );
    }

    scError = a_dispatch.SymCryptIntCopyMixedSize(piIntLarge, piIntQ);
    if (scError != .SYMCRYPT_NO_ERROR) {
        // This should never fail here as we truncated the IntLarge
        return scError;
    }

    // Now we can call IntToModElement as they have the same digit size
    a_dispatch.SymCryptIntToModElement(piIntQ, pmQ, peMsghash, pbScratch, cbScratch); // msghash mod Q

    return scError;
}

pub export fn SymCryptDsaSignEx(
    pKey: PCSYMCRYPT_DLKEY,
    pbHashValue: PCBYTE,
    cbHashValue: SIZE_T,
    piK: ?PCSYMCRYPT_INT,
    format: SYMCRYPT_NUMBER_FORMAT,
    flags: UINT32,
    pbSignature: PBYTE,
    cbSignature: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;
    var pbScratch: ?PBYTE = null;
    var cbScratch: SIZE_T = 0;

    defer {
        if (pbScratch) |ptr| {
            SymCryptWipe(@ptrCast(ptr), cbScratch);
            SymCryptCallbackFree(@ptrCast(ptr));
        }
        if (scError != .SYMCRYPT_NO_ERROR) {
            SymCryptWipe(@ptrCast(pbSignature), cbSignature);
        }
    }

    const pDlgroup: PCSYMCRYPT_DLGROUP = pKey.pDlgroup;

    // Make sure that the key may be used in DSA
    if ((pKey.fAlgorithmInfo & types.SYMCRYPT_FLAG_DLKEY_DSA) == 0) {
        scError = .SYMCRYPT_INVALID_ARGUMENT;
        return scError;
    }

    // Make sure that the group and the key have all the
    // information for dsa, i.e. prime q and private key
    // modulo q, and we are not using a named DH safe-prime
    // group
    if ((pDlgroup.fHasPrimeQ == 0) or
        (pKey.fHasPrivateKey == 0) or
        (pKey.fPrivateModQ == 0) or
        (pDlgroup.isSafePrimeGroup != 0))
    {
        scError = .SYMCRYPT_INVALID_ARGUMENT;
        return scError;
    }

    const pmQ = pDlgroup.pmQ.?;

    const nDigitsOfP: UINT32 = pDlgroup.nDigitsOfP;
    const nDigitsOfQ: UINT32 = pDlgroup.nDigitsOfQ;

    // Calculate the digit size for the HashValue
    const ndIntLarge: UINT32 = a_dispatch.SymCryptDigitsFromBits(@as(UINT32, @intCast(cbHashValue)) * 8);

    // Calculate the sizes of temp objects
    const cbIntLarge: UINT32 = a_dispatch.SymCryptSizeofIntFromDigits(ndIntLarge);
    const cbIntQ: UINT32 = a_dispatch.SymCryptSizeofIntFromDigits(nDigitsOfQ);
    const cbIntP: UINT32 = a_dispatch.SymCryptSizeofIntFromDigits(nDigitsOfP);

    const cbModelementP: UINT32 = a_dispatch.SymCryptSizeofModElementFromModulus(pDlgroup.pmP);
    const cbModelementQ: UINT32 = a_dispatch.SymCryptSizeofModElementFromModulus(pmQ);

    // Allocate scratch space
    const cbScratchInputK: SIZE_T = if (piK) |k|
        types.SYMCRYPT_SCRATCH_BYTES_FOR_INT_DIVMOD(a_dispatch.SymCryptIntDigitsizeOfObject(k), nDigitsOfQ)
    else
        0;

    // From symcrypt_internal.h we have:
    //      - sizeof results are upper bounded by 2^19
    //      - SYMCRYPT_SCRATCH_BYTES results are upper bounded by 2^27 (including RSA and ECURVE)
    // Thus the following calculation does not overflow cbScratch.
    cbScratch = @as(SIZE_T, cbIntLarge) +
        @as(SIZE_T, cbIntQ) +
        @as(SIZE_T, cbIntP) +
        @as(SIZE_T, cbModelementP) +
        4 * @as(SIZE_T, cbModelementQ) +
        @max(
            cbScratchInputK,
            @max(
                types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(nDigitsOfQ),
                @max(
                    types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(nDigitsOfP),
                    @max(
                        types.SYMCRYPT_SCRATCH_BYTES_FOR_MODEXP(nDigitsOfP),
                        types.SYMCRYPT_SCRATCH_BYTES_FOR_MODINV(nDigitsOfQ),
                    ),
                ),
            ),
        );
    pbScratch = SymCryptCallbackAlloc(cbScratch);
    if (pbScratch == null) {
        scError = .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
        return scError;
    }

    // Create the objects
    var pbScratchInternal: PBYTE = pbScratch.?;
    var cbScratchInternal: SIZE_T = cbScratch;

    const piIntLarge = a_dispatch.SymCryptIntCreate(pbScratchInternal, cbIntLarge, ndIntLarge).?;
    pbScratchInternal += cbIntLarge;
    cbScratchInternal -= cbIntLarge;
    const piIntQ = a_dispatch.SymCryptIntCreate(pbScratchInternal, cbIntQ, nDigitsOfQ).?;
    pbScratchInternal += cbIntQ;
    cbScratchInternal -= cbIntQ;
    const piIntP = a_dispatch.SymCryptIntCreate(pbScratchInternal, cbIntP, nDigitsOfP).?;
    pbScratchInternal += cbIntP;
    cbScratchInternal -= cbIntP;

    const peRmodP = a_dispatch.SymCryptModElementCreate(pbScratchInternal, cbModelementP, pDlgroup.pmP).?;
    pbScratchInternal += cbModelementP;
    cbScratchInternal -= cbModelementP;

    const peMsghash = a_dispatch.SymCryptModElementCreate(pbScratchInternal, cbModelementQ, pmQ).?;
    pbScratchInternal += cbModelementQ;
    cbScratchInternal -= cbModelementQ;
    const peRmodQ = a_dispatch.SymCryptModElementCreate(pbScratchInternal, cbModelementQ, pmQ).?;
    pbScratchInternal += cbModelementQ;
    cbScratchInternal -= cbModelementQ;
    const peK = a_dispatch.SymCryptModElementCreate(pbScratchInternal, cbModelementQ, pmQ).?;
    pbScratchInternal += cbModelementQ;
    cbScratchInternal -= cbModelementQ;
    const peS = a_dispatch.SymCryptModElementCreate(pbScratchInternal, cbModelementQ, pmQ).?;
    pbScratchInternal += cbModelementQ;
    cbScratchInternal -= cbModelementQ;

    // Get the message into a modelement
    scError = SymCryptDsaTruncateHash(
        pDlgroup,
        pbHashValue,
        cbHashValue,
        flags,
        peMsghash,
        piIntLarge,
        piIntQ,
        pbScratchInternal,
        cbScratchInternal,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    // Main loop: Stop when both R and S are not zero (unless a specific k is provided)
    var signatureCount: UINT32 = 0;
    while (true) {
        if (piK) |k| {
            a_dispatch.SymCryptIntDivMod(
                k,
                a_dispatch.SymCryptDivisorFromModulus(pmQ),
                null,
                piIntQ,
                pbScratchInternal,
                cbScratchInternal,
            );

            a_dispatch.SymCryptIntToModElement(
                piIntQ,
                pmQ,
                peK,
                pbScratchInternal,
                cbScratchInternal,
            );

            // Make sure that the K passed in is not zero
            if (a_dispatch.SymCryptModElementIsZero(pmQ, peK) != 0) {
                scError = .SYMCRYPT_INVALID_ARGUMENT;
                return scError;
            }
        } else {
            a_dispatch.SymCryptModSetRandom(
                pmQ,
                peK,
                types.SYMCRYPT_FLAG_MODRANDOM_ALLOW_ONE | types.SYMCRYPT_FLAG_MODRANDOM_ALLOW_MINUSONE,
                pbScratchInternal,
                cbScratchInternal,
            );

            a_dispatch.SymCryptModElementToInt(
                pmQ,
                peK,
                piIntQ,
                pbScratchInternal,
                cbScratchInternal,
            );
        }

        // Here piIntQ and peK hold the random exponent K

        // G^K mod P
        a_dispatch.SymCryptModExp(
            pDlgroup.pmP,
            pDlgroup.peG,
            piIntQ,
            pDlgroup.nBitsOfQ,
            0, // Side-channel safe
            peRmodP,
            pbScratchInternal,
            cbScratchInternal,
        );

        // Convert to integer
        a_dispatch.SymCryptModElementToInt(
            pDlgroup.pmP,
            peRmodP,
            piIntP,
            pbScratchInternal,
            cbScratchInternal,
        );

        // Convert to mod Q
        a_dispatch.SymCryptIntDivMod(
            piIntP,
            a_dispatch.SymCryptDivisorFromModulus(pmQ),
            null,
            piIntQ,
            pbScratchInternal,
            cbScratchInternal,
        );

        // Convert to modelement
        a_dispatch.SymCryptIntToModElement(
            piIntQ,
            pmQ,
            peRmodQ,
            pbScratchInternal,
            cbScratchInternal,
        );

        // Invert k mod q
        scError = a_dispatch.SymCryptModInv(
            pmQ,
            peK,
            peK, // In place
            0,
            pbScratchInternal,
            cbScratchInternal,
        );
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }

        // Get the private key X to modelement
        // *** We are sure here that the digit
        // size of it is nDigitsOfQ
        a_dispatch.SymCryptIntToModElement(
            pKey.piPrivateKey.?,
            pmQ,
            peS,
            pbScratchInternal,
            cbScratchInternal,
        );

        // X*R
        a_dispatch.SymCryptModMul(
            pmQ,
            peS,
            peRmodQ,
            peS,
            pbScratchInternal,
            cbScratchInternal,
        );

        // H(m)+X*R
        a_dispatch.SymCryptModAdd(
            pmQ,
            peS,
            peMsghash,
            peS,
            pbScratchInternal,
            cbScratchInternal,
        );

        // S = k^{-1}*(H(m)+X*R)
        a_dispatch.SymCryptModMul(
            pmQ,
            peK,
            peS,
            peS,
            pbScratchInternal,
            cbScratchInternal,
        );

        if ((a_dispatch.SymCryptModElementIsZero(pmQ, peRmodQ) |
            a_dispatch.SymCryptModElementIsZero(pmQ, peS)) == 0)
        {
            break;
        }

        if (piK != null) {
            // piK resulted in 0 signature
            scError = .SYMCRYPT_INVALID_ARGUMENT;
            return scError;
        }

        signatureCount += 1;
        if (signatureCount >= SYMCRYPT_MAX_DSA_SIGNATURE_COUNT) {
            // We have not generated a non-zero signature after SYMCRYPT_MAX_DSA_SIGNATURE_COUNT attempts;
            // Something is wrong with the group setup
            scError = .SYMCRYPT_INVALID_ARGUMENT;
            return scError;
        }
    }

    // Output R
    scError = a_dispatch.SymCryptModElementGetValue(
        pmQ,
        peRmodQ,
        pbSignature,
        cbSignature / 2,
        format,
        pbScratchInternal,
        cbScratchInternal,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    // Output S
    scError = a_dispatch.SymCryptModElementGetValue(
        pmQ,
        peS,
        pbSignature + cbSignature / 2,
        cbSignature / 2,
        format,
        pbScratchInternal,
        cbScratchInternal,
    );
    return scError;
}

pub export fn SymCryptDsaSign(
    pKey: PCSYMCRYPT_DLKEY,
    pbHashValue: PCBYTE,
    cbHashValue: SIZE_T,
    format: SYMCRYPT_NUMBER_FORMAT,
    flags: UINT32,
    pbSignature: PBYTE,
    cbSignature: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    return SymCryptDsaSignEx(
        pKey,
        pbHashValue,
        cbHashValue,
        null,
        format,
        flags,
        pbSignature,
        cbSignature,
    );
}

pub export fn SymCryptDsaVerify(
    pKey: PCSYMCRYPT_DLKEY,
    pbHashValue: PCBYTE,
    cbHashValue: SIZE_T,
    pbSignature: PCBYTE,
    cbSignature: SIZE_T,
    format: SYMCRYPT_NUMBER_FORMAT,
    flags: UINT32,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;
    var fValidSignature: BOOLEAN = 0;

    var pbScratch: ?PBYTE = null;
    var cbScratch: SIZE_T = 0;

    defer {
        if (pbScratch) |ptr| {
            SymCryptWipe(@ptrCast(ptr), cbScratch);
            SymCryptCallbackFree(@ptrCast(ptr));
        }
    }

    const pDlgroup: PCSYMCRYPT_DLGROUP = pKey.pDlgroup;

    // Make sure that the key may be used in DSA
    if ((pKey.fAlgorithmInfo & types.SYMCRYPT_FLAG_DLKEY_DSA) == 0) {
        return .SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE;
    }

    // Make sure that the group has a prime q, and we are not using a named DH safe-prime group
    if ((pDlgroup.fHasPrimeQ == 0) or (pDlgroup.isSafePrimeGroup != 0)) {
        return .SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE;
    }

    const pmQ = pDlgroup.pmQ.?;

    // Digit sizes
    const nDigitsOfP: UINT32 = pDlgroup.nDigitsOfP;
    const nDigitsOfQ: UINT32 = pDlgroup.nDigitsOfQ;

    // Calculate the digit sizes
    var ndIntLarge: UINT32 = a_dispatch.SymCryptDigitsFromBits(@intCast(cbHashValue * 8));
    ndIntLarge = @max(ndIntLarge, a_dispatch.SymCryptDigitsFromBits(@intCast(cbSignature * 4))); // pbSignature contains (R,S)

    // Calculate the sizes of temp objects
    const cbIntLarge: UINT32 = a_dispatch.SymCryptSizeofIntFromDigits(ndIntLarge);
    const cbIntQ: UINT32 = a_dispatch.SymCryptSizeofIntFromDigits(nDigitsOfQ);
    const cbIntP: UINT32 = a_dispatch.SymCryptSizeofIntFromDigits(nDigitsOfP);

    const cbModelementP: UINT32 = a_dispatch.SymCryptSizeofModElementFromModulus(pDlgroup.pmP);
    const cbModelementQ: UINT32 = a_dispatch.SymCryptSizeofModElementFromModulus(pmQ);

    // From symcrypt_internal.h we have:
    //      - sizeof results are upper bounded by 2^19
    //      - SYMCRYPT_SCRATCH_BYTES results are upper bounded by 2^27 (including RSA and ECURVE)
    // Thus the following calculation does not overflow cbScratch.
    cbScratch = @as(SIZE_T, cbIntLarge) +
        @as(SIZE_T, cbIntP) +
        2 * @as(SIZE_T, cbIntQ) +
        @as(SIZE_T, cbModelementP) +
        3 * @as(SIZE_T, cbModelementQ) +
        @max(
            types.SYMCRYPT_SCRATCH_BYTES_FOR_INT_DIVMOD(nDigitsOfP, nDigitsOfQ),
            @max(
                types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(nDigitsOfQ),
                @max(
                    types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(nDigitsOfP),
                    @max(
                        types.SYMCRYPT_SCRATCH_BYTES_FOR_MODMULTIEXP(
                            a_dispatch.SymCryptModulusDigitsizeOfObject(pDlgroup.pmP),
                            2,
                            pDlgroup.nBitsOfQ,
                        ),
                        types.SYMCRYPT_SCRATCH_BYTES_FOR_MODINV(nDigitsOfQ),
                    ),
                ),
            ),
        );
    pbScratch = SymCryptCallbackAlloc(cbScratch);
    if (pbScratch == null) {
        return .SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE;
    }

    // Create the objects
    var pbScratchInternal: PBYTE = pbScratch.?;
    var cbScratchInternal: SIZE_T = cbScratch;

    const piIntLarge = a_dispatch.SymCryptIntCreate(pbScratchInternal, cbIntLarge, ndIntLarge).?;
    pbScratchInternal += cbIntLarge;
    cbScratchInternal -= cbIntLarge;
    const piIntP = a_dispatch.SymCryptIntCreate(pbScratchInternal, cbIntP, nDigitsOfP).?;
    pbScratchInternal += cbIntP;
    cbScratchInternal -= cbIntP;
    var piIntQ: [2]PSYMCRYPT_INT = undefined;
    piIntQ[0] = a_dispatch.SymCryptIntCreate(pbScratchInternal, cbIntQ, nDigitsOfQ).?;
    pbScratchInternal += cbIntQ;
    cbScratchInternal -= cbIntQ;
    piIntQ[1] = a_dispatch.SymCryptIntCreate(pbScratchInternal, cbIntQ, nDigitsOfQ).?;
    pbScratchInternal += cbIntQ;
    cbScratchInternal -= cbIntQ;

    const peResP = a_dispatch.SymCryptModElementCreate(pbScratchInternal, cbModelementP, pDlgroup.pmP).?;
    pbScratchInternal += cbModelementP;
    cbScratchInternal -= cbModelementP;

    const peR = a_dispatch.SymCryptModElementCreate(pbScratchInternal, cbModelementQ, pmQ).?;
    pbScratchInternal += cbModelementQ;
    cbScratchInternal -= cbModelementQ;
    const peS = a_dispatch.SymCryptModElementCreate(pbScratchInternal, cbModelementQ, pmQ).?;
    pbScratchInternal += cbModelementQ;
    cbScratchInternal -= cbModelementQ;
    const peT = a_dispatch.SymCryptModElementCreate(pbScratchInternal, cbModelementQ, pmQ).?;
    pbScratchInternal += cbModelementQ;
    cbScratchInternal -= cbModelementQ;

    // Get R
    scError = a_dispatch.SymCryptIntSetValue(pbSignature, cbSignature / 2, format, piIntLarge);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return .SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE;
    }

    // Check if R is less than Q
    if (a_dispatch.SymCryptIntIsLessThan(piIntLarge, a_dispatch.SymCryptIntFromModulus(pmQ)) == 0) {
        return .SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE;
    }

    // R mod Q (use piIntQ[0] as temp space)
    scError = a_dispatch.SymCryptIntCopyMixedSize(piIntLarge, piIntQ[0]);
    if (scError != .SYMCRYPT_NO_ERROR) {
        // This should never fail here as we verified that IntLarge is less than Q
        return .SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE;
    }
    a_dispatch.SymCryptIntToModElement(piIntQ[0], pmQ, peR, pbScratchInternal, cbScratchInternal);

    // Check if R is zero
    if (a_dispatch.SymCryptModElementIsZero(pmQ, peR) != 0) {
        return .SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE;
    }

    // Get S
    scError = a_dispatch.SymCryptIntSetValue(pbSignature + cbSignature / 2, cbSignature / 2, format, piIntLarge);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return .SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE;
    }

    // Check if S is less than Q
    if (a_dispatch.SymCryptIntIsLessThan(piIntLarge, a_dispatch.SymCryptIntFromModulus(pmQ)) == 0) {
        return .SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE;
    }

    // S mod Q (use piIntQ[0] as temp space)
    scError = a_dispatch.SymCryptIntCopyMixedSize(piIntLarge, piIntQ[0]);
    if (scError != .SYMCRYPT_NO_ERROR) {
        // This should never fail here as we verified that IntLarge is less than Q
        return .SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE;
    }
    a_dispatch.SymCryptIntToModElement(piIntQ[0], pmQ, peS, pbScratchInternal, cbScratchInternal);

    // Check if S is zero
    if (a_dispatch.SymCryptModElementIsZero(pmQ, peS) != 0) {
        return .SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE;
    }

    // Calculate 1/S mod Q
    // S is part of the signature and therefore not a secret.
    // We mark it public to avoid the use of random blinding, which would require a source of randomness
    // just to verify a DSA signature.
    scError = a_dispatch.SymCryptModInv(
        pmQ,
        peS,
        peS,
        types.SYMCRYPT_FLAG_DATA_PUBLIC,
        pbScratchInternal,
        cbScratchInternal,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return .SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE;
    }

    // Get the message into a modelement
    scError = SymCryptDsaTruncateHash(
        pDlgroup,
        pbHashValue,
        cbHashValue,
        flags,
        peT,
        piIntLarge,
        piIntQ[0],
        pbScratchInternal,
        cbScratchInternal,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return .SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE;
    }

    // Calculate U1 = Hash(M)/S modQ
    a_dispatch.SymCryptModMul(
        pmQ,
        peT,
        peS,
        peT,
        pbScratchInternal,
        cbScratchInternal,
    );

    // Convert U1 to integer
    a_dispatch.SymCryptModElementToInt(
        pmQ,
        peT,
        piIntQ[0],
        pbScratchInternal,
        cbScratchInternal,
    );

    // Calculate U2 = R/S modQ
    a_dispatch.SymCryptModMul(
        pmQ,
        peR,
        peS,
        peT,
        pbScratchInternal,
        cbScratchInternal,
    );

    // Convert U2 to integer
    a_dispatch.SymCryptModElementToInt(
        pmQ,
        peT,
        piIntQ[1],
        pbScratchInternal,
        cbScratchInternal,
    );

    // Arrange the pointers for v = G^U1 * Y^U2
    const peBases = [2]PCSYMCRYPT_MODELEMENT{
        pDlgroup.peG,
        pKey.pePublicKey,
    };
    const piExps = [2]PCSYMCRYPT_INT{
        piIntQ[0],
        piIntQ[1],
    };

    // v = G^U1 * Y^U2
    scError = a_dispatch.SymCryptModMultiExp(
        pDlgroup.pmP,
        &peBases,
        &piExps,
        2,
        pDlgroup.nBitsOfQ,
        types.SYMCRYPT_FLAG_DATA_PUBLIC,
        peResP,
        pbScratchInternal,
        cbScratchInternal,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return .SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE;
    }

    // Convert V to a modelement modulo Q
    a_dispatch.SymCryptModElementToInt(
        pDlgroup.pmP,
        peResP,
        piIntP,
        pbScratchInternal,
        cbScratchInternal,
    );
    a_dispatch.SymCryptIntDivMod(
        piIntP,
        a_dispatch.SymCryptDivisorFromModulus(pmQ),
        null,
        piIntQ[0],
        pbScratchInternal,
        cbScratchInternal,
    );
    a_dispatch.SymCryptIntToModElement(
        piIntQ[0],
        pmQ,
        peT,
        pbScratchInternal,
        cbScratchInternal,
    );

    // Comparison V = R
    if (a_dispatch.SymCryptModElementIsEqual(pmQ, peT, peR) != 0) {
        fValidSignature = 1;
    }

    if (fValidSignature == 0) {
        scError = .SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE;
    }

    return scError;
}
