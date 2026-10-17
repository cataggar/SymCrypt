//
// dlkey.zig   Dlkey functions
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

const types = @import("types.zig");
const macros = @import("macros.zig");
const fips_selftest = @import("fips_selftest.zig");
const dsa = @import("dsa.zig");
const a_dispatch = @import("a_dispatch.zig");
const fdef_general = @import("fdef_general.zig");

const SYMCRYPT_CALL = types.SYMCRYPT_CALL;
const SYMCRYPT_ERROR = types.SYMCRYPT_ERROR;
const SYMCRYPT_NUMBER_FORMAT = types.SYMCRYPT_NUMBER_FORMAT;
const BYTE = types.BYTE;
const PBYTE = types.PBYTE;
const PCBYTE = types.PCBYTE;
const UINT32 = types.UINT32;
const PCUINT32 = types.PCUINT32;
const SIZE_T = types.SIZE_T;
const PVOID = types.PVOID;
const BOOLEAN = types.BOOLEAN;
const PSYMCRYPT_MODULUS = types.PSYMCRYPT_MODULUS;
const PSYMCRYPT_MODELEMENT = types.PSYMCRYPT_MODELEMENT;
const PCSYMCRYPT_DLGROUP = types.PCSYMCRYPT_DLGROUP;
const SYMCRYPT_DLKEY = types.SYMCRYPT_DLKEY;
const PSYMCRYPT_DLKEY = types.PSYMCRYPT_DLKEY;
const PCSYMCRYPT_DLKEY = types.PCSYMCRYPT_DLKEY;

extern fn SymCryptCallbackAlloc(nBytes: SIZE_T) callconv(SYMCRYPT_CALL) ?PBYTE;
extern fn SymCryptCallbackFree(pMem: PVOID) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptCallbackRandom(pbBuffer: PBYTE, cbBuffer: SIZE_T) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;
extern fn SymCryptWipe(pbData: PVOID, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void;

pub export fn SymCryptDlkeyAllocate(
    pDlgroup: PCSYMCRYPT_DLGROUP,
) callconv(SYMCRYPT_CALL) ?PSYMCRYPT_DLKEY {
    const cb: SIZE_T = SymCryptSizeofDlkeyFromDlgroup(pDlgroup);

    const p = SymCryptCallbackAlloc(cb) orelse return null;

    return SymCryptDlkeyCreate(p, cb, pDlgroup);
}

pub export fn SymCryptDlkeyFree(
    pkObj: PSYMCRYPT_DLKEY,
) callconv(SYMCRYPT_CALL) void {
    macros.SYMCRYPT_CHECK_MAGIC(pkObj);
    SymCryptDlkeyWipe(pkObj);
    SymCryptCallbackFree(@ptrCast(pkObj));
}

pub export fn SymCryptSizeofDlkeyFromDlgroup(
    pDlgroup: PCSYMCRYPT_DLGROUP,
) callconv(SYMCRYPT_CALL) UINT32 {
    // Always allocate memory for large private keys
    return @as(UINT32, @sizeOf(SYMCRYPT_DLKEY)) +
        a_dispatch.SymCryptSizeofModElementFromModulus(pDlgroup.pmP) +
        a_dispatch.SymCryptSizeofIntFromDigits(pDlgroup.nDigitsOfP);
}

pub export fn SymCryptDlkeyCreate(
    pbBuffer_in: PBYTE,
    cbBuffer: SIZE_T,
    pDlgroup: PCSYMCRYPT_DLGROUP,
) callconv(SYMCRYPT_CALL) ?PSYMCRYPT_DLKEY {
    var pbBuffer = pbBuffer_in;
    const cbModElement: UINT32 = a_dispatch.SymCryptSizeofModElementFromModulus(pDlgroup.pmP);

    macros.SYMCRYPT_ASSERT(cbBuffer >= SymCryptSizeofDlkeyFromDlgroup(pDlgroup));
    macros.SYMCRYPT_ASSERT(cbBuffer >= @sizeOf(SYMCRYPT_DLKEY) + cbModElement);
    macros.SYMCRYPT_ASSERT_ASYM_ALIGNED(pbBuffer);

    const pkRes: PSYMCRYPT_DLKEY = @ptrCast(@alignCast(pbBuffer));

    // DLKEY parameters
    pkRes.fAlgorithmInfo = 0;
    pkRes.pDlgroup = pDlgroup;
    pkRes.fHasPrivateKey = 0;
    pkRes.fPrivateModQ = 0; // This will be properly set during generate or setvalue
    pkRes.nBitsPriv = pDlgroup.nDefaultBitsPriv;

    // Create SymCrypt objects
    pbBuffer += @sizeOf(SYMCRYPT_DLKEY);

    const pePub = a_dispatch.SymCryptModElementCreate(pbBuffer, cbModElement, pDlgroup.pmP);
    if (pePub == null) {
        return pkRes;
    }
    pkRes.pePublicKey = pePub.?;
    pbBuffer += cbModElement;

    //
    // **** Always defer the creation of the private key until the key generation or
    // set value.
    //
    // In place of the pbPrivate pointer store the pointer to the allocated buffer.
    //
    pkRes.pbPrivate = pbBuffer;
    pkRes.piPrivateKey = null;

    // Setting the magic
    pkRes.magic = macros.SYMCRYPT_MAGIC_VALUE(pkRes);

    return pkRes;
}

pub export fn SymCryptDlkeyWipe(
    pkDst: PSYMCRYPT_DLKEY,
) callconv(SYMCRYPT_CALL) void {
    SymCryptWipe(@ptrCast(pkDst), SymCryptSizeofDlkeyFromDlgroup(pkDst.pDlgroup));
}

pub export fn SymCryptDlkeyCopy(
    pkSrc: PCSYMCRYPT_DLKEY,
    pkDst: PSYMCRYPT_DLKEY,
) callconv(SYMCRYPT_CALL) void {
    const pDlgroup: PCSYMCRYPT_DLGROUP = pkSrc.pDlgroup;

    //
    // in-place copy is somewhat common...
    //
    if (pkSrc != pkDst) {
        pkDst.fAlgorithmInfo = pkSrc.fAlgorithmInfo;
        pkDst.fHasPrivateKey = pkSrc.fHasPrivateKey;
        pkDst.fPrivateModQ = pkSrc.fPrivateModQ;
        pkDst.nBitsPriv = pkSrc.nBitsPriv;

        // Copy the public key
        a_dispatch.SymCryptModElementCopy(pDlgroup.pmP, pkSrc.pePublicKey, pkDst.pePublicKey);

        // Copy the private key
        a_dispatch.SymCryptIntCopy(pkSrc.piPrivateKey.?, pkDst.piPrivateKey.?);
    }
}

// DLKEY specific functions

pub export fn SymCryptDlkeySetPrivateKeyLength(
    pkDlkey: PSYMCRYPT_DLKEY,
    nBitsPriv: UINT32,
    flags: UINT32,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    if ((nBitsPriv > pkDlkey.pDlgroup.nBitsOfQ) or
        (nBitsPriv < pkDlkey.pDlgroup.nMinBitsPriv) or
        (flags != 0))
    {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    pkDlkey.nBitsPriv = nBitsPriv;
    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptDlkeyGetGroup(
    pkDlkey: PCSYMCRYPT_DLKEY,
) callconv(SYMCRYPT_CALL) PCSYMCRYPT_DLGROUP {
    return pkDlkey.pDlgroup;
}

pub export fn SymCryptDlkeySizeofPublicKey(
    pkDlkey: PCSYMCRYPT_DLKEY,
) callconv(SYMCRYPT_CALL) UINT32 {
    return pkDlkey.pDlgroup.cbPrimeP;
}

pub export fn SymCryptDlkeySizeofPrivateKey(
    pkDlkey: PCSYMCRYPT_DLKEY,
) callconv(SYMCRYPT_CALL) UINT32 {
    const pDlgroup: PCSYMCRYPT_DLGROUP = pkDlkey.pDlgroup;

    if (pkDlkey.fPrivateModQ != 0) {
        if (pDlgroup.fHasPrimeQ != 0) {
            if (pkDlkey.nBitsPriv != pDlgroup.nBitsOfQ) {
                return (pkDlkey.nBitsPriv + 7) / 8;
            } else {
                return pDlgroup.cbPrimeQ;
            }
        } else {
            return pDlgroup.cbPrimeP; // Somehow the group has no prime Q but the key was set with prime Q, return the safe option
        }
    } else {
        return pDlgroup.cbPrimeP;
    }
}

pub export fn SymCryptDlkeyHasPrivateKey(
    pkDlkey: PCSYMCRYPT_DLKEY,
) callconv(SYMCRYPT_CALL) BOOLEAN {
    return pkDlkey.fHasPrivateKey;
}

pub const SYMCRYPT_FLAG_DLKEY_PUBLIC_KEY_ORDER_VALIDATION: UINT32 = 0x1;

pub export fn SymCryptDlkeyPerformPublicKeyValidation(
    pkDlkey: PCSYMCRYPT_DLKEY,
    flags: UINT32,
    pbScratch_in: PBYTE,
    cbScratch_in: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var pbScratch = pbScratch_in;
    var cbScratch = cbScratch_in;

    const pDlgroup: PCSYMCRYPT_DLGROUP = pkDlkey.pDlgroup;
    const cbModElement: UINT32 = a_dispatch.SymCryptSizeofModElementFromModulus(pDlgroup.pmP);

    macros.SYMCRYPT_ASSERT(
        cbScratch >= (2 * @as(SIZE_T, cbModElement)) +
            types.SYMCRYPT_SCRATCH_BYTES_FOR_MODEXP(pDlgroup.nDigitsOfP),
    );

    // Check if Public key is 0
    if (a_dispatch.SymCryptModElementIsZero(pDlgroup.pmP, pkDlkey.pePublicKey) != 0) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    const peTmp = a_dispatch.SymCryptModElementCreate(pbScratch, cbModElement, pDlgroup.pmP).?;
    pbScratch += cbModElement;
    cbScratch -= cbModElement;

    // Check if Public key is P-1
    a_dispatch.SymCryptModElementSetValueNegUint32(1, pDlgroup.pmP, peTmp, pbScratch, cbScratch);
    if (a_dispatch.SymCryptModElementIsEqual(pDlgroup.pmP, pkDlkey.pePublicKey, peTmp) != 0) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    // Check if Public key is 1 (do this check second as we may reuse 1 element in next check)
    a_dispatch.SymCryptModElementSetValueUint32(1, pDlgroup.pmP, peTmp, pbScratch, cbScratch);
    if (a_dispatch.SymCryptModElementIsEqual(pDlgroup.pmP, pkDlkey.pePublicKey, peTmp) != 0) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    // Perform validation that Public key is in a subgroup of order Q.
    if ((flags & SYMCRYPT_FLAG_DLKEY_PUBLIC_KEY_ORDER_VALIDATION) != 0) {
        const peTmpPublicKeyExpQ = a_dispatch.SymCryptModElementCreate(pbScratch, cbModElement, pDlgroup.pmP).?;
        pbScratch += cbModElement;
        cbScratch -= cbModElement;

        // Ensure that Q is specified in the Dlgroup
        if (pDlgroup.fHasPrimeQ == 0) {
            return .SYMCRYPT_INVALID_ARGUMENT;
        }

        // Calculate peTmpPublicKeyExpQ = (Public key)^Q
        a_dispatch.SymCryptModExp(
            pDlgroup.pmP,
            pkDlkey.pePublicKey,
            a_dispatch.SymCryptIntFromModulus(pDlgroup.pmQ.?),
            pDlgroup.nBitsOfQ,
            types.SYMCRYPT_FLAG_DATA_PUBLIC, // No need for side-channel safety for public key validation
            peTmpPublicKeyExpQ,
            pbScratch,
            cbScratch,
        );

        // Ensure (Public key)^Q == 1 mod P
        if (a_dispatch.SymCryptModElementIsEqual(pDlgroup.pmP, peTmpPublicKeyExpQ, peTmp) == 0) {
            return .SYMCRYPT_INVALID_ARGUMENT;
        }
    }

    return .SYMCRYPT_NO_ERROR;
}

const DLKEY_GEN_RANDOM_GENERIC_LIMIT: UINT32 = 1000;

pub export fn SymCryptDlkeyGenerate(
    flags: UINT32,
    pkDlkey: PSYMCRYPT_DLKEY,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;
    var pbScratch: ?PBYTE = null;
    var cbScratch: SIZE_T = 0;

    defer {
        if (pbScratch) |ptr| {
            SymCryptWipe(@ptrCast(ptr), cbScratch);
            SymCryptCallbackFree(@ptrCast(ptr));
        }
    }

    const pDlgroup: PCSYMCRYPT_DLGROUP = pkDlkey.pDlgroup;

    var pmPriv: PSYMCRYPT_MODULUS = undefined;
    var nDigitsPriv: UINT32 = 0;
    var nBitsPriv: UINT32 = 0;
    var fFlagsForModSetRandom: UINT32 = 0;

    var useModSetRandom: bool = true;
    var nBytesPriv: UINT32 = 0;

    const cbModElement: UINT32 = a_dispatch.SymCryptSizeofModElementFromModulus(pDlgroup.pmP);

    // Ensure caller has specified what algorithm(s) the key will be used with
    const algorithmFlags: UINT32 = types.SYMCRYPT_FLAG_DLKEY_DSA | types.SYMCRYPT_FLAG_DLKEY_DH;
    // Make sure only allowed flags are specified
    const allowedFlags: UINT32 = types.SYMCRYPT_FLAG_DLKEY_GEN_MODP | types.SYMCRYPT_FLAG_KEY_NO_FIPS | algorithmFlags;

    if (((flags & ~allowedFlags) != 0) or
        ((flags & algorithmFlags) == 0))
    {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    // Extra sanity checks when running with FIPS
    // Either Dlgroup is named SafePrime group and key is for DH,
    // or Dlgroup is not named SafePrime group and key is for DSA
    if (((flags & types.SYMCRYPT_FLAG_KEY_NO_FIPS) == 0) and
        (((pDlgroup.isSafePrimeGroup != 0) and ((flags & types.SYMCRYPT_FLAG_DLKEY_DSA) != 0)) or
            ((pDlgroup.isSafePrimeGroup == 0) and ((flags & types.SYMCRYPT_FLAG_DLKEY_DH) != 0))))
    {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    pkDlkey.fPrivateModQ = if (((flags & types.SYMCRYPT_FLAG_DLKEY_GEN_MODP) == 0) and (pDlgroup.fHasPrimeQ != 0)) 1 else 0;

    if (pkDlkey.fPrivateModQ != 0) {
        pmPriv = pDlgroup.pmQ.?;
        nDigitsPriv = pDlgroup.nDigitsOfQ;
        nBitsPriv = pDlgroup.nBitsOfQ;
        fFlagsForModSetRandom = types.SYMCRYPT_FLAG_MODRANDOM_ALLOW_ONE | types.SYMCRYPT_FLAG_MODRANDOM_ALLOW_MINUSONE; // 1 to Q-1

        if ((pDlgroup.isSafePrimeGroup != 0) and (pkDlkey.nBitsPriv != pDlgroup.nBitsOfQ)) {
            useModSetRandom = false;
            macros.SYMCRYPT_ASSERT(pkDlkey.nBitsPriv < pDlgroup.nBitsOfQ); // 2^nBitsPriv < Q

            nBitsPriv = pkDlkey.nBitsPriv; // 1 to (2^nBitsPriv)-1
            nBytesPriv = (pkDlkey.nBitsPriv + 7) / 8;
        }
    } else {
        // We perform Private key range validation by construction
        // The Private key is constructed in the range [1,min(2^nBitsPriv,Q)-1] precisely when pkDlkey->fPrivateModQ
        if ((flags & types.SYMCRYPT_FLAG_KEY_NO_FIPS) == 0) {
            return .SYMCRYPT_INVALID_ARGUMENT;
        }

        pmPriv = pDlgroup.pmP;
        nDigitsPriv = pDlgroup.nDigitsOfP;
        nBitsPriv = pDlgroup.nBitsOfP;
        fFlagsForModSetRandom = types.SYMCRYPT_FLAG_MODRANDOM_ALLOW_ONE; // 1 to P-2
    }

    const cbPrivateKey: UINT32 = a_dispatch.SymCryptSizeofModElementFromModulus(pmPriv);

    // From symcrypt_internal.h we have:
    //      - sizeof results are upper bounded by 2^19
    //      - SYMCRYPT_SCRATCH_BYTES results are upper bounded by 2^27 (including RSA and ECURVE)
    // Thus the following calculation does not overflow cbScratch.
    cbScratch = @max(
        @as(SIZE_T, cbPrivateKey) + types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(nDigitsPriv),
        (2 * @as(SIZE_T, cbModElement)) + types.SYMCRYPT_SCRATCH_BYTES_FOR_MODEXP(pDlgroup.nDigitsOfP),
    );
    pbScratch = SymCryptCallbackAlloc(cbScratch);
    if (pbScratch == null) {
        return .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
    }

    const scratchPtr = pbScratch.?;

    // Create the private key integer
    pkDlkey.piPrivateKey = a_dispatch.SymCryptIntCreate(
        pkDlkey.pbPrivate,
        a_dispatch.SymCryptSizeofIntFromDigits(nDigitsPriv),
        nDigitsPriv,
    );

    if (useModSetRandom) {
        // Create the private key modelement
        const pePrivateKey = a_dispatch.SymCryptModElementCreate(scratchPtr, cbPrivateKey, pmPriv).?;
        const pbScratchInternal: PBYTE = scratchPtr + cbPrivateKey;
        const cbScratchInternal: SIZE_T = cbScratch - cbPrivateKey;

        // Set a modelement from 1 to q-1 (or 1 to p-2)
        a_dispatch.SymCryptModSetRandom(
            pmPriv,
            pePrivateKey,
            fFlagsForModSetRandom,
            pbScratchInternal,
            cbScratchInternal,
        );

        // Set the private key
        a_dispatch.SymCryptModElementToInt(
            pmPriv,
            pePrivateKey,
            pkDlkey.piPrivateKey.?,
            pbScratchInternal,
            cbScratchInternal,
        );
    } else {
        // Set private key from 1 to (2^nBitsPriv)-1
        // Wipe any bytes we won't fill with random
        SymCryptWipe(@ptrCast(scratchPtr + nBytesPriv), (nDigitsPriv * types.SYMCRYPT_FDEF_DIGIT_SIZE) - nBytesPriv);

        const dwShiftBits: u3 = @truncate((0 -% nBitsPriv) & 7);
        const privMask: BYTE = @as(BYTE, 0xff) >> dwShiftBits;

        var cntr: UINT32 = 0;
        while (cntr < DLKEY_GEN_RANDOM_GENERIC_LIMIT) : (cntr += 1) {
            // Try random values until we get one we like
            _ = SymCryptCallbackRandom(scratchPtr, nBytesPriv);

            scratchPtr[nBytesPriv - 1] &= privMask;

            // If non-zero we have a value in range [1, (2^nBitsPriv)-1]
            const pScratchU32: PCUINT32 = @ptrCast(@alignCast(scratchPtr));
            if (fdef_general.SymCryptFdefRawIsEqualUint32(pScratchU32, nDigitsPriv, 0) == 0) {
                break;
            }
        }

        if (cntr >= DLKEY_GEN_RANDOM_GENERIC_LIMIT) {
            macros.SymCryptFatal(comptime macros.multiCharConstant("rndl"));
        }

        scError = a_dispatch.SymCryptIntSetValue(
            scratchPtr,
            nBytesPriv,
            .SYMCRYPT_NUMBER_FORMAT_LSB_FIRST,
            pkDlkey.piPrivateKey.?,
        );
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }
    }

    // Calculate the public key
    a_dispatch.SymCryptModExp(
        pDlgroup.pmP,
        pDlgroup.peG,
        pkDlkey.piPrivateKey.?,
        nBitsPriv,
        0, // Side-channel safe
        pkDlkey.pePublicKey,
        scratchPtr, // We can overwrite pePrivateKey now
        cbScratch,
    );

    // Perform range validation on generated Public key.
    if ((flags & types.SYMCRYPT_FLAG_KEY_NO_FIPS) == 0) {
        // Perform Public key validation.
        // Always perform range validation, and validation that Public key is in subgroup of order Q
        scError = SymCryptDlkeyPerformPublicKeyValidation(
            pkDlkey,
            SYMCRYPT_FLAG_DLKEY_PUBLIC_KEY_ORDER_VALIDATION,
            scratchPtr,
            cbScratch,
        );
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }
    }

    // Set the fHasPrivateKey flag
    pkDlkey.fHasPrivateKey = 1;

    pkDlkey.fAlgorithmInfo = flags; // We want to track all of the flags in the Dlkey

    if ((flags & types.SYMCRYPT_FLAG_KEY_NO_FIPS) == 0) {
        if ((flags & types.SYMCRYPT_FLAG_DLKEY_DSA) != 0) {
            // Ensure DSA algorithm selftest is run before first use of DSA algorithm
            fips_selftest.SYMCRYPT_RUN_SELFTEST_ONCE(
                fips_selftest.SymCryptDsaSelftest,
                fips_selftest.SYMCRYPT_SELFTEST_ALGORITHM_DSA,
            );

            // Run PCT eagerly as the key can only be used for DSA - there is no value in deferring
            if ((pkDlkey.fAlgorithmInfo & (fips_selftest.SYMCRYPT_PCT_DSA | types.SYMCRYPT_FLAG_KEY_NO_FIPS)) == 0) {
                // PCT should never fail on key generation - FIPS assert that it does not
                fips_selftest.SYMCRYPT_FIPS_ASSERT(dsa.SymCryptDsaPct(pkDlkey) == .SYMCRYPT_NO_ERROR);
                _ = @atomicRmw(UINT32, &pkDlkey.fAlgorithmInfo, .Or, fips_selftest.SYMCRYPT_PCT_DSA, .monotonic);
            }
        }

        if ((flags & types.SYMCRYPT_FLAG_DLKEY_DH) != 0) {
            // Ensure we have run the algorithm selftest at least once.
            fips_selftest.SYMCRYPT_RUN_SELFTEST_ONCE(
                fips_selftest.SymCryptDhSecretAgreementSelftest,
                fips_selftest.SYMCRYPT_SELFTEST_ALGORITHM_DH,
            );

            // Run PCT eagerly as the key can only be used for DH

            // DH PCT per SP80056a-rev3 5.6.2.1.4 b)
            // Recompute the public key from the private key
            // Option a) appears to be explicitly overruled by 140-3 IG

            // Calculate the public key from the private key in scratch
            var pbScratchInternal: PBYTE = scratchPtr;
            var cbScratchInternal: SIZE_T = cbScratch;

            const peTmp = a_dispatch.SymCryptModElementCreate(pbScratchInternal, cbModElement, pDlgroup.pmP).?;
            pbScratchInternal += cbModElement;
            cbScratchInternal -= cbModElement;

            a_dispatch.SymCryptModExp(
                pDlgroup.pmP,
                pDlgroup.peG,
                pkDlkey.piPrivateKey.?,
                nBitsPriv, // This is either bits of P, Q, or some caller-defined value i.e. public values
                0, // Side-channel safe
                peTmp,
                pbScratchInternal,
                cbScratchInternal,
            );

            fips_selftest.SYMCRYPT_FIPS_ASSERT(
                a_dispatch.SymCryptModElementIsEqual(pDlgroup.pmP, peTmp, pkDlkey.pePublicKey) != 0,
            );
        }
    }

    return scError;
}

pub export fn SymCryptDlkeySetValue(
    pbPrivateKey: ?PCBYTE,
    cbPrivateKey: SIZE_T,
    pbPublicKey: ?PCBYTE,
    cbPublicKey: SIZE_T,
    numFormat: SYMCRYPT_NUMBER_FORMAT,
    flags: UINT32,
    pkDlkey: PSYMCRYPT_DLKEY,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;
    var pbScratch: ?PBYTE = null;
    var cbScratch: UINT32 = 0;

    defer {
        if (pbScratch) |ptr| {
            SymCryptWipe(@ptrCast(ptr), cbScratch);
            SymCryptCallbackFree(@ptrCast(ptr));
        }
    }

    const pDlgroup: PCSYMCRYPT_DLGROUP = pkDlkey.pDlgroup;

    var nDigitsPriv: UINT32 = 0;
    var nBitsPriv: UINT32 = 0;

    const cbModElement: UINT32 = a_dispatch.SymCryptSizeofModElementFromModulus(pDlgroup.pmP);
    var fValidatePublicKeyOrder: UINT32 = SYMCRYPT_FLAG_DLKEY_PUBLIC_KEY_ORDER_VALIDATION;

    if (((pbPrivateKey == null) and (cbPrivateKey != 0)) or
        ((pbPublicKey == null) and (cbPublicKey != 0)) or
        ((pbPrivateKey == null) and (pbPublicKey == null)))
    {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    // Ensure caller has specified what algorithm(s) the key will be used with
    const algorithmFlags: UINT32 = types.SYMCRYPT_FLAG_DLKEY_DSA | types.SYMCRYPT_FLAG_DLKEY_DH;
    // Make sure only allowed flags are specified
    const allowedFlags: UINT32 = types.SYMCRYPT_FLAG_KEY_NO_FIPS | types.SYMCRYPT_FLAG_KEY_MINIMAL_VALIDATION | algorithmFlags;

    if (((flags & ~allowedFlags) != 0) or
        ((flags & algorithmFlags) == 0))
    {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    // Extra sanity checks when running with FIPS
    // Either Dlgroup is named SafePrime group and key is for DH,
    // or Dlgroup is not named SafePrime group and key is for DSA
    if (((flags & types.SYMCRYPT_FLAG_KEY_NO_FIPS) == 0) and
        (((pDlgroup.isSafePrimeGroup != 0) and ((flags & types.SYMCRYPT_FLAG_DLKEY_DSA) != 0)) or
            ((pDlgroup.isSafePrimeGroup == 0) and ((flags & types.SYMCRYPT_FLAG_DLKEY_DH) != 0))))
    {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    // Check that minimal validation flag only specified with no fips
    if (((flags & types.SYMCRYPT_FLAG_KEY_NO_FIPS) == 0) and
        ((flags & types.SYMCRYPT_FLAG_KEY_MINIMAL_VALIDATION) != 0))
    {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    if ((flags & types.SYMCRYPT_FLAG_KEY_NO_FIPS) != 0) {
        fValidatePublicKeyOrder = 0;
    }

    // From symcrypt_internal.h we have:
    //      - sizeof results are upper bounded by 2^19
    //      - SYMCRYPT_SCRATCH_BYTES results are upper bounded by 2^27 (including RSA and ECURVE)
    // Thus the following calculation does not overflow cbScratch.
    cbScratch = @max(
        cbModElement + types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(pDlgroup.nDigitsOfP),
        (2 * cbModElement) + types.SYMCRYPT_SCRATCH_BYTES_FOR_MODEXP(pDlgroup.nDigitsOfP),
    );
    pbScratch = SymCryptCallbackAlloc(cbScratch);
    if (pbScratch == null) {
        return .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
    }

    const scratchPtr = pbScratch.?;

    if (pbPrivateKey) |privKeyPtr| {
        // Check the size of the imported private key to detect if it is mod P or mod Q
        // If the group does not have a Q assume that the imported key is modulo P as
        // it wouldn't help us assume otherwise (the bitsize of the private key should be kept
        // secret from SC attacks).
        // If the private key has had some non-default value set for nBitsPriv then the caller
        // has explicitly opted in to more stringent range checking.
        pkDlkey.fPrivateModQ = if ((pDlgroup.fHasPrimeQ != 0) and
            ((cbPrivateKey < pDlgroup.cbPrimeQ) or
                ((cbPrivateKey == pDlgroup.cbPrimeQ) and (pDlgroup.cbPrimeQ < pDlgroup.cbPrimeP)) or
                (pkDlkey.nBitsPriv != pDlgroup.nDefaultBitsPriv)))
            1
        else
            0;

        if (pkDlkey.fPrivateModQ != 0) {
            nDigitsPriv = pDlgroup.nDigitsOfQ;
            nBitsPriv = pDlgroup.nBitsOfQ;

            if (pDlgroup.isSafePrimeGroup != 0) {
                nBitsPriv = pkDlkey.nBitsPriv;
            }
        } else {
            nDigitsPriv = pDlgroup.nDigitsOfP;
            nBitsPriv = pDlgroup.nBitsOfP;
        }

        pkDlkey.piPrivateKey = a_dispatch.SymCryptIntCreate(
            pkDlkey.pbPrivate,
            a_dispatch.SymCryptSizeofIntFromDigits(nDigitsPriv),
            nDigitsPriv,
        );

        scError = a_dispatch.SymCryptIntSetValue(
            privKeyPtr,
            cbPrivateKey,
            numFormat,
            pkDlkey.piPrivateKey.?,
        );
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }

        // Perform range validation on imported Private key.
        // Check if Private key is 0 - perform unconditionally as it is cheap
        // and it never makes sense for private key to be 0 intentionally
        if (a_dispatch.SymCryptIntIsEqualUint32(pkDlkey.piPrivateKey.?, 0) != 0) {
            return .SYMCRYPT_INVALID_ARGUMENT;
        }

        // Continue range validation on imported Private key.
        if ((flags & types.SYMCRYPT_FLAG_KEY_NO_FIPS) == 0) {
            // Ensure that Q is specified in the Dlgroup
            if (pDlgroup.fHasPrimeQ == 0) {
                return .SYMCRYPT_INVALID_ARGUMENT;
            }

            // If nBitsPriv is specified, check if Private key is greater than or equal to 2^nBitsPriv
            // Otherwise, check if Private key is greater than or equal to Q
            if (((nBitsPriv < pDlgroup.nBitsOfQ) and
                (a_dispatch.SymCryptIntBitsizeOfValue(pkDlkey.piPrivateKey.?) > nBitsPriv)) or
                ((nBitsPriv >= pDlgroup.nBitsOfQ) and
                    (a_dispatch.SymCryptIntIsLessThan(pkDlkey.piPrivateKey.?, a_dispatch.SymCryptIntFromModulus(pDlgroup.pmQ.?)) == 0)))
            {
                return .SYMCRYPT_INVALID_ARGUMENT;
            }
        }

        pkDlkey.fHasPrivateKey = 1;
    }

    if (pbPublicKey) |pubKeyPtr| {
        scError = a_dispatch.SymCryptModElementSetValue(
            pubKeyPtr,
            cbPublicKey,
            numFormat,
            pDlgroup.pmP,
            pkDlkey.pePublicKey,
            scratchPtr,
            cbScratch,
        );
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }

        // Perform range validation on imported Public key.
        if ((flags & types.SYMCRYPT_FLAG_KEY_MINIMAL_VALIDATION) == 0) {
            // Perform Public key validation.
            // Always perform range validation
            // May also perform validation that Public key is in subgroup of order Q, depending on flags
            scError = SymCryptDlkeyPerformPublicKeyValidation(
                pkDlkey,
                fValidatePublicKeyOrder,
                scratchPtr,
                cbScratch,
            );
            if (scError != .SYMCRYPT_NO_ERROR) {
                return scError;
            }
        }
    }

    // Calculating the public key if no key was provided
    // or if needed for keypair regeneration validation
    if ((pbPublicKey == null) or
        (((flags & types.SYMCRYPT_FLAG_KEY_NO_FIPS) == 0) and
            (pbPrivateKey != null) and (pbPublicKey != null)))
    {
        // Calculate the public key from the private key
        var pbScratchInternal: PBYTE = scratchPtr;
        var cbScratchInternal: UINT32 = cbScratch;

        // By default calculate the public key directly where it will be persisted
        var peTmp: PSYMCRYPT_MODELEMENT = pkDlkey.pePublicKey;

        if (pbPublicKey != null) {
            // If doing regeneration validation calculate the public key in scratch
            peTmp = a_dispatch.SymCryptModElementCreate(pbScratchInternal, cbModElement, pDlgroup.pmP).?;
            pbScratchInternal += cbModElement;
            cbScratchInternal -= cbModElement;
        }

        a_dispatch.SymCryptModExp(
            pDlgroup.pmP,
            pDlgroup.peG,
            pkDlkey.piPrivateKey.?,
            nBitsPriv, // This is either bits of P, Q, or some caller-defined value i.e. public values
            0, // Side-channel safe
            peTmp,
            pbScratchInternal,
            cbScratchInternal,
        );

        if (pbPublicKey != null) {
            if (a_dispatch.SymCryptModElementIsEqual(pDlgroup.pmP, peTmp, pkDlkey.pePublicKey) == 0) {
                return .SYMCRYPT_AUTHENTICATION_FAILURE;
            }
        } else if ((flags & types.SYMCRYPT_FLAG_KEY_MINIMAL_VALIDATION) == 0) {
            // Perform Public key validation on generated public key.
            // Always perform range validation
            // May also perform validation that Public key is in subgroup of order Q, depending on flags
            scError = SymCryptDlkeyPerformPublicKeyValidation(
                pkDlkey,
                fValidatePublicKeyOrder,
                scratchPtr,
                cbScratch,
            );
            if (scError != .SYMCRYPT_NO_ERROR) {
                return scError;
            }
        }
    }

    pkDlkey.fAlgorithmInfo = flags; // We want to track all of the flags in the Dlkey

    if ((flags & types.SYMCRYPT_FLAG_KEY_NO_FIPS) == 0) {
        if ((flags & types.SYMCRYPT_FLAG_DLKEY_DSA) != 0) {
            // Ensure DSA algorithm selftest is run before first use of DSA algorithm
            fips_selftest.SYMCRYPT_RUN_SELFTEST_ONCE(
                fips_selftest.SymCryptDsaSelftest,
                fips_selftest.SYMCRYPT_SELFTEST_ALGORITHM_DSA,
            );

            // PCT does not need to be run on import - mark it as done
            pkDlkey.fAlgorithmInfo |= fips_selftest.SYMCRYPT_PCT_DSA;
        }

        if ((flags & types.SYMCRYPT_FLAG_DLKEY_DH) != 0) {
            fips_selftest.SYMCRYPT_RUN_SELFTEST_ONCE(
                fips_selftest.SymCryptDhSecretAgreementSelftest,
                fips_selftest.SYMCRYPT_SELFTEST_ALGORITHM_DH,
            );
        }
    }

    return scError;
}

pub export fn SymCryptDlkeyGetValue(
    pkDlkey: PCSYMCRYPT_DLKEY,
    pbPrivateKey: ?PBYTE,
    cbPrivateKey: SIZE_T,
    pbPublicKey: ?PBYTE,
    cbPublicKey: SIZE_T,
    numFormat: SYMCRYPT_NUMBER_FORMAT,
    flags: UINT32,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    _ = flags;
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;
    var pbScratch: ?PBYTE = null;
    var cbScratch: UINT32 = 0;

    defer {
        if (pbScratch) |ptr| {
            SymCryptWipe(@ptrCast(ptr), cbScratch);
            SymCryptCallbackFree(@ptrCast(ptr));
        }
    }

    const pDlgroup: PCSYMCRYPT_DLGROUP = pkDlkey.pDlgroup;

    if (((pbPrivateKey == null) and (cbPrivateKey != 0)) or
        ((pbPublicKey == null) and (cbPublicKey != 0)) or
        ((pbPrivateKey == null) and (pbPublicKey == null)) or
        ((pbPrivateKey != null) and (pkDlkey.fHasPrivateKey == 0)))
    {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    if (pbPrivateKey) |privKeyPtr| {
        scError = a_dispatch.SymCryptIntGetValue(
            pkDlkey.piPrivateKey.?,
            privKeyPtr,
            cbPrivateKey,
            numFormat,
        );
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }
    }

    if (pbPublicKey) |pubKeyPtr| {
        cbScratch = types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(pDlgroup.nDigitsOfP);
        pbScratch = SymCryptCallbackAlloc(cbScratch);
        if (pbScratch == null) {
            return .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
        }

        scError = a_dispatch.SymCryptModElementGetValue(
            pDlgroup.pmP,
            pkDlkey.pePublicKey,
            pubKeyPtr,
            cbPublicKey,
            numFormat,
            pbScratch.?,
            cbScratch,
        );
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }
    }

    return scError;
}

pub export fn SymCryptDlkeyExtendKeyUsage(
    pkDlkey: PSYMCRYPT_DLKEY,
    flags: UINT32,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    // Ensure caller has specified what algorithm(s) the key will be used with
    const algorithmFlags: UINT32 = types.SYMCRYPT_FLAG_DLKEY_DSA | types.SYMCRYPT_FLAG_DLKEY_DH;

    if (((flags & ~algorithmFlags) != 0) or
        ((flags & algorithmFlags) == 0))
    {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    pkDlkey.fAlgorithmInfo |= flags;

    return .SYMCRYPT_NO_ERROR;
}
