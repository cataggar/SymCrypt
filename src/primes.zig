//
// primes.zig
// Primality tests and prime number generation
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

const types = @import("types.zig");
const macros = @import("macros.zig");
const aes_ctr_drbg = @import("aes_ctr_drbg.zig");
const a_dispatch = @import("a_dispatch.zig");
const gen_int = @import("gen_int.zig");

const SYMCRYPT_CALL = types.SYMCRYPT_CALL;
const SYMCRYPT_ERROR = types.SYMCRYPT_ERROR;
const PBYTE = types.PBYTE;
const UINT32 = types.UINT32;
const UINT64 = types.UINT64;
const PCUINT64 = types.PCUINT64;
const SIZE_T = types.SIZE_T;
const PSYMCRYPT_INT = types.PSYMCRYPT_INT;
const PCSYMCRYPT_INT = types.PCSYMCRYPT_INT;
const PSYMCRYPT_DIVISOR = types.PSYMCRYPT_DIVISOR;
const PSYMCRYPT_RNG_AES_STATE = types.PSYMCRYPT_RNG_AES_STATE;

extern fn SymCryptCallbackRandom(pbBuffer: PBYTE, cbBuffer: SIZE_T) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;

const SYMCRYPT_PRIME_GENERATION_MR_ITERATIONS: UINT32 = 64;

fn SymCryptIntMillerRabinPrimalityTestEx(
    piSrc: PCSYMCRYPT_INT,
    nBitsSrc: UINT32,
    nIterations: UINT32,
    flags: UINT32,
    pRngState: ?PSYMCRYPT_RNG_AES_STATE,
    pbScratch_in: PBYTE,
    cbScratch_in: SIZE_T,
) callconv(SYMCRYPT_CALL) UINT32 {
    var pbScratch = pbScratch_in;
    var cbScratch = cbScratch_in;

    const nDigitsSrc: UINT32 = a_dispatch.SymCryptIntDigitsizeOfObject(piSrc);
    const cbD: UINT32 = a_dispatch.SymCryptSizeofIntFromDigits(nDigitsSrc);
    const cbModulus: UINT32 = a_dispatch.SymCryptSizeofModulusFromDigits(nDigitsSrc);

    macros.SYMCRYPT_ASSERT(nBitsSrc >= a_dispatch.SymCryptIntBitsizeOfValue(piSrc));
    macros.SYMCRYPT_ASSERT(cbScratch >= cbModulus + types.SYMCRYPT_SCRATCH_BYTES_FOR_INT_TO_MODULUS(nDigitsSrc));

    // Allocate the modulus
    const pmModulus = a_dispatch.SymCryptModulusCreate(pbScratch, cbModulus, nDigitsSrc).?;
    pbScratch += cbModulus;
    cbScratch -= cbModulus;

    // Set the modulus
    a_dispatch.SymCryptIntToModulus(
        piSrc,
        pmModulus,
        nBitsSrc, // Average number of expected operations
        types.SYMCRYPT_FLAG_MODULUS_PARITY_PUBLIC,
        pbScratch,
        cbScratch,
    );

    // Modelement size
    const cbX: UINT32 = a_dispatch.SymCryptSizeofModElementFromModulus(pmModulus);

    macros.SYMCRYPT_ASSERT(
        cbScratch >= 3 * cbX + cbD + types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(nDigitsSrc),
    );

    const peX = a_dispatch.SymCryptModElementCreate(pbScratch, cbX, pmModulus).?;
    pbScratch += cbX;
    cbScratch -= cbX;

    const peOne = a_dispatch.SymCryptModElementCreate(pbScratch, cbX, pmModulus).?;
    pbScratch += cbX;
    cbScratch -= cbX;

    const peMinOne = a_dispatch.SymCryptModElementCreate(pbScratch, cbX, pmModulus).?;
    pbScratch += cbX;
    cbScratch -= cbX;

    // Allocate D
    const piD = a_dispatch.SymCryptIntCreate(pbScratch, cbD, nDigitsSrc).?;
    pbScratch += cbD;
    cbScratch -= cbD;

    // Calculate (piSrc - 1)
    // Note: We should never get a borrow here because the requirement
    // is that Src > 3.
    a_dispatch.SymCryptIntCopy(piSrc, piD);
    const borrow: UINT32 = a_dispatch.SymCryptIntSubUint32(piD, 1, piD);
    macros.SYMCRYPT_ASSERT(borrow == 0);

    macros.SYMCRYPT_ASSERT(a_dispatch.SymCryptIntGetBit(piD, 0) == 0);

    // Check the 3 mod 4 requirement when side-channel safe
    macros.SYMCRYPT_ASSERT(
        ((flags & types.SYMCRYPT_FLAG_DATA_PUBLIC) != 0) or
            (a_dispatch.SymCryptIntGetBit(piD, 1) != 0),
    );

    // Calculate R and D such that Src - 1 = D*2^R
    //      Notice that the loop executes only if
    //      the SYMCRYPT_FLAG_DATA_PUBLIC is
    //      specified (and Src != 3 mod 4)
    var R: UINT32 = 1;
    while (a_dispatch.SymCryptIntGetBit(piD, R) == 0) {
        R += 1;
    }
    a_dispatch.SymCryptIntDivPow2(piD, R, piD);

    // Set peOne and peMinOne
    a_dispatch.SymCryptModElementSetValueUint32(1, pmModulus, peOne, pbScratch, cbScratch);
    a_dispatch.SymCryptModElementSetValueNegUint32(1, pmModulus, peMinOne, pbScratch, cbScratch);

    var i: UINT32 = 0;
    while (i < nIterations) : (i += 1) {
        // Pick a random X in [2, piSrc-2]
        // Therefore the flags parameter is 0 (default: not allowed 0, 1, -1 when modulus > 3)
        a_dispatch.SymCryptModSetRandomEx(pmModulus, peX, 0, @ptrCast(pRngState), pbScratch, cbScratch);

        // X^D mod piSrc
        // Notice that nBitsSrc is public in the call of SymCryptModExp
        a_dispatch.SymCryptModExp(pmModulus, peX, piD, nBitsSrc, 0, peX, pbScratch, cbScratch);

        // Check for 1 or -1
        if ((a_dispatch.SymCryptModElementIsEqual(pmModulus, peX, peOne) |
            a_dispatch.SymCryptModElementIsEqual(pmModulus, peX, peMinOne)) != 0)
        {
            continue;
        }

        // repeat R-1 times
        //      Notice that the inner loop executes only if
        //      the SYMCRYPT_FLAG_DATA_PUBLIC is
        //      specified (and Src != 3 mod 4)
        var innerLoop: bool = true;
        var j: UINT32 = 0;
        while ((j < R - 1) and innerLoop) : (j += 1) {
            // Square X
            a_dispatch.SymCryptModSquare(pmModulus, peX, peX, pbScratch, cbScratch);

            // Check if it is 1
            if (a_dispatch.SymCryptModElementIsEqual(pmModulus, peX, peOne) != 0) {
                return 0x0;
            }

            // Check if it is -1
            if (a_dispatch.SymCryptModElementIsEqual(pmModulus, peX, peMinOne) != 0) {
                innerLoop = false;
                break;
            }
        }

        if (innerLoop) {
            return 0x0;
        }
    }

    return 0xffffffff; // Prime
}

pub export fn SymCryptIntMillerRabinPrimalityTest(
    piSrc: PCSYMCRYPT_INT,
    nBitsSrc: UINT32,
    nIterations: UINT32,
    flags: UINT32,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) UINT32 {
    return SymCryptIntMillerRabinPrimalityTestEx(
        piSrc,
        nBitsSrc,
        nIterations,
        flags,
        null,
        pbScratch,
        cbScratch,
    );
}

pub export fn SymCryptIntGenerateRandomPrimeEx(
    piLow: PCSYMCRYPT_INT,
    piHigh: PCSYMCRYPT_INT,
    pu64PubExp: ?PCUINT64,
    nPubExp: UINT32,
    nTries: UINT32,
    flags: UINT32,
    pRngState: ?PSYMCRYPT_RNG_AES_STATE,
    piDst: PSYMCRYPT_INT,
    pbScratch_in: PBYTE,
    cbScratch_in: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var pbScratch = pbScratch_in;
    var cbScratch = cbScratch_in;

    var scError: SYMCRYPT_ERROR = .SYMCRYPT_EXTERNAL_FAILURE;
    var pdPubExp: [types.SYMCRYPT_RSAKEY_MAX_NUMOF_PUBEXPS]PSYMCRYPT_DIVISOR = undefined;

    const nBits: UINT32 = a_dispatch.SymCryptIntBitsizeOfObject(piDst);
    const nBytes: UINT32 = (nBits + 7) / 8;

    const nBitsHigh: UINT32 = a_dispatch.SymCryptIntBitsizeOfValue(piHigh);

    const pTrialDivisionContext = a_dispatch.SymCryptCreateTrialDivisionContext(a_dispatch.SymCryptIntDigitsizeOfObject(piHigh)) orelse {
        return .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
    };
    defer a_dispatch.SymCryptFreeTrialDivisionContext(pTrialDivisionContext);

    macros.SYMCRYPT_ASSERT(
        cbScratch >= types.SYMCRYPT_SCRATCH_BYTES_FOR_INT_PRIME_GEN(a_dispatch.SymCryptIntDigitsizeOfObject(piDst)),
    );
    macros.SYMCRYPT_ASSERT(nPubExp <= types.SYMCRYPT_RSAKEY_MAX_NUMOF_PUBEXPS);
    macros.SYMCRYPT_ASSERT(a_dispatch.SymCryptDigitsFromBits(64) == 1);

    _ = flags;

    // Allocate divisor objects for each public exponent & initialize them
    var cbObj: SIZE_T = a_dispatch.SymCryptSizeofDivisorFromDigits(1);
    var e: UINT32 = 0;
    while (e < nPubExp) : (e += 1) {
        macros.SYMCRYPT_ASSERT(cbScratch >= cbObj);
        const pubExpArr = pu64PubExp.?;
        if (pubExpArr[e] == 0) {
            return .SYMCRYPT_INVALID_ARGUMENT;
        }

        pdPubExp[e] = a_dispatch.SymCryptDivisorCreate(pbScratch, cbObj, 1).?;
        pbScratch += cbObj;
        cbScratch -= cbObj;

        a_dispatch.SymCryptIntSetValueUint64(pubExpArr[e], a_dispatch.SymCryptIntFromDivisor(pdPubExp[e]));
        a_dispatch.SymCryptIntToDivisor(
            a_dispatch.SymCryptIntFromDivisor(pdPubExp[e]),
            pdPubExp[e],
            1000,
            types.SYMCRYPT_FLAG_DATA_PUBLIC,
            pbScratch,
            cbScratch,
        );
    }

    cbObj = a_dispatch.SymCryptSizeofIntFromDigits(1);
    macros.SYMCRYPT_ASSERT(cbScratch >= cbObj + nBytes);
    const piTmp = a_dispatch.SymCryptIntCreate(pbScratch, cbObj, 1).?;
    pbScratch += cbObj;
    cbScratch -= cbObj;

    var cnt: UINT32 = 0;
    while (true) {
        cnt += 1;

        if (pRngState) |rng| {
            aes_ctr_drbg.SymCryptRngAesGenerate(rng, pbScratch, nBytes);
            scError = .SYMCRYPT_NO_ERROR;
        } else {
            scError = SymCryptCallbackRandom(pbScratch, nBytes);
        }
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }

        scError = a_dispatch.SymCryptIntSetValue(pbScratch, nBytes, .SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, piDst);
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }

        // Set the integer to 3 mod 4
        a_dispatch.SymCryptIntSetBits(piDst, 3, 0, 2);

        // Zero out the top bits above the upper limit
        a_dispatch.SymCryptIntModPow2(piDst, nBitsHigh, piDst);

        // Check if it is in the correct range
        if ((a_dispatch.SymCryptIntIsLessThan(piDst, piLow) != 0) or
            (a_dispatch.SymCryptIntIsLessThan(piDst, piHigh) == 0))
        {
            if (cnt >= nTries) break;
            continue;
        }

        // Fast compositeness check
        if (a_dispatch.SymCryptIntFindSmallDivisor(pTrialDivisionContext, piDst, null, 0) != 0) {
            // We found a small divisor; it is not a prime
            if (cnt >= nTries) break;
            continue;
        }

        // Check for compatibility with public exponents (if provided)
        var reject: bool = false;
        e = 0;
        while (e < nPubExp) : (e += 1) {
            const pubExpArr = pu64PubExp.?;
            a_dispatch.SymCryptIntDivMod(piDst, pdPubExp[e], null, piTmp, pbScratch, cbScratch);

            if (gen_int.SymCryptUint64Gcd(
                pubExpArr[e],
                a_dispatch.SymCryptIntGetValueLsbits64(piTmp) -% 1,
                types.SYMCRYPT_FLAG_GCD_INPUTS_NOT_BOTH_EVEN,
            ) != 1) {
                reject = true;
                break;
            }
        }
        if (reject) {
            if (cnt >= nTries) break;
            continue;
        }

        // Primality check
        if (SymCryptIntMillerRabinPrimalityTestEx(
            piDst,
            nBitsHigh,
            SYMCRYPT_PRIME_GENERATION_MR_ITERATIONS,
            0,
            pRngState,
            pbScratch,
            cbScratch,
        ) != 0) {
            scError = .SYMCRYPT_NO_ERROR;
            break;
        }

        if (cnt >= nTries) break;
    }

    if (cnt >= nTries and scError != .SYMCRYPT_NO_ERROR) {
        scError = .SYMCRYPT_INVALID_ARGUMENT;
    }

    return scError;
}

pub export fn SymCryptIntGenerateRandomPrime(
    piLow: PCSYMCRYPT_INT,
    piHigh: PCSYMCRYPT_INT,
    pu64PubExp: ?PCUINT64,
    nPubExp: UINT32,
    nTries: UINT32,
    flags: UINT32,
    piDst: PSYMCRYPT_INT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    return SymCryptIntGenerateRandomPrimeEx(
        piLow,
        piHigh,
        pu64PubExp,
        nPubExp,
        nTries,
        flags,
        null,
        piDst,
        pbScratch,
        cbScratch,
    );
}
