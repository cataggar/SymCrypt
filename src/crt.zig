//
// crt.zig   Chinese Remainder Theorem Algorithms
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

const types = @import("types.zig");
const macros = @import("macros.zig");
const a_dispatch = @import("a_dispatch.zig");
const gen_int = @import("gen_int.zig");

const SYMCRYPT_CALL = types.SYMCRYPT_CALL;
const SYMCRYPT_ERROR = types.SYMCRYPT_ERROR;
const PBYTE = types.PBYTE;
const UINT32 = types.UINT32;
const SIZE_T = types.SIZE_T;
const PSYMCRYPT_INT = types.PSYMCRYPT_INT;
const PCSYMCRYPT_INT = types.PCSYMCRYPT_INT;
const PSYMCRYPT_MODULUS = types.PSYMCRYPT_MODULUS;
const PCSYMCRYPT_MODULUS = types.PCSYMCRYPT_MODULUS;
const PSYMCRYPT_MODELEMENT = types.PSYMCRYPT_MODELEMENT;
const PCSYMCRYPT_MODELEMENT = types.PCSYMCRYPT_MODELEMENT;

pub export fn SymCryptCrtGenerateForTwoCoprimes(
    pmP: PCSYMCRYPT_MODULUS,
    pmQ: PCSYMCRYPT_MODULUS,
    flags: UINT32,
    peInvQModP: PSYMCRYPT_MODELEMENT,
    peInvPModQ: PSYMCRYPT_MODELEMENT,
    pbScratch_in: PBYTE,
    cbScratch_in: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var pbScratch = pbScratch_in;
    var cbScratch = cbScratch_in;

    const nDigits: UINT32 = @max(
        a_dispatch.SymCryptModulusDigitsizeOfObject(pmP),
        a_dispatch.SymCryptModulusDigitsizeOfObject(pmQ),
    );

    // Create two temporary integers
    const cbInt: UINT32 = a_dispatch.SymCryptSizeofIntFromDigits(nDigits);

    macros.SYMCRYPT_ASSERT(cbScratch >= 2 * cbInt + types.SYMCRYPT_SCRATCH_BYTES_FOR_EXTENDED_GCD(nDigits));

    const piInvSrc1ModSrc2 = a_dispatch.SymCryptIntCreate(pbScratch, cbInt, nDigits).?;
    pbScratch += cbInt;
    cbScratch -= cbInt;
    const piInvSrc2ModSrc1 = a_dispatch.SymCryptIntCreate(pbScratch, cbInt, nDigits).?;
    pbScratch += cbInt;
    cbScratch -= cbInt;

    const oddP: bool = (a_dispatch.SymCryptIntGetValueLsbits32(a_dispatch.SymCryptIntFromModulus(@constCast(pmP))) & 1) == 1;
    var piSrc1: PCSYMCRYPT_INT = undefined;
    var piSrc2: PCSYMCRYPT_INT = undefined;
    if (oddP) {
        piSrc1 = a_dispatch.SymCryptIntFromModulus(@constCast(pmQ));
        piSrc2 = a_dispatch.SymCryptIntFromModulus(@constCast(pmP));
    } else {
        piSrc1 = a_dispatch.SymCryptIntFromModulus(@constCast(pmP));
        piSrc2 = a_dispatch.SymCryptIntFromModulus(@constCast(pmQ));
    }

    // IntExtendedGcd requirements:
    //      - First argument > 0
    //      - Second argument odd
    if (a_dispatch.SymCryptIntIsEqualUint32(piSrc1, 0) != 0 or
        (a_dispatch.SymCryptIntGetValueLsbits32(piSrc2) & 1) != 1)
    {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    // Extended GCD
    gen_int.SymCryptIntExtendedGcd(
        piSrc1,
        piSrc2,
        flags,
        null,
        null,
        piInvSrc1ModSrc2,
        piInvSrc2ModSrc1,
        pbScratch,
        cbScratch,
    );

    if (oddP) {
        a_dispatch.SymCryptIntToModElement(piInvSrc2ModSrc1, pmQ, peInvPModQ, pbScratch, cbScratch);
        a_dispatch.SymCryptIntToModElement(piInvSrc1ModSrc2, pmP, peInvQModP, pbScratch, cbScratch);
    } else {
        a_dispatch.SymCryptIntToModElement(piInvSrc2ModSrc1, pmP, peInvQModP, pbScratch, cbScratch);
        a_dispatch.SymCryptIntToModElement(piInvSrc1ModSrc2, pmQ, peInvPModQ, pbScratch, cbScratch);
    }

    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptCrtGenerateInverses(
    nCoprimes: UINT32,
    ppmCoprimes: [*]const PCSYMCRYPT_MODULUS,
    flags: UINT32,
    ppeCrtInverses: [*]const PSYMCRYPT_MODELEMENT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    if (nCoprimes == 2) {
        _ = SymCryptCrtGenerateForTwoCoprimes(
            ppmCoprimes[0],
            ppmCoprimes[1],
            flags,
            ppeCrtInverses[0],
            ppeCrtInverses[1],
            pbScratch,
            cbScratch,
        );
        return .SYMCRYPT_NO_ERROR;
    } else {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }
}

pub export fn SymCryptCrtSolve(
    nCoprimes: UINT32,
    ppmCoprimes: [*]const PCSYMCRYPT_MODULUS,
    ppeCrtInverses: [*]const PCSYMCRYPT_MODELEMENT,
    ppeCrtRemainders: [*]const PCSYMCRYPT_MODELEMENT,
    flags: UINT32,
    piSolution: PSYMCRYPT_INT,
    pbScratch_in: PBYTE,
    cbScratch_in: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var pbScratch = pbScratch_in;
    var cbScratch = cbScratch_in;

    macros.SYMCRYPT_ASSERT(nCoprimes >= 2);
    _ = flags;

    const nDigitsMax: UINT32 = @max(
        a_dispatch.SymCryptModulusDigitsizeOfObject(ppmCoprimes[0]),
        a_dispatch.SymCryptModulusDigitsizeOfObject(ppmCoprimes[1]),
    );

    const cbInt: UINT32 = a_dispatch.SymCryptSizeofIntFromDigits(nDigitsMax);
    const cbModElement: UINT32 = a_dispatch.SymCryptSizeofModElementFromModulus(ppmCoprimes[0]);
    const cbDouble: UINT32 = a_dispatch.SymCryptSizeofIntFromDigits(2 * nDigitsMax);

    if (cbDouble == 0) {
        // It is possible that cbDouble would not fit within the maximum integer
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    macros.SYMCRYPT_ASSERT(
        cbScratch >= cbInt + cbModElement + cbDouble +
            @max(
                types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(nDigitsMax),
                types.SYMCRYPT_SCRATCH_BYTES_FOR_INT_MUL(2 * nDigitsMax),
            ),
    );

    // Create temporaries
    const piTmp = a_dispatch.SymCryptIntCreate(pbScratch, cbInt, nDigitsMax).?;
    pbScratch += cbInt;
    cbScratch -= cbInt;

    const peTmp = a_dispatch.SymCryptModElementCreate(pbScratch, cbModElement, ppmCoprimes[0]).?;
    pbScratch += cbModElement;
    cbScratch -= cbModElement;

    const piDouble = a_dispatch.SymCryptIntCreate(pbScratch, cbDouble, 2 * nDigitsMax).?;
    pbScratch += cbDouble;
    cbScratch -= cbDouble;

    if (nCoprimes == 2) {
        //
        // Let r0 and r1 be the two remainders modulo p and q respectively
        // Then we calculate (q^{-1}(r0 - r1) mod p)*q + r1
        //
        a_dispatch.SymCryptModElementToInt(ppmCoprimes[1], ppeCrtRemainders[1], piTmp, pbScratch, cbScratch); // Convert r1 to Int
        a_dispatch.SymCryptIntToModElement(piTmp, ppmCoprimes[0], peTmp, pbScratch, cbScratch); // Convert it to r1 mod p

        a_dispatch.SymCryptModSub(ppmCoprimes[0], ppeCrtRemainders[0], peTmp, peTmp, pbScratch, cbScratch); // (r0 - r1) mod p
        a_dispatch.SymCryptModMul(ppmCoprimes[0], ppeCrtInverses[0], peTmp, peTmp, pbScratch, cbScratch); // q^{-1}*(r0 - r1) mod p
        a_dispatch.SymCryptModElementToInt(ppmCoprimes[0], peTmp, piTmp, pbScratch, cbScratch); // Convert it to integer

        a_dispatch.SymCryptIntMulMixedSize(piTmp, a_dispatch.SymCryptIntFromModulus(@constCast(ppmCoprimes[1])), piDouble, pbScratch, cbScratch); // Multiply by q
        const scError = a_dispatch.SymCryptIntCopyMixedSize(piDouble, piSolution); // Copy it into the solution
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }

        a_dispatch.SymCryptModElementToInt(ppmCoprimes[1], ppeCrtRemainders[1], piTmp, pbScratch, cbScratch); // Convert r1 to integer

        const carry: UINT32 = a_dispatch.SymCryptIntAddMixedSize(piTmp, piSolution, piSolution); // Add it to the solution

        if (carry > 0) {
            return .SYMCRYPT_INVALID_ARGUMENT;
        }
        return .SYMCRYPT_NO_ERROR;
    } else {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }
}
