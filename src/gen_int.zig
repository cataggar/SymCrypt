//
// gen_int.zig   Generic integer algorithms (not tied to low-level implementations)
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

const types = @import("types.zig");
const macros = @import("macros.zig");
const a_dispatch = @import("a_dispatch.zig");

const SYMCRYPT_CALL = types.SYMCRYPT_CALL;
const PBYTE = types.PBYTE;
const UINT32 = types.UINT32;
const UINT64 = types.UINT64;
const SIZE_T = types.SIZE_T;
const PSYMCRYPT_INT = types.PSYMCRYPT_INT;
const PCSYMCRYPT_INT = types.PCSYMCRYPT_INT;

pub export fn SymCryptUint64Gcd(a_in: UINT64, b_in: UINT64, flags: UINT32) callconv(SYMCRYPT_CALL) UINT64 {
    var a: UINT64 = a_in;
    var b: UINT64 = b_in;

    macros.SYMCRYPT_ASSERT((flags & types.SYMCRYPT_FLAG_GCD_INPUTS_NOT_BOTH_EVEN) != 0 and ((a | b) & 1) != 0);

    // First we make sure that b is odd
    // If b even: swap (a,b)
    var swap: UINT64 = ~(@as(UINT64, 0) -% (b & 1));
    var tmp: UINT64 = (a ^ b) & swap;
    a ^= tmp;
    b ^= tmp;

    // Each loop iteration reduces len(a) + len(b) by at least 1, so looping 127 times is enough.
    // For inputs (2^63, 2^63 + 1) we get 63 iterations to reduce a to 1, and then another 63 to get
    // the other value to 1, plus one more to make it 0.
    var i: UINT32 = 0;
    while (i < 127) : (i += 1) {
        // Compute the result of the 'else' part of the if( a even ) into (a2, b2)
        // First we evaluate (a < b), which is a bit tricky without access to the carry flag.
        // a < b =      (b>>63) if ((a^b) >> 63) == 1
        //              (a - b) >> 63 otherwise
        tmp = a ^ b;
        tmp = (tmp & b) | (~tmp & (a -% b));
        swap = @as(UINT64, 0) -% (tmp >> 63);

        // Now swap if a < b into (a2, b2)
        tmp = (a ^ b) & swap;
        var a2: UINT64 = a ^ tmp;
        const b2: UINT64 = b ^ tmp;

        a2 = (a2 -% b2) / 2;

        // Compute the (a is odd) condition
        tmp = @as(UINT64, 0) -% (a & 1);

        // Assemble the final result
        a = (tmp & a2) | (~tmp & (a / 2));
        b = (tmp & b2) | (~tmp & b);
    }

    macros.SYMCRYPT_ASSERT(a == 0);
    return b;
}

pub export fn SymCryptIntExtendedGcd(
    piSrc1: PCSYMCRYPT_INT,
    piSrc2: PCSYMCRYPT_INT,
    flags: UINT32,
    piGcd: ?PSYMCRYPT_INT,
    piLcm: ?PSYMCRYPT_INT,
    piInvSrc1ModSrc2: ?PSYMCRYPT_INT,
    piInvSrc2ModSrc1: ?PSYMCRYPT_INT,
    pbScratch_in: PBYTE,
    cbScratch_in: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    var pbScratch = pbScratch_in;
    var cbScratch = cbScratch_in;

    const nDigits: UINT32 = @max(
        a_dispatch.SymCryptIntDigitsizeOfObject(piSrc1),
        a_dispatch.SymCryptIntDigitsizeOfObject(piSrc2),
    );

    _ = flags; // Currently not used to improve performance.

    // Compute how much scratch space we need for the functions we call
    var cbFnScratch: SIZE_T = types.SYMCRYPT_SCRATCH_BYTES_FOR_INT_DIVMOD(2 * nDigits, nDigits);
    cbFnScratch = @max(cbFnScratch, types.SYMCRYPT_SCRATCH_BYTES_FOR_INT_MUL(2 * nDigits));
    cbFnScratch = @max(cbFnScratch, types.SYMCRYPT_SCRATCH_BYTES_FOR_INT_TO_DIVISOR(nDigits));

    const cbInt: UINT32 = a_dispatch.SymCryptSizeofIntFromDigits(nDigits);
    const cbWideInt: UINT32 = a_dispatch.SymCryptSizeofIntFromDigits(2 * nDigits);
    const cbDivisor: UINT32 = a_dispatch.SymCryptSizeofDivisorFromDigits(nDigits);

    macros.SYMCRYPT_ASSERT(cbWideInt != 0);
    macros.SYMCRYPT_ASSERT(
        cbScratch >= 4 * cbInt +
            1 * cbWideInt +
            2 * cbDivisor +
            cbFnScratch,
    );

    const piA = a_dispatch.SymCryptIntCreate(pbScratch, cbInt, nDigits).?;
    pbScratch += cbInt;
    cbScratch -= cbInt;
    // piB is stored inside the pdGcd object created later
    const piTmp = a_dispatch.SymCryptIntCreate(pbScratch, cbInt, nDigits).?;
    pbScratch += cbInt;
    cbScratch -= cbInt;
    const piA1 = a_dispatch.SymCryptIntCreate(pbScratch, cbInt, nDigits).?;
    pbScratch += cbInt;
    cbScratch -= cbInt;
    const piB1 = a_dispatch.SymCryptIntCreate(pbScratch, cbInt, nDigits).?;
    pbScratch += cbInt;
    cbScratch -= cbInt;

    const piTmpDbl = a_dispatch.SymCryptIntCreate(pbScratch, cbWideInt, 2 * nDigits);
    pbScratch += cbWideInt;
    cbScratch -= cbWideInt;

    const pdGcd = a_dispatch.SymCryptDivisorCreate(pbScratch, cbDivisor, nDigits).?;
    pbScratch += cbDivisor;
    cbScratch -= cbDivisor;
    const piB = a_dispatch.SymCryptIntFromDivisor(pdGcd);

    const pdTmp = a_dispatch.SymCryptDivisorCreate(pbScratch, cbDivisor, nDigits).?;
    pbScratch += cbDivisor;
    cbScratch -= cbDivisor;

    _ = a_dispatch.SymCryptIntCopyMixedSize(piSrc1, piA); // Ignore the error return value here as we know
    _ = a_dispatch.SymCryptIntCopyMixedSize(piSrc2, piB); // that the destination integers are large enough.

    a_dispatch.SymCryptIntSetValueUint32(1, piA1);
    a_dispatch.SymCryptIntSetValueUint32(0, piB1);

    // Currently not supported: Src1 to be 0 or Src2 to be even
    macros.SYMCRYPT_ASSERT(a_dispatch.SymCryptIntIsEqualUint32(piA, 0) == 0);
    macros.SYMCRYPT_ASSERT((a_dispatch.SymCryptIntGetValueLsbits32(piB) & 1) != 0);
    if (a_dispatch.SymCryptIntIsEqualUint32(piA, 0) != 0 or
        (a_dispatch.SymCryptIntGetValueLsbits32(piB) & 1) == 0)
    {
        return;
    }

    // Currently not supported: piInvSrc2ModSrc1 != NULL and max( Src1.nDigits, Src2.nDigits ) * 2 > SymCryptDigitsFromBits(SYMCRYPT_INT_MAX_BITS)
    if (piInvSrc2ModSrc1 != null and piTmpDbl == null) {
        return;
    }

    var t: UINT32 = a_dispatch.SymCryptIntBitsizeOfObject(piSrc1) + a_dispatch.SymCryptIntBitsizeOfObject(piSrc2) - 1;
    while (t > 0) {
        t -= 1;

        // if A odd and A < B:
        //     Swap (A, A1) with (B, B1)
        var c: UINT32 = 1 & (a_dispatch.SymCryptIntGetValueLsbits32(piA) & a_dispatch.SymCryptIntSubSameSize(piA, piB, piTmp));
        a_dispatch.SymCryptIntConditionalSwap(piA, piB, c);
        a_dispatch.SymCryptIntConditionalSwap(piA1, piB1, c);

        // if A odd:
        //     A -= B;     A1 -= B1 (mod S2);
        c = 1 & a_dispatch.SymCryptIntGetValueLsbits32(piA);
        _ = a_dispatch.SymCryptIntSubSameSize(piA, piB, piTmp); // Never a carry due to the previous conditional swap
        a_dispatch.SymCryptIntConditionalCopy(piTmp, piA, c);

        var d: UINT32 = a_dispatch.SymCryptIntSubSameSize(piA1, piB1, piTmp);
        a_dispatch.SymCryptIntConditionalCopy(piTmp, piA1, c);
        _ = a_dispatch.SymCryptIntAddMixedSize(piA1, piSrc2, piTmp);
        a_dispatch.SymCryptIntConditionalCopy(piTmp, piA1, c & d);

        // A /= 2;      A1 /= 2 (mod S2);
        macros.SYMCRYPT_ASSERT((a_dispatch.SymCryptIntGetValueLsbits32(piA) & 1) == 0);
        a_dispatch.SymCryptIntShr1(0, piA, piA);
        c = a_dispatch.SymCryptIntGetValueLsbits32(piA1) & 1;
        d = a_dispatch.SymCryptIntAddMixedSize(piA1, piSrc2, piTmp);
        a_dispatch.SymCryptIntConditionalCopy(piTmp, piA1, c);
        a_dispatch.SymCryptIntShr1(c & d, piA1, piA1);
    }

    // B = GCD, B1 * S1 = GCD (mod S2)
    // A = 0, A1 is scratch
    //
    // Algorithm from here:
    // GCD as divisor
    // LCM = S1 * S2 / GCD.
    // P2 = S2 / GCD, as divisor (only for InvS1ModS2)
    // InvS1ModS2 = B1 mod P2
    // InvS2ModS1 = -((B1*S1 - GCD) div S2) mod S1

    if (piGcd) |gcd| {
        _ = a_dispatch.SymCryptIntCopyMixedSize(piB, gcd);
    }

    if (piLcm == null and piInvSrc1ModSrc2 == null and piInvSrc2ModSrc1 == null) {
        // Only GCD needed; don't do the other work
        return;
    }

    _ = a_dispatch.SymCryptIntCopyMixedSize(piB, a_dispatch.SymCryptIntFromDivisor(pdGcd)); // copy into INT of the right size

    // IntToDivisor requirement:
    //      Gcd != 0
    a_dispatch.SymCryptIntToDivisor(a_dispatch.SymCryptIntFromDivisor(pdGcd), pdGcd, 3, 0, pbScratch, cbScratch);

    if (piLcm) |lcm| {
        // LCM = S1 * S2 / GCD
        a_dispatch.SymCryptIntMulMixedSize(piSrc1, piSrc2, lcm, pbScratch, cbScratch);
        a_dispatch.SymCryptIntDivMod(lcm, pdGcd, lcm, null, pbScratch, cbScratch);
    }

    if (piInvSrc1ModSrc2) |inv1| {
        // Future optimization: if GCD == 1 then we can just copy B1.
        a_dispatch.SymCryptIntDivMod(piSrc2, pdGcd, a_dispatch.SymCryptIntFromDivisor(pdTmp), null, pbScratch, cbScratch);

        // IntToDivisor requirement:
        //      Src2 / pdGcd > 0
        a_dispatch.SymCryptIntToDivisor(a_dispatch.SymCryptIntFromDivisor(pdTmp), pdTmp, 1, 0, pbScratch, cbScratch);
        a_dispatch.SymCryptIntDivMod(piB1, pdTmp, null, inv1, pbScratch, cbScratch);
    }

    if (piInvSrc2ModSrc1) |inv2| {
        const tmpDbl = piTmpDbl.?;
        // InvS2ModS1 = - ( (B1*S1 - GCD)/S2 ) mod S1

        // S2 as divisor
        _ = a_dispatch.SymCryptIntCopyMixedSize(piSrc2, a_dispatch.SymCryptIntFromDivisor(pdTmp));

        // IntToDivisor requirement:
        //      Src2 is odd --> Src2 != 0
        a_dispatch.SymCryptIntToDivisor(a_dispatch.SymCryptIntFromDivisor(pdTmp), pdTmp, 1, 0, pbScratch, cbScratch);

        a_dispatch.SymCryptIntMulMixedSize(piB1, piSrc1, tmpDbl, pbScratch, cbScratch);
        _ = a_dispatch.SymCryptIntSubMixedSize(tmpDbl, piB, tmpDbl); // Never a borrow if B1 >= 1
        a_dispatch.SymCryptIntDivMod(tmpDbl, pdTmp, tmpDbl, null, pbScratch, cbScratch);

        // and reduce modulo S1
        _ = a_dispatch.SymCryptIntCopyMixedSize(piSrc1, a_dispatch.SymCryptIntFromDivisor(pdTmp));

        // IntToDivisor requirement:
        //      Src1 > 0
        a_dispatch.SymCryptIntToDivisor(a_dispatch.SymCryptIntFromDivisor(pdTmp), pdTmp, 1, 0, pbScratch, cbScratch);
        a_dispatch.SymCryptIntDivMod(tmpDbl, pdTmp, null, inv2, pbScratch, cbScratch);

        // Negative modulo S1
        _ = a_dispatch.SymCryptIntSubMixedSize(a_dispatch.SymCryptIntFromDivisor(pdTmp), inv2, inv2); // Never a borrow as piInvSrc2ModSrc1 < S1
    }
}
