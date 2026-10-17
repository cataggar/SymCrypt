//
// modexp.zig   Modular exponentiation functions
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

const std = @import("std");
const types = @import("types.zig");
const macros = @import("macros.zig");
const scs_table = @import("scs_table.zig");
const recoding = @import("recoding.zig");
const a_dispatch = @import("a_dispatch.zig");

const SYMCRYPT_CALL = types.SYMCRYPT_CALL;
const SYMCRYPT_ERROR = types.SYMCRYPT_ERROR;
const PBYTE = types.PBYTE;
const UINT32 = types.UINT32;
const PUINT32 = types.PUINT32;
const SIZE_T = types.SIZE_T;
const PVOID = types.PVOID;
const PCSYMCRYPT_INT = types.PCSYMCRYPT_INT;
const PCSYMCRYPT_MODULUS = types.PCSYMCRYPT_MODULUS;
const PSYMCRYPT_MODELEMENT = types.PSYMCRYPT_MODELEMENT;
const PCSYMCRYPT_MODELEMENT = types.PCSYMCRYPT_MODELEMENT;
const SYMCRYPT_SCSTABLE = types.SYMCRYPT_SCSTABLE;

extern fn SymCryptWipe(pbData: PVOID, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void;

// The minimum value of W is W=4 as 2^W should be a multiple
// of the groupsize of the scsTable, which is 4 by default.
const MIN_WINDOW_SIZE: UINT32 = 4;

const cutoffs = [_]UINT32{
    // 5,      // W should be 2 for 5 < B <= 25
    // 25,     // W should be 3 for 25 < B <= 97
    // 97,     // W should be 4 for 97 < B <= 321
    321, // W should be 5 for 321 < B <= 961
    // 961,    // W should be 6 for 961 < B
};

const nCuttoffs: UINT32 = @intCast(cutoffs.len);

pub export fn SymCryptModExpWindowed(
    pmMod: PCSYMCRYPT_MODULUS,
    peBase: PCSYMCRYPT_MODELEMENT,
    piExp: PCSYMCRYPT_INT,
    nBitsExp_in: UINT32,
    peDst: PSYMCRYPT_MODELEMENT,
    pbScratch_in: PBYTE,
    cbScratch_in: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    var pbScratch = pbScratch_in;
    var cbScratch = cbScratch_in;

    var scsPrecomp: SYMCRYPT_SCSTABLE = std.mem.zeroes(SYMCRYPT_SCSTABLE);
    const cbModElement: UINT32 = a_dispatch.SymCryptSizeofModElementFromModulus(pmMod);

    // Truncate the nBitsExp if above the object size
    const nBitsExp: UINT32 = @min(nBitsExp_in, a_dispatch.SymCryptIntBitsizeOfObject(piExp));

    // Calculate the window size
    var W: UINT32 = MIN_WINDOW_SIZE;
    while ((W - MIN_WINDOW_SIZE < nCuttoffs) and (cutoffs[W - MIN_WINDOW_SIZE] < nBitsExp)) {
        W += 1;
    }
    const nTableElements: UINT32 = @as(UINT32, 1) << @intCast(W);

    // Initialize the table of temporary modelements
    const cbScsPrecomp: UINT32 = scs_table.SymCryptScsTableInit(&scsPrecomp, nTableElements, cbModElement);

    macros.SYMCRYPT_ASSERT(
        cbScratch >= cbScsPrecomp + 2 * cbModElement + types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(pmMod.nDigits),
    );

    scs_table.SymCryptScsTableSetBuffer(&scsPrecomp, pbScratch, cbScsPrecomp);
    pbScratch += cbScsPrecomp;
    cbScratch -= cbScsPrecomp;

    // Create the temporary modelements
    const peT1 = a_dispatch.SymCryptModElementCreate(pbScratch, cbModElement, pmMod).?;
    pbScratch += cbModElement;
    cbScratch -= cbModElement;
    const peT2 = a_dispatch.SymCryptModElementCreate(pbScratch, cbModElement, pmMod).?;
    pbScratch += cbModElement;
    cbScratch -= cbModElement;

    // Fill the first element with 1 (**note: this will cause 0^0 = 1)
    // and the second with peBase
    macros.SYMCRYPT_ASSERT(nTableElements >= 2);

    a_dispatch.SymCryptModElementSetValueUint32(1, pmMod, peT1, pbScratch, cbScratch);
    scs_table.SymCryptScsTableStore(&scsPrecomp, 0, @ptrCast(peT1), cbModElement);

    a_dispatch.SymCryptModElementCopy(pmMod, peBase, peT1);
    scs_table.SymCryptScsTableStore(&scsPrecomp, 1, @ptrCast(peT1), cbModElement);

    // Fill the table with the powers of peBase
    var i: UINT32 = 2;
    while (i < nTableElements) : (i += 1) {
        a_dispatch.SymCryptModMul(pmMod, peT1, peBase, peT1, pbScratch, cbScratch);
        scs_table.SymCryptScsTableStore(&scsPrecomp, i, @ptrCast(peT1), cbModElement);
    }

    // Find the number of iterations (minus one) and the starting position bit
    macros.SYMCRYPT_ASSERT(nBitsExp != 0);
    const nIterations: UINT32 = (nBitsExp - 1) / W;
    var iBit: UINT32 = nIterations * W;

    // Do the first chunk (it might be smaller than W bits)
    const nBits: UINT32 = nBitsExp - iBit;
    var index: UINT32 = a_dispatch.SymCryptIntGetBits(piExp, iBit, nBits);
    scs_table.SymCryptScsTableLoad(&scsPrecomp, index, @ptrCast(peT1), cbModElement);

    // Work in batches of W bits in the exponent
    i = 0;
    while (i < nIterations) : (i += 1) {
        // Square W times
        var j: UINT32 = 0;
        while (j < W) : (j += 1) {
            a_dispatch.SymCryptModSquare(pmMod, peT1, peT1, pbScratch, cbScratch);
        }

        iBit -= W;
        index = a_dispatch.SymCryptIntGetBits(piExp, iBit, W);
        scs_table.SymCryptScsTableLoad(&scsPrecomp, index, @ptrCast(peT2), cbModElement);

        a_dispatch.SymCryptModMul(pmMod, peT1, peT2, peT1, pbScratch, cbScratch);
    }

    macros.SYMCRYPT_ASSERT(iBit == 0);

    a_dispatch.SymCryptModElementCopy(pmMod, peT1, peDst);
}

pub export fn SymCryptModExpSquareAndMultiply32(
    pmMod: PCSYMCRYPT_MODULUS,
    peBase: PCSYMCRYPT_MODELEMENT,
    piExp: PCSYMCRYPT_INT,
    peDst: PSYMCRYPT_MODELEMENT,
    pbScratch_in: PBYTE,
    cbScratch_in: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    var pbScratch = pbScratch_in;
    var cbScratch = cbScratch_in;

    const cbModElement: UINT32 = a_dispatch.SymCryptSizeofModElementFromModulus(pmMod);

    // The bits of the exponent when this function is called are
    // always less than 32.
    var exp: UINT32 = a_dispatch.SymCryptIntGetValueLsbits32(piExp);

    macros.SYMCRYPT_ASSERT(
        cbScratch >= 2 * cbModElement + types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(pmMod.nDigits),
    );

    // Create the temporary modelements
    const peT1 = a_dispatch.SymCryptModElementCreate(pbScratch, cbModElement, pmMod).?;
    pbScratch += cbModElement;
    cbScratch -= cbModElement;
    const peT2 = a_dispatch.SymCryptModElementCreate(pbScratch, cbModElement, pmMod).?;
    pbScratch += cbModElement;
    cbScratch -= cbModElement;

    if (exp == 0) {
        a_dispatch.SymCryptModElementSetValueUint32(1, pmMod, peDst, pbScratch, cbScratch);
    } else {
        a_dispatch.SymCryptModElementSetValueUint32(1, pmMod, peT1, pbScratch, cbScratch);
        a_dispatch.SymCryptModElementCopy(pmMod, peBase, peT2);

        while (exp > 1) {
            if (exp % 2 == 1) {
                a_dispatch.SymCryptModMul(pmMod, peT1, peT2, peT1, pbScratch, cbScratch);
            }

            a_dispatch.SymCryptModSquare(pmMod, peT2, peT2, pbScratch, cbScratch);
            exp /= 2;
        }

        a_dispatch.SymCryptModMul(pmMod, peT1, peT2, peDst, pbScratch, cbScratch);
    }
}

pub export fn SymCryptModExpGeneric(
    pmMod: PCSYMCRYPT_MODULUS,
    peBase: PCSYMCRYPT_MODELEMENT,
    piExp: PCSYMCRYPT_INT,
    nBitsExp: UINT32,
    flags: UINT32,
    peDst: PSYMCRYPT_MODELEMENT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    if (((flags & types.SYMCRYPT_FLAG_DATA_PUBLIC) != 0) and (nBitsExp <= @sizeOf(UINT32) * 8)) {
        SymCryptModExpSquareAndMultiply32(pmMod, peBase, piExp, peDst, pbScratch, cbScratch);
    } else {
        SymCryptModExpWindowed(pmMod, peBase, piExp, nBitsExp, peDst, pbScratch, cbScratch); // This is the default
    }
}

//
// MultiExponentiation
//

const SYMCRYPT_MODMULTIEXP_MAX_NPRECOMP: UINT32 = 1 << (types.SYMCRYPT_FDEF_MAX_WINDOW_MODEXP - 1);
const SYMCRYPT_MODMULTIEXP_WINDOW_SIZE: UINT32 = 5;

comptime {
    std.debug.assert((1 << (SYMCRYPT_MODMULTIEXP_WINDOW_SIZE - 1)) <= SYMCRYPT_MODMULTIEXP_MAX_NPRECOMP);
}

pub export fn SymCryptModExpPrecomputation(
    pmP: PCSYMCRYPT_MODULUS,
    nPrecomputedPowers: UINT32,
    pePIs: [*]PSYMCRYPT_MODELEMENT,
    peTemp: PSYMCRYPT_MODELEMENT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    macros.SYMCRYPT_ASSERT(nPrecomputedPowers >= 2);

    // Calculate B^2
    a_dispatch.SymCryptModSquare(pmP, pePIs[0], peTemp, pbScratch, cbScratch);

    var i: UINT32 = 1;
    while (i < nPrecomputedPowers) : (i += 1) {
        // B[i] = B^2*B[i-1]
        a_dispatch.SymCryptModMul(pmP, peTemp, pePIs[i - 1], pePIs[i], pbScratch, cbScratch);
    }
}

pub export fn SymCryptModMultiExpWnafWithInterleaving(
    pmMod: PCSYMCRYPT_MODULUS,
    peBaseArray: [*]const PCSYMCRYPT_MODELEMENT,
    piExpArray: [*]const PCSYMCRYPT_INT,
    nBases: UINT32,
    nBitsExp: UINT32,
    peDst: PSYMCRYPT_MODELEMENT,
    pbScratch_in: PBYTE,
    cbScratch_in: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    var pbScratch = pbScratch_in;
    var cbScratch = cbScratch_in;

    // Masks
    var fOne: [types.SYMCRYPT_MODMULTIEXP_MAX_NBASES]UINT32 = @splat(0);
    var fOneTot: UINT32 = 0xffffffff; // Final result 1

    var fZeroExp: UINT32 = 0; // Zero exponent
    var fZeroTot: UINT32 = 0; // Final result 0

    const cbModElement: UINT32 = a_dispatch.SymCryptSizeofModElementFromModulus(pmMod);

    // Temporaries
    var pePIs: [types.SYMCRYPT_MODMULTIEXP_MAX_NBASES * SYMCRYPT_MODMULTIEXP_MAX_NPRECOMP]PSYMCRYPT_MODELEMENT = undefined;

    // Calculate the window size
    const w: UINT32 = SYMCRYPT_MODMULTIEXP_WINDOW_SIZE;
    const nPrecompPoints: UINT32 = 1 << (w - 1); // We only store odd powers of the base point

    // Number of recoded digits
    const nRecodedDigits: UINT32 = nBitsExp;

    macros.SYMCRYPT_ASSERT(types.SYMCRYPT_MODMULTIEXP_MAX_NBASES >= nBases);
    macros.SYMCRYPT_ASSERT(SYMCRYPT_MODMULTIEXP_MAX_NPRECOMP >= nPrecompPoints);

    // Creating temporary precomputed modelements
    var i: UINT32 = 0;
    while (i < nBases * nPrecompPoints) : (i += 1) {
        macros.SYMCRYPT_ASSERT(cbScratch >= cbModElement);
        pePIs[i] = a_dispatch.SymCryptModElementCreate(pbScratch, cbModElement, pmMod).?;
        pbScratch += cbModElement;
        cbScratch -= cbModElement;
    }

    macros.SYMCRYPT_ASSERT(
        cbScratch >= 2 * cbModElement +
            ((nBases * nRecodedDigits * @sizeOf(UINT32) + types.SYMCRYPT_ASYM_ALIGN_VALUE - 1) / types.SYMCRYPT_ASYM_ALIGN_VALUE) * types.SYMCRYPT_ASYM_ALIGN_VALUE +
            types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(a_dispatch.SymCryptModulusDigitsizeOfObject(pmMod)),
    );

    // Creating temporary points
    const peTemp = a_dispatch.SymCryptModElementCreate(pbScratch, cbModElement, pmMod).?;
    pbScratch += cbModElement;
    cbScratch -= cbModElement;

    const peOne = a_dispatch.SymCryptModElementCreate(pbScratch, cbModElement, pmMod).?;
    pbScratch += cbModElement;
    cbScratch -= cbModElement;

    // Fixing pointers to recoded digits (be careful that the remaining space is SYMCRYPT_ASYM_ALIGNed)
    const absofKIs: PUINT32 = @ptrCast(@alignCast(pbScratch));
    const cbRecoded: usize = @as(usize, nBases) * @as(usize, nRecodedDigits) * @sizeOf(UINT32);
    pbScratch += cbRecoded;
    cbScratch -= cbRecoded;

    // Update cbScratch first using pbScratch, as the amount of scratch skipped for alignment depends upon the alignment of pbScratch
    const alignMask: usize = types.SYMCRYPT_ASYM_ALIGN_VALUE - 1;
    const addr: usize = @intFromPtr(pbScratch);
    const skip: usize = ((addr + alignMask) & ~alignMask) - addr;
    cbScratch -= skip;
    pbScratch += skip;

    //
    // Main algorithm
    //

    // Set peOne to 1
    a_dispatch.SymCryptModElementSetValueUint32(1, pmMod, peOne, pbScratch, cbScratch);

    // Zero-out all recoded digits
    SymCryptWipe(@ptrCast(absofKIs), cbRecoded);

    var j: UINT32 = 0;
    while (j < nBases) : (j += 1) {
        // Check if the exponent is zero
        fZeroExp = a_dispatch.SymCryptIntIsEqualUint32(piExpArray[j], 0);

        // Check if the result is 0 (i.e. 0^e with e!=0)
        if (fZeroExp == 0 and a_dispatch.SymCryptModElementIsZero(pmMod, peBaseArray[j]) != 0) {
            fZeroTot = 0xffffffff;
            break;
        }

        // Check if the exponent is 0 or if the base point is 1
        fOne[j] = fZeroExp | a_dispatch.SymCryptModElementIsEqual(pmMod, peBaseArray[j], peOne);
        fOneTot &= fOne[j];

        // Skip the recoding stage (and all remaining steps) if this point will give result 1
        if (fOne[j] == 0) {
            // Recoding stage
            recoding.SymCryptPositiveWidthNafRecoding(
                w,
                piExpArray[j],
                nBitsExp,
                absofKIs + @as(usize, j) * @as(usize, nRecodedDigits),
                nRecodedDigits,
            );

            // Copy the base in the start of the pePIs array
            a_dispatch.SymCryptModElementCopy(pmMod, peBaseArray[j], pePIs[j * nPrecompPoints]);

            // Precomputation stage
            SymCryptModExpPrecomputation(
                pmMod,
                nPrecompPoints,
                @ptrCast(&pePIs[j * nPrecompPoints]),
                peTemp,
                pbScratch,
                cbScratch,
            );
        }
    }

    if (fZeroTot != 0) {
        a_dispatch.SymCryptModElementSetValueUint32(0, pmMod, peDst, pbScratch, cbScratch);
    } else {
        a_dispatch.SymCryptModElementSetValueUint32(1, pmMod, peTemp, pbScratch, cbScratch);

        if (fOneTot == 0) {
            // Main loop
            var idx: i32 = @as(i32, @intCast(nRecodedDigits)) - 1;
            while (idx > -1) : (idx -= 1) {
                const uIdx: usize = @intCast(idx);
                a_dispatch.SymCryptModSquare(pmMod, peTemp, peTemp, pbScratch, cbScratch);

                j = 0;
                while (j < nBases) : (j += 1) {
                    const ki: UINT32 = absofKIs[@as(usize, j) * @as(usize, nRecodedDigits) + uIdx];
                    if (ki != 0) {
                        a_dispatch.SymCryptModMul(
                            pmMod,
                            peTemp,
                            pePIs[j * nPrecompPoints + ki / 2],
                            peTemp,
                            pbScratch,
                            cbScratch,
                        );
                    }
                }
            }
        }

        // Copy the result into the destination
        a_dispatch.SymCryptModElementCopy(pmMod, peTemp, peDst);
    }
}

pub export fn SymCryptModMultiExpGeneric(
    pmMod: PCSYMCRYPT_MODULUS,
    peBaseArray: [*]const PCSYMCRYPT_MODELEMENT,
    piExpArray: [*]const PCSYMCRYPT_INT,
    nBases: UINT32,
    nBitsExp: UINT32,
    flags: UINT32,
    peDst: PSYMCRYPT_MODELEMENT,
    pbScratch_in: PBYTE,
    cbScratch_in: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var pbScratch = pbScratch_in;
    var cbScratch = cbScratch_in;

    if ((nBases > types.SYMCRYPT_MODMULTIEXP_MAX_NBASES) or
        (nBitsExp > types.SYMCRYPT_MODMULTIEXP_MAX_NBITSEXP))
    {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    if ((flags & types.SYMCRYPT_FLAG_DATA_PUBLIC) != 0) {
        SymCryptModMultiExpWnafWithInterleaving(pmMod, peBaseArray, piExpArray, nBases, nBitsExp, peDst, pbScratch, cbScratch);
    } else {
        // Use two temporary modelements to store the results
        // *** Make sure that the scratch space is enough i.e. the scratch space of ModMultiExp is
        //  at least 2 modelements bigger than the scratch space of ModExp
        const cbModElement: UINT32 = a_dispatch.SymCryptSizeofModElementFromModulus(pmMod);

        macros.SYMCRYPT_ASSERT(
            types.SYMCRYPT_SCRATCH_BYTES_FOR_MODEXP(a_dispatch.SymCryptModulusDigitsizeOfObject(pmMod)) + 2 * cbModElement <=
                types.SYMCRYPT_SCRATCH_BYTES_FOR_MODMULTIEXP(a_dispatch.SymCryptModulusDigitsizeOfObject(pmMod), nBases, nBitsExp),
        );
        macros.SYMCRYPT_ASSERT(
            cbScratch >= 2 * cbModElement + types.SYMCRYPT_SCRATCH_BYTES_FOR_MODEXP(a_dispatch.SymCryptModulusDigitsizeOfObject(pmMod)),
        );

        const peTemp = a_dispatch.SymCryptModElementCreate(pbScratch, cbModElement, pmMod).?;
        pbScratch += cbModElement;
        cbScratch -= cbModElement;

        const peAcc = a_dispatch.SymCryptModElementCreate(pbScratch, cbModElement, pmMod).?;
        pbScratch += cbModElement;
        cbScratch -= cbModElement;

        // Set peAcc to 1
        a_dispatch.SymCryptModElementSetValueUint32(1, pmMod, peAcc, pbScratch, cbScratch);

        var i: UINT32 = 0;
        while (i < nBases) : (i += 1) {
            SymCryptModExpWindowed(pmMod, peBaseArray[i], piExpArray[i], nBitsExp, peTemp, pbScratch, cbScratch);

            a_dispatch.SymCryptModMul(pmMod, peAcc, peTemp, peAcc, pbScratch, cbScratch);
        }

        // Copy the result into the destination
        a_dispatch.SymCryptModElementCopy(pmMod, peAcc, peDst);
    }

    return .SYMCRYPT_NO_ERROR;
}
