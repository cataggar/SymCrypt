//
// ec_mul.zig   Generic multiplication algorithms for elliptic curves
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

const types = @import("types.zig");
const macros = @import("macros.zig");
const a_dispatch = @import("a_dispatch.zig");
const recoding = @import("recoding.zig");
const ecurve = @import("ecurve.zig");
const ecpoint = @import("ecpoint.zig");
const ec_dispatch = @import("ec_dispatch.zig");

const PBYTE = types.PBYTE;
const UINT32 = types.UINT32;
const PUINT32 = types.PUINT32;
const INT32 = types.INT32;
const SIZE_T = types.SIZE_T;
const SYMCRYPT_CALL = types.SYMCRYPT_CALL;
const SYMCRYPT_ERROR = types.SYMCRYPT_ERROR;
const PSYMCRYPT_ECURVE = types.PSYMCRYPT_ECURVE;
const PCSYMCRYPT_ECURVE = types.PCSYMCRYPT_ECURVE;
const PSYMCRYPT_ECPOINT = types.PSYMCRYPT_ECPOINT;
const PCSYMCRYPT_ECPOINT = types.PCSYMCRYPT_ECPOINT;
const PSYMCRYPT_INT = types.PSYMCRYPT_INT;
const PCSYMCRYPT_INT = types.PCSYMCRYPT_INT;
const PCSYMCRYPT_MODULUS = types.PCSYMCRYPT_MODULUS;
const PSYMCRYPT_MODELEMENT = types.PSYMCRYPT_MODELEMENT;

// Mask which is 0xffffffff only when _index == _target
inline fn DELTA_MASK(index: UINT32, target: UINT32) UINT32 {
    return macros.SYMCRYPT_MASK32_ZERO(index ^ target);
}

pub export fn SymCryptPrecomputation(
    pCurve: PCSYMCRYPT_ECURVE,
    nPoints: UINT32,
    poPIs: [*]PSYMCRYPT_ECPOINT,
    poQ: PSYMCRYPT_ECPOINT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    @setRuntimeSafety(false);
    macros.SYMCRYPT_ASSERT(ecurve.SymCryptEcurveIsSame(pCurve, poQ.pCurve) != 0);
    // Calculation for Q = 2*P
    ec_dispatch.SymCryptEcpointDouble(pCurve, poPIs[0], poQ, 0, pbScratch, cbScratch);

    var i: UINT32 = 1;
    while (i < nPoints) : (i += 1) {
        // Calculation for (2i+1)*P = i*Q + P
        ec_dispatch.SymCryptEcpointAddDiffNonZero(pCurve, poQ, poPIs[i - 1], poPIs[i], pbScratch, cbScratch);
    }
}

pub export fn SymCryptOfflinePrecomputation(
    pCurve: PSYMCRYPT_ECURVE,
    pbScratch_in: PBYTE,
    cbScratch_in: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    @setRuntimeSafety(false);
    var pbScratch = pbScratch_in;
    var cbScratch = cbScratch_in;
    const cbEcpoint: UINT32 = ecpoint.SymCryptSizeofEcpointFromCurve(pCurve);

    macros.SYMCRYPT_ASSERT(cbScratch >= cbEcpoint + types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(pCurve.FModDigits));

    const poQ: PSYMCRYPT_ECPOINT = ecpoint.SymCryptEcpointCreate(pbScratch, cbEcpoint, pCurve).?;
    pbScratch += cbEcpoint;
    cbScratch -= cbEcpoint;

    SymCryptPrecomputation(
        pCurve,
        pCurve.info.sw.nPrecompPoints,
        @ptrCast(&pCurve.info.sw.poPrecompPoints[0]),
        poQ,
        pbScratch,
        cbScratch,
    );
}

pub export fn SymCryptEcpointScalarMulFixedWindow(
    pCurve: PCSYMCRYPT_ECURVE,
    piScalar: PCSYMCRYPT_INT,
    poSrc_in: ?PCSYMCRYPT_ECPOINT,
    flags: UINT32,
    poDst: PSYMCRYPT_ECPOINT,
    pbScratch_in: PBYTE,
    cbScratch_in: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    @setRuntimeSafety(false);
    const FMod: PCSYMCRYPT_MODULUS = pCurve.FMod;
    var pbScratch = pbScratch_in;
    var cbScratch = cbScratch_in;

    const w: UINT32 = pCurve.info.sw.window;
    const nPrecompPoints: UINT32 = pCurve.info.sw.nPrecompPoints;
    const nRecodedDigits: UINT32 = ((pCurve.GOrdBitsize + w - 2) / (w - 1)) + 1;

    var fZero: UINT32 = 0;
    var fEven: UINT32 = 0;
    var indexMask: UINT32 = 0;

    var bPrecompOffline: bool = false;

    var poPIs: [types.SYMCRYPT_ECURVE_SW_MAX_NPRECOMP_POINTS]PSYMCRYPT_ECPOINT = undefined;

    const cbEcpoint: SIZE_T = ecpoint.SymCryptSizeofEcpointFromCurve(pCurve);
    const cbScalar: SIZE_T = a_dispatch.SymCryptSizeofIntFromDigits(pCurve.GOrdDigits);

    if ((flags & ~types.SYMCRYPT_FLAG_ECC_LL_COFACTOR_MUL) != 0) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    const poSrc: PCSYMCRYPT_ECPOINT = if (poSrc_in) |s| s else blk: {
        bPrecompOffline = true;
        break :blk pCurve.G;
    };

    macros.SYMCRYPT_ASSERT(
        types.SYMCRYPT_CURVE_IS_SHORT_WEIERSTRASS_TYPE(pCurve) or
            types.SYMCRYPT_CURVE_IS_TWISTED_EDWARDS_TYPE(pCurve),
    );
    macros.SYMCRYPT_ASSERT(
        ecurve.SymCryptEcurveIsSame(pCurve, poSrc.pCurve) != 0 and
            ecurve.SymCryptEcurveIsSame(pCurve, poDst.pCurve) != 0,
    );
    macros.SYMCRYPT_ASSERT(cbScratch >= types.SYMCRYPT_SCRATCH_BYTES_FOR_SCALAR_ECURVE_OPERATIONS(pCurve, 1));

    const asym_align: SIZE_T = types.SYMCRYPT_ASYM_ALIGN_VALUE;
    const cbRecodedAligned: SIZE_T = ((2 * @as(SIZE_T, nRecodedDigits) * @sizeOf(UINT32) + asym_align - 1) / asym_align) * asym_align;

    macros.SYMCRYPT_ASSERT(
        cbScratch >=
            pCurve.cbModElement +
                (nPrecompPoints + 2) * cbEcpoint +
                2 * cbScalar +
                cbRecodedAligned +
                types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_ECURVE_OPERATIONS(pCurve),
    );

    // Creating temporary modelement
    const peT: PSYMCRYPT_MODELEMENT = a_dispatch.SymCryptModElementCreate(pbScratch, pCurve.cbModElement, FMod).?;
    _ = peT;
    pbScratch += pCurve.cbModElement;

    macros.SYMCRYPT_ASSERT(nPrecompPoints <= types.SYMCRYPT_ECURVE_SW_MAX_NPRECOMP_POINTS);
    var i: UINT32 = 0;
    while (i < nPrecompPoints) : (i += 1) {
        if (bPrecompOffline) {
            poPIs[i] = pCurve.info.sw.poPrecompPoints[i].?;
        } else {
            poPIs[i] = ecpoint.SymCryptEcpointCreate(pbScratch, cbEcpoint, pCurve).?;
            pbScratch += cbEcpoint;
        }
    }

    const poQ: PSYMCRYPT_ECPOINT = ecpoint.SymCryptEcpointCreate(pbScratch, cbEcpoint, pCurve).?;
    pbScratch += cbEcpoint;

    const poTmp: PSYMCRYPT_ECPOINT = ecpoint.SymCryptEcpointCreate(pbScratch, cbEcpoint, pCurve).?;
    pbScratch += cbEcpoint;

    const piRem: PSYMCRYPT_INT = a_dispatch.SymCryptIntCreate(pbScratch, cbScalar, pCurve.GOrdDigits).?;
    pbScratch += cbScalar;

    const piTmp: PSYMCRYPT_INT = a_dispatch.SymCryptIntCreate(pbScratch, cbScalar, pCurve.GOrdDigits).?;
    pbScratch += cbScalar;

    const absofKIs: PUINT32 = @ptrCast(@alignCast(pbScratch));
    pbScratch += @as(SIZE_T, nRecodedDigits) * @sizeOf(UINT32);
    const sigofKIs: PUINT32 = @ptrCast(@alignCast(pbScratch));
    pbScratch += @as(SIZE_T, nRecodedDigits) * @sizeOf(UINT32);
    pbScratch = @ptrFromInt((@intFromPtr(pbScratch) + asym_align - 1) & ~(asym_align - 1));

    cbScratch -= (pCurve.cbModElement + (nPrecompPoints + 2) * cbEcpoint + 2 * cbScalar);
    cbScratch -= cbRecodedAligned;

    // It is the caller's responsibility to ensure that the provided piScalar <= GOrd, double check this in debug mode
    macros.SYMCRYPT_ASSERT(a_dispatch.SymCryptIntIsLessThan(a_dispatch.SymCryptIntFromModulus(pCurve.GOrd), piScalar) == 0);

    a_dispatch.SymCryptIntCopy(piScalar, piRem);

    fZero = a_dispatch.SymCryptIntIsEqualUint32(piRem, 0);
    fZero |= ec_dispatch.SymCryptEcpointIsZero(pCurve, poSrc, pbScratch, cbScratch);

    fEven = macros.SYMCRYPT_MASK32_ZERO(a_dispatch.SymCryptIntGetBit(piRem, 0));
    _ = a_dispatch.SymCryptIntSubSameSize(a_dispatch.SymCryptIntFromModulus(pCurve.GOrd), piRem, piTmp);
    a_dispatch.SymCryptIntMaskedCopy(piTmp, piRem, fEven);

    recoding.SymCryptFixedWindowRecoding(w, piRem, piTmp, absofKIs, sigofKIs, nRecodedDigits);

    if (!bPrecompOffline) {
        ecpoint.SymCryptEcpointCopy(pCurve, poSrc, poPIs[0]);
        SymCryptPrecomputation(pCurve, nPrecompPoints, &poPIs, poQ, pbScratch, cbScratch);
    }

    var j: UINT32 = 0;
    while (j < nPrecompPoints) : (j += 1) {
        indexMask = DELTA_MASK(j, absofKIs[nRecodedDigits - 1]);
        ecpoint.SymCryptEcpointMaskedCopy(pCurve, poPIs[j], poQ, indexMask);
    }

    i = nRecodedDigits - 2;
    while (i > 0) : (i -= 1) {
        j = 0;
        while (j < w - 1) : (j += 1) {
            ec_dispatch.SymCryptEcpointDouble(pCurve, poQ, poQ, 0, pbScratch, cbScratch);
        }

        j = 0;
        while (j < nPrecompPoints) : (j += 1) {
            indexMask = DELTA_MASK(j, absofKIs[i]);
            ecpoint.SymCryptEcpointMaskedCopy(pCurve, poPIs[j], poTmp, indexMask);
        }

        ec_dispatch.SymCryptEcpointNegate(pCurve, poTmp, sigofKIs[i], pbScratch, cbScratch);

        ec_dispatch.SymCryptEcpointAddDiffNonZero(pCurve, poQ, poTmp, poQ, pbScratch, cbScratch);
    }

    j = 0;
    while (j < w - 1) : (j += 1) {
        ec_dispatch.SymCryptEcpointDouble(pCurve, poQ, poQ, 0, pbScratch, cbScratch);
    }

    j = 0;
    while (j < nPrecompPoints) : (j += 1) {
        indexMask = DELTA_MASK(j, absofKIs[0]);
        ecpoint.SymCryptEcpointMaskedCopy(pCurve, poPIs[j], poTmp, indexMask);
    }

    ec_dispatch.SymCryptEcpointNegate(pCurve, poTmp, sigofKIs[0], pbScratch, cbScratch);

    ec_dispatch.SymCryptEcpointAdd(pCurve, poQ, poTmp, poQ, 0, pbScratch, cbScratch);

    ec_dispatch.SymCryptEcpointNegate(pCurve, poQ, fEven, pbScratch, cbScratch);

    if ((pCurve.coFactorPower != 0) and ((flags & types.SYMCRYPT_FLAG_ECC_LL_COFACTOR_MUL) != 0)) {
        j = 0;
        while (j < pCurve.coFactorPower) : (j += 1) {
            ec_dispatch.SymCryptEcpointDouble(pCurve, poQ, poQ, 0, pbScratch, cbScratch);
        }
    }

    fZero |= ec_dispatch.SymCryptEcpointIsZero(pCurve, poQ, pbScratch, cbScratch);

    ec_dispatch.SymCryptEcpointSetZero(pCurve, poTmp, pbScratch, cbScratch);
    ecpoint.SymCryptEcpointMaskedCopy(pCurve, poTmp, poQ, fZero);

    ecpoint.SymCryptEcpointCopy(pCurve, poQ, poDst);

    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptEcpointMultiScalarMulWnafWithInterleaving(
    pCurve: PCSYMCRYPT_ECURVE,
    piSrcScalarArray: [*]const PCSYMCRYPT_INT,
    poSrcEcpointArray: [*]const ?PCSYMCRYPT_ECPOINT,
    nPoints: UINT32,
    flags: UINT32,
    poDst: PSYMCRYPT_ECPOINT,
    pbScratch_in: PBYTE,
    cbScratch_in: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    @setRuntimeSafety(false);
    var pbScratch = pbScratch_in;
    var cbScratch = cbScratch_in;

    const w: UINT32 = pCurve.info.sw.window;
    const nPrecompPoints: UINT32 = pCurve.info.sw.nPrecompPoints;
    const nRecodedDigits: UINT32 = pCurve.GOrdBitsize + 1;

    var fZero: [types.SYMCRYPT_ECURVE_MULTI_SCALAR_MUL_MAX_NPOINTS]UINT32 = .{ 0, 0 };
    var fZeroTot: UINT32 = 0xffffffff;

    var bPrecompOffline: bool = false;

    var poPIs: [types.SYMCRYPT_ECURVE_MULTI_SCALAR_MUL_MAX_NPOINTS * types.SYMCRYPT_ECURVE_SW_MAX_NPRECOMP_POINTS]PSYMCRYPT_ECPOINT = undefined;

    const cbEcpoint: SIZE_T = ecpoint.SymCryptSizeofEcpointFromCurve(pCurve);
    const cbScalar: SIZE_T = a_dispatch.SymCryptSizeofIntFromDigits(pCurve.GOrdDigits);

    const pbScratchEnd: usize = @intFromPtr(pbScratch) + cbScratch;

    if ((flags & ~(types.SYMCRYPT_FLAG_DATA_PUBLIC | types.SYMCRYPT_FLAG_ECC_LL_COFACTOR_MUL)) != 0) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    if (nPoints > types.SYMCRYPT_ECURVE_MULTI_SCALAR_MUL_MAX_NPOINTS) {
        return .SYMCRYPT_NOT_IMPLEMENTED;
    }

    const poSrcEcpointArrayMut: [*]?PCSYMCRYPT_ECPOINT = @constCast(poSrcEcpointArray);
    if (poSrcEcpointArrayMut[0] == null) {
        poSrcEcpointArrayMut[0] = pCurve.G;
        bPrecompOffline = true;
    }

    if ((flags & types.SYMCRYPT_FLAG_DATA_PUBLIC) == 0) {
        return .SYMCRYPT_NOT_IMPLEMENTED;
    }

    macros.SYMCRYPT_ASSERT(
        types.SYMCRYPT_CURVE_IS_SHORT_WEIERSTRASS_TYPE(pCurve) or
            types.SYMCRYPT_CURVE_IS_TWISTED_EDWARDS_TYPE(pCurve),
    );
    macros.SYMCRYPT_ASSERT(ecurve.SymCryptEcurveIsSame(pCurve, poDst.pCurve) != 0);
    macros.SYMCRYPT_ASSERT(cbScratch >= types.SYMCRYPT_SCRATCH_BYTES_FOR_SCALAR_ECURVE_OPERATIONS(pCurve, nPoints));

    var i: UINT32 = 0;
    while (i < nPoints * nPrecompPoints) : (i += 1) {
        if ((i < nPrecompPoints) and bPrecompOffline) {
            poPIs[i] = pCurve.info.sw.poPrecompPoints[i].?;
        } else {
            macros.SYMCRYPT_ASSERT(@intFromPtr(pbScratch) + cbEcpoint <= pbScratchEnd);
            poPIs[i] = ecpoint.SymCryptEcpointCreate(pbScratch, cbEcpoint, pCurve).?;
            pbScratch += cbEcpoint;
        }
    }

    macros.SYMCRYPT_ASSERT(
        @intFromPtr(pbScratch) + 2 * cbEcpoint + 2 * cbScalar + 2 * @as(SIZE_T, nPoints) * @as(SIZE_T, nRecodedDigits) * @sizeOf(UINT32) <= pbScratchEnd,
    );

    const poQ: PSYMCRYPT_ECPOINT = ecpoint.SymCryptEcpointCreate(pbScratch, cbEcpoint, pCurve).?;
    pbScratch += cbEcpoint;

    const poTmp: PSYMCRYPT_ECPOINT = ecpoint.SymCryptEcpointCreate(pbScratch, cbEcpoint, pCurve).?;
    pbScratch += cbEcpoint;

    const piRem: PSYMCRYPT_INT = a_dispatch.SymCryptIntCreate(pbScratch, cbScalar, pCurve.GOrdDigits).?;
    pbScratch += cbScalar;

    const piTmp: PSYMCRYPT_INT = a_dispatch.SymCryptIntCreate(pbScratch, cbScalar, pCurve.GOrdDigits).?;
    _ = piTmp;
    pbScratch += cbScalar;

    const asym_align: SIZE_T = types.SYMCRYPT_ASYM_ALIGN_VALUE;
    const absofKIs: PUINT32 = @ptrCast(@alignCast(pbScratch));
    pbScratch += @as(SIZE_T, nPoints) * @as(SIZE_T, nRecodedDigits) * @sizeOf(UINT32);
    const sigofKIs: PUINT32 = @ptrCast(@alignCast(pbScratch));
    pbScratch += @as(SIZE_T, nPoints) * @as(SIZE_T, nRecodedDigits) * @sizeOf(UINT32);
    pbScratch = @ptrFromInt((@intFromPtr(pbScratch) + asym_align - 1) & ~(asym_align - 1));

    const cbRecodedAligned: SIZE_T = ((2 * @as(SIZE_T, nPoints) * @as(SIZE_T, nRecodedDigits) * @sizeOf(UINT32) + asym_align - 1) / asym_align) * asym_align;
    cbScratch -= ((@as(SIZE_T, nPoints * nPrecompPoints) + 2) * cbEcpoint + 2 * cbScalar);
    cbScratch -= cbRecodedAligned;

    var j: UINT32 = 0;
    while (j < nPoints) : (j += 1) {
        const poSrcJ = poSrcEcpointArrayMut[j].?;
        macros.SYMCRYPT_ASSERT(ecurve.SymCryptEcurveIsSame(pCurve, poSrcJ.pCurve) != 0);

        fZero[j] = a_dispatch.SymCryptIntIsEqualUint32(piSrcScalarArray[j], 0) |
            ec_dispatch.SymCryptEcpointIsZero(pCurve, poSrcJ, pbScratch, cbScratch);
        fZeroTot &= fZero[j];

        if (fZero[j] == 0) {
            a_dispatch.SymCryptIntCopy(piSrcScalarArray[j], piRem);

            recoding.SymCryptWidthNafRecoding(
                w,
                piRem,
                absofKIs + j * nRecodedDigits,
                sigofKIs + j * nRecodedDigits,
                nRecodedDigits,
            );

            if ((j > 0) or !bPrecompOffline) {
                ecpoint.SymCryptEcpointCopy(pCurve, poSrcJ, poPIs[j * nPrecompPoints]);
                SymCryptPrecomputation(pCurve, nPrecompPoints, @ptrCast(&poPIs[j * nPrecompPoints]), poQ, pbScratch, cbScratch);
            }
        }
    }

    ec_dispatch.SymCryptEcpointSetZero(pCurve, poQ, pbScratch, cbScratch);

    if (fZeroTot == 0) {
        var k: INT32 = @as(INT32, @intCast(nRecodedDigits)) - 1;
        while (k > -1) : (k -= 1) {
            const idx: UINT32 = @intCast(k);
            ec_dispatch.SymCryptEcpointDouble(pCurve, poQ, poQ, 0, pbScratch, cbScratch);

            j = 0;
            while (j < nPoints) : (j += 1) {
                const digitIdx: usize = @intCast(j * nRecodedDigits + idx);
                if (fZero[j] == 0 and sigofKIs[digitIdx] != 0) {
                    ecpoint.SymCryptEcpointCopy(
                        pCurve,
                        poPIs[j * nPrecompPoints + absofKIs[digitIdx] / 2],
                        poTmp,
                    );

                    if (sigofKIs[digitIdx] == 0xffffffff) {
                        ec_dispatch.SymCryptEcpointNegate(pCurve, poTmp, 0xffffffff, pbScratch, cbScratch);
                    }

                    ec_dispatch.SymCryptEcpointAdd(pCurve, poQ, poTmp, poQ, types.SYMCRYPT_FLAG_DATA_PUBLIC, pbScratch, cbScratch);
                }
            }
        }
    }

    if ((pCurve.coFactorPower != 0) and ((flags & types.SYMCRYPT_FLAG_ECC_LL_COFACTOR_MUL) != 0)) {
        j = 0;
        while (j < pCurve.coFactorPower) : (j += 1) {
            ec_dispatch.SymCryptEcpointDouble(pCurve, poQ, poQ, 0, pbScratch, cbScratch);
        }
    }

    if (ec_dispatch.SymCryptEcpointIsZero(pCurve, poQ, pbScratch, cbScratch) != 0) {
        ec_dispatch.SymCryptEcpointSetZero(pCurve, poQ, pbScratch, cbScratch);
    }

    ecpoint.SymCryptEcpointCopy(pCurve, poQ, poDst);

    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptEcpointGenericSetRandom(
    pCurve: PCSYMCRYPT_ECURVE,
    piScalar: PSYMCRYPT_INT,
    poDst: PSYMCRYPT_ECPOINT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    @setRuntimeSafety(false);
    macros.SYMCRYPT_ASSERT(ecurve.SymCryptEcurveIsSame(pCurve, poDst.pCurve) != 0);
    macros.SYMCRYPT_ASSERT(cbScratch >= types.SYMCRYPT_SCRATCH_BYTES_FOR_SCALAR_ECURVE_OPERATIONS(pCurve, 1));
    macros.SYMCRYPT_ASSERT(cbScratch >= pCurve.cbModElement);

    const peScalar: PSYMCRYPT_MODELEMENT = a_dispatch.SymCryptModElementCreate(pbScratch, pCurve.cbModElement, pCurve.GOrd).?;

    a_dispatch.SymCryptModSetRandom(
        pCurve.GOrd,
        peScalar,
        types.SYMCRYPT_FLAG_MODRANDOM_ALLOW_ONE | types.SYMCRYPT_FLAG_MODRANDOM_ALLOW_MINUSONE,
        pbScratch + pCurve.cbModElement,
        cbScratch - pCurve.cbModElement,
    );

    a_dispatch.SymCryptModElementToInt(
        pCurve.GOrd,
        peScalar,
        piScalar,
        pbScratch + pCurve.cbModElement,
        cbScratch - pCurve.cbModElement,
    );

    _ = ec_dispatch.SymCryptEcpointScalarMul(pCurve, piScalar, null, 0, poDst, pbScratch, cbScratch);
}
