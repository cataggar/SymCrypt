//
// ec_montgomery.zig   Montgomery Implementation
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

const types = @import("types.zig");
const macros = @import("macros.zig");
const a_dispatch = @import("a_dispatch.zig");
const ecurve = @import("ecurve.zig");
const ecpoint = @import("ecpoint.zig");

const PBYTE = types.PBYTE;
const UINT32 = types.UINT32;
const SIZE_T = types.SIZE_T;
const SYMCRYPT_CALL = types.SYMCRYPT_CALL;
const SYMCRYPT_ERROR = types.SYMCRYPT_ERROR;
const PSYMCRYPT_ECURVE = types.PSYMCRYPT_ECURVE;
const PCSYMCRYPT_ECURVE = types.PCSYMCRYPT_ECURVE;
const PSYMCRYPT_ECPOINT = types.PSYMCRYPT_ECPOINT;
const PCSYMCRYPT_ECPOINT = types.PCSYMCRYPT_ECPOINT;
const PCSYMCRYPT_INT = types.PCSYMCRYPT_INT;
const PSYMCRYPT_MODULUS = types.PSYMCRYPT_MODULUS;
const PCSYMCRYPT_MODULUS = types.PCSYMCRYPT_MODULUS;
const PSYMCRYPT_MODELEMENT = types.PSYMCRYPT_MODELEMENT;
const PCSYMCRYPT_MODELEMENT = types.PCSYMCRYPT_MODELEMENT;

pub export fn SymCryptMontgomeryFillScratchSpaces(pCurve: PSYMCRYPT_ECURVE) callconv(SYMCRYPT_CALL) void {
    @setRuntimeSafety(false);
    const nDigits: UINT32 = a_dispatch.SymCryptDigitsFromBits(pCurve.FModBitsize);
    const nBytes: UINT32 = a_dispatch.SymCryptSizeofModElementFromModulus(pCurve.FMod);
    const nCommon: UINT32 = @max(
        a_dispatch.SymCryptSizeofIntFromDigits(nDigits),
        @max(
            types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(nDigits),
            types.SYMCRYPT_SCRATCH_BYTES_FOR_MODINV(nDigits),
        ),
    );
    const cbModElement: UINT32 = pCurve.cbModElement;
    const nDigitsFieldLength: UINT32 = pCurve.FModDigits;

    pCurve.cbScratchCommon = nCommon;
    pCurve.cbScratchScalar =
        a_dispatch.SymCryptSizeofIntFromDigits(nDigits) +
        6 * nBytes +
        nCommon;

    pCurve.cbScratchScalarMulti = 0;
    pCurve.cbScratchGetSetValue =
        ecpoint.SymCryptSizeofEcpointEx(cbModElement, types.SYMCRYPT_ECPOINT_FORMAT_MAX_LENGTH) +
        2 * cbModElement +
        @max(
            types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(nDigitsFieldLength),
            types.SYMCRYPT_SCRATCH_BYTES_FOR_MODINV(nDigitsFieldLength),
        );

    pCurve.cbScratchGetSetValue = @max(
        pCurve.cbScratchGetSetValue,
        a_dispatch.SymCryptSizeofIntFromDigits(nDigits),
    );

    pCurve.cbScratchEckey =
        @max(
            cbModElement + a_dispatch.SymCryptSizeofIntFromDigits(ecurve.SymCryptEcurveDigitsofScalarMultiplier(pCurve)),
            ecpoint.SymCryptSizeofEcpointFromCurve(pCurve),
        ) +
        @max(pCurve.cbScratchScalar, pCurve.cbScratchGetSetValue);
}

pub export fn SymCryptMontgomerySetDistinguished(
    pCurve: PCSYMCRYPT_ECURVE,
    poDst: PSYMCRYPT_ECPOINT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    @setRuntimeSafety(false);
    macros.SYMCRYPT_ASSERT(types.SYMCRYPT_CURVE_IS_MONTGOMERY_TYPE(pCurve));
    macros.SYMCRYPT_ASSERT(ecurve.SymCryptEcurveIsSame(pCurve, poDst.pCurve) != 0);

    _ = pbScratch;
    _ = cbScratch;

    ecpoint.SymCryptEcpointCopy(pCurve, pCurve.G, poDst);
}

//
//  Verify poSrc1(X1, Z1) = poSrc2(X2, Z2)
//  To avoid ModInv for 1/Z, we do
//     X1 * Z2 = X2 * Z1
//
//  This function currently ignores the flags parameter as there is no distinction between equal and
//  negative equal case in Single Projective Coordinates used in Montgomery curves. We accept the flags
//  to maintain the same API as for other curves.
//
pub export fn SymCryptMontgomeryIsEqual(
    pCurve: PCSYMCRYPT_ECURVE,
    poSrc1: PCSYMCRYPT_ECPOINT,
    poSrc2: PCSYMCRYPT_ECPOINT,
    flags: UINT32,
    pbScratch_in: PBYTE,
    cbScratch_in: SIZE_T,
) callconv(SYMCRYPT_CALL) UINT32 {
    @setRuntimeSafety(false);
    var peTemp: [2]PSYMCRYPT_MODELEMENT = undefined;
    const pmMod: PSYMCRYPT_MODULUS = pCurve.FMod;
    var pbScratch = pbScratch_in;
    var cbScratch = cbScratch_in;

    macros.SYMCRYPT_ASSERT((flags & ~(types.SYMCRYPT_FLAG_ECPOINT_EQUAL | types.SYMCRYPT_FLAG_ECPOINT_NEG_EQUAL)) == 0);
    macros.SYMCRYPT_ASSERT(types.SYMCRYPT_CURVE_IS_MONTGOMERY_TYPE(pCurve));
    macros.SYMCRYPT_ASSERT(
        ecurve.SymCryptEcurveIsSame(pCurve, poSrc1.pCurve) != 0 and
            ecurve.SymCryptEcurveIsSame(pCurve, poSrc2.pCurve) != 0,
    );
    macros.SYMCRYPT_ASSERT(cbScratch >= types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_ECURVE_OPERATIONS(pCurve));

    const nBytes: SIZE_T = a_dispatch.SymCryptSizeofModElementFromModulus(pmMod);

    macros.SYMCRYPT_ASSERT(cbScratch >= 2 * nBytes);

    var i: usize = 0;
    while (i < 2) : (i += 1) {
        peTemp[i] = a_dispatch.SymCryptModElementCreate(pbScratch, nBytes, pmMod).?;
        pbScratch += nBytes;
        cbScratch -= nBytes;
    }

    const peSrc1X: PSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(0, pCurve, poSrc1);
    const peSrc1Z: PSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(1, pCurve, poSrc1);

    const peSrc2X: PSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(0, pCurve, poSrc2);
    const peSrc2Z: PSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(1, pCurve, poSrc2);

    // peTemp[0] = X1 * Z2
    a_dispatch.SymCryptModMul(pmMod, peSrc1X, peSrc2Z, peTemp[0], pbScratch, cbScratch);

    // peTemp[1] = X2 * Z1
    a_dispatch.SymCryptModMul(pmMod, peSrc2X, peSrc1Z, peTemp[1], pbScratch, cbScratch);

    return a_dispatch.SymCryptModElementIsEqual(pmMod, peTemp[0], peTemp[1]);
}

pub export fn SymCryptMontgomeryIsZero(
    pCurve: PCSYMCRYPT_ECURVE,
    poSrc: PCSYMCRYPT_ECPOINT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) UINT32 {
    @setRuntimeSafety(false);
    const FMod: PCSYMCRYPT_MODULUS = pCurve.FMod;

    macros.SYMCRYPT_ASSERT(types.SYMCRYPT_CURVE_IS_MONTGOMERY_TYPE(pCurve));
    macros.SYMCRYPT_ASSERT(ecurve.SymCryptEcurveIsSame(pCurve, poSrc.pCurve) != 0);

    _ = pbScratch;
    _ = cbScratch;

    const peZ: PSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(1, pCurve, poSrc);
    return a_dispatch.SymCryptModElementIsZero(FMod, peZ);
}

pub fn SymCryptMontgomeryDoubleAndAdd(
    pmMod: PCSYMCRYPT_MODULUS,
    peX1: PCSYMCRYPT_MODELEMENT,
    peZ1: ?PCSYMCRYPT_MODELEMENT,
    peA24: PCSYMCRYPT_MODELEMENT,
    peX2: PSYMCRYPT_MODELEMENT,
    peZ2: PSYMCRYPT_MODELEMENT,
    peX3: PSYMCRYPT_MODELEMENT,
    peZ3: PSYMCRYPT_MODELEMENT,
    peTemp1: PSYMCRYPT_MODELEMENT,
    peTemp2: PSYMCRYPT_MODELEMENT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) void {
    @setRuntimeSafety(false);
    // Temp1 =          A = X2 + Z2
    a_dispatch.SymCryptModAdd(pmMod, peX2, peZ2, peTemp1, pbScratch, cbScratch);

    // Z2 =             B = X2 - Z2
    a_dispatch.SymCryptModSub(pmMod, peX2, peZ2, peZ2, pbScratch, cbScratch);

    // Temp2 =          C = X3 + Z3
    a_dispatch.SymCryptModAdd(pmMod, peX3, peZ3, peTemp2, pbScratch, cbScratch);

    // Z3 =             D = X3 - Z3
    a_dispatch.SymCryptModSub(pmMod, peX3, peZ3, peZ3, pbScratch, cbScratch);

    // X3 =             CB = C * B      = Temp2 * Z2
    a_dispatch.SymCryptModMul(pmMod, peTemp2, peZ2, peX3, pbScratch, cbScratch);

    // Z3 =             DA = D * A      = Z3 * Temp1
    a_dispatch.SymCryptModMul(pmMod, peZ3, peTemp1, peZ3, pbScratch, cbScratch);

    // X2 =             AA = A * A      = Temp1 * Temp1
    a_dispatch.SymCryptModSquare(pmMod, peTemp1, peX2, pbScratch, cbScratch);

    // Temp1 =          BB = B * B      = Z2 * Z2
    a_dispatch.SymCryptModSquare(pmMod, peZ2, peTemp1, pbScratch, cbScratch);

    // Temp2 =          E = AA - BB     = X2 - Temp1
    a_dispatch.SymCryptModSub(pmMod, peX2, peTemp1, peTemp2, pbScratch, cbScratch);

    // X2 =             X4 = AA * BB    = X2 * Temp1
    a_dispatch.SymCryptModMul(pmMod, peX2, peTemp1, peX2, pbScratch, cbScratch);

    // Z2 =             A24E = A24 * E    = A24 * Temp2
    a_dispatch.SymCryptModMul(pmMod, peA24, peTemp2, peZ2, pbScratch, cbScratch);

    // Z2 =             BAE = (BB + a24 * E) = BB + A24E = Temp1 + Z2
    a_dispatch.SymCryptModAdd(pmMod, peTemp1, peZ2, peZ2, pbScratch, cbScratch);

    // Z2 =             Z4 = E * BAE        = Temp2 * Z2
    a_dispatch.SymCryptModMul(pmMod, peTemp2, peZ2, peZ2, pbScratch, cbScratch);

    // Now we compute (X5, Z5)

    // Temp1 =          DApCB = DA + CB     = Z3 + X3
    a_dispatch.SymCryptModAdd(pmMod, peZ3, peX3, peTemp1, pbScratch, cbScratch);

    // Z3 =             DAmCB = DA - CB     = Z3 - X3
    a_dispatch.SymCryptModSub(pmMod, peZ3, peX3, peZ3, pbScratch, cbScratch);

    // X3 =             DApCB^2 = Temp1 ^ 2 ( = X5 when (peZ1 == NULL) => Z1 == 1)
    a_dispatch.SymCryptModSquare(pmMod, peTemp1, peX3, pbScratch, cbScratch);

    if (peZ1) |z1| {
        // X3 =             X5 = Z1 * DApCB^2   = Z1 * X3
        a_dispatch.SymCryptModMul(pmMod, z1, peX3, peX3, pbScratch, cbScratch);
    }

    // Z3 =             DAmCB2 = DAmCB ^ 2  = Z3 ^ 2
    a_dispatch.SymCryptModSquare(pmMod, peZ3, peZ3, pbScratch, cbScratch);

    // Z3 =             Z5 = X1 * DAmCB2        = X1 * Z3
    a_dispatch.SymCryptModMul(pmMod, peX1, peZ3, peZ3, pbScratch, cbScratch);
}

//
// Montgomery point multiplication only works on X-coordinates.
// We ignore the Y-coordinates.
//
pub export fn SymCryptMontgomeryPointScalarMul(
    pCurve: PCSYMCRYPT_ECURVE,
    piScalar: PCSYMCRYPT_INT,
    poSrc_in: ?PCSYMCRYPT_ECPOINT,
    flags: UINT32,
    poDst: PSYMCRYPT_ECPOINT,
    pbScratch_in: PBYTE,
    cbScratch_in: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    @setRuntimeSafety(false);
    var pbScratch = pbScratch_in;
    var cbScratch = cbScratch_in;

    macros.SYMCRYPT_ASSERT(types.SYMCRYPT_CURVE_IS_MONTGOMERY_TYPE(pCurve));
    macros.SYMCRYPT_ASSERT(
        (poSrc_in == null or ecurve.SymCryptEcurveIsSame(pCurve, poSrc_in.?.pCurve) != 0) and
            ecurve.SymCryptEcurveIsSame(pCurve, poDst.pCurve) != 0,
    );

    if ((flags & ~types.SYMCRYPT_FLAG_ECC_LL_COFACTOR_MUL) != 0) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    const poSrc: PCSYMCRYPT_ECPOINT = poSrc_in orelse pCurve.G;

    const pmMod: PSYMCRYPT_MODULUS = pCurve.FMod;

    const nDigits: UINT32 = a_dispatch.SymCryptDigitsFromBits(pCurve.FModBitsize);
    const nBytes: UINT32 = a_dispatch.SymCryptSizeofModElementFromModulus(pmMod);
    const nCommon: UINT32 = @max(
        a_dispatch.SymCryptSizeofIntFromDigits(nDigits),
        @max(
            types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(nDigits),
            types.SYMCRYPT_SCRATCH_BYTES_FOR_MODINV(nDigits),
        ),
    );

    macros.SYMCRYPT_ASSERT(cbScratch >= 6 * nBytes + nCommon);

    const peX2: PSYMCRYPT_MODELEMENT = a_dispatch.SymCryptModElementCreate(pbScratch, nBytes, pmMod).?;
    pbScratch += nBytes;

    const peZ2: PSYMCRYPT_MODELEMENT = a_dispatch.SymCryptModElementCreate(pbScratch, nBytes, pmMod).?;
    pbScratch += nBytes;

    const peX3: PSYMCRYPT_MODELEMENT = a_dispatch.SymCryptModElementCreate(pbScratch, nBytes, pmMod).?;
    pbScratch += nBytes;

    const peZ3: PSYMCRYPT_MODELEMENT = a_dispatch.SymCryptModElementCreate(pbScratch, nBytes, pmMod).?;
    pbScratch += nBytes;

    const peTemp1: PSYMCRYPT_MODELEMENT = a_dispatch.SymCryptModElementCreate(pbScratch, nBytes, pmMod).?;
    pbScratch += nBytes;

    const peTemp2: PSYMCRYPT_MODELEMENT = a_dispatch.SymCryptModElementCreate(pbScratch, nBytes, pmMod).?;
    pbScratch += nBytes;

    cbScratch = nCommon;

    const peA24: PSYMCRYPT_MODELEMENT = pCurve.A;

    const peX1: PSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(0, pCurve, poSrc);
    var peZ1: ?PCSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(1, pCurve, poSrc);

    a_dispatch.SymCryptModElementSetValueUint32(1, pmMod, peX2, pbScratch, cbScratch);
    a_dispatch.SymCryptModElementSetValueUint32(0, pmMod, peZ2, pbScratch, cbScratch);
    a_dispatch.SymCryptModElementCopy(pmMod, peX1, peX3);
    a_dispatch.SymCryptModElementCopy(pmMod, peZ1.?, peZ3);

    if (poSrc.normalized != 0) {
        peZ1 = null;
    }

    var i: UINT32 = pCurve.GOrdBitsize + pCurve.coFactorPower;
    var cond: UINT32 = 0;
    while (i != 0) {
        i -= 1;
        const newcond: UINT32 = a_dispatch.SymCryptIntGetBit(piScalar, i);
        cond ^= newcond;

        a_dispatch.SymCryptModElementConditionalSwap(pmMod, peX2, peX3, cond);
        a_dispatch.SymCryptModElementConditionalSwap(pmMod, peZ2, peZ3, cond);

        cond = newcond;

        SymCryptMontgomeryDoubleAndAdd(pmMod, peX1, peZ1, peA24, peX2, peZ2, peX3, peZ3, peTemp1, peTemp2, pbScratch, cbScratch);
    }

    a_dispatch.SymCryptModElementConditionalSwap(pmMod, peX2, peX3, cond);
    a_dispatch.SymCryptModElementConditionalSwap(pmMod, peZ2, peZ3, cond);

    if ((flags & types.SYMCRYPT_FLAG_ECC_LL_COFACTOR_MUL) != 0) {
        i = pCurve.coFactorPower;
        while (i != 0) {
            i -= 1;
            SymCryptMontgomeryDoubleAndAdd(pmMod, peX1, null, peA24, peX2, peZ2, peX3, peZ3, peTemp1, peTemp2, pbScratch, cbScratch);
        }
    }

    var peResult: PSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(0, pCurve, poDst);
    a_dispatch.SymCryptModElementCopy(pCurve.FMod, peX2, peResult);

    peResult = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(1, pCurve, poDst);
    a_dispatch.SymCryptModElementCopy(pCurve.FMod, peZ2, peResult);

    poDst.normalized = types.FALSE;

    return .SYMCRYPT_NO_ERROR;
}
