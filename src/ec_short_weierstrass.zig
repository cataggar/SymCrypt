//
// ec_short_weierstrass.zig   ECPOINT functions for short Weierstrass curves.
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

const types = @import("types.zig");
const macros = @import("macros.zig");
const a_dispatch = @import("a_dispatch.zig");
const ecurve = @import("ecurve.zig");
const ecpoint = @import("ecpoint.zig");
const ec_dispatch = @import("ec_dispatch.zig");

const PBYTE = types.PBYTE;
const UINT32 = types.UINT32;
const SIZE_T = types.SIZE_T;
const SYMCRYPT_CALL = types.SYMCRYPT_CALL;
const PSYMCRYPT_ECURVE = types.PSYMCRYPT_ECURVE;
const PCSYMCRYPT_ECURVE = types.PCSYMCRYPT_ECURVE;
const PSYMCRYPT_ECPOINT = types.PSYMCRYPT_ECPOINT;
const PCSYMCRYPT_ECPOINT = types.PCSYMCRYPT_ECPOINT;
const PCSYMCRYPT_MODULUS = types.PCSYMCRYPT_MODULUS;
const PSYMCRYPT_MODELEMENT = types.PSYMCRYPT_MODELEMENT;
const PCSYMCRYPT_MODELEMENT = types.PCSYMCRYPT_MODELEMENT;

pub export fn SymCryptShortWeierstrassFillScratchSpaces(pCurve: PSYMCRYPT_ECURVE) callconv(SYMCRYPT_CALL) void {
    @setRuntimeSafety(false);
    const nDigits: UINT32 = a_dispatch.SymCryptDigitsFromBits(pCurve.FModBitsize);
    const asym_align: UINT32 = @intCast(types.SYMCRYPT_ASYM_ALIGN_VALUE);

    // Common
    pCurve.cbScratchCommon =
        8 * pCurve.cbModElement +
        2 * ecpoint.SymCryptSizeofEcpointFromCurve(pCurve) +
        types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(pCurve.FModDigits);

    // Scalar (Overhead)
    pCurve.cbScratchScalar =
        pCurve.cbModElement +
        2 * ecpoint.SymCryptSizeofEcpointFromCurve(pCurve) +
        2 * a_dispatch.SymCryptSizeofIntFromDigits(pCurve.GOrdDigits) +
        @max(
            pCurve.cbScratchCommon,
            types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(pCurve.GOrdDigits),
        );

    // Scalar dependent on precomp points (be careful to align the UINT32 arrays properly)
    pCurve.cbScratchScalarMulti =
        pCurve.info.sw.nPrecompPoints * ecpoint.SymCryptSizeofEcpointFromCurve(pCurve) +
        ((2 * pCurve.info.sw.nRecodedDigits * @as(UINT32, @sizeOf(UINT32)) + asym_align - 1) / asym_align) * asym_align;

    // GetSetValue
    pCurve.cbScratchGetSetValue =
        ecpoint.SymCryptSizeofEcpointEx(pCurve.cbModElement, types.SYMCRYPT_ECPOINT_FORMAT_MAX_LENGTH) +
        2 * pCurve.cbModElement +
        @max(
            types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(pCurve.FModDigits),
            types.SYMCRYPT_SCRATCH_BYTES_FOR_MODINV(pCurve.FModDigits),
        );

    pCurve.cbScratchGetSetValue = @max(
        pCurve.cbScratchGetSetValue,
        a_dispatch.SymCryptSizeofIntFromDigits(nDigits),
    );

    // Eckey
    pCurve.cbScratchEckey =
        @max(
            pCurve.cbModElement + a_dispatch.SymCryptSizeofIntFromDigits(ecurve.SymCryptEcurveDigitsofScalarMultiplier(pCurve)),
            ecpoint.SymCryptSizeofEcpointFromCurve(pCurve),
        ) +
        @max(
            pCurve.cbScratchScalar + pCurve.cbScratchScalarMulti,
            pCurve.cbScratchGetSetValue,
        );
}

//
// The following function sets the point to (1:1:0) in Jacobian coordinates.
//
pub export fn SymCryptShortWeierstrassSetZero(
    pCurve: PCSYMCRYPT_ECURVE,
    poDst: PSYMCRYPT_ECPOINT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    @setRuntimeSafety(false);
    const FMod: PCSYMCRYPT_MODULUS = pCurve.FMod;

    macros.SYMCRYPT_ASSERT(types.SYMCRYPT_CURVE_IS_SHORT_WEIERSTRASS_TYPE(pCurve));
    macros.SYMCRYPT_ASSERT(ecurve.SymCryptEcurveIsSame(pCurve, poDst.pCurve) != 0);
    macros.SYMCRYPT_ASSERT(cbScratch >= types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(pCurve.FModDigits));

    // Getting handle to X and setting to 1
    var peTmp: PSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(0, pCurve, poDst);
    a_dispatch.SymCryptModElementSetValueUint32(1, FMod, peTmp, pbScratch, cbScratch);

    // Getting handle to Y and setting to 1
    peTmp = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(1, pCurve, poDst);
    a_dispatch.SymCryptModElementSetValueUint32(1, FMod, peTmp, pbScratch, cbScratch);

    // Getting handle to Z and setting to 0
    peTmp = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(2, pCurve, poDst);
    a_dispatch.SymCryptModElementSetValueUint32(0, pCurve.FMod, peTmp, pbScratch, cbScratch);
}

pub export fn SymCryptShortWeierstrassSetDistinguished(
    pCurve: PCSYMCRYPT_ECURVE,
    poDst: PSYMCRYPT_ECPOINT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    @setRuntimeSafety(false);
    macros.SYMCRYPT_ASSERT(types.SYMCRYPT_CURVE_IS_SHORT_WEIERSTRASS_TYPE(pCurve));
    macros.SYMCRYPT_ASSERT(ecurve.SymCryptEcurveIsSame(pCurve, poDst.pCurve) != 0);

    _ = pbScratch;
    _ = cbScratch;

    ecpoint.SymCryptEcpointCopy(pCurve, pCurve.G, poDst);
}

//
// The following function checks if
//      - X1*Z2^2 = X2*Z1^2 and Y1*Z2^3 = Y2*Z1^3 (Equal case)
//      - X1*Z2^2 = X2*Z1^2 and Y1*Z2^3 = -Y2*Z1^3 (Negative case)
//
// Remark: The case where Z1 = Z2 = 0 is covered above (the zero point
//         is equal to its negative).
//
pub export fn SymCryptShortWeierstrassIsEqual(
    pCurve: PCSYMCRYPT_ECURVE,
    poSrc1: PCSYMCRYPT_ECPOINT,
    poSrc2: PCSYMCRYPT_ECPOINT,
    flags_in: UINT32,
    pbScratch_in: PBYTE,
    cbScratch_in: SIZE_T,
) callconv(SYMCRYPT_CALL) UINT32 {
    @setRuntimeSafety(false);
    const FMod: PCSYMCRYPT_MODULUS = pCurve.FMod;
    var flags = flags_in;
    var pbScratch = pbScratch_in;
    var cbScratch = cbScratch_in;

    var peT: [4]PSYMCRYPT_MODELEMENT = undefined;

    macros.SYMCRYPT_ASSERT(types.SYMCRYPT_CURVE_IS_SHORT_WEIERSTRASS_TYPE(pCurve));
    macros.SYMCRYPT_ASSERT(
        ecurve.SymCryptEcurveIsSame(pCurve, poSrc1.pCurve) != 0 and
            ecurve.SymCryptEcurveIsSame(pCurve, poSrc2.pCurve) != 0,
    );
    macros.SYMCRYPT_ASSERT((flags & ~(types.SYMCRYPT_FLAG_ECPOINT_EQUAL | types.SYMCRYPT_FLAG_ECPOINT_NEG_EQUAL)) == 0);
    macros.SYMCRYPT_ASSERT(cbScratch >= types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(pCurve.FModDigits) + 4 * pCurve.cbModElement);

    var i: usize = 0;
    while (i < 4) : (i += 1) {
        peT[i] = a_dispatch.SymCryptModElementCreate(pbScratch, pCurve.cbModElement, FMod).?;
        pbScratch += pCurve.cbModElement;
    }
    cbScratch -= 4 * pCurve.cbModElement;

    const peX1: PSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(0, pCurve, poSrc1);
    const peY1: PSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(1, pCurve, poSrc1);
    const peZ1: PSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(2, pCurve, poSrc1);
    const peX2: PSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(0, pCurve, poSrc2);
    const peY2: PSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(1, pCurve, poSrc2);
    const peZ2: PSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(2, pCurve, poSrc2);

    // Setting the default flag if flags == 0
    flags |= (macros.SYMCRYPT_MASK32_ZERO(flags) & types.SYMCRYPT_FLAG_ECPOINT_EQUAL);

    a_dispatch.SymCryptModSquare(FMod, peZ1, peT[0], pbScratch, cbScratch); // T0 := Z1 * Z1 = Z1^2
    a_dispatch.SymCryptModSquare(FMod, peZ2, peT[1], pbScratch, cbScratch); // T1 := Z2 * Z2 = Z2^2
    a_dispatch.SymCryptModMul(FMod, peX1, peT[1], peT[2], pbScratch, cbScratch); // T2 := X1 * T1 = X1*Z2^2
    a_dispatch.SymCryptModMul(FMod, peX2, peT[0], peT[3], pbScratch, cbScratch); // T3 := X2 * T0 = X2*Z1^2

    const dResX: UINT32 = a_dispatch.SymCryptModElementIsEqual(FMod, peT[2], peT[3]);

    a_dispatch.SymCryptModMul(FMod, peZ1, peT[0], peT[0], pbScratch, cbScratch); // T0 := Z1 * T0 = Z1^3
    a_dispatch.SymCryptModMul(FMod, peZ2, peT[1], peT[1], pbScratch, cbScratch); // T1 := Z2 * T1 = Z2^3
    a_dispatch.SymCryptModMul(FMod, peY1, peT[1], peT[2], pbScratch, cbScratch); // T2 := Y1 * T1 = Y1*Z2^3
    a_dispatch.SymCryptModMul(FMod, peY2, peT[0], peT[3], pbScratch, cbScratch); // T3 := Y2 * T0 = Y2*Z1^3

    const dResY: UINT32 = a_dispatch.SymCryptModElementIsEqual(FMod, peT[2], peT[3]);

    a_dispatch.SymCryptModNeg(FMod, peT[3], peT[3], pbScratch, cbScratch); // T3 := -T3 = -Y2*Z1^3

    const dResYN: UINT32 = a_dispatch.SymCryptModElementIsEqual(FMod, peT[2], peT[3]);

    return (macros.SYMCRYPT_MASK32_NONZERO(flags & types.SYMCRYPT_FLAG_ECPOINT_EQUAL) & dResX & dResY) |
        (macros.SYMCRYPT_MASK32_NONZERO(flags & types.SYMCRYPT_FLAG_ECPOINT_NEG_EQUAL) & dResX & dResYN);
}

pub export fn SymCryptShortWeierstrassIsZero(
    pCurve: PCSYMCRYPT_ECURVE,
    poSrc: PCSYMCRYPT_ECPOINT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) UINT32 {
    @setRuntimeSafety(false);
    const FMod: PCSYMCRYPT_MODULUS = pCurve.FMod;

    macros.SYMCRYPT_ASSERT(types.SYMCRYPT_CURVE_IS_SHORT_WEIERSTRASS_TYPE(pCurve));
    macros.SYMCRYPT_ASSERT(ecurve.SymCryptEcurveIsSame(pCurve, poSrc.pCurve) != 0);

    _ = pbScratch;
    _ = cbScratch;

    const peZ: PSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(2, pCurve, poSrc);
    return a_dispatch.SymCryptModElementIsZero(FMod, peZ);
}

//
// The following function verifies if the point (X:Y:Z) in Jacobian
// coordinates satisfies the equation Y^2 = X^3 + aXZ^4+bZ^6 .
//
pub export fn SymCryptShortWeierstrassOnCurve(
    pCurve: PCSYMCRYPT_ECURVE,
    poSrc: PCSYMCRYPT_ECPOINT,
    pbScratch_in: PBYTE,
    cbScratch_in: SIZE_T,
) callconv(SYMCRYPT_CALL) UINT32 {
    @setRuntimeSafety(false);
    const FMod: PCSYMCRYPT_MODULUS = pCurve.FMod;
    var pbScratch = pbScratch_in;
    var cbScratch = cbScratch_in;

    var peT: [2]PSYMCRYPT_MODELEMENT = undefined;

    macros.SYMCRYPT_ASSERT(types.SYMCRYPT_CURVE_IS_SHORT_WEIERSTRASS_TYPE(pCurve));
    macros.SYMCRYPT_ASSERT(ecurve.SymCryptEcurveIsSame(pCurve, poSrc.pCurve) != 0);
    macros.SYMCRYPT_ASSERT(cbScratch >= types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(pCurve.FModDigits) + 2 * pCurve.cbModElement);

    var i: usize = 0;
    while (i < 2) : (i += 1) {
        peT[i] = a_dispatch.SymCryptModElementCreate(pbScratch, pCurve.cbModElement, FMod).?;
        pbScratch += pCurve.cbModElement;
    }
    cbScratch -= 2 * pCurve.cbModElement;

    const peX: PSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(0, pCurve, poSrc);
    const peY: PSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(1, pCurve, poSrc);
    const peZ: PSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(2, pCurve, poSrc);

    a_dispatch.SymCryptModSquare(FMod, peZ, peT[0], pbScratch, cbScratch); // T1 := Z * Z = Z^2
    a_dispatch.SymCryptModSquare(FMod, peT[0], peT[1], pbScratch, cbScratch); // T2 := T1 * T1 = Z^4
    a_dispatch.SymCryptModMul(FMod, peT[0], peT[1], peT[0], pbScratch, cbScratch); // T1 := T1 * T2 = Z^6

    a_dispatch.SymCryptModMul(FMod, peT[0], pCurve.B, peT[0], pbScratch, cbScratch); // T1 := T1 * b = bZ^6

    a_dispatch.SymCryptModMul(FMod, peT[1], peX, peT[1], pbScratch, cbScratch); // T2 := T2 * X = XZ^4
    a_dispatch.SymCryptModMul(FMod, peT[1], pCurve.A, peT[1], pbScratch, cbScratch); // T2 := T2 * a = aXZ^4

    a_dispatch.SymCryptModAdd(FMod, peT[0], peT[1], peT[1], pbScratch, cbScratch); // T2 := T1 + T2 = aXZ^4 + bZ^6

    a_dispatch.SymCryptModSquare(FMod, peX, peT[0], pbScratch, cbScratch); // T1 := X * X = X^2
    a_dispatch.SymCryptModMul(FMod, peT[0], peX, peT[0], pbScratch, cbScratch); // T1 := T1 * X = X^3
    a_dispatch.SymCryptModAdd(FMod, peT[0], peT[1], peT[1], pbScratch, cbScratch); // T2 := T1 + T2 = X^3 + aXZ^4 + bZ^6

    a_dispatch.SymCryptModSquare(FMod, peY, peT[0], pbScratch, cbScratch); // T1 := Y * Y = Y^2

    return a_dispatch.SymCryptModElementIsEqual(FMod, peT[0], peT[1]);
}

pub export fn SymCryptShortWeierstrassDouble(
    pCurve: PCSYMCRYPT_ECURVE,
    poSrc: PCSYMCRYPT_ECPOINT,
    poDst: PSYMCRYPT_ECPOINT,
    flags: UINT32,
    pbScratch_in: PBYTE,
    cbScratch_in: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    @setRuntimeSafety(false);
    const FMod: PCSYMCRYPT_MODULUS = pCurve.FMod;
    var pbScratch = pbScratch_in;
    var cbScratch = cbScratch_in;
    var peT: [3]PSYMCRYPT_MODELEMENT = undefined;

    const peX1: PCSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(0, pCurve, poSrc);
    const peY1: PCSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(1, pCurve, poSrc);
    const peZ1: PCSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(2, pCurve, poSrc);

    const peX3: PSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(0, pCurve, poDst);
    const peY3: PSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(1, pCurve, poDst);
    const peZ3: PSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(2, pCurve, poDst);

    macros.SYMCRYPT_ASSERT(pCurve.type == .SYMCRYPT_INTERNAL_ECURVE_TYPE_SHORT_WEIERSTRASS);
    macros.SYMCRYPT_ASSERT(
        ecurve.SymCryptEcurveIsSame(pCurve, poSrc.pCurve) != 0 and
            ecurve.SymCryptEcurveIsSame(pCurve, poDst.pCurve) != 0,
    );
    macros.SYMCRYPT_ASSERT(cbScratch >= types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(pCurve.FModDigits) + 3 * pCurve.cbModElement);

    _ = flags;

    var i: usize = 0;
    while (i < 3) : (i += 1) {
        peT[i] = a_dispatch.SymCryptModElementCreate(pbScratch, pCurve.cbModElement, FMod).?;
        pbScratch += pCurve.cbModElement;
    }
    cbScratch -= 3 * pCurve.cbModElement;

    a_dispatch.SymCryptModAdd(FMod, peY1, peY1, peT[0], pbScratch, cbScratch); // T0 := Y1 + Y1 = 2Y
    a_dispatch.SymCryptModSquare(FMod, peZ1, peT[1], pbScratch, cbScratch); // T1 := Z1 * Z1 = ZZ
    a_dispatch.SymCryptModMul(FMod, peT[0], peZ1, peZ3, pbScratch, cbScratch); // Z3 := 2Y * Z1 = 2YZ

    a_dispatch.SymCryptModMul(FMod, peY1, peT[0], peY3, pbScratch, cbScratch); // Y3 := 2Y * Y1 = 2YY
    a_dispatch.SymCryptModAdd(FMod, peY3, peY3, peT[0], pbScratch, cbScratch); // T0 := 2YY + 2YY = 4YY
    a_dispatch.SymCryptModMul(FMod, peT[0], peY3, peY3, pbScratch, cbScratch); // Y3 := 2YY * 4YY = 8YYYY

    a_dispatch.SymCryptModMul(FMod, peT[0], peX1, peT[0], pbScratch, cbScratch); // T0 := X1 * 4YY = 4XYY = S

    a_dispatch.SymCryptModSquare(FMod, peT[1], peT[1], pbScratch, cbScratch); // T1 := T1 * T1 = ZZZZ
    a_dispatch.SymCryptModSquare(FMod, peX1, peT[2], pbScratch, cbScratch); // T2 := X1 * X1 = XX
    a_dispatch.SymCryptModMul(FMod, peT[1], pCurve.A, peT[1], pbScratch, cbScratch); // T1 := T1 * a = a*ZZZZ
    a_dispatch.SymCryptModAdd(FMod, peT[2], peT[1], peT[1], pbScratch, cbScratch); // T1 := T2 + T1 = XX + a*ZZZZ
    a_dispatch.SymCryptModAdd(FMod, peT[2], peT[2], peT[2], pbScratch, cbScratch); // T2 := T2 + T2 = 2*XX
    a_dispatch.SymCryptModAdd(FMod, peT[0], peT[0], peX3, pbScratch, cbScratch); // X3 := 2*S
    a_dispatch.SymCryptModAdd(FMod, peT[2], peT[1], peT[1], pbScratch, cbScratch); // T1 := T2 + T1 = 3*XX + a*ZZZZ = M

    a_dispatch.SymCryptModSquare(FMod, peT[1], peT[2], pbScratch, cbScratch); // T2 := M^2
    a_dispatch.SymCryptModSub(FMod, peT[2], peX3, peX3, pbScratch, cbScratch); // X3 := M^2 - 2*S = T

    a_dispatch.SymCryptModSub(FMod, peT[0], peX3, peT[0], pbScratch, cbScratch); // T0 := S - T
    a_dispatch.SymCryptModMul(FMod, peT[1], peT[0], peT[0], pbScratch, cbScratch); // T0 := M * (S - T)
    a_dispatch.SymCryptModSub(FMod, peT[0], peY3, peY3, pbScratch, cbScratch); // Y3 := M * (S - T) - 8*YYYY
}

pub export fn SymCryptShortWeierstrassDoubleSpecializedAm3(
    pCurve: PCSYMCRYPT_ECURVE,
    poSrc: PCSYMCRYPT_ECPOINT,
    poDst: PSYMCRYPT_ECPOINT,
    flags: UINT32,
    pbScratch_in: PBYTE,
    cbScratch_in: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    @setRuntimeSafety(false);
    const FMod: PCSYMCRYPT_MODULUS = pCurve.FMod;
    var pbScratch = pbScratch_in;
    var cbScratch = cbScratch_in;
    var peT: [3]PSYMCRYPT_MODELEMENT = undefined;

    const peX1: PCSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(0, pCurve, poSrc);
    const peY1: PCSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(1, pCurve, poSrc);
    const peZ1: PCSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(2, pCurve, poSrc);

    const peX3: PSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(0, pCurve, poDst);
    const peY3: PSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(1, pCurve, poDst);
    const peZ3: PSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(2, pCurve, poDst);

    macros.SYMCRYPT_ASSERT(pCurve.type == .SYMCRYPT_INTERNAL_ECURVE_TYPE_SHORT_WEIERSTRASS_AM3);
    macros.SYMCRYPT_ASSERT(
        ecurve.SymCryptEcurveIsSame(pCurve, poSrc.pCurve) != 0 and
            ecurve.SymCryptEcurveIsSame(pCurve, poDst.pCurve) != 0,
    );
    macros.SYMCRYPT_ASSERT(cbScratch >= types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(pCurve.FModDigits) + 3 * pCurve.cbModElement);

    _ = flags;

    var i: usize = 0;
    while (i < 3) : (i += 1) {
        peT[i] = a_dispatch.SymCryptModElementCreate(pbScratch, pCurve.cbModElement, FMod).?;
        pbScratch += pCurve.cbModElement;
    }
    cbScratch -= 3 * pCurve.cbModElement;

    a_dispatch.SymCryptModAdd(FMod, peY1, peY1, peT[0], pbScratch, cbScratch); // T0 := Y1 + Y1 = 2Y
    a_dispatch.SymCryptModSquare(FMod, peZ1, peT[1], pbScratch, cbScratch); // T1 := Z1 * Z1 = ZZ
    a_dispatch.SymCryptModMul(FMod, peY1, peT[0], peY3, pbScratch, cbScratch); // Y3 := 2Y * Y1 = 2YY

    a_dispatch.SymCryptModMul(FMod, peT[0], peZ1, peZ3, pbScratch, cbScratch); // Z3 := 2Y * Z1 = 2YZ

    a_dispatch.SymCryptModAdd(FMod, peY3, peY3, peT[0], pbScratch, cbScratch); // T0 := 2YY + 2YY = 4YY
    a_dispatch.SymCryptModAdd(FMod, peX1, peT[1], peT[2], pbScratch, cbScratch); // T2 := X1 + ZZ
    a_dispatch.SymCryptModMul(FMod, peT[0], peY3, peY3, pbScratch, cbScratch); // Y3 := 2YY * 4YY = 8YYYY

    a_dispatch.SymCryptModSub(FMod, peX1, peT[1], peT[1], pbScratch, cbScratch); // T1 := X1 - ZZ
    a_dispatch.SymCryptModMul(FMod, peT[0], peX1, peT[0], pbScratch, cbScratch); // T0 := X1 * 4YY = 4XYY = S

    a_dispatch.SymCryptModMul(FMod, peT[2], peT[1], peT[2], pbScratch, cbScratch); // T2 := (X1 + ZZ)*(X1 - ZZ) = XX - ZZZZ
    a_dispatch.SymCryptModAdd(FMod, peT[2], peT[2], peT[1], pbScratch, cbScratch); // T1 := 2*(XX - ZZZZ)
    a_dispatch.SymCryptModAdd(FMod, peT[0], peT[0], peX3, pbScratch, cbScratch); // X3 := 2*S
    a_dispatch.SymCryptModAdd(FMod, peT[1], peT[2], peT[1], pbScratch, cbScratch); // T1 := 3*(XX - ZZZZ) = M

    a_dispatch.SymCryptModSquare(FMod, peT[1], peT[2], pbScratch, cbScratch); // T2 := M^2
    a_dispatch.SymCryptModSub(FMod, peT[2], peX3, peX3, pbScratch, cbScratch); // X3 := M^2 - 2*S = T

    a_dispatch.SymCryptModSub(FMod, peT[0], peX3, peT[0], pbScratch, cbScratch); // T0 := S - T
    a_dispatch.SymCryptModMul(FMod, peT[1], peT[0], peT[0], pbScratch, cbScratch); // T0 := M * (S - T)
    a_dispatch.SymCryptModSub(FMod, peT[0], peY3, peY3, pbScratch, cbScratch); // Y3 := M * (S - T) - 8*YYYY
}

pub export fn SymCryptShortWeierstrassAddDiffNonZero(
    pCurve: PCSYMCRYPT_ECURVE,
    poSrc1: PCSYMCRYPT_ECPOINT,
    poSrc2: PCSYMCRYPT_ECPOINT,
    poDst: PSYMCRYPT_ECPOINT,
    pbScratch_in: PBYTE,
    cbScratch_in: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    @setRuntimeSafety(false);
    const FMod: PCSYMCRYPT_MODULUS = pCurve.FMod;
    var pbScratch = pbScratch_in;
    var cbScratch = cbScratch_in;

    const peX1: PCSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(0, pCurve, poSrc1);
    const peY1: PCSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(1, pCurve, poSrc1);
    const peZ1: PCSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(2, pCurve, poSrc1);

    const peX2: PCSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(0, pCurve, poSrc2);
    const peY2: PCSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(1, pCurve, poSrc2);
    const peZ2: PCSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(2, pCurve, poSrc2);

    const peX3: PSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(0, pCurve, poDst);
    const peY3: PSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(1, pCurve, poDst);
    const peZ3: PSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(2, pCurve, poDst);

    var peT: [7]PSYMCRYPT_MODELEMENT = undefined;

    macros.SYMCRYPT_ASSERT(types.SYMCRYPT_CURVE_IS_SHORT_WEIERSTRASS_TYPE(pCurve));
    macros.SYMCRYPT_ASSERT(
        ecurve.SymCryptEcurveIsSame(pCurve, poSrc1.pCurve) != 0 and
            ecurve.SymCryptEcurveIsSame(pCurve, poSrc2.pCurve) != 0 and
            ecurve.SymCryptEcurveIsSame(pCurve, poDst.pCurve) != 0,
    );
    macros.SYMCRYPT_ASSERT(cbScratch >= types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(pCurve.FModDigits) + 7 * pCurve.cbModElement);

    var i: usize = 0;
    while (i < 7) : (i += 1) {
        peT[i] = a_dispatch.SymCryptModElementCreate(pbScratch, pCurve.cbModElement, FMod).?;
        pbScratch += pCurve.cbModElement;
    }
    cbScratch -= 7 * pCurve.cbModElement;

    a_dispatch.SymCryptModSquare(FMod, peZ1, peT[0], pbScratch, cbScratch); // T0 := Z1 * Z1 = Z1Z1
    a_dispatch.SymCryptModMul(FMod, peZ1, peT[0], peT[1], pbScratch, cbScratch); // T1 := Z1*Z1Z1

    a_dispatch.SymCryptModSquare(FMod, peZ2, peT[6], pbScratch, cbScratch); // T6 := Z2 * Z2 = Z2Z2
    a_dispatch.SymCryptModMul(FMod, peX1, peT[6], peT[2], pbScratch, cbScratch); // T2 := X1 * T6 = X1*Z2Z2 = U1
    a_dispatch.SymCryptModMul(FMod, peX2, peT[0], peT[3], pbScratch, cbScratch); // T3 := X2 * Z1Z1 = U2
    a_dispatch.SymCryptModSub(FMod, peT[3], peT[2], peT[5], pbScratch, cbScratch); // T5 := T3 - T2 = U2 - U1 = H
    a_dispatch.SymCryptModAdd(FMod, peT[5], peT[5], peT[3], pbScratch, cbScratch); // T3 := T5 + T5 = 2H

    a_dispatch.SymCryptModMul(FMod, peZ1, peZ2, peT[4], pbScratch, cbScratch); // T4 := Z1 * Z2

    a_dispatch.SymCryptModMul(FMod, peZ2, peT[6], peT[6], pbScratch, cbScratch); // T6 := Z2 * T6 = Z2*Z2Z2
    a_dispatch.SymCryptModMul(FMod, peT[4], peT[3], peZ3, pbScratch, cbScratch); // Z3 := T4 * T3 = Z1*Z2*2H

    a_dispatch.SymCryptModMul(FMod, peY1, peT[6], peT[6], pbScratch, cbScratch); // T6 := Y1 * T6 = Y1*Z2*Z2Z2 = S1
    a_dispatch.SymCryptModMul(FMod, peY2, peT[1], peT[4], pbScratch, cbScratch); // T4 := Y2*Z1*Z1Z1 = S2
    a_dispatch.SymCryptModSub(FMod, peT[4], peT[6], peT[4], pbScratch, cbScratch); // T4 := T4 - T6 = S2-S1
    a_dispatch.SymCryptModAdd(FMod, peT[4], peT[4], peT[4], pbScratch, cbScratch); // T4 := T4 + T4 = 2*(S2-S1) = r

    a_dispatch.SymCryptModSquare(FMod, peT[3], peT[3], pbScratch, cbScratch); // T3 := T3 * T3 = (2*H)^2 = I
    a_dispatch.SymCryptModMul(FMod, peT[3], peT[5], peT[5], pbScratch, cbScratch); // T5 := T3 * T5 = H*I = J
    a_dispatch.SymCryptModMul(FMod, peT[2], peT[3], peT[3], pbScratch, cbScratch); // T3 := T2 * T3 = U1*I = V

    a_dispatch.SymCryptModSquare(FMod, peT[4], peT[2], pbScratch, cbScratch); // T2 := T4 * T4 = r^2
    a_dispatch.SymCryptModSub(FMod, peT[2], peT[5], peT[2], pbScratch, cbScratch); // T2 := T2 - T5 = r^2 - J
    a_dispatch.SymCryptModSub(FMod, peT[2], peT[3], peT[2], pbScratch, cbScratch); // T2 := T2 - T3 = r^2 - J - V
    a_dispatch.SymCryptModSub(FMod, peT[2], peT[3], peX3, pbScratch, cbScratch); // T2 := T2 - T3 = r^2 - J - 2*V = X3

    a_dispatch.SymCryptModSub(FMod, peT[3], peX3, peT[3], pbScratch, cbScratch); // T3 := T3 - T2 = V - X3
    a_dispatch.SymCryptModMul(FMod, peT[3], peT[4], peT[3], pbScratch, cbScratch); // T3 := T3 * T4 = r*(V-X3)
    a_dispatch.SymCryptModMul(FMod, peT[6], peT[5], peT[6], pbScratch, cbScratch); // T6 := T6 * T5 = S1*J
    a_dispatch.SymCryptModAdd(FMod, peT[6], peT[6], peT[6], pbScratch, cbScratch); // T6 := T6 + T6 = 2*S1*J
    a_dispatch.SymCryptModSub(FMod, peT[3], peT[6], peY3, pbScratch, cbScratch); // Y3 := T6 - T3 = r*(V-X3) - 2*S1*J
}

pub export fn SymCryptShortWeierstrassAddSideChannelUnsafe(
    pCurve: PCSYMCRYPT_ECURVE,
    poSrc1: PCSYMCRYPT_ECPOINT,
    poSrc2: PCSYMCRYPT_ECPOINT,
    poDst: PSYMCRYPT_ECPOINT,
    pbScratch_in: PBYTE,
    cbScratch_in: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    @setRuntimeSafety(false);
    const FMod: PCSYMCRYPT_MODULUS = pCurve.FMod;
    var pbScratch = pbScratch_in;
    var cbScratch = cbScratch_in;

    const peX1: PCSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(0, pCurve, poSrc1);
    const peY1: PCSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(1, pCurve, poSrc1);
    const peZ1: PCSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(2, pCurve, poSrc1);

    const peX2: PCSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(0, pCurve, poSrc2);
    const peY2: PCSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(1, pCurve, poSrc2);
    const peZ2: PCSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(2, pCurve, poSrc2);

    var peT: [8]PSYMCRYPT_MODELEMENT = undefined;

    macros.SYMCRYPT_ASSERT(types.SYMCRYPT_CURVE_IS_SHORT_WEIERSTRASS_TYPE(pCurve));
    macros.SYMCRYPT_ASSERT(
        ecurve.SymCryptEcurveIsSame(pCurve, poSrc1.pCurve) != 0 and
            ecurve.SymCryptEcurveIsSame(pCurve, poSrc2.pCurve) != 0 and
            ecurve.SymCryptEcurveIsSame(pCurve, poDst.pCurve) != 0,
    );
    macros.SYMCRYPT_ASSERT(cbScratch >= types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(pCurve.FModDigits) + 8 * pCurve.cbModElement);

    if (a_dispatch.SymCryptModElementIsZero(FMod, peZ1) != 0) {
        ecpoint.SymCryptEcpointCopy(pCurve, poSrc2, poDst);
        return;
    }

    if (a_dispatch.SymCryptModElementIsZero(FMod, peZ2) != 0) {
        ecpoint.SymCryptEcpointCopy(pCurve, poSrc1, poDst);
        return;
    }

    var i: usize = 0;
    while (i < 8) : (i += 1) {
        peT[i] = a_dispatch.SymCryptModElementCreate(pbScratch, pCurve.cbModElement, FMod).?;
        pbScratch += pCurve.cbModElement;
    }
    cbScratch -= 8 * pCurve.cbModElement;

    a_dispatch.SymCryptModSquare(FMod, peZ1, peT[0], pbScratch, cbScratch); // T0 := Z1 * Z1 = Z1Z1
    a_dispatch.SymCryptModMul(FMod, peZ1, peT[0], peT[1], pbScratch, cbScratch); // T1 := Z1*Z1Z1

    a_dispatch.SymCryptModSquare(FMod, peZ2, peT[6], pbScratch, cbScratch); // T6 := Z2 * Z2 = Z2Z2
    a_dispatch.SymCryptModMul(FMod, peX1, peT[6], peT[2], pbScratch, cbScratch); // T2 := X1 * T6 = X1*Z2Z2 = U1
    a_dispatch.SymCryptModMul(FMod, peX2, peT[0], peT[3], pbScratch, cbScratch); // T3 := X2 * Z1Z1 = U2
    a_dispatch.SymCryptModSub(FMod, peT[3], peT[2], peT[5], pbScratch, cbScratch); // T5 := T3 - T2 = U2 - U1 = H

    a_dispatch.SymCryptModMul(FMod, peY2, peT[1], peT[7], pbScratch, cbScratch); // T7 := Y2 * T1 = Y2*Z1*Z1Z1 = S2
    a_dispatch.SymCryptModMul(FMod, peZ2, peT[6], peT[1], pbScratch, cbScratch); // T1 := Z2 * T6 = Z2*Z2Z2
    a_dispatch.SymCryptModMul(FMod, peY1, peT[1], peT[1], pbScratch, cbScratch); // T1 := Y1 * T1 = Y1*Z2*Z2Z2 = S1
    a_dispatch.SymCryptModSub(FMod, peT[7], peT[1], peT[7], pbScratch, cbScratch); // T7 := T7 - T1 = S2-S1

    if ((a_dispatch.SymCryptModElementIsZero(FMod, peT[5]) & a_dispatch.SymCryptModElementIsZero(FMod, peT[7])) != 0) {
        // Points are equal - run double on poSrc1
        a_dispatch.SymCryptModElementCopy(FMod, peT[0], peT[4]); // Move Z1Z1 for later

        a_dispatch.SymCryptModSquare(FMod, peX1, peT[0], pbScratch, cbScratch); // T0 := X1 * X1 = XX
        a_dispatch.SymCryptModSquare(FMod, peY1, peT[3], pbScratch, cbScratch); // T3 := Y1 * Y1 = YY
        a_dispatch.SymCryptModSquare(FMod, peT[3], peT[5], pbScratch, cbScratch); // T5 := T3 * T3 = YYYY

        a_dispatch.SymCryptModAdd(FMod, peX1, peT[3], peT[1], pbScratch, cbScratch); // T1 := X1 + T3 = X + YY
        a_dispatch.SymCryptModSquare(FMod, peT[1], peT[1], pbScratch, cbScratch); // T1 := T1 * T1 = (X + YY)^2
        a_dispatch.SymCryptModSub(FMod, peT[1], peT[0], peT[1], pbScratch, cbScratch); // T1 := T1 - T0 = (X + YY)^2 - XX
        a_dispatch.SymCryptModSub(FMod, peT[1], peT[5], peT[1], pbScratch, cbScratch); // T1 := T1 - T5 = (X + YY)^2 - XX - YYYY
        a_dispatch.SymCryptModAdd(FMod, peT[1], peT[1], peT[1], pbScratch, cbScratch); // T1 := T1 + T1 = 2*((X + YY)^2 - XX - YYYY) = S

        a_dispatch.SymCryptModSquare(FMod, peT[4], peT[2], pbScratch, cbScratch); // T2 := T4 * T4 = ZZ^2
        a_dispatch.SymCryptModMul(FMod, peT[2], pCurve.A, peT[2], pbScratch, cbScratch); // T2 := T2 * a = a*ZZ^2
        a_dispatch.SymCryptModAdd(FMod, peT[2], peT[0], peT[2], pbScratch, cbScratch); // T2 := T2 + T0 = XX + a*ZZ^2
        a_dispatch.SymCryptModAdd(FMod, peT[0], peT[0], peT[0], pbScratch, cbScratch); // T0 := T0 + T0 = 2*XX
        a_dispatch.SymCryptModAdd(FMod, peT[2], peT[0], peT[2], pbScratch, cbScratch); // T2 := T2 + T0 = 3*XX + a*ZZ^2 = M

        a_dispatch.SymCryptModSquare(FMod, peT[2], peT[0], pbScratch, cbScratch); // T0 := T2 * T2 = M^2
        a_dispatch.SymCryptModSub(FMod, peT[0], peT[1], peT[0], pbScratch, cbScratch); // T0 := T0 - T1 = M^2 - S
        a_dispatch.SymCryptModSub(FMod, peT[0], peT[1], peT[0], pbScratch, cbScratch); // T0 := T0 - T1 = M^2 - 2*S = T = X3

        a_dispatch.SymCryptModSub(FMod, peT[1], peT[0], peT[1], pbScratch, cbScratch); // T1 := T1 - T0 = S - T
        a_dispatch.SymCryptModMul(FMod, peT[2], peT[1], peT[1], pbScratch, cbScratch); // T1 := T2 * T1 = M * (S - T)
        a_dispatch.SymCryptModAdd(FMod, peT[5], peT[5], peT[5], pbScratch, cbScratch); // T5 := T5 + T5 = 2*YYYY
        a_dispatch.SymCryptModAdd(FMod, peT[5], peT[5], peT[5], pbScratch, cbScratch); // T5 := T5 + T5 = 4*YYYY
        a_dispatch.SymCryptModAdd(FMod, peT[5], peT[5], peT[5], pbScratch, cbScratch); // T5 := T5 + T5 = 8*YYYY
        a_dispatch.SymCryptModSub(FMod, peT[1], peT[5], peT[1], pbScratch, cbScratch); // T1 := T1 - T5 = M * (S - T) - 8*YYYY = Y3

        a_dispatch.SymCryptModAdd(FMod, peY1, peZ1, peT[2], pbScratch, cbScratch); // T2 := Y1 + Z1
        a_dispatch.SymCryptModSquare(FMod, peT[2], peT[2], pbScratch, cbScratch); // T2 := T2 * T2 = (Y + Z )^2
        a_dispatch.SymCryptModSub(FMod, peT[2], peT[3], peT[2], pbScratch, cbScratch); // T2 := T2 - T3 = (Y + Z )^2 - YY
        a_dispatch.SymCryptModSub(FMod, peT[2], peT[4], peT[2], pbScratch, cbScratch); // T2 := T2 - T4 = (Y + Z )^2 - YY - ZZ = Z3

        a_dispatch.SymCryptModElementCopy(FMod, peT[0], types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(0, pCurve, poDst));
        a_dispatch.SymCryptModElementCopy(FMod, peT[1], types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(1, pCurve, poDst));
        a_dispatch.SymCryptModElementCopy(FMod, peT[2], types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(2, pCurve, poDst));
    } else {
        // Continue the addition
        a_dispatch.SymCryptModAdd(FMod, peZ1, peZ2, peT[4], pbScratch, cbScratch); // T4 := Z1 + Z2
        a_dispatch.SymCryptModSquare(FMod, peT[4], peT[4], pbScratch, cbScratch); // T4 := T4 * T4 = (Z1 + Z2)^2
        a_dispatch.SymCryptModSub(FMod, peT[4], peT[0], peT[4], pbScratch, cbScratch); // T4 := T4 - Z1Z1 = (Z1 + Z2)^2 - Z1Z1
        a_dispatch.SymCryptModSub(FMod, peT[4], peT[6], peT[4], pbScratch, cbScratch); // T4 := T4 - T6 = (Z1 + Z2)^2 - Z1Z1 - Z2Z2
        a_dispatch.SymCryptModMul(FMod, peT[4], peT[5], peT[4], pbScratch, cbScratch); // T4 := T4 * T5 = ((Z1 + Z2)^2 - Z1Z1 - Z2Z2)*H = Z3

        a_dispatch.SymCryptModAdd(FMod, peT[7], peT[7], peT[7], pbScratch, cbScratch); // T7 := T7 + T7 = 2*(S2-S1) = r

        a_dispatch.SymCryptModAdd(FMod, peT[5], peT[5], peT[3], pbScratch, cbScratch); // T3 := T5 + T5 = 2*H
        a_dispatch.SymCryptModSquare(FMod, peT[3], peT[3], pbScratch, cbScratch); // T3 := T3 * T3 = (2*H)^2 = I
        a_dispatch.SymCryptModMul(FMod, peT[3], peT[5], peT[5], pbScratch, cbScratch); // T5 := T3 * T5 = H*I = J
        a_dispatch.SymCryptModMul(FMod, peT[2], peT[3], peT[3], pbScratch, cbScratch); // T3 := T2 * T3 = U1*I = V

        a_dispatch.SymCryptModSquare(FMod, peT[7], peT[2], pbScratch, cbScratch); // T2 := T7 * T7 = r^2
        a_dispatch.SymCryptModSub(FMod, peT[2], peT[5], peT[2], pbScratch, cbScratch); // T2 := T2 - T5 = r^2 - J
        a_dispatch.SymCryptModSub(FMod, peT[2], peT[3], peT[2], pbScratch, cbScratch); // T2 := T2 - T3 = r^2 - J - V
        a_dispatch.SymCryptModSub(FMod, peT[2], peT[3], peT[2], pbScratch, cbScratch); // T2 := T2 - T3 = r^2 - J - 2*V = X3

        a_dispatch.SymCryptModSub(FMod, peT[3], peT[2], peT[3], pbScratch, cbScratch); // T3 := T3 - T2 = V - X3
        a_dispatch.SymCryptModMul(FMod, peT[3], peT[7], peT[3], pbScratch, cbScratch); // T3 := T3 * T7 = r*(V-X3)
        a_dispatch.SymCryptModMul(FMod, peT[1], peT[5], peT[6], pbScratch, cbScratch); // T6 := T1 * T5 = S1*J
        a_dispatch.SymCryptModAdd(FMod, peT[6], peT[6], peT[6], pbScratch, cbScratch); // T6 := T6 + T6 = 2*S1*J
        a_dispatch.SymCryptModSub(FMod, peT[3], peT[6], peT[3], pbScratch, cbScratch); // T3 := T6 - T3 = r*(V-X3) - 2*S1*J = Y3

        a_dispatch.SymCryptModElementCopy(FMod, peT[2], types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(0, pCurve, poDst));
        a_dispatch.SymCryptModElementCopy(FMod, peT[3], types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(1, pCurve, poDst));
        a_dispatch.SymCryptModElementCopy(FMod, peT[4], types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(2, pCurve, poDst));
    }
}

pub export fn SymCryptShortWeierstrassAdd(
    pCurve: PCSYMCRYPT_ECURVE,
    poSrc1: PCSYMCRYPT_ECPOINT,
    poSrc2: PCSYMCRYPT_ECPOINT,
    poDst: PSYMCRYPT_ECPOINT,
    flags: UINT32,
    pbScratch_in: PBYTE,
    cbScratch_in: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    @setRuntimeSafety(false);
    var pbScratch = pbScratch_in;
    var cbScratch = cbScratch_in;

    const cbEcpoint: SIZE_T = ecpoint.SymCryptSizeofEcpointFromCurve(pCurve);

    macros.SYMCRYPT_ASSERT(types.SYMCRYPT_CURVE_IS_SHORT_WEIERSTRASS_TYPE(pCurve));
    macros.SYMCRYPT_ASSERT(
        ecurve.SymCryptEcurveIsSame(pCurve, poSrc1.pCurve) != 0 and
            ecurve.SymCryptEcurveIsSame(pCurve, poSrc2.pCurve) != 0 and
            ecurve.SymCryptEcurveIsSame(pCurve, poDst.pCurve) != 0,
    );
    macros.SYMCRYPT_ASSERT(cbScratch >= types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_ECURVE_OPERATIONS(pCurve));
    macros.SYMCRYPT_ASSERT(cbScratch > 2 * cbEcpoint);

    if ((flags & types.SYMCRYPT_FLAG_DATA_PUBLIC) != 0) {
        SymCryptShortWeierstrassAddSideChannelUnsafe(pCurve, poSrc1, poSrc2, poDst, pbScratch, cbScratch);
    } else {
        const poQ0: PSYMCRYPT_ECPOINT = ecpoint.SymCryptEcpointCreate(pbScratch, cbEcpoint, pCurve).?;
        pbScratch += cbEcpoint;

        const poQ1: PSYMCRYPT_ECPOINT = ecpoint.SymCryptEcpointCreate(pbScratch, cbEcpoint, pCurve).?;
        pbScratch += cbEcpoint;

        cbScratch -= 2 * cbEcpoint;

        const dSrc1Zero: UINT32 = SymCryptShortWeierstrassIsZero(pCurve, poSrc1, pbScratch, cbScratch);
        const dSrc2Zero: UINT32 = SymCryptShortWeierstrassIsZero(pCurve, poSrc2, pbScratch, cbScratch);
        const dSrcEqual: UINT32 = SymCryptShortWeierstrassIsEqual(pCurve, poSrc1, poSrc2, types.SYMCRYPT_FLAG_ECPOINT_EQUAL, pbScratch, cbScratch);

        SymCryptShortWeierstrassAddDiffNonZero(pCurve, poSrc1, poSrc2, poQ0, pbScratch, cbScratch);

        ec_dispatch.SymCryptEcpointDouble(pCurve, poSrc1, poQ1, 0, pbScratch, cbScratch);
        ecpoint.SymCryptEcpointMaskedCopy(pCurve, poQ1, poQ0, dSrcEqual);

        ecpoint.SymCryptEcpointMaskedCopy(pCurve, poSrc1, poQ0, dSrc2Zero);
        ecpoint.SymCryptEcpointMaskedCopy(pCurve, poSrc2, poQ0, dSrc1Zero);

        ecpoint.SymCryptEcpointCopy(pCurve, poQ0, poDst);
    }
}

pub export fn SymCryptShortWeierstrassNegate(
    pCurve: PCSYMCRYPT_ECURVE,
    poSrc: PSYMCRYPT_ECPOINT,
    mask: UINT32,
    pbScratch_in: PBYTE,
    cbScratch_in: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    @setRuntimeSafety(false);
    const FMod: PCSYMCRYPT_MODULUS = pCurve.FMod;
    const peY: PSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(1, pCurve, poSrc);
    var pbScratch = pbScratch_in;
    var cbScratch = cbScratch_in;

    macros.SYMCRYPT_ASSERT(types.SYMCRYPT_CURVE_IS_SHORT_WEIERSTRASS_TYPE(pCurve));
    macros.SYMCRYPT_ASSERT(ecurve.SymCryptEcurveIsSame(pCurve, poSrc.pCurve) != 0);
    macros.SYMCRYPT_ASSERT(cbScratch >= types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(pCurve.FModDigits) + pCurve.cbModElement);

    const peTmp: PSYMCRYPT_MODELEMENT = a_dispatch.SymCryptModElementCreate(pbScratch, pCurve.cbModElement, FMod).?;
    pbScratch += pCurve.cbModElement;
    cbScratch -= pCurve.cbModElement;

    a_dispatch.SymCryptModNeg(FMod, peY, peTmp, pbScratch, cbScratch);
    a_dispatch.SymCryptModElementMaskedCopy(FMod, peTmp, peY, mask);
}
