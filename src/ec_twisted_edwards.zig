//
// ec_twisted_edwards.zig   Twisted Edwards Curve Implementation
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
const PSYMCRYPT_ECURVE = types.PSYMCRYPT_ECURVE;
const PCSYMCRYPT_ECURVE = types.PCSYMCRYPT_ECURVE;
const PSYMCRYPT_ECPOINT = types.PSYMCRYPT_ECPOINT;
const PCSYMCRYPT_ECPOINT = types.PCSYMCRYPT_ECPOINT;
const PSYMCRYPT_MODULUS = types.PSYMCRYPT_MODULUS;
const PCSYMCRYPT_MODULUS = types.PCSYMCRYPT_MODULUS;
const PSYMCRYPT_MODELEMENT = types.PSYMCRYPT_MODELEMENT;

pub export fn SymCryptTwistedEdwardsFillScratchSpaces(pCurve: PSYMCRYPT_ECURVE) callconv(SYMCRYPT_CALL) void {
    @setRuntimeSafety(false);
    const nDigits: UINT32 = a_dispatch.SymCryptDigitsFromBits(pCurve.FModBitsize);
    const cbModElement: UINT32 = pCurve.cbModElement;
    const nDigitsFieldLength: UINT32 = pCurve.FModDigits;
    const asym_align: UINT32 = @intCast(types.SYMCRYPT_ASYM_ALIGN_VALUE);

    pCurve.cbScratchCommon = 8 * cbModElement + types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(nDigits);

    pCurve.cbScratchScalar =
        pCurve.cbModElement +
        2 * ecpoint.SymCryptSizeofEcpointFromCurve(pCurve) +
        2 * a_dispatch.SymCryptSizeofIntFromDigits(pCurve.GOrdDigits) +
        @max(
            pCurve.cbScratchCommon,
            types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(pCurve.GOrdDigits),
        );

    pCurve.cbScratchScalarMulti =
        pCurve.info.sw.nPrecompPoints * ecpoint.SymCryptSizeofEcpointFromCurve(pCurve) +
        ((2 * pCurve.info.sw.nRecodedDigits * @as(UINT32, @sizeOf(UINT32)) + asym_align - 1) / asym_align) * asym_align;

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
            pCurve.cbModElement + a_dispatch.SymCryptSizeofIntFromDigits(ecurve.SymCryptEcurveDigitsofScalarMultiplier(pCurve)),
            ecpoint.SymCryptSizeofEcpointFromCurve(pCurve),
        ) +
        @max(
            pCurve.cbScratchScalar + pCurve.cbScratchScalarMulti,
            pCurve.cbScratchGetSetValue,
        );
}

pub export fn SymCryptTwistedEdwardsSetDistinguished(
    pCurve: PCSYMCRYPT_ECURVE,
    poDst: PSYMCRYPT_ECPOINT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    @setRuntimeSafety(false);
    macros.SYMCRYPT_ASSERT(types.SYMCRYPT_CURVE_IS_TWISTED_EDWARDS_TYPE(pCurve));
    macros.SYMCRYPT_ASSERT(ecurve.SymCryptEcurveIsSame(pCurve, poDst.pCurve) != 0);

    _ = pbScratch;
    _ = cbScratch;

    ecpoint.SymCryptEcpointCopy(pCurve, pCurve.G, poDst);
}

pub export fn SymCryptTwistedEdwardsIsZero(
    pCurve: PCSYMCRYPT_ECURVE,
    poSrc: PCSYMCRYPT_ECPOINT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) UINT32 {
    @setRuntimeSafety(false);
    const pmMod: PSYMCRYPT_MODULUS = pCurve.FMod;

    macros.SYMCRYPT_ASSERT(types.SYMCRYPT_CURVE_IS_TWISTED_EDWARDS_TYPE(pCurve));
    macros.SYMCRYPT_ASSERT(ecurve.SymCryptEcurveIsSame(pCurve, poSrc.pCurve) != 0);

    _ = pbScratch;
    _ = cbScratch;

    const peSrcX: PSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(0, pCurve, poSrc);
    const peSrcY: PSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(1, pCurve, poSrc);
    const peSrcZ: PSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(2, pCurve, poSrc);

    const dResX: UINT32 = a_dispatch.SymCryptModElementIsZero(pmMod, peSrcX);
    const dResY: UINT32 = a_dispatch.SymCryptModElementIsEqual(pmMod, peSrcY, peSrcZ);

    return dResX & dResY;
}

//
// Verify that
//   a * x^2 + y^2 = 1 + d * x^2 * y^2
//   x = X/Z, y = Y/Z,
// To avoid mod inv calculation which is expensive,
// we verify Z^2(aX^2 + Y^2) = Z^4 + d * X^2 * Y^2
//
pub export fn SymCryptTwistedEdwardsOnCurve(
    pCurve: PCSYMCRYPT_ECURVE,
    poSrc: PCSYMCRYPT_ECPOINT,
    pbScratch_in: PBYTE,
    cbScratch_in: SIZE_T,
) callconv(SYMCRYPT_CALL) UINT32 {
    @setRuntimeSafety(false);
    var peTemp: [4]PSYMCRYPT_MODELEMENT = undefined;
    const pmMod: PSYMCRYPT_MODULUS = pCurve.FMod;
    var pbScratch = pbScratch_in;
    var cbScratch = cbScratch_in;

    macros.SYMCRYPT_ASSERT(types.SYMCRYPT_CURVE_IS_TWISTED_EDWARDS_TYPE(pCurve));
    macros.SYMCRYPT_ASSERT(ecurve.SymCryptEcurveIsSame(pCurve, poSrc.pCurve) != 0);
    macros.SYMCRYPT_ASSERT(cbScratch >= types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_ECURVE_OPERATIONS(pCurve));

    const nBytes: SIZE_T = a_dispatch.SymCryptSizeofModElementFromModulus(pmMod);

    macros.SYMCRYPT_ASSERT(cbScratch >= 4 * nBytes);

    var i: usize = 0;
    while (i < 4) : (i += 1) {
        peTemp[i] = a_dispatch.SymCryptModElementCreate(pbScratch, nBytes, pmMod).?;
        pbScratch += nBytes;
        cbScratch -= nBytes;
    }

    const peSrcX: PSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(0, pCurve, poSrc);
    const peSrcY: PSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(1, pCurve, poSrc);
    const peSrcZ: PSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(2, pCurve, poSrc);

    // peTemp[0] = X^2
    a_dispatch.SymCryptModSquare(pmMod, peSrcX, peTemp[0], pbScratch, cbScratch);

    // peTemp[1] = Y^2
    a_dispatch.SymCryptModSquare(pmMod, peSrcY, peTemp[1], pbScratch, cbScratch);

    // peTemp[2] = Z^2
    a_dispatch.SymCryptModSquare(pmMod, peSrcZ, peTemp[2], pbScratch, cbScratch);

    // peTemp[3] = a * X^2
    a_dispatch.SymCryptModMul(pmMod, pCurve.A, peTemp[0], peTemp[3], pbScratch, cbScratch);

    // peTemp[3] = a * X^2 + Y^2
    a_dispatch.SymCryptModAdd(pmMod, peTemp[3], peTemp[1], peTemp[3], pbScratch, cbScratch);

    // peTemp[3] = Z^2 (a * X^2 + Y^2)
    a_dispatch.SymCryptModMul(pmMod, peTemp[3], peTemp[2], peTemp[3], pbScratch, cbScratch);

    // peTemp[1] = X^2 * Y^2
    a_dispatch.SymCryptModMul(pmMod, peTemp[0], peTemp[1], peTemp[1], pbScratch, cbScratch);

    // peTemp[1] = d * X^2 * Y^2
    a_dispatch.SymCryptModMul(pmMod, pCurve.B, peTemp[1], peTemp[1], pbScratch, cbScratch);

    // peTemp[2] = Z^4
    a_dispatch.SymCryptModMul(pmMod, peTemp[2], peTemp[2], peTemp[2], pbScratch, cbScratch);

    // peTemp[1] = Z^4 + d * X^2 * Y^2
    a_dispatch.SymCryptModAdd(pmMod, peTemp[2], peTemp[1], peTemp[1], pbScratch, cbScratch);

    return a_dispatch.SymCryptModElementIsEqual(pmMod, peTemp[1], peTemp[3]);
}

pub export fn SymCryptTwistedEdwardsDouble(
    pCurve: PCSYMCRYPT_ECURVE,
    poSrc: PCSYMCRYPT_ECPOINT,
    poDst: PSYMCRYPT_ECPOINT,
    flags: UINT32,
    pbScratch_in: PBYTE,
    cbScratch_in: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    @setRuntimeSafety(false);
    var peTemp: [8]PSYMCRYPT_MODELEMENT = undefined;
    const pmMod: PSYMCRYPT_MODULUS = pCurve.FMod;
    var pbScratch = pbScratch_in;
    var cbScratch = cbScratch_in;

    macros.SYMCRYPT_ASSERT(types.SYMCRYPT_CURVE_IS_TWISTED_EDWARDS_TYPE(pCurve));
    macros.SYMCRYPT_ASSERT(
        ecurve.SymCryptEcurveIsSame(pCurve, poSrc.pCurve) != 0 and
            ecurve.SymCryptEcurveIsSame(pCurve, poDst.pCurve) != 0,
    );
    macros.SYMCRYPT_ASSERT(cbScratch >= types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_ECURVE_OPERATIONS(pCurve));

    _ = flags;

    const nBytes: SIZE_T = a_dispatch.SymCryptSizeofModElementFromModulus(pmMod);

    macros.SYMCRYPT_ASSERT(cbScratch >= 8 * nBytes);

    var i: usize = 0;
    while (i < 8) : (i += 1) {
        peTemp[i] = a_dispatch.SymCryptModElementCreate(pbScratch, nBytes, pmMod).?;
        pbScratch += nBytes;
        cbScratch -= nBytes;
    }

    const peSrcX: PSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(0, pCurve, poSrc);
    const peSrcY: PSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(1, pCurve, poSrc);
    const peSrcZ: PSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(2, pCurve, poSrc);

    const peDstX: PSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(0, pCurve, poDst);
    const peDstY: PSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(1, pCurve, poDst);
    const peDstZ: PSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(2, pCurve, poDst);
    const peDstT: PSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(3, pCurve, poDst);

    const peA: PSYMCRYPT_MODELEMENT = peTemp[0];
    const peB: PSYMCRYPT_MODELEMENT = peTemp[1];
    const peC: PSYMCRYPT_MODELEMENT = peTemp[2];
    const peD: PSYMCRYPT_MODELEMENT = peTemp[3];
    const peE: PSYMCRYPT_MODELEMENT = peTemp[4];
    const peF: PSYMCRYPT_MODELEMENT = peTemp[5];
    const peG: PSYMCRYPT_MODELEMENT = peTemp[6];
    const peH: PSYMCRYPT_MODELEMENT = peTemp[7];

    // A = X1^2
    a_dispatch.SymCryptModSquare(pmMod, peSrcX, peA, pbScratch, cbScratch);

    // B = Y1^2
    a_dispatch.SymCryptModSquare(pmMod, peSrcY, peB, pbScratch, cbScratch);

    // C1 = Z1^2
    a_dispatch.SymCryptModSquare(pmMod, peSrcZ, peC, pbScratch, cbScratch);

    // C = C1 + C1 = Z1^2 + Z1^2 = 2 * Z1^2
    a_dispatch.SymCryptModAdd(pmMod, peC, peC, peC, pbScratch, cbScratch);

    // D = a * A
    a_dispatch.SymCryptModMul(pmMod, pCurve.A, peA, peD, pbScratch, cbScratch);

    // E1 = X1 + Y1
    a_dispatch.SymCryptModAdd(pmMod, peSrcX, peSrcY, peE, pbScratch, cbScratch);

    // E2 = E1^2 = (X1 + Y1)^2
    a_dispatch.SymCryptModSquare(pmMod, peE, peE, pbScratch, cbScratch);

    // E3 = E2 - A = (X1 + Y1)^2 - A
    a_dispatch.SymCryptModSub(pmMod, peE, peA, peE, pbScratch, cbScratch);

    // E = E3 - B = (X1 + Y1)^2 - A - B
    a_dispatch.SymCryptModSub(pmMod, peE, peB, peE, pbScratch, cbScratch);

    // G = D + B
    a_dispatch.SymCryptModAdd(pmMod, peD, peB, peG, pbScratch, cbScratch);

    // F = G - C
    a_dispatch.SymCryptModSub(pmMod, peG, peC, peF, pbScratch, cbScratch);

    // H = D - B
    a_dispatch.SymCryptModSub(pmMod, peD, peB, peH, pbScratch, cbScratch);

    // X3 = E * F
    a_dispatch.SymCryptModMul(pmMod, peE, peF, peDstX, pbScratch, cbScratch);

    // Y3 = G * H
    a_dispatch.SymCryptModMul(pmMod, peG, peH, peDstY, pbScratch, cbScratch);

    // T3 = E * H
    a_dispatch.SymCryptModMul(pmMod, peE, peH, peDstT, pbScratch, cbScratch);

    // Z3 = F * G
    a_dispatch.SymCryptModMul(pmMod, peF, peG, peDstZ, pbScratch, cbScratch);
}

pub export fn SymCryptTwistedEdwardsAdd(
    pCurve: PCSYMCRYPT_ECURVE,
    poSrc1: PCSYMCRYPT_ECPOINT,
    poSrc2: PCSYMCRYPT_ECPOINT,
    poDst: PSYMCRYPT_ECPOINT,
    flags: UINT32,
    pbScratch_in: PBYTE,
    cbScratch_in: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    @setRuntimeSafety(false);
    var peTemp: [8]PSYMCRYPT_MODELEMENT = undefined;
    const pmMod: PSYMCRYPT_MODULUS = pCurve.FMod;
    var pbScratch = pbScratch_in;
    var cbScratch = cbScratch_in;

    macros.SYMCRYPT_ASSERT(types.SYMCRYPT_CURVE_IS_TWISTED_EDWARDS_TYPE(pCurve));
    macros.SYMCRYPT_ASSERT(
        ecurve.SymCryptEcurveIsSame(pCurve, poSrc1.pCurve) != 0 and
            ecurve.SymCryptEcurveIsSame(pCurve, poSrc2.pCurve) != 0 and
            ecurve.SymCryptEcurveIsSame(pCurve, poDst.pCurve) != 0,
    );
    macros.SYMCRYPT_ASSERT(cbScratch >= types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_ECURVE_OPERATIONS(pCurve));

    _ = flags;

    const nBytes: SIZE_T = a_dispatch.SymCryptSizeofModElementFromModulus(pmMod);

    macros.SYMCRYPT_ASSERT(cbScratch >= 8 * nBytes);

    var i: usize = 0;
    while (i < 8) : (i += 1) {
        peTemp[i] = a_dispatch.SymCryptModElementCreate(pbScratch, nBytes, pmMod).?;
        pbScratch += nBytes;
        cbScratch -= nBytes;
    }

    const peSrc1X: PSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(0, pCurve, poSrc1);
    const peSrc1Y: PSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(1, pCurve, poSrc1);
    const peSrc1Z: PSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(2, pCurve, poSrc1);
    const peSrc1T: PSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(3, pCurve, poSrc1);

    const peSrc2X: PSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(0, pCurve, poSrc2);
    const peSrc2Y: PSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(1, pCurve, poSrc2);
    const peSrc2Z: PSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(2, pCurve, poSrc2);
    const peSrc2T: PSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(3, pCurve, poSrc2);

    const peDstX: PSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(0, pCurve, poDst);
    const peDstY: PSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(1, pCurve, poDst);
    const peDstZ: PSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(2, pCurve, poDst);
    const peDstT: PSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(3, pCurve, poDst);

    const peA: PSYMCRYPT_MODELEMENT = peTemp[0];
    const peB: PSYMCRYPT_MODELEMENT = peTemp[1];
    const peC: PSYMCRYPT_MODELEMENT = peTemp[2];
    const peD: PSYMCRYPT_MODELEMENT = peTemp[3];
    const peE: PSYMCRYPT_MODELEMENT = peTemp[4];
    const peF: PSYMCRYPT_MODELEMENT = peTemp[5];
    const peG: PSYMCRYPT_MODELEMENT = peTemp[6];
    const peH: PSYMCRYPT_MODELEMENT = peTemp[7];

    // A = X1 * X2
    a_dispatch.SymCryptModMul(pmMod, peSrc1X, peSrc2X, peA, pbScratch, cbScratch);

    // B = Y1 * Y2
    a_dispatch.SymCryptModMul(pmMod, peSrc1Y, peSrc2Y, peB, pbScratch, cbScratch);

    // C1 = T1 * T2
    a_dispatch.SymCryptModMul(pmMod, peSrc1T, peSrc2T, peC, pbScratch, cbScratch);

    // C = d * C1 = d * T1 * T2
    a_dispatch.SymCryptModMul(pmMod, pCurve.B, peC, peC, pbScratch, cbScratch);

    // D = Z1 * Z2
    a_dispatch.SymCryptModMul(pmMod, peSrc1Z, peSrc2Z, peD, pbScratch, cbScratch);

    // E1 = X1 + Y1
    a_dispatch.SymCryptModAdd(pmMod, peSrc1X, peSrc1Y, peE, pbScratch, cbScratch);

    // E2 = X2 + Y2
    a_dispatch.SymCryptModAdd(pmMod, peSrc2X, peSrc2Y, peF, pbScratch, cbScratch);

    // E = E * F
    a_dispatch.SymCryptModMul(pmMod, peE, peF, peE, pbScratch, cbScratch);

    // E = E - A
    a_dispatch.SymCryptModSub(pmMod, peE, peA, peE, pbScratch, cbScratch);

    // E = E - B
    a_dispatch.SymCryptModSub(pmMod, peE, peB, peE, pbScratch, cbScratch);

    // F = D - C
    a_dispatch.SymCryptModSub(pmMod, peD, peC, peF, pbScratch, cbScratch);

    // G = D + C
    a_dispatch.SymCryptModAdd(pmMod, peD, peC, peG, pbScratch, cbScratch);

    // H = a * A
    a_dispatch.SymCryptModMul(pmMod, pCurve.A, peA, peH, pbScratch, cbScratch);

    // H = B - a * A
    a_dispatch.SymCryptModSub(pmMod, peB, peH, peH, pbScratch, cbScratch);

    // X3 = E * F
    a_dispatch.SymCryptModMul(pmMod, peE, peF, peDstX, pbScratch, cbScratch);

    // Y3 = G * H
    a_dispatch.SymCryptModMul(pmMod, peG, peH, peDstY, pbScratch, cbScratch);

    // T3 = E * H
    a_dispatch.SymCryptModMul(pmMod, peE, peH, peDstT, pbScratch, cbScratch);

    // Z3 = F * G
    a_dispatch.SymCryptModMul(pmMod, peF, peG, peDstZ, pbScratch, cbScratch);
}

pub export fn SymCryptTwistedEdwardsAddDiffNonZero(
    pCurve: PCSYMCRYPT_ECURVE,
    poSrc1: PCSYMCRYPT_ECPOINT,
    poSrc2: PCSYMCRYPT_ECPOINT,
    poDst: PSYMCRYPT_ECPOINT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    @setRuntimeSafety(false);
    SymCryptTwistedEdwardsAdd(pCurve, poSrc1, poSrc2, poDst, 0, pbScratch, cbScratch);
}

pub export fn SymCryptTwistedEdwardsIsEqual(
    pCurve: PCSYMCRYPT_ECURVE,
    poSrc1: PCSYMCRYPT_ECPOINT,
    poSrc2: PCSYMCRYPT_ECPOINT,
    flags_in: UINT32,
    pbScratch_in: PBYTE,
    cbScratch_in: SIZE_T,
) callconv(SYMCRYPT_CALL) UINT32 {
    @setRuntimeSafety(false);
    var peTemp: [2]PSYMCRYPT_MODELEMENT = undefined;
    const pmMod: PSYMCRYPT_MODULUS = pCurve.FMod;
    var flags = flags_in;
    var pbScratch = pbScratch_in;
    var cbScratch = cbScratch_in;

    macros.SYMCRYPT_ASSERT(types.SYMCRYPT_CURVE_IS_TWISTED_EDWARDS_TYPE(pCurve));
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
    const peSrc1Y: PSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(1, pCurve, poSrc1);
    const peSrc1Z: PSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(2, pCurve, poSrc1);

    const peSrc2X: PSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(0, pCurve, poSrc2);
    const peSrc2Y: PSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(1, pCurve, poSrc2);
    const peSrc2Z: PSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(2, pCurve, poSrc2);

    // Setting the default flag if flags == 0
    flags |= (macros.SYMCRYPT_MASK32_ZERO(flags) & types.SYMCRYPT_FLAG_ECPOINT_EQUAL);

    // peTemp[0] = X1 * Z2
    a_dispatch.SymCryptModMul(pmMod, peSrc1X, peSrc2Z, peTemp[0], pbScratch, cbScratch);

    // peTemp[1] = X2 * Z1
    a_dispatch.SymCryptModMul(pmMod, peSrc2X, peSrc1Z, peTemp[1], pbScratch, cbScratch);

    const dResX: UINT32 = a_dispatch.SymCryptModElementIsEqual(pmMod, peTemp[0], peTemp[1]);

    // Neg peTemp[1]
    a_dispatch.SymCryptModNeg(pmMod, peTemp[1], peTemp[1], pbScratch, cbScratch);
    const dResXN: UINT32 = a_dispatch.SymCryptModElementIsEqual(pmMod, peTemp[0], peTemp[1]);

    // peTemp[0] = Y1 * Z2
    a_dispatch.SymCryptModMul(pmMod, peSrc1Y, peSrc2Z, peTemp[0], pbScratch, cbScratch);

    // peTemp[1] = Y2 * Z1
    a_dispatch.SymCryptModMul(pmMod, peSrc2Y, peSrc1Z, peTemp[1], pbScratch, cbScratch);

    const dResY: UINT32 = a_dispatch.SymCryptModElementIsEqual(pmMod, peTemp[0], peTemp[1]);

    return (macros.SYMCRYPT_MASK32_NONZERO(flags & types.SYMCRYPT_FLAG_ECPOINT_EQUAL) & dResX & dResY) |
        (macros.SYMCRYPT_MASK32_NONZERO(flags & types.SYMCRYPT_FLAG_ECPOINT_NEG_EQUAL) & dResXN & dResY);
}

pub export fn SymCryptTwistedEdwardsSetZero(
    pCurve: PCSYMCRYPT_ECURVE,
    poDst: PSYMCRYPT_ECPOINT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    @setRuntimeSafety(false);
    macros.SYMCRYPT_ASSERT(types.SYMCRYPT_CURVE_IS_TWISTED_EDWARDS_TYPE(pCurve));
    macros.SYMCRYPT_ASSERT(ecurve.SymCryptEcurveIsSame(pCurve, poDst.pCurve) != 0);
    macros.SYMCRYPT_ASSERT(cbScratch >= types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_ECURVE_OPERATIONS(pCurve));

    const pmMod: PSYMCRYPT_MODULUS = pCurve.FMod;

    const peDstX: PSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(0, pCurve, poDst);
    const peDstY: PSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(1, pCurve, poDst);
    const peDstZ: PSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(2, pCurve, poDst);
    const peDstT: PSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(3, pCurve, poDst);

    a_dispatch.SymCryptModElementSetValueUint32(0, pmMod, peDstX, pbScratch, cbScratch);
    a_dispatch.SymCryptModElementSetValueUint32(1, pmMod, peDstY, pbScratch, cbScratch);
    a_dispatch.SymCryptModElementSetValueUint32(1, pmMod, peDstZ, pbScratch, cbScratch);
    a_dispatch.SymCryptModElementSetValueUint32(0, pmMod, peDstT, pbScratch, cbScratch);
}

pub export fn SymCryptTwistedEdwardsNegate(
    pCurve: PCSYMCRYPT_ECURVE,
    poSrc: PSYMCRYPT_ECPOINT,
    mask: UINT32,
    pbScratch_in: PBYTE,
    cbScratch_in: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    @setRuntimeSafety(false);
    const FMod: PCSYMCRYPT_MODULUS = pCurve.FMod;
    const peX: PSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(0, pCurve, poSrc);
    const peT: PSYMCRYPT_MODELEMENT = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(3, pCurve, poSrc);
    var pbScratch = pbScratch_in;
    var cbScratch = cbScratch_in;

    macros.SYMCRYPT_ASSERT(types.SYMCRYPT_CURVE_IS_TWISTED_EDWARDS_TYPE(pCurve));
    macros.SYMCRYPT_ASSERT(ecurve.SymCryptEcurveIsSame(pCurve, poSrc.pCurve) != 0);
    macros.SYMCRYPT_ASSERT(cbScratch >= types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(pCurve.FModDigits) + pCurve.cbModElement);

    const peTmp: PSYMCRYPT_MODELEMENT = a_dispatch.SymCryptModElementCreate(pbScratch, pCurve.cbModElement, FMod).?;
    pbScratch += pCurve.cbModElement;
    cbScratch -= pCurve.cbModElement;

    a_dispatch.SymCryptModNeg(FMod, peX, peTmp, pbScratch, cbScratch);
    a_dispatch.SymCryptModElementMaskedCopy(FMod, peTmp, peX, mask);

    a_dispatch.SymCryptModNeg(FMod, peT, peTmp, pbScratch, cbScratch);
    a_dispatch.SymCryptModElementMaskedCopy(FMod, peTmp, peT, mask);
}
