//
// ec_dispatch.zig   Dispatch code for the modular operations
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

const types = @import("types.zig");
const macros = @import("macros.zig");

const PBYTE = types.PBYTE;
const UINT32 = types.UINT32;
const SIZE_T = types.SIZE_T;
const SYMCRYPT_CALL = types.SYMCRYPT_CALL;
const SYMCRYPT_ERROR = types.SYMCRYPT_ERROR;
const PSYMCRYPT_ECURVE = types.PSYMCRYPT_ECURVE;
const PCSYMCRYPT_ECURVE = types.PCSYMCRYPT_ECURVE;
const PSYMCRYPT_ECPOINT = types.PSYMCRYPT_ECPOINT;
const PCSYMCRYPT_ECPOINT = types.PCSYMCRYPT_ECPOINT;
const PSYMCRYPT_INT = types.PSYMCRYPT_INT;
const PCSYMCRYPT_INT = types.PCSYMCRYPT_INT;
const SYMCRYPT_ECURVE_FUNCTIONS = types.SYMCRYPT_ECURVE_FUNCTIONS;

// Extern group-law and scalar-multiplication functions from C (ec_short_weierstrass.c, ec_twisted_edwards.c, ec_montgomery.c, ec_mul.c)
pub extern fn SymCryptShortWeierstrassSetZero(
    pCurve: PCSYMCRYPT_ECURVE,
    poDst: PSYMCRYPT_ECPOINT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void;

pub extern fn SymCryptShortWeierstrassSetDistinguished(
    pCurve: PCSYMCRYPT_ECURVE,
    poDst: PSYMCRYPT_ECPOINT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void;

pub extern fn SymCryptShortWeierstrassIsEqual(
    pCurve: PCSYMCRYPT_ECURVE,
    poSrc1: PCSYMCRYPT_ECPOINT,
    poSrc2: PCSYMCRYPT_ECPOINT,
    flags: UINT32,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) UINT32;

pub extern fn SymCryptShortWeierstrassIsZero(
    pCurve: PCSYMCRYPT_ECURVE,
    poSrc: PCSYMCRYPT_ECPOINT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) UINT32;

pub extern fn SymCryptShortWeierstrassOnCurve(
    pCurve: PCSYMCRYPT_ECURVE,
    poSrc: PCSYMCRYPT_ECPOINT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) UINT32;

pub extern fn SymCryptShortWeierstrassAdd(
    pCurve: PCSYMCRYPT_ECURVE,
    poSrc1: PCSYMCRYPT_ECPOINT,
    poSrc2: PCSYMCRYPT_ECPOINT,
    poDst: PSYMCRYPT_ECPOINT,
    flags: UINT32,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void;

pub extern fn SymCryptShortWeierstrassAddDiffNonZero(
    pCurve: PCSYMCRYPT_ECURVE,
    poSrc1: PCSYMCRYPT_ECPOINT,
    poSrc2: PCSYMCRYPT_ECPOINT,
    poDst: PSYMCRYPT_ECPOINT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void;

pub extern fn SymCryptShortWeierstrassDouble(
    pCurve: PCSYMCRYPT_ECURVE,
    poSrc: PCSYMCRYPT_ECPOINT,
    poDst: PSYMCRYPT_ECPOINT,
    flags: UINT32,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void;

pub extern fn SymCryptShortWeierstrassDoubleSpecializedAm3(
    pCurve: PCSYMCRYPT_ECURVE,
    poSrc: PCSYMCRYPT_ECPOINT,
    poDst: PSYMCRYPT_ECPOINT,
    flags: UINT32,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void;

pub extern fn SymCryptShortWeierstrassNegate(
    pCurve: PCSYMCRYPT_ECURVE,
    poSrc: PSYMCRYPT_ECPOINT,
    mask: UINT32,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void;

pub extern fn SymCryptShortWeierstrassFillScratchSpaces(
    pCurve: PSYMCRYPT_ECURVE,
) callconv(SYMCRYPT_CALL) void;

pub extern fn SymCryptTwistedEdwardsSetZero(
    pCurve: PCSYMCRYPT_ECURVE,
    poDst: PSYMCRYPT_ECPOINT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void;

pub extern fn SymCryptTwistedEdwardsSetDistinguished(
    pCurve: PCSYMCRYPT_ECURVE,
    poDst: PSYMCRYPT_ECPOINT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void;

pub extern fn SymCryptTwistedEdwardsIsEqual(
    pCurve: PCSYMCRYPT_ECURVE,
    poSrc1: PCSYMCRYPT_ECPOINT,
    poSrc2: PCSYMCRYPT_ECPOINT,
    flags: UINT32,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) UINT32;

pub extern fn SymCryptTwistedEdwardsIsZero(
    pCurve: PCSYMCRYPT_ECURVE,
    poSrc: PCSYMCRYPT_ECPOINT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) UINT32;

pub extern fn SymCryptTwistedEdwardsOnCurve(
    pCurve: PCSYMCRYPT_ECURVE,
    poSrc: PCSYMCRYPT_ECPOINT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) UINT32;

pub extern fn SymCryptTwistedEdwardsAdd(
    pCurve: PCSYMCRYPT_ECURVE,
    poSrc1: PCSYMCRYPT_ECPOINT,
    poSrc2: PCSYMCRYPT_ECPOINT,
    poDst: PSYMCRYPT_ECPOINT,
    flags: UINT32,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void;

pub extern fn SymCryptTwistedEdwardsAddDiffNonZero(
    pCurve: PCSYMCRYPT_ECURVE,
    poSrc1: PCSYMCRYPT_ECPOINT,
    poSrc2: PCSYMCRYPT_ECPOINT,
    poDst: PSYMCRYPT_ECPOINT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void;

pub extern fn SymCryptTwistedEdwardsDouble(
    pCurve: PCSYMCRYPT_ECURVE,
    poSrc: PCSYMCRYPT_ECPOINT,
    poDst: PSYMCRYPT_ECPOINT,
    flags: UINT32,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void;

pub extern fn SymCryptTwistedEdwardsNegate(
    pCurve: PCSYMCRYPT_ECURVE,
    poSrc: PSYMCRYPT_ECPOINT,
    mask: UINT32,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void;

pub extern fn SymCryptTwistedEdwardsFillScratchSpaces(
    pCurve: PSYMCRYPT_ECURVE,
) callconv(SYMCRYPT_CALL) void;

pub extern fn SymCryptMontgomerySetDistinguished(
    pCurve: PCSYMCRYPT_ECURVE,
    poDst: PSYMCRYPT_ECPOINT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void;

pub extern fn SymCryptMontgomeryIsEqual(
    pCurve: PCSYMCRYPT_ECURVE,
    poSrc1: PCSYMCRYPT_ECPOINT,
    poSrc2: PCSYMCRYPT_ECPOINT,
    flags: UINT32,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) UINT32;

pub extern fn SymCryptMontgomeryIsZero(
    pCurve: PCSYMCRYPT_ECURVE,
    poSrc: PCSYMCRYPT_ECPOINT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) UINT32;

pub extern fn SymCryptMontgomeryPointScalarMul(
    pCurve: PCSYMCRYPT_ECURVE,
    piScalar: PCSYMCRYPT_INT,
    poSrc: ?PCSYMCRYPT_ECPOINT,
    flags: UINT32,
    poDst: PSYMCRYPT_ECPOINT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;

pub extern fn SymCryptMontgomeryFillScratchSpaces(
    pCurve: PSYMCRYPT_ECURVE,
) callconv(SYMCRYPT_CALL) void;

pub extern fn SymCryptEcpointGenericSetRandom(
    pCurve: PCSYMCRYPT_ECURVE,
    piScalar: PSYMCRYPT_INT,
    poDst: PSYMCRYPT_ECPOINT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void;

pub extern fn SymCryptEcpointScalarMulFixedWindow(
    pCurve: PCSYMCRYPT_ECURVE,
    piScalar: PCSYMCRYPT_INT,
    poSrc: ?PCSYMCRYPT_ECPOINT,
    flags: UINT32,
    poDst: PSYMCRYPT_ECPOINT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;

pub extern fn SymCryptEcpointMultiScalarMulWnafWithInterleaving(
    pCurve: PCSYMCRYPT_ECURVE,
    piTableScalars: [*]const PCSYMCRYPT_INT,
    poTablePoints: [*]const ?PCSYMCRYPT_ECPOINT,
    nPoints: UINT32,
    flags: UINT32,
    poDst: PSYMCRYPT_ECPOINT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;

const nullEntry: SYMCRYPT_ECURVE_FUNCTIONS = .{
    .setZeroFunc = null,
    .setDistinguishedFunc = null,
    .setRandomFunc = null,
    .isEqualFunc = null,
    .isZeroFunc = null,
    .onCurveFunc = null,
    .addFunc = null,
    .addDiffFunc = null,
    .doubleFunc = null,
    .negateFunc = null,
    .scalarMulFunc = null,
    .multiScalarMulFunc = null,
    .fillScratchSpacesFunc = null,
};

pub export const SymCryptEcurveDispatchTable: [8]SYMCRYPT_ECURVE_FUNCTIONS = .{
    // NULL Type
    nullEntry,
    // Short Weierstrass
    .{
        .setZeroFunc = &SymCryptShortWeierstrassSetZero,
        .setDistinguishedFunc = &SymCryptShortWeierstrassSetDistinguished,
        .setRandomFunc = &SymCryptEcpointGenericSetRandom,
        .isEqualFunc = &SymCryptShortWeierstrassIsEqual,
        .isZeroFunc = &SymCryptShortWeierstrassIsZero,
        .onCurveFunc = &SymCryptShortWeierstrassOnCurve,
        .addFunc = &SymCryptShortWeierstrassAdd,
        .addDiffFunc = &SymCryptShortWeierstrassAddDiffNonZero,
        .doubleFunc = &SymCryptShortWeierstrassDouble,
        .negateFunc = &SymCryptShortWeierstrassNegate,
        .scalarMulFunc = &SymCryptEcpointScalarMulFixedWindow,
        .multiScalarMulFunc = &SymCryptEcpointMultiScalarMulWnafWithInterleaving,
        .fillScratchSpacesFunc = &SymCryptShortWeierstrassFillScratchSpaces,
    },
    // Twisted Edwards
    .{
        .setZeroFunc = &SymCryptTwistedEdwardsSetZero,
        .setDistinguishedFunc = &SymCryptTwistedEdwardsSetDistinguished,
        .setRandomFunc = &SymCryptEcpointGenericSetRandom,
        .isEqualFunc = &SymCryptTwistedEdwardsIsEqual,
        .isZeroFunc = &SymCryptTwistedEdwardsIsZero,
        .onCurveFunc = &SymCryptTwistedEdwardsOnCurve,
        .addFunc = &SymCryptTwistedEdwardsAdd,
        .addDiffFunc = &SymCryptTwistedEdwardsAddDiffNonZero,
        .doubleFunc = &SymCryptTwistedEdwardsDouble,
        .negateFunc = &SymCryptTwistedEdwardsNegate,
        .scalarMulFunc = &SymCryptEcpointScalarMulFixedWindow,
        .multiScalarMulFunc = &SymCryptEcpointMultiScalarMulWnafWithInterleaving,
        .fillScratchSpacesFunc = &SymCryptTwistedEdwardsFillScratchSpaces,
    },
    // Montgomery
    .{
        .setZeroFunc = null,
        .setDistinguishedFunc = &SymCryptMontgomerySetDistinguished,
        .setRandomFunc = &SymCryptEcpointGenericSetRandom,
        .isEqualFunc = &SymCryptMontgomeryIsEqual,
        .isZeroFunc = &SymCryptMontgomeryIsZero,
        .onCurveFunc = null,
        .addFunc = null,
        .addDiffFunc = null,
        .doubleFunc = null,
        .negateFunc = null,
        .scalarMulFunc = &SymCryptMontgomeryPointScalarMul,
        .multiScalarMulFunc = null,
        .fillScratchSpacesFunc = &SymCryptMontgomeryFillScratchSpaces,
    },
    // Short Weierstrass with A==-3
    .{
        .setZeroFunc = &SymCryptShortWeierstrassSetZero,
        .setDistinguishedFunc = &SymCryptShortWeierstrassSetDistinguished,
        .setRandomFunc = &SymCryptEcpointGenericSetRandom,
        .isEqualFunc = &SymCryptShortWeierstrassIsEqual,
        .isZeroFunc = &SymCryptShortWeierstrassIsZero,
        .onCurveFunc = &SymCryptShortWeierstrassOnCurve,
        .addFunc = &SymCryptShortWeierstrassAdd,
        .addDiffFunc = &SymCryptShortWeierstrassAddDiffNonZero,
        .doubleFunc = &SymCryptShortWeierstrassDoubleSpecializedAm3,
        .negateFunc = &SymCryptShortWeierstrassNegate,
        .scalarMulFunc = &SymCryptEcpointScalarMulFixedWindow,
        .multiScalarMulFunc = &SymCryptEcpointMultiScalarMulWnafWithInterleaving,
        .fillScratchSpacesFunc = &SymCryptShortWeierstrassFillScratchSpaces,
    },
    // Slack to make dispatch table size a power of 2
    nullEntry,
    nullEntry,
    nullEntry,
};

const SYMCRYPT_ECURVE_DISPATCH_TABLE_SIZE: usize = @sizeOf(@TypeOf(SymCryptEcurveDispatchTable));
const SYMCRYPT_ECURVE_DISPATCH_TABLE_MASK: UINT32 = @intCast((SYMCRYPT_ECURVE_DISPATCH_TABLE_SIZE / @sizeOf(SYMCRYPT_ECURVE_FUNCTIONS)) - 1);

comptime {
    if ((SYMCRYPT_ECURVE_DISPATCH_TABLE_SIZE & (SYMCRYPT_ECURVE_DISPATCH_TABLE_SIZE - 1)) != 0) {
        @compileError("SYMCRYPT_ECURVE_DISPATCH_TABLE_SIZE must be a power of 2");
    }
    if (@sizeOf(types.SYMCRYPT_INTERNAL_ECURVE_TYPE) != 4) {
        @compileError("SYMCRYPT_INTERNAL_ECURVE_TYPE must be 4 bytes");
    }
}

inline fn dispatchEntry(pCurve: PCSYMCRYPT_ECURVE) *const SYMCRYPT_ECURVE_FUNCTIONS {
    const idx: usize = macros.SYMCRYPT_FORCE_READ32(@as(*const volatile UINT32, @ptrCast(&pCurve.type))) & SYMCRYPT_ECURVE_DISPATCH_TABLE_MASK;
    return &SymCryptEcurveDispatchTable[idx];
}

pub export fn SymCryptEcpointSetZero(
    pCurve: PCSYMCRYPT_ECURVE,
    poDst: PSYMCRYPT_ECPOINT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    dispatchEntry(pCurve).setZeroFunc.?(pCurve, poDst, pbScratch, cbScratch);
}

pub export fn SymCryptEcpointSetDistinguishedPoint(
    pCurve: PCSYMCRYPT_ECURVE,
    poDst: PSYMCRYPT_ECPOINT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    dispatchEntry(pCurve).setDistinguishedFunc.?(pCurve, poDst, pbScratch, cbScratch);
}

pub export fn SymCryptEcpointSetRandom(
    pCurve: PCSYMCRYPT_ECURVE,
    piScalar: PSYMCRYPT_INT,
    poDst: PSYMCRYPT_ECPOINT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    dispatchEntry(pCurve).setRandomFunc.?(pCurve, piScalar, poDst, pbScratch, cbScratch);
}

pub export fn SymCryptEcpointIsEqual(
    pCurve: PCSYMCRYPT_ECURVE,
    poSrc1: PCSYMCRYPT_ECPOINT,
    poSrc2: PCSYMCRYPT_ECPOINT,
    flags: UINT32,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) UINT32 {
    return dispatchEntry(pCurve).isEqualFunc.?(pCurve, poSrc1, poSrc2, flags, pbScratch, cbScratch);
}

pub export fn SymCryptEcpointIsZero(
    pCurve: PCSYMCRYPT_ECURVE,
    poSrc: PCSYMCRYPT_ECPOINT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) UINT32 {
    return dispatchEntry(pCurve).isZeroFunc.?(pCurve, poSrc, pbScratch, cbScratch);
}

pub export fn SymCryptEcpointOnCurve(
    pCurve: PCSYMCRYPT_ECURVE,
    poSrc: PCSYMCRYPT_ECPOINT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) UINT32 {
    return dispatchEntry(pCurve).onCurveFunc.?(pCurve, poSrc, pbScratch, cbScratch);
}

pub export fn SymCryptEcpointAdd(
    pCurve: PCSYMCRYPT_ECURVE,
    poSrc1: PCSYMCRYPT_ECPOINT,
    poSrc2: PCSYMCRYPT_ECPOINT,
    poDst: PSYMCRYPT_ECPOINT,
    flags: UINT32,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    dispatchEntry(pCurve).addFunc.?(pCurve, poSrc1, poSrc2, poDst, flags, pbScratch, cbScratch);
}

pub export fn SymCryptEcpointAddDiffNonZero(
    pCurve: PCSYMCRYPT_ECURVE,
    poSrc1: PCSYMCRYPT_ECPOINT,
    poSrc2: PCSYMCRYPT_ECPOINT,
    poDst: PSYMCRYPT_ECPOINT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    dispatchEntry(pCurve).addDiffFunc.?(pCurve, poSrc1, poSrc2, poDst, pbScratch, cbScratch);
}

pub export fn SymCryptEcpointDouble(
    pCurve: PCSYMCRYPT_ECURVE,
    poSrc: PCSYMCRYPT_ECPOINT,
    poDst: PSYMCRYPT_ECPOINT,
    flags: UINT32,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    dispatchEntry(pCurve).doubleFunc.?(pCurve, poSrc, poDst, flags, pbScratch, cbScratch);
}

pub export fn SymCryptEcpointNegate(
    pCurve: PCSYMCRYPT_ECURVE,
    poSrc: PSYMCRYPT_ECPOINT,
    mask: UINT32,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    dispatchEntry(pCurve).negateFunc.?(pCurve, poSrc, mask, pbScratch, cbScratch);
}

pub export fn SymCryptEcpointScalarMul(
    pCurve: PCSYMCRYPT_ECURVE,
    piScalar: PCSYMCRYPT_INT,
    poSrc: ?PCSYMCRYPT_ECPOINT,
    flags: UINT32,
    poDst: PSYMCRYPT_ECPOINT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    return dispatchEntry(pCurve).scalarMulFunc.?(pCurve, piScalar, poSrc, flags, poDst, pbScratch, cbScratch);
}

pub export fn SymCryptEcpointMultiScalarMul(
    pCurve: PCSYMCRYPT_ECURVE,
    piTableScalars: [*]const PCSYMCRYPT_INT,
    poTablePoints: [*]const ?PCSYMCRYPT_ECPOINT,
    nPoints: UINT32,
    flags: UINT32,
    poDst: PSYMCRYPT_ECPOINT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    return dispatchEntry(pCurve).multiScalarMulFunc.?(pCurve, piTableScalars, poTablePoints, nPoints, flags, poDst, pbScratch, cbScratch);
}

pub export fn SymCryptEcurveFillScratchSpaces(
    pCurve: PSYMCRYPT_ECURVE,
) callconv(SYMCRYPT_CALL) void {
    dispatchEntry(pCurve).fillScratchSpacesFunc.?(pCurve);
}
