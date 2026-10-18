//
// ieee802_11_sae_custom.zig  Implementation of the custom crypto of IEEE 802.11 SAE
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

const std = @import("std");
const types = @import("types.zig");
const macros = @import("macros.zig");
const a_dispatch = @import("a_dispatch.zig");
const hmac = @import("hmac.zig");
const hkdf = @import("hkdf.zig");

const SYMCRYPT_CALL = types.SYMCRYPT_CALL;
const SYMCRYPT_ERROR = types.SYMCRYPT_ERROR;
const SYMCRYPT_NUMBER_FORMAT = types.SYMCRYPT_NUMBER_FORMAT;
const SYMCRYPT_ECPOINT_FORMAT = types.SYMCRYPT_ECPOINT_FORMAT;
const SYMCRYPT_802_11_SAE_GROUP = types.SYMCRYPT_802_11_SAE_GROUP;
const SYMCRYPT_802_11_SAE_CUSTOM_STATE = types.SYMCRYPT_802_11_SAE_CUSTOM_STATE;
const PSYMCRYPT_802_11_SAE_CUSTOM_STATE = types.PSYMCRYPT_802_11_SAE_CUSTOM_STATE;
const PCSYMCRYPT_802_11_SAE_CUSTOM_STATE = types.PCSYMCRYPT_802_11_SAE_CUSTOM_STATE;
const BYTE = types.BYTE;
const PBYTE = types.PBYTE;
const PCBYTE = types.PCBYTE;
const UINT32 = types.UINT32;
const PUINT32 = types.PUINT32;
const UINT64 = types.UINT64;
const SIZE_T = types.SIZE_T;
const PVOID = types.PVOID;
const PSYMCRYPT_INT = types.PSYMCRYPT_INT;
const PCSYMCRYPT_INT = types.PCSYMCRYPT_INT;
const PSYMCRYPT_MODULUS = types.PSYMCRYPT_MODULUS;
const PCSYMCRYPT_MODULUS = types.PCSYMCRYPT_MODULUS;
const PSYMCRYPT_MODELEMENT = types.PSYMCRYPT_MODELEMENT;
const PCSYMCRYPT_MODELEMENT = types.PCSYMCRYPT_MODELEMENT;
const PSYMCRYPT_ECURVE = types.PSYMCRYPT_ECURVE;
const PCSYMCRYPT_ECURVE = types.PCSYMCRYPT_ECURVE;
const PCSYMCRYPT_ECURVE_PARAMS = types.PCSYMCRYPT_ECURVE_PARAMS;
const PSYMCRYPT_ECPOINT = types.PSYMCRYPT_ECPOINT;
const PCSYMCRYPT_ECPOINT = types.PCSYMCRYPT_ECPOINT;
const PCSYMCRYPT_MAC = types.PCSYMCRYPT_MAC;
const SYMCRYPT_MAC_EXPANDED_KEY = hkdf.SYMCRYPT_MAC_EXPANDED_KEY;
const SYMCRYPT_MAC_STATE = hkdf.SYMCRYPT_MAC_STATE;
const SYMCRYPT_HKDF_EXPANDED_KEY = hkdf.SYMCRYPT_HKDF_EXPANDED_KEY;
const SYMCRYPT_HMAC_SHA256_EXPANDED_KEY = hmac.SYMCRYPT_HMAC_SHA256_EXPANDED_KEY;
const SYMCRYPT_HMAC_SHA256_STATE = hmac.SYMCRYPT_HMAC_SHA256_STATE;

extern fn SymCryptCallbackAlloc(nBytes: SIZE_T) callconv(SYMCRYPT_CALL) ?PBYTE;
extern fn SymCryptCallbackFree(pMem: PVOID) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptWipe(pbData: PVOID, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void;

extern const SymCryptEcurveParamsNistP256: PCSYMCRYPT_ECURVE_PARAMS;
extern const SymCryptEcurveParamsNistP384: PCSYMCRYPT_ECURVE_PARAMS;

extern fn SymCryptEcurveAllocate(
    pParams: PCSYMCRYPT_ECURVE_PARAMS,
    flags: UINT32,
) callconv(SYMCRYPT_CALL) ?PSYMCRYPT_ECURVE;

extern fn SymCryptEcurveFree(
    pCurve: PSYMCRYPT_ECURVE,
) callconv(SYMCRYPT_CALL) void;

extern fn SymCryptEcurveDigitsofScalarMultiplier(
    pCurve: PCSYMCRYPT_ECURVE,
) callconv(SYMCRYPT_CALL) UINT32;

extern fn SymCryptEcurveDigitsofFieldElement(
    pCurve: PCSYMCRYPT_ECURVE,
) callconv(SYMCRYPT_CALL) UINT32;

extern fn SymCryptEcpointAllocate(
    pCurve: PCSYMCRYPT_ECURVE,
) callconv(SYMCRYPT_CALL) ?PSYMCRYPT_ECPOINT;

extern fn SymCryptEcpointFree(
    pCurve: PCSYMCRYPT_ECURVE,
    poDst: PSYMCRYPT_ECPOINT,
) callconv(SYMCRYPT_CALL) void;

extern fn SymCryptEcpointMaskedCopy(
    pCurve: PCSYMCRYPT_ECURVE,
    poSrc: PCSYMCRYPT_ECPOINT,
    poDst: PSYMCRYPT_ECPOINT,
    mask: UINT32,
) callconv(.c) void;

extern fn SymCryptEcpointOnCurve(
    pCurve: PCSYMCRYPT_ECURVE,
    poSrc: PCSYMCRYPT_ECPOINT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) UINT32;

extern fn SymCryptEcpointSetValue(
    pCurve: PCSYMCRYPT_ECURVE,
    pbSrc: PCBYTE,
    cbSrc: SIZE_T,
    numFormat: SYMCRYPT_NUMBER_FORMAT,
    ecpointFormat: SYMCRYPT_ECPOINT_FORMAT,
    poDst: PSYMCRYPT_ECPOINT,
    flags: UINT32,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;

extern fn SymCryptEcpointGetValue(
    pCurve: PCSYMCRYPT_ECURVE,
    poSrc: PCSYMCRYPT_ECPOINT,
    numFormat: SYMCRYPT_NUMBER_FORMAT,
    ecpointFormat: SYMCRYPT_ECPOINT_FORMAT,
    pbDst: PBYTE,
    cbDst: SIZE_T,
    flags: UINT32,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;

extern fn SymCryptEcpointIsZero(
    pCurve: PCSYMCRYPT_ECURVE,
    poSrc: PCSYMCRYPT_ECPOINT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) UINT32;

extern fn SymCryptEcpointAdd(
    pCurve: PCSYMCRYPT_ECURVE,
    poSrc1: PCSYMCRYPT_ECPOINT,
    poSrc2: PCSYMCRYPT_ECPOINT,
    poDst: PSYMCRYPT_ECPOINT,
    flags: UINT32,
    pbScratch: ?PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void;

extern fn SymCryptEcpointNegate(
    pCurve: PCSYMCRYPT_ECURVE,
    poSrc: PSYMCRYPT_ECPOINT,
    mask: UINT32,
    pbScratch: ?PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void;

extern fn SymCryptEcpointScalarMul(
    pCurve: PCSYMCRYPT_ECURVE,
    piScalar: PCSYMCRYPT_INT,
    poSrc: ?PCSYMCRYPT_ECPOINT,
    flags: UINT32,
    poDst: PSYMCRYPT_ECPOINT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;

// Used in SAE Hunting and Pecking methods where NIST P256 is hardcoded
const PRIME_LENGTH_BITS: UINT32 = 256;

const SYMCRYPT_SAE_GROUP_DATA = struct {
    group: SYMCRYPT_802_11_SAE_GROUP,
    pCurveParams: PCSYMCRYPT_ECURVE_PARAMS,
    macAlgorithm: PCSYMCRYPT_MAC,
    z: i32,
};

fn SymCryptSaeFindGroupData(ianaGroup: SYMCRYPT_802_11_SAE_GROUP) ?SYMCRYPT_SAE_GROUP_DATA {
    return switch (ianaGroup) {
        .SYMCRYPT_SAE_GROUP_19 => .{
            .group = .SYMCRYPT_SAE_GROUP_19,
            .pCurveParams = SymCryptEcurveParamsNistP256,
            .macAlgorithm = hmac.SymCryptHmacSha256Algorithm,
            .z = -10,
        },
        .SYMCRYPT_SAE_GROUP_20 => .{
            .group = .SYMCRYPT_SAE_GROUP_20,
            .pCurveParams = SymCryptEcurveParamsNistP384,
            .macAlgorithm = hmac.SymCryptHmacSha384Algorithm,
            .z = -12,
        },
        else => null,
    };
}

pub export fn SymCrypt802_11SaeGetGroupSizes(
    group: SYMCRYPT_802_11_SAE_GROUP,
    pcbScalar: ?*SIZE_T,
    pcbPoint: ?*SIZE_T,
) callconv(.c) void {
    var cbScalar: SIZE_T = 0;
    var cbPoint: SIZE_T = 0;

    if (SymCryptSaeFindGroupData(group)) |groupData| {
        cbScalar = groupData.pCurveParams.cbFieldLength;
        cbPoint = 2 * cbScalar;
    }

    if (pcbScalar) |p| {
        p.* = cbScalar;
    }

    if (pcbPoint) |p| {
        p.* = cbPoint;
    }
}

pub export fn SymCryptModSqrt(
    pmMod: PSYMCRYPT_MODULUS,
    peVal: PSYMCRYPT_MODELEMENT,
    puIsQuadraticResidue: *UINT32,
    peSqrtArg: ?PSYMCRYPT_MODELEMENT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(.c) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;

    const piTmp = a_dispatch.SymCryptIntAllocate(a_dispatch.SymCryptDigitsFromBits(pmMod.Divisor.nBits));
    const peSqrt = a_dispatch.SymCryptModElementAllocate(pmMod);
    const peTmp = a_dispatch.SymCryptModElementAllocate(pmMod);
    defer {
        if (piTmp) |p| a_dispatch.SymCryptIntFree(p);
        if (peSqrt) |p| a_dispatch.SymCryptModElementFree(pmMod, p);
        if (peTmp) |p| a_dispatch.SymCryptModElementFree(pmMod, p);
    }

    if (piTmp == null or peSqrt == null or peTmp == null) {
        scError = .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
        return scError;
    }

    // Sqrt( v ) = v^{(P+1)/4} mod P when P = 3 mod 4 as it is here
    a_dispatch.SymCryptIntCopy(a_dispatch.SymCryptIntFromModulus(pmMod), piTmp.?);
    _ = a_dispatch.SymCryptIntAddUint32(piTmp.?, 1, piTmp.?); // No overflow as our prime is not 2^256 - 1

    macros.SYMCRYPT_ASSERT((a_dispatch.SymCryptIntGetValueLsbits32(piTmp.?) & 3) == 0);
    a_dispatch.SymCryptIntDivPow2(piTmp.?, 2, piTmp.?);
    // iX = (P+1)/4

    // Compute Sqrt( v ) if it exists
    a_dispatch.SymCryptModExp(pmMod, peVal, piTmp.?, pmMod.Divisor.nBits - 2, 0, peSqrt.?, pbScratch, cbScratch);

    a_dispatch.SymCryptModSquare(pmMod, peSqrt.?, peTmp.?, pbScratch, cbScratch);
    puIsQuadraticResidue.* = a_dispatch.SymCryptModElementIsEqual(pmMod, peTmp.?, peVal);

    if (peSqrtArg) |pSqrtArg| {
        a_dispatch.SymCryptModElementCopy(pmMod, peSqrt.?, pSqrtArg);
    }

    return scError;
}

pub export fn SymCryptSswu(
    pCurve: PSYMCRYPT_ECURVE,
    z: i32,
    peU: PSYMCRYPT_MODELEMENT,
    poP: PSYMCRYPT_ECPOINT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(.c) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;
    var selectionMask: UINT32 = 0;

    var pointBuf: [types.SYMCRYPT_SAE_MAX_EC_POINT_SIZE_BYTES]BYTE = @splat(0);
    defer SymCryptWipe(@ptrCast(&pointBuf), @sizeOf(@TypeOf(pointBuf)));

    macros.SYMCRYPT_ASSERT(z < 0);

    const piTmp = a_dispatch.SymCryptIntAllocate(a_dispatch.SymCryptDigitsFromBits(pCurve.FModBitsize));
    const peTmp = a_dispatch.SymCryptModElementAllocate(pCurve.FMod);
    const peZ = a_dispatch.SymCryptModElementAllocate(pCurve.FMod);
    const peM = a_dispatch.SymCryptModElementAllocate(pCurve.FMod);
    const peT = a_dispatch.SymCryptModElementAllocate(pCurve.FMod);
    const peX1 = a_dispatch.SymCryptModElementAllocate(pCurve.FMod);
    const peX2 = a_dispatch.SymCryptModElementAllocate(pCurve.FMod);
    const peGX1 = a_dispatch.SymCryptModElementAllocate(pCurve.FMod);
    const peGX2 = a_dispatch.SymCryptModElementAllocate(pCurve.FMod);
    defer {
        if (peGX2) |p| a_dispatch.SymCryptModElementFree(pCurve.FMod, p);
        if (peGX1) |p| a_dispatch.SymCryptModElementFree(pCurve.FMod, p);
        if (peX2) |p| a_dispatch.SymCryptModElementFree(pCurve.FMod, p);
        if (peX1) |p| a_dispatch.SymCryptModElementFree(pCurve.FMod, p);
        if (peT) |p| a_dispatch.SymCryptModElementFree(pCurve.FMod, p);
        if (peM) |p| a_dispatch.SymCryptModElementFree(pCurve.FMod, p);
        if (peZ) |p| a_dispatch.SymCryptModElementFree(pCurve.FMod, p);
        if (peTmp) |p| a_dispatch.SymCryptModElementFree(pCurve.FMod, p);
        if (piTmp) |p| a_dispatch.SymCryptIntFree(p);
    }

    if (piTmp == null or peTmp == null or peZ == null or peM == null or peT == null or
        peX1 == null or peX2 == null or peGX1 == null or peGX2 == null)
    {
        return .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
    }

    // Convert z to mod element
    a_dispatch.SymCryptModElementSetValueNegUint32(@intCast(-z), pCurve.FMod, peZ.?, pbScratch, cbScratch);

    // Set peTmp to 1 for convenience later
    a_dispatch.SymCryptModElementSetValueUint32(1, pCurve.FMod, peTmp.?, pbScratch, cbScratch);

    // m = ( z^2 * u^4 + z * u^2 ) = (z * u^2)(z * u^2 + 1) modulo p
    a_dispatch.SymCryptModSquare(pCurve.FMod, peU, peM.?, pbScratch, cbScratch); // M = u^2
    a_dispatch.SymCryptModMul(pCurve.FMod, peM.?, peZ.?, peM.?, pbScratch, cbScratch); // M = z * u^2
    a_dispatch.SymCryptModAdd(pCurve.FMod, peM.?, peTmp.?, peTmp.?, pbScratch, cbScratch); // tmp = (z * u^2 + 1)
    a_dispatch.SymCryptModMul(pCurve.FMod, peM.?, peTmp.?, peM.?, pbScratch, cbScratch); // M = M * tmp = (z * u^2)(z * u^2 + 1)

    // l = CEQ( m, 0 )
    selectionMask = a_dispatch.SymCryptModElementIsZero(pCurve.FMod, peM.?);

    // t = inverse( m ) where inverse ( m ) = m^( p-2 ) modulo p
    _ = a_dispatch.SymCryptIntSubUint32(a_dispatch.SymCryptIntFromModulus(pCurve.FMod), 2, piTmp.?);
    a_dispatch.SymCryptModExp(pCurve.FMod, peM.?, piTmp.?, pCurve.FModBitsize, 0, peT.?, pbScratch, cbScratch);

    // x1 = CSEL( l, ( b / ( z * a ) modulo p ), ( ( - b / a ) * ( 1 + t ) ) modulo p )
    a_dispatch.SymCryptModMul(pCurve.FMod, peZ.?, pCurve.A, peTmp.?, pbScratch, cbScratch); // tmp = z * a
    _ = a_dispatch.SymCryptModInv(pCurve.FMod, peTmp.?, peTmp.?, types.SYMCRYPT_FLAG_DATA_PUBLIC | types.SYMCRYPT_FLAG_MODULUS_PRIME, pbScratch, cbScratch); // tmp = 1/(z * a)
    a_dispatch.SymCryptModMul(pCurve.FMod, pCurve.B, peTmp.?, peX1.?, pbScratch, cbScratch); // x1A = B * 1/(z * a)

    _ = a_dispatch.SymCryptModInv(pCurve.FMod, pCurve.A, peTmp.?, types.SYMCRYPT_FLAG_DATA_PUBLIC | types.SYMCRYPT_FLAG_MODULUS_PRIME, pbScratch, cbScratch); // tmp = 1/a
    a_dispatch.SymCryptModMul(pCurve.FMod, pCurve.B, peTmp.?, peTmp.?, pbScratch, cbScratch); // tmp = b * 1/a
    a_dispatch.SymCryptModNeg(pCurve.FMod, peTmp.?, peTmp.?, pbScratch, cbScratch); // tmp = -(b * 1/a)

    a_dispatch.SymCryptIntSetValueUint32(1, piTmp.?);
    a_dispatch.SymCryptIntToModElement(piTmp.?, pCurve.FMod, peX2.?, pbScratch, cbScratch); // X1B = 1
    a_dispatch.SymCryptModAdd(pCurve.FMod, peX2.?, peT.?, peX2.?, pbScratch, cbScratch); // X1B = 1 + t
    a_dispatch.SymCryptModMul(pCurve.FMod, peX2.?, peTmp.?, peX2.?, pbScratch, cbScratch); // X1B = -(b * 1/a)(1 + t)

    a_dispatch.SymCryptModElementMaskedCopy(pCurve.FMod, peX2.?, peX1.?, ~selectionMask);

    // gx1 = ( x1^3 + a * x1 + b ) = (x1^2 + a)*x1 + b modulo p
    a_dispatch.SymCryptModSquare(pCurve.FMod, peX1.?, peGX1.?, pbScratch, cbScratch); // gx1 = x1^2
    a_dispatch.SymCryptModAdd(pCurve.FMod, peGX1.?, pCurve.A, peGX1.?, pbScratch, cbScratch); // gx1 = x1^2 + a
    a_dispatch.SymCryptModMul(pCurve.FMod, peGX1.?, peX1.?, peGX1.?, pbScratch, cbScratch); // gx1 = (x1^2 + a)*x1
    a_dispatch.SymCryptModAdd(pCurve.FMod, peGX1.?, pCurve.B, peGX1.?, pbScratch, cbScratch); // gx1 = (x1^2 + a)*x1 + b

    // x2 = ( z * u^2 * x1 ) modulo p
    a_dispatch.SymCryptModSquare(pCurve.FMod, peU, peX2.?, pbScratch, cbScratch); // x2 = u^2
    a_dispatch.SymCryptModMul(pCurve.FMod, peX2.?, peZ.?, peX2.?, pbScratch, cbScratch); // x2 = u^2 * z
    a_dispatch.SymCryptModMul(pCurve.FMod, peX2.?, peX1.?, peX2.?, pbScratch, cbScratch); // x2 = u^2 * z * x1

    // gx2 = ( x2^3 + a * x2 + b ) = (x2^2 + a)*x2 + b modulo p
    a_dispatch.SymCryptModSquare(pCurve.FMod, peX2.?, peGX2.?, pbScratch, cbScratch); // gx2 = x2^2
    a_dispatch.SymCryptModAdd(pCurve.FMod, peGX2.?, pCurve.A, peGX2.?, pbScratch, cbScratch); // gx2 = x2^2 + a
    a_dispatch.SymCryptModMul(pCurve.FMod, peGX2.?, peX2.?, peGX2.?, pbScratch, cbScratch); // gx2 = (x2^2 + a)*x2
    a_dispatch.SymCryptModAdd(pCurve.FMod, peGX2.?, pCurve.B, peGX2.?, pbScratch, cbScratch); // gx2 = (x2^2 + a)*x2 + b

    // l = gx1 is a quadratic residue modulo p
    scError = SymCryptModSqrt(pCurve.FMod, peGX1.?, &selectionMask, null, pbScratch, cbScratch);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    // v = CSEL( l, gx1, gx2 )
    a_dispatch.SymCryptModElementMaskedCopy(pCurve.FMod, peGX2.?, peGX1.?, ~selectionMask);

    // x = CSEL( l, x1, x2 )
    a_dispatch.SymCryptModElementMaskedCopy(pCurve.FMod, peX2.?, peX1.?, ~selectionMask);

    // y = sqrt( v ) = v^{(P+1)/4}
    scError = SymCryptModSqrt(pCurve.FMod, peGX1.?, &selectionMask, peGX1.?, pbScratch, cbScratch);

    // l = CEQ( LSB( u ), LSB( y ) )
    a_dispatch.SymCryptModElementToInt(pCurve.FMod, peU, piTmp.?, pbScratch, cbScratch);
    const u: UINT32 = a_dispatch.SymCryptIntGetValueLsbits32(piTmp.?);

    a_dispatch.SymCryptModElementToInt(pCurve.FMod, peGX1.?, piTmp.?, pbScratch, cbScratch);
    const y: UINT32 = a_dispatch.SymCryptIntGetValueLsbits32(piTmp.?);

    selectionMask = macros.SYMCRYPT_MASK32_EQ(u & 1, y & 1);

    // P = CSEL( l, ( x, y ), ( x, p - y ) )
    a_dispatch.SymCryptModNeg(pCurve.FMod, peGX1.?, peTmp.?, pbScratch, cbScratch);
    a_dispatch.SymCryptModElementMaskedCopy(pCurve.FMod, peTmp.?, peGX1.?, ~selectionMask);

    _ = a_dispatch.SymCryptModElementGetValue(pCurve.FMod, peX1.?, pointBuf[0..].ptr, pCurve.FModBytesize, .SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, pbScratch, cbScratch);
    _ = a_dispatch.SymCryptModElementGetValue(pCurve.FMod, peGX1.?, pointBuf[pCurve.FModBytesize..].ptr, pCurve.FModBytesize, .SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, pbScratch, cbScratch);

    scError = SymCryptEcpointSetValue(
        pCurve,
        pointBuf[0..].ptr,
        2 * @as(SIZE_T, pCurve.FModBytesize),
        .SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        .SYMCRYPT_ECPOINT_FORMAT_XY,
        poP,
        0,
        pbScratch,
        cbScratch,
    );
    return scError;
}

pub export fn SymCrypt802_11SaeCustomSetRandMask(
    pState: PSYMCRYPT_802_11_SAE_CUSTOM_STATE,
    pbRand: ?PBYTE,
    cbRand: SIZE_T,
    pbMask: ?PBYTE,
    cbMask: SIZE_T,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(.c) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;
    const pcCurve: PCSYMCRYPT_ECURVE = pState.pCurve.?;

    a_dispatch.SymCryptModElementSetValueUint32(0, pcCurve.GOrd, pState.peRand.?, pbScratch, cbScratch);
    if (pbRand) |randPtr| {
        scError = a_dispatch.SymCryptModElementSetValue(randPtr, cbRand, .SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, pcCurve.GOrd, pState.peRand.?, pbScratch, cbScratch);
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }
    }

    if (a_dispatch.SymCryptModElementIsZero(pcCurve.GOrd, pState.peRand.?) != 0) {
        a_dispatch.SymCryptModSetRandom(pcCurve.GOrd, pState.peRand.?, types.SYMCRYPT_FLAG_MODRANDOM_ALLOW_MINUSONE, pbScratch, cbScratch);
    }

    if (pbRand) |randPtr| {
        scError = a_dispatch.SymCryptModElementGetValue(pcCurve.GOrd, pState.peRand.?, randPtr, cbRand, .SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, pbScratch, cbScratch);
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }
    }

    a_dispatch.SymCryptModElementSetValueUint32(0, pcCurve.GOrd, pState.peMask.?, pbScratch, cbScratch);
    if (pbMask) |maskPtr| {
        scError = a_dispatch.SymCryptModElementSetValue(maskPtr, cbMask, .SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, pcCurve.GOrd, pState.peMask.?, pbScratch, cbScratch);
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }
    }

    if (a_dispatch.SymCryptModElementIsZero(pcCurve.GOrd, pState.peMask.?) != 0) {
        a_dispatch.SymCryptModSetRandom(pcCurve.GOrd, pState.peMask.?, types.SYMCRYPT_FLAG_MODRANDOM_ALLOW_MINUSONE, pbScratch, cbScratch);
    }

    if (pbMask) |maskPtr| {
        scError = a_dispatch.SymCryptModElementGetValue(pcCurve.GOrd, pState.peMask.?, maskPtr, cbMask, .SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, pbScratch, cbScratch);
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }
    }

    return scError;
}

pub export fn SymCrypt802_11SaeCustomInit(
    pState: PSYMCRYPT_802_11_SAE_CUSTOM_STATE,
    pbMac1: PCBYTE,
    pbMac2: PCBYTE,
    pbPassword: PCBYTE,
    cbPassword: SIZE_T,
    pbCounter: ?*BYTE,
    pbRand: ?PBYTE,
    pbMask: ?PBYTE,
) callconv(.c) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;
    var minMac: UINT64 = undefined;
    var maxMac: UINT64 = undefined;
    var macBuffer: [16]BYTE = @splat(0);
    var hmacKey: SYMCRYPT_HMAC_SHA256_EXPANDED_KEY = undefined;
    var hmacState: SYMCRYPT_HMAC_SHA256_STATE = undefined;
    var pwdSeed: [32]BYTE = @splat(0);
    var pwdValue: [32]BYTE = @splat(0);
    var pointBuf: [64]BYTE = @splat(0);
    defer {
        SymCryptWipe(@ptrCast(&hmacKey), @sizeOf(@TypeOf(hmacKey)));
        SymCryptWipe(@ptrCast(&hmacState), @sizeOf(@TypeOf(hmacState)));
        SymCryptWipe(@ptrCast(&pwdSeed), @sizeOf(@TypeOf(pwdSeed)));
        SymCryptWipe(@ptrCast(&pwdValue), @sizeOf(@TypeOf(pwdValue)));
        SymCryptWipe(@ptrCast(&pointBuf), @sizeOf(@TypeOf(pointBuf)));
    }

    var counter: BYTE = 0;
    var foundMask: UINT32 = 0;
    var solutionMask: UINT32 = undefined;

    var piTmp: ?PSYMCRYPT_INT = null;
    var peX: ?PSYMCRYPT_MODELEMENT = null;
    var peY: ?PSYMCRYPT_MODELEMENT = null;
    var peCubic: ?PSYMCRYPT_MODELEMENT = null;
    var peTmp: ?PSYMCRYPT_MODELEMENT = null;
    var poPWECandidate: ?PSYMCRYPT_ECPOINT = null;
    var pbScratch: ?PBYTE = null;
    var cbScratch: SIZE_T = 0;

    // Set state to 0 so that our pointers have valid values.
    SymCryptWipe(@ptrCast(pState), @sizeOf(SYMCRYPT_802_11_SAE_CUSTOM_STATE));

    var pCurve: ?PSYMCRYPT_ECURVE = null;

    defer {
        if (piTmp) |p| a_dispatch.SymCryptIntFree(p);
        if (peX) |p| a_dispatch.SymCryptModElementFree(pCurve.?.FMod, p);
        if (peY) |p| a_dispatch.SymCryptModElementFree(pCurve.?.FMod, p);
        if (peCubic) |p| a_dispatch.SymCryptModElementFree(pCurve.?.FMod, p);
        if (peTmp) |p| a_dispatch.SymCryptModElementFree(pCurve.?.FMod, p);
        if (poPWECandidate) |p| SymCryptEcpointFree(pCurve.?, p);
        if (scError != .SYMCRYPT_NO_ERROR) {
            SymCrypt802_11SaeCustomDestroy(pState);
        }
        if (pbScratch) |p| {
            SymCryptWipe(@ptrCast(p), cbScratch);
            SymCryptCallbackFree(@ptrCast(p));
        }
    }

    pCurve = SymCryptEcurveAllocate(SymCryptEcurveParamsNistP256, 0);
    if (pCurve == null) {
        scError = .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
        return scError;
    }

    pState.pCurve = pCurve;

    pState.peRand = a_dispatch.SymCryptModElementAllocate(pCurve.?.GOrd);
    if (pState.peRand == null) {
        scError = .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
        return scError;
    }

    pState.peMask = a_dispatch.SymCryptModElementAllocate(pCurve.?.GOrd);
    if (pState.peMask == null) {
        scError = .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
        return scError;
    }

    pState.poPWE = SymCryptEcpointAllocate(pCurve.?);
    if (pState.poPWE == null) {
        scError = .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
        return scError;
    }

    const nDigits: UINT32 = a_dispatch.SymCryptDigitsFromBits(PRIME_LENGTH_BITS);
    piTmp = a_dispatch.SymCryptIntAllocate(nDigits);
    peX = a_dispatch.SymCryptModElementAllocate(pCurve.?.FMod);
    peY = a_dispatch.SymCryptModElementAllocate(pCurve.?.FMod);
    peCubic = a_dispatch.SymCryptModElementAllocate(pCurve.?.FMod);
    peTmp = a_dispatch.SymCryptModElementAllocate(pCurve.?.FMod);
    poPWECandidate = SymCryptEcpointAllocate(pCurve.?);

    cbScratch = @max(
        types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(nDigits),
        @max(
            types.SYMCRYPT_SCRATCH_BYTES_FOR_MODEXP(nDigits),
            types.SYMCRYPT_SCRATCH_BYTES_FOR_GETSET_VALUE_ECURVE_OPERATIONS(pCurve.?),
        ),
    );
    pbScratch = SymCryptCallbackAlloc(cbScratch);

    if (piTmp == null or peX == null or peY == null or peCubic == null or peTmp == null or poPWECandidate == null or pbScratch == null) {
        scError = .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
        return scError;
    }

    @memcpy(macBuffer[0..6], pbMac1[0..6]);
    minMac = macros.SYMCRYPT_LOAD_MSBFIRST64(&macBuffer);
    @memcpy(macBuffer[0..6], pbMac2[0..6]);
    maxMac = macros.SYMCRYPT_LOAD_MSBFIRST64(&macBuffer);

    if (minMac > maxMac) {
        minMac ^= maxMac;
        maxMac ^= minMac;
        minMac ^= maxMac;
    }

    macros.SYMCRYPT_STORE_MSBFIRST64(&macBuffer, maxMac);
    macros.SYMCRYPT_STORE_MSBFIRST64(macBuffer[6..].ptr, minMac);

    _ = hmac.SymCryptHmacSha256ExpandKey(&hmacKey, macBuffer[0..].ptr, 12);

    const pbPrimeP: PCBYTE = @as([*]const BYTE, @ptrCast(SymCryptEcurveParamsNistP256)) + @sizeOf(types.SYMCRYPT_ECURVE_PARAMS);
    const kdfPrefix = "SAE Hunting and Pecking";
    var kdfConstant1: [2]BYTE = .{ 1, 0 };
    var kdfConstantPrimeLen: [2]BYTE = .{
        @truncate(PRIME_LENGTH_BITS & 0xff),
        @truncate(PRIME_LENGTH_BITS >> 8),
    };

    counter = 1;
    while (counter <= 40 or foundMask == 0) : (counter +%= 1) {
        hmac.SymCryptHmacSha256Init(&hmacState, &hmacKey);
        hmac.SymCryptHmacSha256Append(&hmacState, pbPassword, cbPassword);
        hmac.SymCryptHmacSha256Append(&hmacState, @ptrCast(&counter), 1);
        hmac.SymCryptHmacSha256Result(&hmacState, &pwdSeed);

        _ = hmac.SymCryptHmacSha256ExpandKey(&hmacKey, pwdSeed[0..].ptr, 32);
        hmac.SymCryptHmacSha256Init(&hmacState, &hmacKey);
        hmac.SymCryptHmacSha256Append(&hmacState, kdfConstant1[0..].ptr, 2);
        hmac.SymCryptHmacSha256Append(&hmacState, kdfPrefix.ptr, 23);
        hmac.SymCryptHmacSha256Append(&hmacState, pbPrimeP, 32);
        hmac.SymCryptHmacSha256Append(&hmacState, kdfConstantPrimeLen[0..].ptr, 2);
        hmac.SymCryptHmacSha256Result(&hmacState, &pwdValue);

        _ = hmac.SymCryptHmacSha256ExpandKey(&hmacKey, macBuffer[0..].ptr, 12);

        _ = a_dispatch.SymCryptIntSetValue(pwdValue[0..].ptr, 32, .SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, piTmp.?);

        solutionMask = a_dispatch.SymCryptIntIsLessThan(piTmp.?, a_dispatch.SymCryptIntFromModulus(pCurve.?.FMod));

        a_dispatch.SymCryptIntToModElement(piTmp.?, pCurve.?.FMod, peX.?, pbScratch.?, cbScratch);
        a_dispatch.SymCryptModSquare(pCurve.?.FMod, peX.?, peCubic.?, pbScratch.?, cbScratch);
        a_dispatch.SymCryptModAdd(pCurve.?.FMod, peCubic.?, pCurve.?.A, peCubic.?, pbScratch.?, cbScratch);
        a_dispatch.SymCryptModMul(pCurve.?.FMod, peCubic.?, peX.?, peCubic.?, pbScratch.?, cbScratch);
        a_dispatch.SymCryptModAdd(pCurve.?.FMod, peCubic.?, pCurve.?.B, peCubic.?, pbScratch.?, cbScratch);

        var isQuadraticResidue: UINT32 = 0;
        scError = SymCryptModSqrt(pCurve.?.FMod, peCubic.?, &isQuadraticResidue, peY.?, pbScratch.?, cbScratch);
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }
        solutionMask &= isQuadraticResidue;

        // If solutionMask is TRUE, we have found a valid X and Y.
        // Fix up the parity of Y to match the pwdSeed.
        a_dispatch.SymCryptModElementToInt(pCurve.?.FMod, peY.?, piTmp.?, pbScratch.?, cbScratch);
        a_dispatch.SymCryptModNeg(pCurve.?.FMod, peY.?, peTmp.?, pbScratch.?, cbScratch);
        a_dispatch.SymCryptModElementMaskedCopy(
            pCurve.?.FMod,
            peTmp.?,
            peY.?,
            0 -% ((a_dispatch.SymCryptIntGetValueLsbits32(piTmp.?) ^ pwdSeed[31]) & 1),
        );

        _ = a_dispatch.SymCryptModElementGetValue(pCurve.?.FMod, peX.?, pointBuf[0..].ptr, 32, .SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, pbScratch.?, cbScratch);
        _ = a_dispatch.SymCryptModElementGetValue(pCurve.?.FMod, peY.?, pointBuf[32..].ptr, 32, .SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, pbScratch.?, cbScratch);
        scError = SymCryptEcpointSetValue(
            pCurve.?,
            pointBuf[0..].ptr,
            64,
            .SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            .SYMCRYPT_ECPOINT_FORMAT_XY,
            poPWECandidate.?,
            0,
            pbScratch.?,
            cbScratch,
        );
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }

        // Only update the result with the first solution that we find
        solutionMask &= ~foundMask;
        foundMask |= solutionMask;

        if (pbCounter) |pCnt| {
            pCnt.* = @truncate((pCnt.* & ~solutionMask) | (counter & solutionMask));
        }

        SymCryptEcpointMaskedCopy(pCurve.?, poPWECandidate.?, pState.poPWE.?, solutionMask);
    }

    scError = SymCrypt802_11SaeCustomSetRandMask(pState, pbRand, 32, pbMask, 32, pbScratch.?, cbScratch);
    return scError;
}

pub export fn SymCrypt802_11SaeCustomCreatePTGeneric(
    group: SYMCRYPT_802_11_SAE_GROUP,
    pbSsid: PCBYTE,
    cbSsid: SIZE_T,
    pbPassword: PCBYTE,
    cbPassword: SIZE_T,
    pbPasswordIdentifier: ?PCBYTE,
    cbPasswordIdentifier: SIZE_T,
    pbPT: PBYTE,
    cbPT: SIZE_T,
) callconv(.c) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;
    var hkdfKey: SYMCRYPT_HKDF_EXPANDED_KEY = undefined;
    defer SymCryptWipe(@ptrCast(&hkdfKey), @sizeOf(@TypeOf(hkdfKey)));

    const pGroupData = SymCryptSaeFindGroupData(group) orelse return .SYMCRYPT_INVALID_ARGUMENT;

    const pCurve = SymCryptEcurveAllocate(pGroupData.pCurveParams, 0) orelse return .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
    defer SymCryptEcurveFree(pCurve);

    const pMacAlgorithm: PCSYMCRYPT_MAC = pGroupData.macAlgorithm;
    const nDigits: UINT32 = SymCryptEcurveDigitsofFieldElement(pCurve);

    const cbIkm: SIZE_T = cbPassword + cbPasswordIdentifier;
    const cbScratch: SIZE_T = @max(
        cbIkm,
        @max(
            types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(nDigits),
            @max(
                types.SYMCRYPT_SCRATCH_BYTES_FOR_MODEXP(nDigits),
                @max(
                    types.SYMCRYPT_SCRATCH_BYTES_FOR_GETSET_VALUE_ECURVE_OPERATIONS(pCurve),
                    types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_ECURVE_OPERATIONS(pCurve),
                ),
            ),
        ),
    );
    const pbScratch = SymCryptCallbackAlloc(cbScratch);
    defer if (pbScratch) |p| {
        SymCryptWipe(@ptrCast(p), cbScratch);
        SymCryptCallbackFree(@ptrCast(p));
    };

    // len = olen( p ) + floor( olen( p ) / 2 )
    const cbPwdValue: UINT32 = ((pCurve.FModBitsize + 7) / 8) + ((pCurve.FModBitsize + 7) / 8) / 2;
    const pbPwdValue = SymCryptCallbackAlloc(cbPwdValue);
    defer if (pbPwdValue) |p| {
        SymCryptWipe(@ptrCast(p), cbPwdValue);
        SymCryptCallbackFree(@ptrCast(p));
    };

    const piU1 = a_dispatch.SymCryptIntAllocate(a_dispatch.SymCryptDigitsFromBits(cbPwdValue * 8));
    const piU2 = a_dispatch.SymCryptIntAllocate(a_dispatch.SymCryptDigitsFromBits(cbPwdValue * 8));
    const peU1 = a_dispatch.SymCryptModElementAllocate(pCurve.FMod);
    const peU2 = a_dispatch.SymCryptModElementAllocate(pCurve.FMod);
    const poP1 = SymCryptEcpointAllocate(pCurve);
    const poP2 = SymCryptEcpointAllocate(pCurve);
    const poPT = SymCryptEcpointAllocate(pCurve);
    defer {
        if (poP2) |p| SymCryptEcpointFree(pCurve, p);
        if (poP1) |p| SymCryptEcpointFree(pCurve, p);
        if (poPT) |p| SymCryptEcpointFree(pCurve, p);
        if (peU2) |p| a_dispatch.SymCryptModElementFree(pCurve.FMod, p);
        if (peU1) |p| a_dispatch.SymCryptModElementFree(pCurve.FMod, p);
        if (piU2) |p| a_dispatch.SymCryptIntFree(p);
        if (piU1) |p| a_dispatch.SymCryptIntFree(p);
    }

    if (pbScratch == null or pbPwdValue == null or piU1 == null or piU2 == null or
        peU1 == null or peU2 == null or poP1 == null or poP2 == null or poPT == null)
    {
        return .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
    }

    // pwd-seed = HKDF-Extract( ssid, password [|| identifier] )
    @memcpy(pbScratch.?[0..cbPassword], pbPassword[0..cbPassword]);
    if (pbPasswordIdentifier) |idPtr| {
        @memcpy(pbScratch.?[cbPassword .. cbPassword + cbPasswordIdentifier], idPtr[0..cbPasswordIdentifier]);
    }

    scError = hkdf.SymCryptHkdfExpandKey(&hkdfKey, pMacAlgorithm, pbScratch.?, cbIkm, pbSsid, cbSsid);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    // pwd-value = HKDF-Expand( pwd-seed, "SAE Hash to Element u1 P1", len )
    scError = hkdf.SymCryptHkdfDerive(&hkdfKey, "SAE Hash to Element u1 P1".ptr, 25, pbPwdValue.?, cbPwdValue);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    // u1 = pwd-value modulo p
    scError = a_dispatch.SymCryptIntSetValue(pbPwdValue.?, cbPwdValue, .SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, piU1.?);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    a_dispatch.SymCryptIntToModElement(piU1.?, pCurve.FMod, peU1.?, pbScratch.?, cbScratch);

    // P1 = SSWU( u1 )
    _ = SymCryptSswu(pCurve, pGroupData.z, peU1.?, poP1.?, pbScratch.?, cbScratch);

    // pwd-value = HKDF-Expand( pwd-seed, "SAE Hash to Element u2 P2", len )
    scError = hkdf.SymCryptHkdfDerive(&hkdfKey, "SAE Hash to Element u2 P2".ptr, 25, pbPwdValue.?, cbPwdValue);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    // u2 = pwd-value modulo p
    scError = a_dispatch.SymCryptIntSetValue(pbPwdValue.?, cbPwdValue, .SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, piU2.?);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    a_dispatch.SymCryptIntToModElement(piU2.?, pCurve.FMod, peU2.?, pbScratch.?, cbScratch);

    // P2 = SSWU( u2 )
    scError = SymCryptSswu(pCurve, pGroupData.z, peU2.?, poP2.?, pbScratch.?, cbScratch);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    // PT = P1 + P2
    SymCryptEcpointAdd(pCurve, poP1.?, poP2.?, poPT.?, 0, pbScratch.?, cbScratch);

    scError = SymCryptEcpointGetValue(
        pCurve,
        poPT.?,
        .SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        .SYMCRYPT_ECPOINT_FORMAT_XY,
        pbPT,
        cbPT,
        0,
        pbScratch.?,
        cbScratch,
    );
    macros.SYMCRYPT_ASSERT(scError == .SYMCRYPT_NO_ERROR);

    return scError;
}

pub export fn SymCrypt802_11SaeCustomCreatePT(
    pbSsid: PCBYTE,
    cbSsid: SIZE_T,
    pbPassword: PCBYTE,
    cbPassword: SIZE_T,
    pbPasswordIdentifier: ?PCBYTE,
    cbPasswordIdentifier: SIZE_T,
    pbPT: PBYTE,
) callconv(.c) SYMCRYPT_ERROR {
    return SymCrypt802_11SaeCustomCreatePTGeneric(
        .SYMCRYPT_SAE_GROUP_19,
        pbSsid,
        cbSsid,
        pbPassword,
        cbPassword,
        pbPasswordIdentifier,
        cbPasswordIdentifier,
        pbPT,
        64,
    );
}

pub export fn SymCrypt802_11SaeCustomInitH2EGeneric(
    pState: PSYMCRYPT_802_11_SAE_CUSTOM_STATE,
    group: SYMCRYPT_802_11_SAE_GROUP,
    pbPT: PCBYTE,
    cbPT: SIZE_T,
    pbMacA: PCBYTE,
    pbMacB: PCBYTE,
    pbRand: ?PBYTE,
    cbRand: SIZE_T,
    pbMask: ?PBYTE,
    cbMask: SIZE_T,
) callconv(.c) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;

    var hmacKeyBytes: [types.SYMCRYPT_SAE_MAX_HMAC_OUTPUT_SIZE_BYTES]BYTE = @splat(0);
    var valBytes: [types.SYMCRYPT_SAE_MAX_HMAC_OUTPUT_SIZE_BYTES]BYTE = @splat(0);
    var macBuffer: [16]BYTE = @splat(0);
    var hmacKey: SYMCRYPT_MAC_EXPANDED_KEY = std.mem.zeroes(SYMCRYPT_MAC_EXPANDED_KEY);
    var hmacState: SYMCRYPT_MAC_STATE = std.mem.zeroes(SYMCRYPT_MAC_STATE);
    defer {
        SymCryptWipe(@ptrCast(&hmacKeyBytes), @sizeOf(@TypeOf(hmacKeyBytes)));
        SymCryptWipe(@ptrCast(&valBytes), @sizeOf(@TypeOf(valBytes)));
        SymCryptWipe(@ptrCast(&hmacKey), @sizeOf(@TypeOf(hmacKey)));
        SymCryptWipe(@ptrCast(&hmacState), @sizeOf(@TypeOf(hmacState)));
    }

    var cbScratch: SIZE_T = 0;
    var pbScratch: ?PBYTE = null;

    var minMac: UINT64 = 0;
    var maxMac: UINT64 = 0;

    var nDigits: UINT32 = 0;

    var piTmp: ?PSYMCRYPT_INT = null;
    var pmMod: ?PSYMCRYPT_MODULUS = null;
    var peVal: ?PSYMCRYPT_MODELEMENT = null;
    var peTmp: ?PSYMCRYPT_MODELEMENT = null;
    var poPT: ?PSYMCRYPT_ECPOINT = null;
    var pCurve: ?PSYMCRYPT_ECURVE = null;

    SymCryptWipe(@ptrCast(pState), @sizeOf(SYMCRYPT_802_11_SAE_CUSTOM_STATE));

    defer {
        if (peTmp) |p| a_dispatch.SymCryptModElementFree(pmMod.?, p);
        if (peVal) |p| a_dispatch.SymCryptModElementFree(pmMod.?, p);
        if (poPT) |p| SymCryptEcpointFree(pCurve.?, p);
        if (pmMod) |p| a_dispatch.SymCryptModulusFree(p);
        if (piTmp) |p| a_dispatch.SymCryptIntFree(p);
        if (pbScratch) |p| {
            SymCryptWipe(@ptrCast(p), cbScratch);
            SymCryptCallbackFree(@ptrCast(p));
        }
        if (scError != .SYMCRYPT_NO_ERROR) {
            SymCrypt802_11SaeCustomDestroy(pState);
        }
    }

    const pGroupData = SymCryptSaeFindGroupData(group) orelse {
        scError = .SYMCRYPT_INVALID_ARGUMENT;
        return scError;
    };

    pCurve = SymCryptEcurveAllocate(pGroupData.pCurveParams, 0);
    if (pCurve == null) {
        scError = .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
        return scError;
    }

    pState.pCurve = pCurve;

    const pMacAlgorithm: PCSYMCRYPT_MAC = pGroupData.macAlgorithm;
    const cbHMACOutputSize: SIZE_T = pMacAlgorithm.resultSize;

    pState.peRand = a_dispatch.SymCryptModElementAllocate(pCurve.?.GOrd);
    if (pState.peRand == null) {
        scError = .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
        return scError;
    }

    pState.peMask = a_dispatch.SymCryptModElementAllocate(pCurve.?.GOrd);
    if (pState.peMask == null) {
        scError = .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
        return scError;
    }

    pState.poPWE = SymCryptEcpointAllocate(pCurve.?);
    if (pState.poPWE == null) {
        scError = .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
        return scError;
    }

    nDigits = a_dispatch.SymCryptDigitsFromBits(pCurve.?.GOrdBitsize);

    piTmp = a_dispatch.SymCryptIntAllocate(nDigits);
    pmMod = a_dispatch.SymCryptModulusAllocate(nDigits);
    poPT = SymCryptEcpointAllocate(pCurve.?);

    cbScratch = @max(
        types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(nDigits),
        @max(
            types.SYMCRYPT_SCRATCH_BYTES_FOR_GETSET_VALUE_ECURVE_OPERATIONS(pCurve.?),
            @max(
                types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_ECURVE_OPERATIONS(pCurve.?),
                types.SYMCRYPT_SCRATCH_BYTES_FOR_SCALAR_ECURVE_OPERATIONS(pCurve.?, 1),
            ),
        ),
    );
    pbScratch = SymCryptCallbackAlloc(cbScratch);

    if (piTmp == null or pmMod == null or poPT == null or pbScratch == null) {
        scError = .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
        return scError;
    }

    @memcpy(macBuffer[0..6], pbMacA[0..6]);
    minMac = macros.SYMCRYPT_LOAD_MSBFIRST64(&macBuffer);
    @memcpy(macBuffer[0..6], pbMacB[0..6]);
    maxMac = macros.SYMCRYPT_LOAD_MSBFIRST64(&macBuffer);

    if (minMac > maxMac) {
        minMac ^= maxMac;
        maxMac ^= minMac;
        minMac ^= maxMac;
    }

    macros.SYMCRYPT_STORE_MSBFIRST64(&macBuffer, maxMac);
    macros.SYMCRYPT_STORE_MSBFIRST64(macBuffer[6..].ptr, minMac);

    _ = pMacAlgorithm.expandKeyFunc.?(@ptrCast(&hmacKey), hmacKeyBytes[0..].ptr, cbHMACOutputSize);
    pMacAlgorithm.initFunc.?(@ptrCast(&hmacState), @ptrCast(&hmacKey));
    pMacAlgorithm.appendFunc.?(@ptrCast(&hmacState), macBuffer[0..].ptr, 12);
    pMacAlgorithm.resultFunc.?(@ptrCast(&hmacState), @ptrCast(valBytes[0..].ptr));

    _ = a_dispatch.SymCryptIntSubUint32(a_dispatch.SymCryptIntFromModulus(pCurve.?.GOrd), 1, piTmp.?);
    a_dispatch.SymCryptIntToModulus(piTmp.?, pmMod.?, 1, types.SYMCRYPT_FLAG_DATA_PUBLIC, pbScratch.?, cbScratch);

    peVal = a_dispatch.SymCryptModElementAllocate(pmMod.?);
    peTmp = a_dispatch.SymCryptModElementAllocate(pmMod.?);

    if (peVal == null or peTmp == null) {
        scError = .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
        return scError;
    }

    scError = a_dispatch.SymCryptModElementSetValue(valBytes[0..].ptr, cbHMACOutputSize, .SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, pmMod.?, peVal.?, pbScratch.?, cbScratch);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    a_dispatch.SymCryptModElementSetValueUint32(1, pmMod.?, peTmp.?, pbScratch.?, cbScratch);
    a_dispatch.SymCryptModAdd(pmMod.?, peVal.?, peTmp.?, peVal.?, pbScratch.?, cbScratch);

    a_dispatch.SymCryptModElementToInt(pmMod.?, peVal.?, piTmp.?, pbScratch.?, cbScratch);

    scError = SymCryptEcpointSetValue(
        pCurve.?,
        pbPT,
        cbPT,
        .SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        .SYMCRYPT_ECPOINT_FORMAT_XY,
        poPT.?,
        0,
        pbScratch.?,
        cbScratch,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    scError = SymCryptEcpointScalarMul(pCurve.?, piTmp.?, poPT.?, 0, pState.poPWE.?, pbScratch.?, cbScratch);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    scError = SymCrypt802_11SaeCustomSetRandMask(pState, pbRand, cbRand, pbMask, cbMask, pbScratch.?, cbScratch);
    return scError;
}

pub export fn SymCrypt802_11SaeCustomInitH2E(
    pState: PSYMCRYPT_802_11_SAE_CUSTOM_STATE,
    pbPT: PCBYTE,
    pbMacA: PCBYTE,
    pbMacB: PCBYTE,
    pbRand: ?PBYTE,
    pbMask: ?PBYTE,
) callconv(.c) SYMCRYPT_ERROR {
    return SymCrypt802_11SaeCustomInitH2EGeneric(
        pState,
        .SYMCRYPT_SAE_GROUP_19,
        pbPT,
        64,
        pbMacA,
        pbMacB,
        pbRand,
        32,
        pbMask,
        32,
    );
}

pub export fn SymCrypt802_11SaeCustomDestroy(
    pState: PSYMCRYPT_802_11_SAE_CUSTOM_STATE,
) callconv(.c) void {
    const pCurve = pState.pCurve;

    if (pState.poPWE) |poPWE| {
        SymCryptEcpointFree(pCurve.?, poPWE);
    }

    if (pState.peMask) |peMask| {
        a_dispatch.SymCryptModElementFree(pCurve.?.GOrd, peMask);
    }

    if (pState.peRand) |peRand| {
        a_dispatch.SymCryptModElementFree(pCurve.?.GOrd, peRand);
    }

    if (pCurve) |c| {
        SymCryptEcurveFree(c);
    }

    SymCryptWipe(@ptrCast(pState), @sizeOf(SYMCRYPT_802_11_SAE_CUSTOM_STATE));
}

pub export fn SymCrypt802_11SaeCustomCommitCreateGeneric(
    pState: PCSYMCRYPT_802_11_SAE_CUSTOM_STATE,
    pbCommitScalar: PBYTE,
    cbCommitScalar: SIZE_T,
    pbCommitElement: PBYTE,
    cbCommitElement: SIZE_T,
) callconv(.c) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;

    const pCurve: PCSYMCRYPT_ECURVE = pState.pCurve.?;

    const nDigits: UINT32 = a_dispatch.SymCryptDigitsFromBits(pCurve.FModBitsize);
    const cbScratch: SIZE_T = @max(
        types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(nDigits),
        @max(
            types.SYMCRYPT_SCRATCH_BYTES_FOR_SCALAR_ECURVE_OPERATIONS(pCurve, 1),
            types.SYMCRYPT_SCRATCH_BYTES_FOR_GETSET_VALUE_ECURVE_OPERATIONS(pCurve),
        ),
    );

    const pbScratch = SymCryptCallbackAlloc(cbScratch);
    const peTmp = a_dispatch.SymCryptModElementAllocate(pCurve.GOrd);
    const piTmp = a_dispatch.SymCryptIntAllocate(SymCryptEcurveDigitsofScalarMultiplier(pCurve));
    const poPoint = SymCryptEcpointAllocate(pCurve);
    defer {
        if (piTmp) |p| a_dispatch.SymCryptIntFree(p);
        if (peTmp) |p| a_dispatch.SymCryptModElementFree(pCurve.GOrd, p);
        if (poPoint) |p| SymCryptEcpointFree(pCurve, p);
        if (pbScratch) |p| {
            SymCryptWipe(@ptrCast(p), cbScratch);
            SymCryptCallbackFree(@ptrCast(p));
        }
    }

    if (peTmp == null or piTmp == null or poPoint == null or pbScratch == null) {
        return .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
    }

    a_dispatch.SymCryptModAdd(pCurve.GOrd, pState.peRand.?, pState.peMask.?, peTmp.?, pbScratch.?, cbScratch);
    scError = a_dispatch.SymCryptModElementGetValue(pCurve.GOrd, peTmp.?, pbCommitScalar, cbCommitScalar, .SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, pbScratch.?, cbScratch);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    a_dispatch.SymCryptModElementToInt(pCurve.GOrd, pState.peMask.?, piTmp.?, pbScratch.?, cbScratch);
    scError = SymCryptEcpointScalarMul(
        pCurve,
        piTmp.?,
        pState.poPWE.?,
        0,
        poPoint.?,
        pbScratch.?,
        cbScratch,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    // Now we have mask * PWE, but we need the negative...
    SymCryptEcpointNegate(pCurve, poPoint.?, 0xFFFFFFFF, pbScratch.?, cbScratch);

    scError = SymCryptEcpointGetValue(
        pCurve,
        poPoint.?,
        .SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        .SYMCRYPT_ECPOINT_FORMAT_XY,
        pbCommitElement,
        cbCommitElement,
        0,
        pbScratch.?,
        cbScratch,
    );
    return scError;
}

pub export fn SymCrypt802_11SaeCustomCommitCreate(
    pState: PCSYMCRYPT_802_11_SAE_CUSTOM_STATE,
    pbCommitScalar: PBYTE,
    pbCommitElement: PBYTE,
) callconv(.c) SYMCRYPT_ERROR {
    return SymCrypt802_11SaeCustomCommitCreateGeneric(
        pState,
        pbCommitScalar,
        32,
        pbCommitElement,
        64,
    );
}

pub export fn SymCrypt802_11SaeCustomCommitProcessGeneric(
    pState: PCSYMCRYPT_802_11_SAE_CUSTOM_STATE,
    pbPeerCommitScalar: PCBYTE,
    cbPeerCommitScalar: SIZE_T,
    pbPeerCommitElement: PCBYTE,
    cbPeerCommitElement: SIZE_T,
    pbSharedSecret: PBYTE,
    cbSharedSecret: SIZE_T,
    pbScalarSum: PBYTE,
    cbScalarSum: SIZE_T,
) callconv(.c) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;

    const pCurve: PSYMCRYPT_ECURVE = pState.pCurve.?;
    const nDigits: UINT32 = a_dispatch.SymCryptDigitsFromBits(pCurve.FModBitsize);
    const cbScratch: SIZE_T = @max(
        types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(nDigits),
        @max(
            types.SYMCRYPT_SCRATCH_BYTES_FOR_SCALAR_ECURVE_OPERATIONS(pCurve, 1),
            @max(
                types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_ECURVE_OPERATIONS(pCurve),
                types.SYMCRYPT_SCRATCH_BYTES_FOR_GETSET_VALUE_ECURVE_OPERATIONS(pCurve),
            ),
        ),
    );
    const pbScratch = SymCryptCallbackAlloc(cbScratch);

    const peCommitScalarSum = a_dispatch.SymCryptModElementAllocate(pCurve.GOrd);
    const poPeerCommitElement = SymCryptEcpointAllocate(pCurve);
    const poTmp = SymCryptEcpointAllocate(pCurve);
    const piTmp = a_dispatch.SymCryptIntAllocate(SymCryptEcurveDigitsofScalarMultiplier(pCurve));
    defer {
        if (peCommitScalarSum) |p| a_dispatch.SymCryptModElementFree(pCurve.GOrd, p);
        if (poPeerCommitElement) |p| SymCryptEcpointFree(pCurve, p);
        if (poTmp) |p| SymCryptEcpointFree(pCurve, p);
        if (piTmp) |p| a_dispatch.SymCryptIntFree(p);
        if (pbScratch) |p| {
            SymCryptWipe(@ptrCast(p), cbScratch);
            SymCryptCallbackFree(@ptrCast(p));
        }
    }

    if (pbScratch == null or peCommitScalarSum == null or poPeerCommitElement == null or poTmp == null or piTmp == null) {
        return .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
    }

    // piTmp = peer commit value
    scError = a_dispatch.SymCryptIntSetValue(pbPeerCommitScalar, cbPeerCommitScalar, .SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, piTmp.?);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    // The Standard requires a check that the Peer commit value must be 1 < peer-commit < r where r is the group order.
    if (a_dispatch.SymCryptIntIsLessThan(piTmp.?, a_dispatch.SymCryptIntFromModulus(pCurve.GOrd)) == 0 or
        a_dispatch.SymCryptIntIsEqualUint32(piTmp.?, 0) != 0 or
        a_dispatch.SymCryptIntIsEqualUint32(piTmp.?, 1) != 0)
    {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    a_dispatch.SymCryptIntToModElement(piTmp.?, pCurve.GOrd, peCommitScalarSum.?, pbScratch.?, cbScratch);

    // Now compute the sum of the scalar commit values
    a_dispatch.SymCryptModAdd(pCurve.GOrd, peCommitScalarSum.?, pState.peRand.?, peCommitScalarSum.?, pbScratch.?, cbScratch);
    a_dispatch.SymCryptModAdd(pCurve.GOrd, peCommitScalarSum.?, pState.peMask.?, peCommitScalarSum.?, pbScratch.?, cbScratch);

    scError = SymCryptEcpointSetValue(
        pCurve,
        pbPeerCommitElement,
        cbPeerCommitElement,
        .SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        .SYMCRYPT_ECPOINT_FORMAT_XY,
        poPeerCommitElement.?,
        0,
        pbScratch.?,
        cbScratch,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    if (SymCryptEcpointOnCurve(pCurve, poPeerCommitElement.?, pbScratch.?, cbScratch) == 0 or
        SymCryptEcpointIsZero(pCurve, poPeerCommitElement.?, pbScratch.?, cbScratch) != 0)
    {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    scError = SymCryptEcpointScalarMul(
        pCurve,
        piTmp.?,
        pState.poPWE.?,
        0,
        poTmp.?,
        pbScratch.?,
        cbScratch,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    SymCryptEcpointAdd(pCurve, poTmp.?, poPeerCommitElement.?, poTmp.?, 0, pbScratch.?, cbScratch);

    a_dispatch.SymCryptModElementToInt(pCurve.GOrd, pState.peRand.?, piTmp.?, pbScratch.?, cbScratch);
    scError = SymCryptEcpointScalarMul(
        pCurve,
        piTmp.?,
        poTmp.?,
        0,
        poTmp.?,
        pbScratch.?,
        cbScratch,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    scError = SymCryptEcpointGetValue(
        pCurve,
        poTmp.?,
        .SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        .SYMCRYPT_ECPOINT_FORMAT_X,
        pbSharedSecret,
        cbSharedSecret,
        0,
        pbScratch.?,
        cbScratch,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    scError = a_dispatch.SymCryptModElementGetValue(pCurve.GOrd, peCommitScalarSum.?, pbScalarSum, cbScalarSum, .SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, pbScratch.?, cbScratch);
    return scError;
}

pub export fn SymCrypt802_11SaeCustomCommitProcess(
    pState: PCSYMCRYPT_802_11_SAE_CUSTOM_STATE,
    pbPeerCommitScalar: PCBYTE,
    pbPeerCommitElement: PCBYTE,
    pbSharedSecret: PBYTE,
    pbScalarSum: PBYTE,
) callconv(.c) SYMCRYPT_ERROR {
    return SymCrypt802_11SaeCustomCommitProcessGeneric(
        pState,
        pbPeerCommitScalar,
        32,
        pbPeerCommitElement,
        64,
        pbSharedSecret,
        32,
        pbScalarSum,
        32,
    );
}
