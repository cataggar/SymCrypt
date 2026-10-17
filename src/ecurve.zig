//
// ecurve.zig   Curve allocation and helper functions
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

const types = @import("types.zig");
const macros = @import("macros.zig");
const a_dispatch = @import("a_dispatch.zig");
const ec_internal_curve_params = @import("ec_internal_curve_params.zig");
const ec_dispatch = @import("ec_dispatch.zig");
const ecpoint = @import("ecpoint.zig");

extern fn SymCryptCallbackAlloc(cbData: SIZE_T) callconv(SYMCRYPT_CALL) ?PBYTE;
extern fn SymCryptCallbackFree(pMem: *anyopaque) callconv(SYMCRYPT_CALL) void;

const PBYTE = types.PBYTE;
const PCBYTE = types.PCBYTE;
const UINT32 = types.UINT32;
const SIZE_T = types.SIZE_T;
const BOOLEAN = types.BOOLEAN;
const SYMCRYPT_CALL = types.SYMCRYPT_CALL;
const SYMCRYPT_ERROR = types.SYMCRYPT_ERROR;
const SYMCRYPT_ECURVE = types.SYMCRYPT_ECURVE;
const PSYMCRYPT_ECURVE = types.PSYMCRYPT_ECURVE;
const PCSYMCRYPT_ECURVE = types.PCSYMCRYPT_ECURVE;
const PSYMCRYPT_ECURVE_PARAMS = types.PSYMCRYPT_ECURVE_PARAMS;
const PCSYMCRYPT_ECURVE_PARAMS = types.PCSYMCRYPT_ECURVE_PARAMS;
const SYMCRYPT_ECURVE_PARAMS_V2_EXTENSION = types.SYMCRYPT_ECURVE_PARAMS_V2_EXTENSION;
const SYMCRYPT_ECPOINT_COORDINATES = types.SYMCRYPT_ECPOINT_COORDINATES;
const PCSYMCRYPT_MODULUS = types.PCSYMCRYPT_MODULUS;

const TRUE: BOOLEAN = 1;
const FALSE: BOOLEAN = 0;

inline fn SYMCRYPT_INTERNAL_ECURVE_MODULUS_NUMOF_OPERATIONS(bitsize: UINT32) UINT32 {
    return 100 * bitsize;
}
const SYMCRYPT_INTERNAL_ECURVE_GROUP_ORDER_NUMOF_OPERATIONS: UINT32 = 1;
const SYMCRYPT_INTERNAL_MAX_ECURVE_SIZE: UINT32 = 1024;

const SYMCRYPT_ECURVE_SIZES = struct {
    nDigitsFieldLength: UINT32,
    nDigitsSubgroupOrder: UINT32,
    nDigitsCoFactor: UINT32,
    cbAlloc: UINT32,
    cbModulus: UINT32,
    cbModElement: UINT32,
    cbEcpoint: UINT32,
    cbSubgroupOrder: UINT32,
    cbCoFactor: UINT32,
    cbScratch: UINT32,
    eCoordinates: SYMCRYPT_ECPOINT_COORDINATES,
};

pub const ec_mul = @import("ec_mul.zig");
const SymCryptOfflinePrecomputation = ec_mul.SymCryptOfflinePrecomputation;

fn SymCryptEcurveValidateAndComputeSizes(
    pParams: PCSYMCRYPT_ECURVE_PARAMS,
    pSizes: *SYMCRYPT_ECURVE_SIZES,
) BOOLEAN {
    macros.SYMCRYPT_ASSERT(pParams.version == 1 or pParams.version == 2);
    macros.SYMCRYPT_ASSERT(pParams.cbFieldLength != 0);
    macros.SYMCRYPT_ASSERT(pParams.cbSubgroupOrder != 0);
    macros.SYMCRYPT_ASSERT(pParams.cbCofactor != 0);
    macros.SYMCRYPT_ASSERT(
        pParams.type == .SYMCRYPT_ECURVE_TYPE_SHORT_WEIERSTRASS or
            pParams.type == .SYMCRYPT_ECURVE_TYPE_TWISTED_EDWARDS or
            pParams.type == .SYMCRYPT_ECURVE_TYPE_MONTGOMERY,
    );

    if (pParams.cbFieldLength > SYMCRYPT_INTERNAL_MAX_ECURVE_SIZE / 8 or
        pParams.cbSubgroupOrder > SYMCRYPT_INTERNAL_MAX_ECURVE_SIZE / 8 + 1 or
        pParams.cbCofactor > 2 or
        pParams.cbSeed > 256)
    {
        return FALSE;
    }

    pSizes.nDigitsFieldLength = a_dispatch.SymCryptDigitsFromBits(pParams.cbFieldLength * 8);
    pSizes.nDigitsSubgroupOrder = a_dispatch.SymCryptDigitsFromBits(pParams.cbSubgroupOrder * 8);
    pSizes.nDigitsCoFactor = a_dispatch.SymCryptDigitsFromBits(pParams.cbCofactor * 8);

    pSizes.cbModulus = a_dispatch.SymCryptSizeofModulusFromDigits(pSizes.nDigitsFieldLength);
    pSizes.cbSubgroupOrder = a_dispatch.SymCryptSizeofModulusFromDigits(pSizes.nDigitsSubgroupOrder);
    pSizes.cbCoFactor = a_dispatch.SymCryptSizeofIntFromDigits(pSizes.nDigitsCoFactor);

    pSizes.cbModElement = types.SYMCRYPT_SIZEOF_MODELEMENT_FROM_BITS(pParams.cbFieldLength * 8);

    switch (pParams.type) {
        .SYMCRYPT_ECURVE_TYPE_SHORT_WEIERSTRASS => {
            pSizes.eCoordinates = .SYMCRYPT_ECPOINT_COORDINATES_JACOBIAN;
        },
        .SYMCRYPT_ECURVE_TYPE_TWISTED_EDWARDS => {
            pSizes.eCoordinates = .SYMCRYPT_ECPOINT_COORDINATES_EXTENDED_PROJECTIVE;
        },
        .SYMCRYPT_ECURVE_TYPE_MONTGOMERY => {
            pSizes.eCoordinates = .SYMCRYPT_ECPOINT_COORDINATES_SINGLE_PROJECTIVE;
        },
        else => return FALSE,
    }

    pSizes.cbEcpoint = ecpoint.SymCryptSizeofEcpointEx(
        pSizes.cbModElement,
        types.SYMCRYPT_INTERNAL_NUMOF_COORDINATES(pSizes.eCoordinates),
    );

    pSizes.cbAlloc = @as(UINT32, @sizeOf(SYMCRYPT_ECURVE)) +
        pSizes.cbModulus +
        2 * pSizes.cbModElement +
        pSizes.cbSubgroupOrder +
        pSizes.cbCoFactor;

    if (pParams.type == .SYMCRYPT_ECURVE_TYPE_SHORT_WEIERSTRASS or
        pParams.type == .SYMCRYPT_ECURVE_TYPE_TWISTED_EDWARDS)
    {
        pSizes.cbAlloc += (@as(UINT32, 1) << (types.SYMCRYPT_ECURVE_SW_DEF_WINDOW - 2)) * pSizes.cbEcpoint;
    } else {
        pSizes.cbAlloc += pSizes.cbEcpoint;
    }

    pSizes.cbScratch = ecpoint.SymCryptSizeofEcpointEx(pSizes.cbModElement, types.SYMCRYPT_ECPOINT_FORMAT_MAX_LENGTH) +
        8 * pSizes.cbModElement +
        @max(
            types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(pSizes.nDigitsFieldLength),
            types.SYMCRYPT_SCRATCH_BYTES_FOR_MODINV(pSizes.nDigitsFieldLength),
        );
    pSizes.cbScratch = @max(
        pSizes.cbScratch,
        types.SYMCRYPT_SCRATCH_BYTES_FOR_INT_TO_MODULUS(@max(pSizes.nDigitsFieldLength, pSizes.nDigitsSubgroupOrder)),
    );
    pSizes.cbScratch = @max(
        pSizes.cbScratch,
        types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(pSizes.nDigitsFieldLength),
    );

    return TRUE;
}

pub export fn SymCryptEcurveBufferSizesFromParams(
    pParams: PCSYMCRYPT_ECURVE_PARAMS,
    pcbCurve: *SIZE_T,
    pcbScratch: *SIZE_T,
) callconv(SYMCRYPT_CALL) BOOLEAN {
    var sizes: SYMCRYPT_ECURVE_SIZES = undefined;

    if (SymCryptEcurveValidateAndComputeSizes(pParams, &sizes) == 0) {
        return FALSE;
    }

    pcbCurve.* = sizes.cbAlloc;
    pcbScratch.* = sizes.cbScratch;

    return TRUE;
}

fn SymCryptEcurveInitialize(
    pParams: PCSYMCRYPT_ECURVE_PARAMS,
    flags: UINT32,
    pSizes: *const SYMCRYPT_ECURVE_SIZES,
    pbCurve: PBYTE,
    pbScratch: PBYTE,
) ?PSYMCRYPT_ECURVE {
    _ = flags;

    var fSuccess: BOOLEAN = FALSE;
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;

    const pCurve: PSYMCRYPT_ECURVE = @ptrCast(@alignCast(pbCurve));

    defer {
        if (fSuccess == 0) {
            macros.SymCryptWipe(pbCurve, pSizes.cbAlloc);
        }
    }

    pCurve.version = types.SYMCRYPT_INTERNAL_ECURVE_VERSION_LATEST;
    pCurve.type = @fromBackingInt(@intCast(@backingInt(pParams.type)));
    pCurve.eCoordinates = pSizes.eCoordinates;
    pCurve.FModDigits = pSizes.nDigitsFieldLength;
    pCurve.GOrdDigits = pSizes.nDigitsSubgroupOrder;
    pCurve.FModBytesize = pParams.cbFieldLength;
    pCurve.GOrdBytesize = pParams.cbSubgroupOrder;
    pCurve.cbModElement = pSizes.cbModElement;
    pCurve.cbAlloc = pSizes.cbAlloc;

    var pDst: PBYTE = pbCurve + @sizeOf(SYMCRYPT_ECURVE);
    var pSrc: PCBYTE = @as(PCBYTE, @ptrCast(pParams)) + @sizeOf(types.SYMCRYPT_ECURVE_PARAMS);

    // Field Modulus
    const pmFMod = a_dispatch.SymCryptModulusCreate(pDst, pSizes.cbModulus, pSizes.nDigitsFieldLength) orelse return null;
    pCurve.FMod = pmFMod;

    var pTempInt = a_dispatch.SymCryptIntFromModulus(pCurve.FMod);
    scError = a_dispatch.SymCryptIntSetValue(pSrc, pParams.cbFieldLength, .SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, pTempInt);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return null;
    }

    pCurve.FModBitsize = a_dispatch.SymCryptIntBitsizeOfValue(pTempInt);
    if (pCurve.FModBitsize < types.SYMCRYPT_ECURVE_MIN_BITSIZE_FMOD) {
        return null;
    }

    if ((a_dispatch.SymCryptIntGetValueLsbits32(pTempInt) & 1) == 0) {
        return null;
    }

    a_dispatch.SymCryptIntToModulus(
        pTempInt,
        pCurve.FMod,
        SYMCRYPT_INTERNAL_ECURVE_MODULUS_NUMOF_OPERATIONS(8 * pParams.cbFieldLength),
        types.SYMCRYPT_FLAG_DATA_PUBLIC | types.SYMCRYPT_FLAG_MODULUS_PRIME,
        pbScratch,
        pSizes.cbScratch,
    );

    pDst += pSizes.cbModulus;
    pSrc += pParams.cbFieldLength;

    // A constant
    const peA = a_dispatch.SymCryptModElementCreate(pDst, pSizes.cbModElement, pCurve.FMod) orelse return null;
    pCurve.A = peA;
    scError = a_dispatch.SymCryptModElementSetValue(
        pSrc,
        pParams.cbFieldLength,
        .SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        pCurve.FMod,
        pCurve.A,
        pbScratch,
        pSizes.cbScratch,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return null;
    }
    pDst += pSizes.cbModElement;
    pSrc += pParams.cbFieldLength;

    // B constant
    const peB = a_dispatch.SymCryptModElementCreate(pDst, pSizes.cbModElement, pCurve.FMod) orelse return null;
    pCurve.B = peB;

    if (pParams.type == .SYMCRYPT_ECURVE_TYPE_SHORT_WEIERSTRASS) {
        a_dispatch.SymCryptModElementSetValueNegUint32(
            3,
            pCurve.FMod,
            pCurve.B,
            pbScratch,
            pSizes.cbScratch,
        );
        if (a_dispatch.SymCryptModElementIsEqual(pCurve.FMod, pCurve.A, pCurve.B) != 0) {
            pCurve.type = .SYMCRYPT_INTERNAL_ECURVE_TYPE_SHORT_WEIERSTRASS_AM3;
        }
    }

    scError = a_dispatch.SymCryptModElementSetValue(
        pSrc,
        pParams.cbFieldLength,
        .SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        pCurve.FMod,
        pCurve.B,
        pbScratch,
        pSizes.cbScratch,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return null;
    }
    pDst += pSizes.cbModElement;
    pSrc += pParams.cbFieldLength;

    const pSrcGenerator: PCBYTE = pSrc;
    pSrc += pParams.cbFieldLength * 2;

    // Subgroup Order
    const pmGOrd = a_dispatch.SymCryptModulusCreate(pDst, pSizes.cbSubgroupOrder, pSizes.nDigitsSubgroupOrder) orelse return null;
    pCurve.GOrd = pmGOrd;

    pTempInt = a_dispatch.SymCryptIntFromModulus(pCurve.GOrd);
    scError = a_dispatch.SymCryptIntSetValue(pSrc, pParams.cbSubgroupOrder, .SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, pTempInt);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return null;
    }

    pCurve.GOrdBitsize = a_dispatch.SymCryptIntBitsizeOfValue(pTempInt);
    if (pCurve.GOrdBitsize < types.SYMCRYPT_ECURVE_MIN_BITSIZE_GORD) {
        return null;
    }

    if ((a_dispatch.SymCryptIntGetValueLsbits32(pTempInt) & 1) == 0) {
        return null;
    }

    a_dispatch.SymCryptIntToModulus(
        pTempInt,
        pCurve.GOrd,
        SYMCRYPT_INTERNAL_ECURVE_GROUP_ORDER_NUMOF_OPERATIONS,
        types.SYMCRYPT_FLAG_DATA_PUBLIC | types.SYMCRYPT_FLAG_MODULUS_PRIME,
        pbScratch,
        pSizes.cbScratch,
    );

    pDst += pSizes.cbSubgroupOrder;
    pSrc += pParams.cbSubgroupOrder;

    // Cofactor
    const piH = a_dispatch.SymCryptIntCreate(pDst, pSizes.cbCoFactor, pSizes.nDigitsCoFactor) orelse return null;
    pCurve.H = piH;
    scError = a_dispatch.SymCryptIntSetValue(
        pSrc,
        pParams.cbCofactor,
        .SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        pCurve.H,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return null;
    }

    pCurve.coFactorPower = a_dispatch.SymCryptIntBitsizeOfValue(pCurve.H) -% 1;
    if (pCurve.coFactorPower == @as(UINT32, @bitCast(@as(i32, -1))) or
        pCurve.coFactorPower > types.SYMCRYPT_ECURVE_MAX_COFACTOR_POWER)
    {
        return null;
    }

    if (a_dispatch.SymCryptIntIsEqualUint32(pCurve.H, @as(UINT32, 1) << @intCast(pCurve.coFactorPower)) == 0) {
        return null;
    }

    pDst += pSizes.cbCoFactor;
    pSrc += pParams.cbCofactor;

    if (pParams.type == .SYMCRYPT_ECURVE_TYPE_SHORT_WEIERSTRASS or
        pParams.type == .SYMCRYPT_ECURVE_TYPE_TWISTED_EDWARDS)
    {
        pCurve.info.sw.window = types.SYMCRYPT_ECURVE_SW_DEF_WINDOW;
        pCurve.info.sw.nPrecompPoints = @as(UINT32, 1) << (types.SYMCRYPT_ECURVE_SW_DEF_WINDOW - 2);
        pCurve.info.sw.nRecodedDigits = pCurve.GOrdBitsize + 1;
    }

    ec_dispatch.SymCryptEcurveFillScratchSpaces(pCurve);

    // Distinguished point
    const poG = ecpoint.SymCryptEcpointCreate(pDst, pSizes.cbEcpoint, pCurve) orelse return null;
    pCurve.G = poG;
    scError = ecpoint.SymCryptEcpointSetValue(
        pCurve,
        pSrcGenerator,
        pParams.cbFieldLength * 2,
        .SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        .SYMCRYPT_ECPOINT_FORMAT_XY,
        pCurve.G,
        types.SYMCRYPT_FLAG_DATA_PUBLIC,
        pbScratch,
        pSizes.cbScratch,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return null;
    }
    pDst += pSizes.cbEcpoint;

    if (pParams.type == .SYMCRYPT_ECURVE_TYPE_SHORT_WEIERSTRASS or
        pParams.type == .SYMCRYPT_ECURVE_TYPE_TWISTED_EDWARDS)
    {
        pCurve.info.sw.poPrecompPoints[0] = pCurve.G;

        var i: UINT32 = 1;
        while (i < pCurve.info.sw.nPrecompPoints) : (i += 1) {
            const poPrecomp = ecpoint.SymCryptEcpointCreate(pDst, pSizes.cbEcpoint, pCurve) orelse return null;
            pCurve.info.sw.poPrecompPoints[i] = poPrecomp;
            pDst += pSizes.cbEcpoint;
        }

        SymCryptOfflinePrecomputation(pCurve, pbScratch, pSizes.cbScratch);
    }

    if (pParams.type == .SYMCRYPT_ECURVE_TYPE_MONTGOMERY) {
        const peTemp = a_dispatch.SymCryptModElementCreate(pbScratch, pSizes.cbModElement, pCurve.FMod).?;
        a_dispatch.SymCryptModElementSetValueUint32(
            2,
            pCurve.FMod,
            peTemp,
            pbScratch + pSizes.cbModElement,
            pSizes.cbScratch - pSizes.cbModElement,
        );
        a_dispatch.SymCryptModAdd(
            pCurve.FMod,
            pCurve.A,
            peTemp,
            pCurve.A,
            pbScratch + pSizes.cbModElement,
            pSizes.cbScratch - pSizes.cbModElement,
        );
        a_dispatch.SymCryptModDivPow2(
            pCurve.FMod,
            pCurve.A,
            2,
            pCurve.A,
            pbScratch + pSizes.cbModElement,
            pSizes.cbScratch - pSizes.cbModElement,
        );
    }

    var paramsV2Ext: SYMCRYPT_ECURVE_PARAMS_V2_EXTENSION = undefined;
    if (pParams.version == 2) {
        pSrc += pParams.cbSeed;
        const pcUnaligned: *align(1) const SYMCRYPT_ECURVE_PARAMS_V2_EXTENSION = @ptrCast(pSrc);
        paramsV2Ext = pcUnaligned.*;
    } else {
        if (pParams.type == .SYMCRYPT_ECURVE_TYPE_SHORT_WEIERSTRASS) {
            paramsV2Ext = ec_internal_curve_params.SymCryptEcurveParamsV2ExtensionShortWeierstrass.*;
        } else if (pParams.type == .SYMCRYPT_ECURVE_TYPE_TWISTED_EDWARDS) {
            paramsV2Ext = ec_internal_curve_params.SymCryptEcurveParamsV2ExtensionTwistedEdwards.*;
        } else if (pParams.type == .SYMCRYPT_ECURVE_TYPE_MONTGOMERY) {
            paramsV2Ext = ec_internal_curve_params.SymCryptEcurveParamsV2ExtensionMontgomery.*;
        }
    }

    pCurve.PrivateKeyDefaultFormat = paramsV2Ext.PrivateKeyDefaultFormat;
    pCurve.HighBitRestrictionNumOfBits = paramsV2Ext.HighBitRestrictionNumOfBits;
    pCurve.HighBitRestrictionPosition = paramsV2Ext.HighBitRestrictionPosition;
    pCurve.HighBitRestrictionValue = paramsV2Ext.HighBitRestrictionValue;

    if (pCurve.HighBitRestrictionNumOfBits > 32 or
        (pCurve.HighBitRestrictionNumOfBits > 0 and
            pCurve.HighBitRestrictionPosition + pCurve.HighBitRestrictionNumOfBits > pCurve.GOrdBitsize + pCurve.coFactorPower))
    {
        return null;
    }

    macros.SYMCRYPT_SET_MAGIC(pCurve);

    fSuccess = TRUE;
    return pCurve;
}

pub export fn SymCryptEcurveCreate(
    pParams: PSYMCRYPT_ECURVE_PARAMS,
    flags: UINT32,
    pbCurve: PBYTE,
    cbCurve: SIZE_T,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) ?PSYMCRYPT_ECURVE {
    var sizes: SYMCRYPT_ECURVE_SIZES = undefined;

    if (SymCryptEcurveValidateAndComputeSizes(pParams, &sizes) == 0) {
        return null;
    }

    if (cbCurve < sizes.cbAlloc or cbScratch < sizes.cbScratch) {
        return null;
    }

    return SymCryptEcurveInitialize(pParams, flags, &sizes, pbCurve, pbScratch);
}

pub export fn SymCryptEcurveAllocate(
    pParams: PCSYMCRYPT_ECURVE_PARAMS,
    flags: UINT32,
) callconv(SYMCRYPT_CALL) ?PSYMCRYPT_ECURVE {
    var sizes: SYMCRYPT_ECURVE_SIZES = undefined;

    if (SymCryptEcurveValidateAndComputeSizes(pParams, &sizes) == 0) {
        return null;
    }

    var pbCurve = SymCryptCallbackAlloc(sizes.cbAlloc);
    if (pbCurve == null) {
        return null;
    }

    const pbScratch = SymCryptCallbackAlloc(sizes.cbScratch);
    if (pbScratch == null) {
        SymCryptCallbackFree(@ptrCast(pbCurve.?));
        return null;
    }

    const pCurve = SymCryptEcurveInitialize(pParams, flags, &sizes, @ptrCast(pbCurve.?), @ptrCast(pbScratch.?));
    if (pCurve != null) {
        pbCurve = null;
    }

    macros.SymCryptWipe(@ptrCast(pbScratch.?), sizes.cbScratch);
    SymCryptCallbackFree(@ptrCast(pbScratch.?));

    if (pbCurve != null) {
        SymCryptCallbackFree(@ptrCast(pbCurve.?));
    }

    return pCurve;
}

pub export fn SymCryptEcurveFree(pCurve: PSYMCRYPT_ECURVE) callconv(SYMCRYPT_CALL) void {
    macros.SYMCRYPT_CHECK_MAGIC(pCurve);
    macros.SymCryptWipe(@ptrCast(pCurve), pCurve.cbAlloc);
    SymCryptCallbackFree(@ptrCast(pCurve));
}

pub export fn SymCryptEcurveBitsizeofFieldModulus(pCurve: PCSYMCRYPT_ECURVE) callconv(SYMCRYPT_CALL) UINT32 {
    return pCurve.FModBitsize;
}

pub export fn SymCryptEcurveBitsizeofGroupOrder(pCurve: PCSYMCRYPT_ECURVE) callconv(SYMCRYPT_CALL) UINT32 {
    return pCurve.GOrdBitsize;
}

pub export fn SymCryptEcurveDigitsofFieldElement(pCurve: PCSYMCRYPT_ECURVE) callconv(SYMCRYPT_CALL) UINT32 {
    return pCurve.FModDigits;
}

pub export fn SymCryptEcurveSizeofFieldElement(pCurve: PCSYMCRYPT_ECURVE) callconv(SYMCRYPT_CALL) UINT32 {
    return pCurve.FModBytesize;
}

pub export fn SymCryptEcurveSizeofScalarMultiplier(pCurve: PCSYMCRYPT_ECURVE) callconv(SYMCRYPT_CALL) UINT32 {
    return pCurve.GOrdBytesize;
}

pub export fn SymCryptEcurveGroupOrder(pCurve: PCSYMCRYPT_ECURVE) callconv(SYMCRYPT_CALL) PCSYMCRYPT_MODULUS {
    return pCurve.GOrd;
}

pub export fn SymCryptEcurveDigitsofScalarMultiplier(pCurve: PCSYMCRYPT_ECURVE) callconv(SYMCRYPT_CALL) UINT32 {
    return a_dispatch.SymCryptDigitsFromBits(pCurve.GOrdBitsize + pCurve.coFactorPower);
}

pub export fn SymCryptEcurvePrivateKeyDefaultFormat(pCurve: PCSYMCRYPT_ECURVE) callconv(SYMCRYPT_CALL) UINT32 {
    return pCurve.PrivateKeyDefaultFormat;
}

pub export fn SymCryptEcurveHighBitRestrictionNumOfBits(pCurve: PCSYMCRYPT_ECURVE) callconv(SYMCRYPT_CALL) UINT32 {
    return pCurve.HighBitRestrictionNumOfBits;
}

pub export fn SymCryptEcurveHighBitRestrictionPosition(pCurve: PCSYMCRYPT_ECURVE) callconv(SYMCRYPT_CALL) UINT32 {
    return pCurve.HighBitRestrictionPosition;
}

pub export fn SymCryptEcurveHighBitRestrictionValue(pCurve: PCSYMCRYPT_ECURVE) callconv(SYMCRYPT_CALL) UINT32 {
    return pCurve.HighBitRestrictionValue;
}

pub export fn SymCryptEcurveIsSame(
    pCurve1: PCSYMCRYPT_ECURVE,
    pCurve2: PCSYMCRYPT_ECURVE,
) callconv(SYMCRYPT_CALL) BOOLEAN {
    if (pCurve1 == pCurve2) {
        return TRUE;
    }

    if (pCurve1.type != pCurve2.type or
        a_dispatch.SymCryptIntIsEqual(
            a_dispatch.SymCryptIntFromModulus(pCurve1.FMod),
            a_dispatch.SymCryptIntFromModulus(pCurve2.FMod),
        ) == 0 or
        a_dispatch.SymCryptModElementIsEqual(pCurve1.FMod, pCurve1.A, pCurve2.A) == 0 or
        a_dispatch.SymCryptModElementIsEqual(pCurve1.FMod, pCurve1.B, pCurve2.B) == 0)
    {
        return FALSE;
    }

    return TRUE;
}
