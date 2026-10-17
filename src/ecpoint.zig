//
// ecpoint.zig   Transformations for ECPOINT structures
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

const types = @import("types.zig");
const macros = @import("macros.zig");
const fdef_general = @import("fdef_general.zig");
const a_dispatch = @import("a_dispatch.zig");
const ecurve = @import("ecurve.zig");

extern fn SymCryptCallbackAlloc(cbData: SIZE_T) callconv(SYMCRYPT_CALL) ?PBYTE;
extern fn SymCryptCallbackFree(pMem: *anyopaque) callconv(SYMCRYPT_CALL) void;

const PBYTE = types.PBYTE;
const PCBYTE = types.PCBYTE;
const UINT32 = types.UINT32;
const SIZE_T = types.SIZE_T;
const BOOLEAN = types.BOOLEAN;
const SYMCRYPT_CALL = types.SYMCRYPT_CALL;
const SYMCRYPT_ERROR = types.SYMCRYPT_ERROR;
const SYMCRYPT_NUMBER_FORMAT = types.SYMCRYPT_NUMBER_FORMAT;
const SYMCRYPT_ECPOINT_FORMAT = types.SYMCRYPT_ECPOINT_FORMAT;
const SYMCRYPT_ECPOINT_COORDINATES = types.SYMCRYPT_ECPOINT_COORDINATES;
const SYMCRYPT_ECPOINT = types.SYMCRYPT_ECPOINT;
const PSYMCRYPT_ECPOINT = types.PSYMCRYPT_ECPOINT;
const PCSYMCRYPT_ECPOINT = types.PCSYMCRYPT_ECPOINT;
const PCSYMCRYPT_ECURVE = types.PCSYMCRYPT_ECURVE;
const PSYMCRYPT_MODELEMENT = types.PSYMCRYPT_MODELEMENT;

const TRUE: BOOLEAN = 1;
const FALSE: BOOLEAN = 0;

// Table with the number of field elements for each point format
pub export const SymCryptEcpointFormatNumberofElements: [4]UINT32 = .{
    0,
    1, // SYMCRYPT_ECPOINT_FORMAT_X
    2, // SYMCRYPT_ECPOINT_FORMAT_XY
    0,
};

pub export fn SymCryptSizeofEcpointEx(
    cbModElement: UINT32,
    numOfCoordinates: UINT32,
) callconv(SYMCRYPT_CALL) UINT32 {
    macros.SYMCRYPT_ASSERT(numOfCoordinates > 0);
    macros.SYMCRYPT_ASSERT(numOfCoordinates <= types.SYMCRYPT_ECPOINT_FORMAT_MAX_LENGTH);

    if (numOfCoordinates == 0 or numOfCoordinates > types.SYMCRYPT_ECPOINT_FORMAT_MAX_LENGTH) {
        return 0;
    }

    return @as(UINT32, @sizeOf(SYMCRYPT_ECPOINT)) + numOfCoordinates * cbModElement;
}

pub export fn SymCryptSizeofEcpointFromCurve(pCurve: PCSYMCRYPT_ECURVE) callconv(SYMCRYPT_CALL) UINT32 {
    return SymCryptSizeofEcpointEx(
        pCurve.cbModElement,
        types.SYMCRYPT_INTERNAL_NUMOF_COORDINATES(pCurve.eCoordinates),
    );
}

pub export fn SymCryptEcpointAllocate(pCurve: PCSYMCRYPT_ECURVE) callconv(SYMCRYPT_CALL) ?PSYMCRYPT_ECPOINT {
    var p: ?PBYTE = null;
    const cb: SIZE_T = SymCryptSizeofEcpointFromCurve(pCurve);

    if (cb != 0) {
        p = SymCryptCallbackAlloc(cb);
    }

    if (p == null) {
        return null;
    }

    return SymCryptEcpointCreate(p.?, cb, pCurve);
}

pub export fn SymCryptEcpointFree(
    pCurve: PCSYMCRYPT_ECURVE,
    poDst: PSYMCRYPT_ECPOINT,
) callconv(SYMCRYPT_CALL) void {
    macros.SYMCRYPT_CHECK_MAGIC(poDst);
    SymCryptEcpointWipe(pCurve, poDst);
    SymCryptCallbackFree(@ptrCast(poDst));
}

pub export fn SymCryptEcpointCreateEx(
    pbBuffer: PBYTE,
    cbBuffer: SIZE_T,
    pCurve: PCSYMCRYPT_ECURVE,
    numOfCoordinates: UINT32,
) callconv(SYMCRYPT_CALL) ?PSYMCRYPT_ECPOINT {
    const cbModElement = pCurve.cbModElement;

    macros.SYMCRYPT_ASSERT(@intFromPtr(pCurve.FMod) != 0);
    macros.SYMCRYPT_ASSERT(pCurve.cbModElement != 0);
    macros.SYMCRYPT_ASSERT(cbBuffer >= SymCryptSizeofEcpointEx(pCurve.cbModElement, numOfCoordinates));
    if (cbBuffer == 0 or numOfCoordinates == 0) {
        return null;
    }

    macros.SYMCRYPT_ASSERT_ASYM_ALIGNED(pbBuffer);

    const poPoint: PSYMCRYPT_ECPOINT = @ptrCast(@alignCast(pbBuffer));
    var pCurr: PBYTE = pbBuffer + @sizeOf(SYMCRYPT_ECPOINT);

    var i: UINT32 = 0;
    while (i < numOfCoordinates) : (i += 1) {
        const pmTmp = a_dispatch.SymCryptModElementCreate(pCurr, cbModElement, pCurve.FMod);
        if (pmTmp == null) {
            return null;
        }
        pCurr += cbModElement;
    }

    poPoint.normalized = FALSE;
    poPoint.pCurve = pCurve;

    macros.SYMCRYPT_SET_MAGIC(poPoint);

    return poPoint;
}

pub export fn SymCryptEcpointCreate(
    pbBuffer: PBYTE,
    cbBuffer: SIZE_T,
    pCurve: PCSYMCRYPT_ECURVE,
) callconv(SYMCRYPT_CALL) ?PSYMCRYPT_ECPOINT {
    macros.SYMCRYPT_ASSERT(@backingInt(pCurve.eCoordinates) != 0);

    return SymCryptEcpointCreateEx(
        pbBuffer,
        cbBuffer,
        pCurve,
        types.SYMCRYPT_INTERNAL_NUMOF_COORDINATES(pCurve.eCoordinates),
    );
}

pub export fn SymCryptEcpointRetrieveHandle(pbBuffer: PBYTE) callconv(SYMCRYPT_CALL) PSYMCRYPT_ECPOINT {
    macros.SYMCRYPT_ASSERT_ASYM_ALIGNED(pbBuffer);
    return @ptrCast(@alignCast(pbBuffer));
}

pub export fn SymCryptEcpointWipe(
    pCurve: PCSYMCRYPT_ECURVE,
    poDst: PSYMCRYPT_ECPOINT,
) callconv(SYMCRYPT_CALL) void {
    macros.SYMCRYPT_ASSERT(ecurve.SymCryptEcurveIsSame(pCurve, poDst.pCurve) != 0);

    macros.SymCryptWipe(@ptrCast(poDst), SymCryptSizeofEcpointFromCurve(pCurve));
}

pub export fn SymCryptEcpointCopy(
    pCurve: PCSYMCRYPT_ECURVE,
    poSrc: PCSYMCRYPT_ECPOINT,
    poDst: PSYMCRYPT_ECPOINT,
) callconv(.c) void {
    macros.SYMCRYPT_ASSERT(
        ecurve.SymCryptEcurveIsSame(pCurve, poSrc.pCurve) != 0 and
            ecurve.SymCryptEcurveIsSame(pCurve, poDst.pCurve) != 0,
    );

    if (poSrc != poDst) {
        poDst.normalized = poSrc.normalized;

        const cbCopy: usize = @as(usize, types.SYMCRYPT_INTERNAL_NUMOF_COORDINATES(pCurve.eCoordinates)) *
            @as(usize, pCurve.FModDigits) *
            types.SYMCRYPT_FDEF_DIGIT_SIZE;
        const pSrcBytes: PCBYTE = @as(PCBYTE, @ptrCast(poSrc)) + @sizeOf(SYMCRYPT_ECPOINT);
        const pDstBytes: PBYTE = @as(PBYTE, @ptrCast(poDst)) + @sizeOf(SYMCRYPT_ECPOINT);
        @memcpy(pDstBytes[0..cbCopy], pSrcBytes[0..cbCopy]);
    }
}

pub export fn SymCryptEcpointMaskedCopy(
    pCurve: PCSYMCRYPT_ECURVE,
    poSrc: PCSYMCRYPT_ECPOINT,
    poDst: PSYMCRYPT_ECPOINT,
    mask: UINT32,
) callconv(.c) void {
    macros.SYMCRYPT_ASSERT(mask == 0 or mask == 0xffffffff);
    macros.SYMCRYPT_ASSERT(
        ecurve.SymCryptEcurveIsSame(pCurve, poSrc.pCurve) != 0 and
            ecurve.SymCryptEcurveIsSame(pCurve, poDst.pCurve) != 0,
    );

    poDst.normalized &= poSrc.normalized;

    fdef_general.SymCryptFdefMaskedCopy(
        @as(PCBYTE, @ptrCast(poSrc)) + @sizeOf(SYMCRYPT_ECPOINT),
        @as(PBYTE, @ptrCast(poDst)) + @sizeOf(SYMCRYPT_ECPOINT),
        types.SYMCRYPT_INTERNAL_NUMOF_COORDINATES(pCurve.eCoordinates) * pCurve.FModDigits,
        mask,
    );
}

pub export fn SymCryptEcpointTransform(
    pCurve: PCSYMCRYPT_ECURVE,
    poSrc: PCSYMCRYPT_ECPOINT,
    poDst: PSYMCRYPT_ECPOINT,
    eformat: SYMCRYPT_ECPOINT_FORMAT,
    setValue: BOOLEAN,
    flags: UINT32,
    pbScratch_in: PBYTE,
    cbScratch_in: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;
    var pbScratch = pbScratch_in;
    var cbScratch = cbScratch_in;

    var peSrc: PSYMCRYPT_MODELEMENT = undefined;
    var peDst: PSYMCRYPT_MODELEMENT = undefined;
    var peX: PSYMCRYPT_MODELEMENT = undefined;
    var peY: PSYMCRYPT_MODELEMENT = undefined;

    var coFrom: SYMCRYPT_ECPOINT_COORDINATES = .SYMCRYPT_ECPOINT_COORDINATES_INVALID;
    var coTo: SYMCRYPT_ECPOINT_COORDINATES = .SYMCRYPT_ECPOINT_COORDINATES_INVALID;

    var peT: [2]PSYMCRYPT_MODELEMENT = undefined;

    macros.SYMCRYPT_ASSERT((flags & ~types.SYMCRYPT_FLAG_DATA_PUBLIC) == 0);
    macros.SYMCRYPT_ASSERT(
        ecurve.SymCryptEcurveIsSame(pCurve, poSrc.pCurve) != 0 and
            ecurve.SymCryptEcurveIsSame(pCurve, poDst.pCurve) != 0,
    );
    macros.SYMCRYPT_ASSERT(
        cbScratch >= @max(
            types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(pCurve.FModDigits),
            types.SYMCRYPT_SCRATCH_BYTES_FOR_MODINV(pCurve.FModDigits),
        ) + 2 * pCurve.cbModElement,
    );

    switch (eformat) {
        .SYMCRYPT_ECPOINT_FORMAT_X => {
            coFrom = .SYMCRYPT_ECPOINT_COORDINATES_SINGLE;
        },
        .SYMCRYPT_ECPOINT_FORMAT_XY => {
            coFrom = .SYMCRYPT_ECPOINT_COORDINATES_AFFINE;
        },
        else => {
            return .SYMCRYPT_INVALID_ARGUMENT;
        },
    }

    if (setValue != 0) {
        coTo = pCurve.eCoordinates;
    } else {
        coTo = coFrom;
        coFrom = pCurve.eCoordinates;
    }

    if (coFrom == coTo) {
        SymCryptEcpointCopy(pCurve, poSrc, poDst);
    } else if (coFrom == .SYMCRYPT_ECPOINT_COORDINATES_SINGLE) {
        if (coTo == .SYMCRYPT_ECPOINT_COORDINATES_AFFINE) {
            peX = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(0, pCurve, poSrc);
            peDst = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(0, pCurve, poDst);
            a_dispatch.SymCryptModElementCopy(pCurve.FMod, peX, peDst);

            peDst = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(1, pCurve, poDst);
            a_dispatch.SymCryptModElementSetValueUint32(0, pCurve.FMod, peDst, pbScratch, cbScratch);
        } else if (coTo == .SYMCRYPT_ECPOINT_COORDINATES_SINGLE_PROJECTIVE) {
            peX = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(0, pCurve, poSrc);
            peDst = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(0, pCurve, poDst);
            a_dispatch.SymCryptModElementCopy(pCurve.FMod, peX, peDst);

            peDst = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(1, pCurve, poDst);
            a_dispatch.SymCryptModElementSetValueUint32(1, pCurve.FMod, peDst, pbScratch, cbScratch);

            poDst.normalized = TRUE;
        } else {
            scError = .SYMCRYPT_NOT_IMPLEMENTED;
        }
    } else if (coFrom == .SYMCRYPT_ECPOINT_COORDINATES_AFFINE) {
        if (coTo == .SYMCRYPT_ECPOINT_COORDINATES_SINGLE or
            coTo == .SYMCRYPT_ECPOINT_COORDINATES_JACOBIAN or
            coTo == .SYMCRYPT_ECPOINT_COORDINATES_EXTENDED_PROJECTIVE or
            coTo == .SYMCRYPT_ECPOINT_COORDINATES_SINGLE_PROJECTIVE)
        {
            peX = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(0, pCurve, poSrc);
            peDst = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(0, pCurve, poDst);
            a_dispatch.SymCryptModElementCopy(pCurve.FMod, peX, peDst);

            if (coTo == .SYMCRYPT_ECPOINT_COORDINATES_JACOBIAN or
                coTo == .SYMCRYPT_ECPOINT_COORDINATES_EXTENDED_PROJECTIVE)
            {
                peY = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(1, pCurve, poSrc);
                peDst = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(1, pCurve, poDst);
                a_dispatch.SymCryptModElementCopy(pCurve.FMod, peY, peDst);

                peDst = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(2, pCurve, poDst);
                a_dispatch.SymCryptModElementSetValueUint32(1, pCurve.FMod, peDst, pbScratch, cbScratch);

                if (coTo == .SYMCRYPT_ECPOINT_COORDINATES_EXTENDED_PROJECTIVE) {
                    peDst = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(3, pCurve, poDst);
                    a_dispatch.SymCryptModMul(pCurve.FMod, peX, peY, peDst, pbScratch, cbScratch);
                }

                poDst.normalized = TRUE;
            } else if (coTo == .SYMCRYPT_ECPOINT_COORDINATES_SINGLE_PROJECTIVE) {
                peDst = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(1, pCurve, poDst);
                a_dispatch.SymCryptModElementSetValueUint32(1, pCurve.FMod, peDst, pbScratch, cbScratch);
                poDst.normalized = TRUE;
            }
        } else {
            scError = .SYMCRYPT_NOT_IMPLEMENTED;
        }
    } else if (coFrom == .SYMCRYPT_ECPOINT_COORDINATES_JACOBIAN) {
        if (coTo == .SYMCRYPT_ECPOINT_COORDINATES_SINGLE or
            coTo == .SYMCRYPT_ECPOINT_COORDINATES_AFFINE)
        {
            var i: usize = 0;
            while (i < 2) : (i += 1) {
                peT[i] = a_dispatch.SymCryptModElementCreate(pbScratch, pCurve.cbModElement, pCurve.FMod).?;
                pbScratch += pCurve.cbModElement;
            }
            cbScratch -= 2 * pCurve.cbModElement;

            peSrc = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(2, pCurve, poSrc);
            if (a_dispatch.SymCryptModElementIsZero(pCurve.FMod, peSrc) != 0) {
                return .SYMCRYPT_INCOMPATIBLE_FORMAT;
            }

            scError = a_dispatch.SymCryptModInv(pCurve.FMod, peSrc, peT[0], flags, pbScratch, cbScratch);
            if (scError != .SYMCRYPT_NO_ERROR) {
                return scError;
            }

            a_dispatch.SymCryptModMul(pCurve.FMod, peT[0], peT[0], peT[1], pbScratch, cbScratch);

            peSrc = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(0, pCurve, poSrc);
            peDst = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(0, pCurve, poDst);
            a_dispatch.SymCryptModMul(pCurve.FMod, peSrc, peT[1], peDst, pbScratch, cbScratch);

            if (coTo == .SYMCRYPT_ECPOINT_COORDINATES_AFFINE) {
                a_dispatch.SymCryptModMul(pCurve.FMod, peT[0], peT[1], peT[1], pbScratch, cbScratch);

                peSrc = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(1, pCurve, poSrc);
                peDst = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(1, pCurve, poDst);
                a_dispatch.SymCryptModMul(pCurve.FMod, peSrc, peT[1], peDst, pbScratch, cbScratch);
            }
        } else {
            scError = .SYMCRYPT_NOT_IMPLEMENTED;
        }
    } else if (coFrom == .SYMCRYPT_ECPOINT_COORDINATES_EXTENDED_PROJECTIVE) {
        if (coTo == .SYMCRYPT_ECPOINT_COORDINATES_SINGLE or
            coTo == .SYMCRYPT_ECPOINT_COORDINATES_AFFINE)
        {
            peT[0] = a_dispatch.SymCryptModElementCreate(pbScratch, pCurve.cbModElement, pCurve.FMod).?;
            pbScratch += pCurve.cbModElement;
            cbScratch -= 2 * pCurve.cbModElement;

            peSrc = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(2, pCurve, poSrc);
            if (a_dispatch.SymCryptModElementIsZero(pCurve.FMod, peSrc) != 0) {
                return .SYMCRYPT_INCOMPATIBLE_FORMAT;
            }

            scError = a_dispatch.SymCryptModInv(pCurve.FMod, peSrc, peT[0], flags, pbScratch, cbScratch);
            if (scError != .SYMCRYPT_NO_ERROR) {
                return scError;
            }

            peSrc = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(0, pCurve, poSrc);
            peDst = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(0, pCurve, poDst);
            a_dispatch.SymCryptModMul(pCurve.FMod, peSrc, peT[0], peDst, pbScratch, cbScratch);

            if (coTo == .SYMCRYPT_ECPOINT_COORDINATES_AFFINE) {
                peSrc = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(1, pCurve, poSrc);
                peDst = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(1, pCurve, poDst);
                a_dispatch.SymCryptModMul(pCurve.FMod, peSrc, peT[0], peDst, pbScratch, cbScratch);
            }
        } else {
            scError = .SYMCRYPT_NOT_IMPLEMENTED;
        }
    } else if (coFrom == .SYMCRYPT_ECPOINT_COORDINATES_SINGLE_PROJECTIVE) {
        if (coTo == .SYMCRYPT_ECPOINT_COORDINATES_SINGLE or
            coTo == .SYMCRYPT_ECPOINT_COORDINATES_AFFINE)
        {
            peT[0] = a_dispatch.SymCryptModElementCreate(pbScratch, pCurve.cbModElement, pCurve.FMod).?;
            pbScratch += pCurve.cbModElement;
            cbScratch -= pCurve.cbModElement;

            peSrc = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(1, pCurve, poSrc);
            if (a_dispatch.SymCryptModElementIsZero(pCurve.FMod, peSrc) != 0) {
                return .SYMCRYPT_INCOMPATIBLE_FORMAT;
            }

            scError = a_dispatch.SymCryptModInv(pCurve.FMod, peSrc, peT[0], flags, pbScratch, cbScratch);
            if (scError != .SYMCRYPT_NO_ERROR) {
                return scError;
            }

            peSrc = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(0, pCurve, poSrc);
            peDst = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(0, pCurve, poDst);
            a_dispatch.SymCryptModMul(pCurve.FMod, peSrc, peT[0], peDst, pbScratch, cbScratch);

            if (coTo == .SYMCRYPT_ECPOINT_COORDINATES_AFFINE) {
                peDst = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(1, pCurve, poDst);
                a_dispatch.SymCryptModElementSetValueUint32(0, pCurve.FMod, peDst, pbScratch, cbScratch);
            }
        }
    } else {
        scError = .SYMCRYPT_NOT_IMPLEMENTED;
    }

    return scError;
}

inline fn formatNumElements(eformat: SYMCRYPT_ECPOINT_FORMAT) UINT32 {
    const idx = @backingInt(eformat);
    if (idx < 0 or idx >= 3) {
        return 0;
    }
    return SymCryptEcpointFormatNumberofElements[@intCast(idx)];
}

pub export fn SymCryptEcpointSetValue(
    pCurve: PCSYMCRYPT_ECURVE,
    pbSrc_in: PCBYTE,
    cbSrc_in: SIZE_T,
    nformat: SYMCRYPT_NUMBER_FORMAT,
    eformat: SYMCRYPT_ECPOINT_FORMAT,
    poDst: PSYMCRYPT_ECPOINT,
    flags: UINT32,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NOT_IMPLEMENTED;
    var pbSrc = pbSrc_in;
    var cbSrc = cbSrc_in;

    const publicKeyDigits = ecurve.SymCryptEcurveDigitsofFieldElement(pCurve);

    macros.SYMCRYPT_ASSERT((flags & ~types.SYMCRYPT_FLAG_DATA_PUBLIC) == 0);
    macros.SYMCRYPT_ASSERT(@intFromPtr(pCurve.FMod) != 0);
    macros.SYMCRYPT_ASSERT(@backingInt(pCurve.eCoordinates) != 0);
    macros.SYMCRYPT_ASSERT(pCurve.cbModElement != 0);
    macros.SYMCRYPT_ASSERT(cbScratch >= types.SYMCRYPT_SCRATCH_BYTES_FOR_GETSET_VALUE_ECURVE_OPERATIONS(pCurve));

    const numElem = formatNumElements(eformat);
    if (numElem == 0 or cbSrc != numElem * ecurve.SymCryptEcurveSizeofFieldElement(pCurve)) {
        return .SYMCRYPT_BUFFER_TOO_SMALL;
    }
    cbSrc = cbSrc / numElem;

    const cbTemp = a_dispatch.SymCryptSizeofIntFromDigits(publicKeyDigits);
    macros.SYMCRYPT_ASSERT(cbScratch > cbTemp);

    const piTemp = a_dispatch.SymCryptIntCreate(pbScratch, cbTemp, publicKeyDigits).?;

    var i: UINT32 = 0;
    while (i < numElem) : (i += 1) {
        scError = a_dispatch.SymCryptIntSetValue(pbSrc + i * cbSrc, cbSrc, nformat, piTemp);
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }

        if (a_dispatch.SymCryptIntIsLessThan(piTemp, a_dispatch.SymCryptIntFromModulus(pCurve.FMod)) == 0) {
            return .SYMCRYPT_INVALID_ARGUMENT;
        }
    }

    const cbLarge = SymCryptSizeofEcpointEx(pCurve.cbModElement, types.SYMCRYPT_ECPOINT_FORMAT_MAX_LENGTH);
    macros.SYMCRYPT_ASSERT(cbScratch > cbLarge);
    const poLarge = SymCryptEcpointCreateEx(pbScratch, cbLarge, pCurve, types.SYMCRYPT_ECPOINT_FORMAT_MAX_LENGTH) orelse {
        return .SYMCRYPT_INVALID_BLOB;
    };

    i = 0;
    while (i < numElem) : (i += 1) {
        const peTmp = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(i, pCurve, poLarge);
        scError = a_dispatch.SymCryptModElementSetValue(
            pbSrc,
            cbSrc,
            nformat,
            pCurve.FMod,
            peTmp,
            pbScratch + cbLarge,
            cbScratch - cbLarge,
        );
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }
        pbSrc += cbSrc;
    }

    scError = SymCryptEcpointTransform(
        pCurve,
        poLarge,
        poDst,
        eformat,
        TRUE,
        flags,
        pbScratch + cbLarge,
        cbScratch - cbLarge,
    );

    return scError;
}

pub export fn SymCryptEcpointGetValue(
    pCurve: PCSYMCRYPT_ECURVE,
    poSrc: PCSYMCRYPT_ECPOINT,
    nformat: SYMCRYPT_NUMBER_FORMAT,
    eformat: SYMCRYPT_ECPOINT_FORMAT,
    pbDst_in: PBYTE,
    cbDst_in: SIZE_T,
    flags: UINT32,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NOT_IMPLEMENTED;
    var pbDst = pbDst_in;
    var cbDst = cbDst_in;

    macros.SYMCRYPT_ASSERT((flags & ~types.SYMCRYPT_FLAG_DATA_PUBLIC) == 0);
    macros.SYMCRYPT_ASSERT(@intFromPtr(pCurve.FMod) != 0);
    macros.SYMCRYPT_ASSERT(@backingInt(pCurve.eCoordinates) != 0);
    macros.SYMCRYPT_ASSERT(pCurve.cbModElement != 0);
    macros.SYMCRYPT_ASSERT(cbScratch >= types.SYMCRYPT_SCRATCH_BYTES_FOR_GETSET_VALUE_ECURVE_OPERATIONS(pCurve));

    const numElem = formatNumElements(eformat);
    if (numElem == 0 or cbDst != numElem * ecurve.SymCryptEcurveSizeofFieldElement(pCurve)) {
        return .SYMCRYPT_BUFFER_TOO_SMALL;
    }
    const cbDstElem = cbDst / numElem;

    const cbLarge = SymCryptSizeofEcpointEx(pCurve.cbModElement, types.SYMCRYPT_ECPOINT_FORMAT_MAX_LENGTH);
    macros.SYMCRYPT_ASSERT(cbScratch > cbLarge);
    const poLarge = SymCryptEcpointCreateEx(pbScratch, cbLarge, pCurve, types.SYMCRYPT_ECPOINT_FORMAT_MAX_LENGTH) orelse {
        return .SYMCRYPT_INVALID_BLOB;
    };

    scError = SymCryptEcpointTransform(
        pCurve,
        poSrc,
        poLarge,
        eformat,
        FALSE,
        flags,
        pbScratch + cbLarge,
        cbScratch - cbLarge,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    var i: UINT32 = 0;
    while (i < numElem) : (i += 1) {
        macros.SYMCRYPT_ASSERT(cbDst >= cbDstElem);
        const peTmp = types.SYMCRYPT_INTERNAL_ECPOINT_COORDINATE(i, pCurve, poLarge);
        scError = a_dispatch.SymCryptModElementGetValue(
            pCurve.FMod,
            peTmp,
            pbDst,
            cbDstElem,
            nformat,
            pbScratch + cbLarge,
            cbScratch - cbLarge,
        );
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }
        pbDst += cbDstElem;
        cbDst -= cbDstElem;
    }

    return scError;
}
