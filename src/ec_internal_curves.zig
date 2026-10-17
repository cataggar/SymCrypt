//
// ec_internal_curves.zig   Caching of specific curve allocations in the main SymCrypt library
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

const std = @import("std");
const types = @import("types.zig");
const ec_internal_curve_params = @import("ec_internal_curve_params.zig");
const ecurve = @import("ecurve.zig");

const SYMCRYPT_CALL = types.SYMCRYPT_CALL;
const SYMCRYPT_CACHED_ECURVE_ID = types.SYMCRYPT_CACHED_ECURVE_ID;
const PSYMCRYPT_ECURVE = types.PSYMCRYPT_ECURVE;
const PCSYMCRYPT_ECURVE = types.PCSYMCRYPT_ECURVE;
const PCSYMCRYPT_ECURVE_PARAMS = types.PCSYMCRYPT_ECURVE_PARAMS;

const CACHED_CURVE_COUNT: usize = @intCast(@backingInt(SYMCRYPT_CACHED_ECURVE_ID.SYMCRYPT_CACHED_ECURVE_ID_COUNT));
var g_CachedCurves: [CACHED_CURVE_COUNT]?PSYMCRYPT_ECURVE = @splat(null);

fn getCurveParams(curveId: SYMCRYPT_CACHED_ECURVE_ID) ?PCSYMCRYPT_ECURVE_PARAMS {
    return switch (curveId) {
        .SYMCRYPT_CACHED_ECURVE_ID_NIST_P256 => ec_internal_curve_params.SymCryptEcurveParamsNistP256,
        .SYMCRYPT_CACHED_ECURVE_ID_NIST_P384 => ec_internal_curve_params.SymCryptEcurveParamsNistP384,
        .SYMCRYPT_CACHED_ECURVE_ID_CURVE_25519 => ec_internal_curve_params.SymCryptEcurveParamsCurve25519,
        else => null,
    };
}

pub export fn SymCryptGetCachedEcurve(curveId: SYMCRYPT_CACHED_ECURVE_ID) callconv(SYMCRYPT_CALL) ?PCSYMCRYPT_ECURVE {
    const idx_signed = @backingInt(curveId);
    if (idx_signed < 0 or idx_signed >= @backingInt(SYMCRYPT_CACHED_ECURVE_ID.SYMCRYPT_CACHED_ECURVE_ID_COUNT)) {
        return null;
    }
    const idx: usize = @intCast(idx_signed);

    var pCachedCurve = @atomicLoad(?PSYMCRYPT_ECURVE, &g_CachedCurves[idx], .seq_cst);
    if (pCachedCurve == null) {
        const pParams = getCurveParams(curveId) orelse return null;

        pCachedCurve = ecurve.SymCryptEcurveAllocate(pParams, 0);
        if (pCachedCurve != null) {
            if (@cmpxchgStrong(
                ?PSYMCRYPT_ECURVE,
                &g_CachedCurves[idx],
                null,
                pCachedCurve,
                .seq_cst,
                .seq_cst,
            ) != null) {
                ecurve.SymCryptEcurveFree(pCachedCurve.?);
                pCachedCurve = @atomicLoad(?PSYMCRYPT_ECURVE, &g_CachedCurves[idx], .seq_cst);
            }
        }
    }

    return if (pCachedCurve) |p| p else null;
}
