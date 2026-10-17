//
// ec_dh.zig   ECDH function
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

const types = @import("types.zig");
const macros = @import("macros.zig");
const ecurve = @import("ecurve.zig");
const ecpoint = @import("ecpoint.zig");
const ec_dispatch = @import("ec_dispatch.zig");

extern fn SymCryptCallbackAlloc(cbData: SIZE_T) callconv(SYMCRYPT_CALL) ?PBYTE;
extern fn SymCryptCallbackFree(pMem: *anyopaque) callconv(SYMCRYPT_CALL) void;

const PBYTE = types.PBYTE;
const UINT32 = types.UINT32;
const SIZE_T = types.SIZE_T;
const SYMCRYPT_CALL = types.SYMCRYPT_CALL;
const SYMCRYPT_ERROR = types.SYMCRYPT_ERROR;
const SYMCRYPT_NUMBER_FORMAT = types.SYMCRYPT_NUMBER_FORMAT;
const PCSYMCRYPT_ECURVE = types.PCSYMCRYPT_ECURVE;
const PSYMCRYPT_ECPOINT = types.PSYMCRYPT_ECPOINT;
const PCSYMCRYPT_ECKEY = types.PCSYMCRYPT_ECKEY;

pub export fn SymCryptEcDhSecretAgreement(
    pkPrivate: PCSYMCRYPT_ECKEY,
    pkPublic: PCSYMCRYPT_ECKEY,
    format: SYMCRYPT_NUMBER_FORMAT,
    flags: UINT32,
    pbAgreedSecret: PBYTE,
    cbAgreedSecret: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    @setRuntimeSafety(false);
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;
    var pbScratch: ?PBYTE = null;
    var cbScratch: SIZE_T = 0;

    defer {
        if (pbScratch) |ptr| {
            macros.SymCryptWipe(@ptrCast(ptr), cbScratch);
            SymCryptCallbackFree(@ptrCast(ptr));
        }
    }

    // Make sure that the keys may be used in ECDH
    if (((pkPrivate.fAlgorithmInfo & types.SYMCRYPT_FLAG_ECKEY_ECDH) == 0) or
        ((pkPublic.fAlgorithmInfo & types.SYMCRYPT_FLAG_ECKEY_ECDH) == 0))
    {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    // Make sure we only specify the correct flags and that
    // there is a private key
    if ((flags != 0) or (pkPrivate.hasPrivateKey == 0)) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    // Check that the curve is the same for both keys
    if (ecurve.SymCryptEcurveIsSame(pkPrivate.pCurve, pkPublic.pCurve) == 0) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }
    const pCurve: PCSYMCRYPT_ECURVE = pkPrivate.pCurve;

    // Objects and scratch space size calculation
    const cbQ: UINT32 = ecpoint.SymCryptSizeofEcpointFromCurve(pCurve);
    const cbX: UINT32 = ecurve.SymCryptEcurveSizeofFieldElement(pCurve);

    // Check the output buffer has the correct size
    if (cbAgreedSecret != cbX) {
        return .SYMCRYPT_WRONG_BLOCK_SIZE;
    }

    const cbScratchInternal: SIZE_T = @max(
        types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_ECURVE_OPERATIONS(pCurve),
        @max(
            types.SYMCRYPT_SCRATCH_BYTES_FOR_SCALAR_ECURVE_OPERATIONS(pCurve, 1),
            types.SYMCRYPT_SCRATCH_BYTES_FOR_GETSET_VALUE_ECURVE_OPERATIONS(pCurve),
        ),
    );

    cbScratch = cbScratchInternal + cbQ + cbX;

    // Scratch space allocation
    pbScratch = SymCryptCallbackAlloc(cbScratch) orelse {
        return .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
    };

    // Creating temporaries
    var pCurr: PBYTE = pbScratch.? + cbScratchInternal;
    const poQ: PSYMCRYPT_ECPOINT = ecpoint.SymCryptEcpointCreate(pCurr, cbQ, pCurve).?;
    pCurr += cbQ;
    const pbX: PBYTE = pCurr;

    // Make sure that the public key is not the zero point
    if (ec_dispatch.SymCryptEcpointIsZero(pCurve, pkPublic.poPublicKey, pbScratch.?, cbScratchInternal) != 0) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    // Calculate the secret
    scError = ec_dispatch.SymCryptEcpointScalarMul(
        pCurve,
        pkPrivate.piPrivateKey,
        pkPublic.poPublicKey,
        types.SYMCRYPT_FLAG_ECC_LL_COFACTOR_MUL,
        poQ,
        pbScratch.?,
        cbScratchInternal,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    // Check if the result is the identity point
    if (ec_dispatch.SymCryptEcpointIsZero(pCurve, poQ, pbScratch.?, cbScratchInternal) != 0) {
        return .SYMCRYPT_INVALID_BLOB;
    }

    // Get the x from poQ
    scError = ecpoint.SymCryptEcpointGetValue(
        pCurve,
        poQ,
        format,
        .SYMCRYPT_ECPOINT_FORMAT_X,
        pbX,
        cbX,
        0,
        pbScratch.?,
        cbScratchInternal,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    // Store it in the destination
    @memcpy(pbAgreedSecret[0..cbX], pbX[0..cbX]);

    return scError;
}
