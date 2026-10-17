//
// dh.zig   Diffie-Hellman secret agreement algorithm
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

const types = @import("types.zig");
const fips_selftest = @import("fips_selftest.zig");
const a_dispatch = @import("a_dispatch.zig");
const dlgroup = @import("dlgroup.zig");
const dlkey = @import("dlkey.zig");

const SYMCRYPT_CALL = types.SYMCRYPT_CALL;
const SYMCRYPT_ERROR = types.SYMCRYPT_ERROR;
const SYMCRYPT_NUMBER_FORMAT = types.SYMCRYPT_NUMBER_FORMAT;
const PBYTE = types.PBYTE;
const UINT32 = types.UINT32;
const SIZE_T = types.SIZE_T;
const PVOID = types.PVOID;
const PCSYMCRYPT_DLGROUP = types.PCSYMCRYPT_DLGROUP;
const PCSYMCRYPT_DLKEY = types.PCSYMCRYPT_DLKEY;

extern fn SymCryptCallbackAlloc(nBytes: SIZE_T) callconv(SYMCRYPT_CALL) ?PBYTE;
extern fn SymCryptCallbackFree(pMem: PVOID) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptWipe(pbData: PVOID, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void;

pub const SymCryptDhSecretAgreementSelftest = fips_selftest.SymCryptDhSecretAgreementSelftest;

pub export fn SymCryptDhSecretAgreement(
    pkPrivate: PCSYMCRYPT_DLKEY,
    pkPublic: PCSYMCRYPT_DLKEY,
    format: SYMCRYPT_NUMBER_FORMAT,
    flags: UINT32,
    pbAgreedSecret: PBYTE,
    cbAgreedSecret: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;
    var pbScratch: ?PBYTE = null;
    var cbScratch: SIZE_T = 0;

    defer {
        if (pbScratch) |ptr| {
            SymCryptWipe(@ptrCast(ptr), cbScratch);
            SymCryptCallbackFree(@ptrCast(ptr));
        }
    }

    // Make sure that the keys may be used in DH
    if (((pkPrivate.fAlgorithmInfo & types.SYMCRYPT_FLAG_DLKEY_DH) == 0) or
        ((pkPublic.fAlgorithmInfo & types.SYMCRYPT_FLAG_DLKEY_DH) == 0))
    {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    // Make sure we only specify the correct flags and that
    // there is a private key
    if ((flags != 0) or (pkPrivate.fHasPrivateKey == 0)) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    // Check that the group is the same for both keys
    var pDlgroup: PCSYMCRYPT_DLGROUP = undefined;
    if (dlgroup.SymCryptDlgroupIsSame(pkPrivate.pDlgroup, pkPublic.pDlgroup) != 0) {
        pDlgroup = pkPrivate.pDlgroup;
    } else {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    // Check the output buffer has the correct size
    if (cbAgreedSecret != dlkey.SymCryptDlkeySizeofPublicKey(pkPrivate)) {
        return .SYMCRYPT_WRONG_BLOCK_SIZE;
    }

    // Objects and scratch space size calculation
    const cbModelement: UINT32 = a_dispatch.SymCryptSizeofModElementFromModulus(pDlgroup.pmP);
    cbScratch = @as(SIZE_T, cbModelement) +
        @max(
            types.SYMCRYPT_SCRATCH_BYTES_FOR_MODEXP(pDlgroup.nDigitsOfP),
            types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(pDlgroup.nDigitsOfP),
        );

    // Scratch space allocation
    pbScratch = SymCryptCallbackAlloc(cbScratch);
    if (pbScratch == null) {
        return .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
    }

    // Creating temporary
    var pbScratchInternal: PBYTE = pbScratch.?;
    var cbScratchInternal: SIZE_T = cbScratch;
    const peRes = a_dispatch.SymCryptModElementCreate(pbScratchInternal, cbModelement, pDlgroup.pmP).?;
    pbScratchInternal += cbModelement;
    cbScratchInternal -= cbModelement;

    // Fix the bits of the exponent (the private key might be either mod Q, mod 2^nBitsPriv, or mod P)
    const nBitsOfExp: UINT32 = if (pkPrivate.fPrivateModQ != 0) pkPrivate.nBitsPriv else pDlgroup.nBitsOfP;

    // Calculate the secret
    a_dispatch.SymCryptModExp(
        pDlgroup.pmP,
        pkPublic.pePublicKey,
        pkPrivate.piPrivateKey.?,
        nBitsOfExp,
        0, // SC safe
        peRes,
        pbScratchInternal,
        cbScratchInternal,
    );

    // Check if the result is zero
    if (a_dispatch.SymCryptModElementIsZero(pDlgroup.pmP, peRes) != 0) {
        return .SYMCRYPT_INVALID_BLOB;
    }

    // Output the result
    scError = a_dispatch.SymCryptModElementGetValue(
        pDlgroup.pmP,
        peRes,
        pbAgreedSecret,
        cbAgreedSecret,
        format,
        pbScratchInternal,
        cbScratchInternal,
    );
    return scError;
}
