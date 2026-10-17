// Copyright (c) Microsoft Corporation. Licensed under the MIT license.

const std = @import("std");
const h = @import("main_harness.zig");
const cb = @import("callback.zig");

const SYMCRYPT_NO_ERROR: u32 = 0;
const SYMCRYPT_WRONG_KEY_SIZE: u32 = 0x8001;
const SYMCRYPT_INVALID_BLOB: u32 = 0x800c;
const SYMCRYPT_INVALID_ARGUMENT: u32 = 0x800e;

const SYMCRYPT_NUMBER_FORMAT_LSB_FIRST: i32 = 1;
const SYMCRYPT_NUMBER_FORMAT_MSB_FIRST: i32 = 2;

const SYMCRYPT_ECPOINT_FORMAT_X: i32 = 1;
const SYMCRYPT_ECPOINT_FORMAT_XY: i32 = 2;

const SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT_NULL: i32 = 0;
const SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT_SEC1_UNCOMPRESSED: i32 = 1;
const SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT_RAW_X_LE: i32 = 2;

const SYMCRYPT_ECKEY_IETF_PRIVATE_KEY_FORMAT_NULL: i32 = 0;
const SYMCRYPT_ECKEY_IETF_PRIVATE_KEY_FORMAT_NIST_SCALAR: i32 = 1;
const SYMCRYPT_ECKEY_IETF_PRIVATE_KEY_FORMAT_C25519: i32 = 2;

const SYMCRYPT_FLAG_ECKEY_ECDH: u32 = 0x2000;

const MAX_ENCODED_IETF_PK_SIZE: usize = 1 + 2 * 66;
const MAX_ENCODED_IETF_SK_SIZE: usize = 66;

extern const SymCryptEcurveParamsNistP256: *const anyopaque;
extern const SymCryptEcurveParamsNistP384: *const anyopaque;
extern const SymCryptEcurveParamsNistP521: *const anyopaque;
extern const SymCryptEcurveParamsCurve25519: *const anyopaque;

extern fn SymCryptEcurveAllocate(pParams: *const anyopaque, flags: u32) callconv(.c) ?*anyopaque;
extern fn SymCryptEcurveFree(pCurve: ?*anyopaque) callconv(.c) void;
extern fn SymCryptEckeyAllocate(pCurve: ?*const anyopaque) callconv(.c) ?*anyopaque;
extern fn SymCryptEckeyFree(pkObj: ?*anyopaque) callconv(.c) void;
extern fn SymCryptEckeySetRandom(flags: u32, pkDst: ?*anyopaque) callconv(.c) u32;
extern fn SymCryptEckeySizeofPublicKey(pkEckey: ?*const anyopaque, ecPointFormat: i32) callconv(.c) u32;
extern fn SymCryptEckeySizeofPrivateKey(pkEckey: ?*const anyopaque) callconv(.c) u32;
extern fn SymCryptEckeyGetValue(
    pkEckey: ?*const anyopaque,
    pbPrivateKey: ?[*]u8,
    cbPrivateKey: usize,
    pbPublicKey: ?[*]u8,
    cbPublicKey: usize,
    numFormat: i32,
    ecPointFormat: i32,
    flags: u32,
) callconv(.c) u32;
extern fn SymCryptEckeyGetValueIetfPublicKey(
    pEckey: ?*const anyopaque,
    format: i32,
    pbDst: [*]u8,
    cbDst: usize,
) callconv(.c) u32;
extern fn SymCryptEckeySetValueIetfPublicKey(
    pbSrc: [*]const u8,
    cbSrc: usize,
    format: i32,
    flags: u32,
    pEckey: ?*anyopaque,
) callconv(.c) u32;
extern fn SymCryptEckeySetValueIetfPrivateKey(
    pbSrc: [*]const u8,
    cbSrc: usize,
    format: i32,
    flags: u32,
    pEckey: ?*anyopaque,
) callconv(.c) u32;
extern fn SymCryptEcpointIsEqual(
    pCurve: ?*const anyopaque,
    poSrc1: ?*const anyopaque,
    poSrc2: ?*const anyopaque,
    flags: u32,
    pbScratch: [*]u8,
    cbScratch: usize,
) callconv(.c) u32;

extern fn SymCryptCallbackAlloc(nBytes: usize) callconv(.c) ?*anyopaque;
extern fn SymCryptCallbackFree(ptr: ?*anyopaque) callconv(.c) void;
extern fn SymCryptWipe(pbData: [*]u8, cbData: usize) callconv(.c) void;

extern fn scTestEckeyGetPublicKey(pkEckey: ?*const anyopaque) callconv(.c) ?*anyopaque;
extern fn scTestEcurveScratchCommon(pCurve: ?*const anyopaque) callconv(.c) u32;

const TestEcEncodingCurveParams = struct {
    pCurveParams: *const anyopaque,
    format: i32,
    privateFormat: i32,
    pszCurveName: [*:0]const u8,
};

fn testEcIetfPublicKeyEncoding() void {
    var scError: u32 = SYMCRYPT_NO_ERROR;

    h.ziprint("    > EC IETF Public Key Encoding Tests\n", .{});

    const rgTestEcEncodingCurveParams = [_]TestEcEncodingCurveParams{
        .{ .pCurveParams = SymCryptEcurveParamsNistP256, .format = SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT_SEC1_UNCOMPRESSED, .privateFormat = SYMCRYPT_ECKEY_IETF_PRIVATE_KEY_FORMAT_NIST_SCALAR, .pszCurveName = "nistP256" },
        .{ .pCurveParams = SymCryptEcurveParamsNistP384, .format = SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT_SEC1_UNCOMPRESSED, .privateFormat = SYMCRYPT_ECKEY_IETF_PRIVATE_KEY_FORMAT_NIST_SCALAR, .pszCurveName = "nistP384" },
        .{ .pCurveParams = SymCryptEcurveParamsNistP521, .format = SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT_SEC1_UNCOMPRESSED, .privateFormat = SYMCRYPT_ECKEY_IETF_PRIVATE_KEY_FORMAT_NIST_SCALAR, .pszCurveName = "nistP521" },
        .{ .pCurveParams = SymCryptEcurveParamsCurve25519, .format = SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT_RAW_X_LE, .privateFormat = SYMCRYPT_ECKEY_IETF_PRIVATE_KEY_FORMAT_C25519, .pszCurveName = "curve25519" },
    };

    for (rgTestEcEncodingCurveParams) |params| {
        var rgbEncodedPk: [MAX_ENCODED_IETF_PK_SIZE]u8 = undefined;
        var cbEncodedPk: usize = 0;
        var rgbEncodedSk: [MAX_ENCODED_IETF_SK_SIZE]u8 = undefined;
        var cbEncodedSk: usize = 0;
        var privateNumFormat: i32 = SYMCRYPT_NUMBER_FORMAT_MSB_FIRST;
        var privateEcPointFormat: i32 = SYMCRYPT_ECPOINT_FORMAT_XY;

        h.ziprint("        Testing curve {s}\n", .{std.mem.span(params.pszCurveName)});

        const pCurve = SymCryptEcurveAllocate(params.pCurveParams, 0);
        h.check3(pCurve != null, "SymCryptEcurveAllocate failed for curve %s", params.pszCurveName);

        const cbScratch: usize = scTestEcurveScratchCommon(pCurve);
        const pbScratchRaw = SymCryptCallbackAlloc(cbScratch);
        h.check(pbScratchRaw != null, "Scratch allocation failed");
        const pbScratch: [*]u8 = @ptrCast(pbScratchRaw.?);

        const pEckey = SymCryptEckeyAllocate(pCurve);
        h.check3(pEckey != null, "SymCryptEckeyAllocate failed for curve %s", params.pszCurveName);

        const pEckeyDecoded = SymCryptEckeyAllocate(pCurve);
        h.check3(pEckeyDecoded != null, "SymCryptEckeyAllocate failed for curve %s", params.pszCurveName);

        switch (params.format) {
            SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT_SEC1_UNCOMPRESSED => {
                cbEncodedPk = 1 + SymCryptEckeySizeofPublicKey(pEckey, SYMCRYPT_ECPOINT_FORMAT_XY);
            },
            SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT_RAW_X_LE => {
                cbEncodedPk = SymCryptEckeySizeofPublicKey(pEckey, SYMCRYPT_ECPOINT_FORMAT_X);
            },
            else => {
                cbEncodedPk = 0;
                h.check(false, "Unexpected format");
            },
        }
        h.check(cbEncodedPk <= MAX_ENCODED_IETF_PK_SIZE, "MAX_ENCODED_IETF_PK_SIZE is too small");

        switch (params.privateFormat) {
            SYMCRYPT_ECKEY_IETF_PRIVATE_KEY_FORMAT_NIST_SCALAR => {
                privateNumFormat = SYMCRYPT_NUMBER_FORMAT_MSB_FIRST;
                privateEcPointFormat = SYMCRYPT_ECPOINT_FORMAT_XY;
            },
            SYMCRYPT_ECKEY_IETF_PRIVATE_KEY_FORMAT_C25519 => {
                privateNumFormat = SYMCRYPT_NUMBER_FORMAT_LSB_FIRST;
                privateEcPointFormat = SYMCRYPT_ECPOINT_FORMAT_X;
            },
            else => {
                h.check(false, "Unexpected private format");
            },
        }
        cbEncodedSk = SymCryptEckeySizeofPrivateKey(pEckey);
        h.check(cbEncodedSk <= MAX_ENCODED_IETF_SK_SIZE, "MAX_ENCODED_IETF_SK_SIZE is too small");

        var iter: u32 = 0;
        while (iter < 10) : (iter += 1) {
            scError = SymCryptEckeySetRandom(SYMCRYPT_FLAG_ECKEY_ECDH, pEckey);
            h.check3(scError == SYMCRYPT_NO_ERROR, "SymCryptEckeySetRandom failed for curve %s", params.pszCurveName);

            scError = SymCryptEckeyGetValueIetfPublicKey(pEckey, params.format, &rgbEncodedPk, cbEncodedPk + 1);
            h.check3(
                scError == SYMCRYPT_WRONG_KEY_SIZE,
                "SymCryptEckeyGetValueIetfPublicKey should fail with incorrect size (curve %s)",
                params.pszCurveName,
            );

            scError = SymCryptEckeyGetValueIetfPublicKey(pEckey, params.format, &rgbEncodedPk, cbEncodedPk);
            h.check3(
                scError == SYMCRYPT_NO_ERROR,
                "SymCryptEckeyGetValueIetfPublicKey failed for curve %s",
                params.pszCurveName,
            );

            if (params.format == SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT_SEC1_UNCOMPRESSED) {
                h.check3(
                    rgbEncodedPk[0] == 0x04,
                    "Expected SEC1 uncompressed tag for curve %s",
                    params.pszCurveName,
                );
            }

            scError = SymCryptEckeySetValueIetfPublicKey(&rgbEncodedPk, cbEncodedPk + 1, params.format, SYMCRYPT_FLAG_ECKEY_ECDH, pEckeyDecoded);
            h.check3(
                scError == SYMCRYPT_WRONG_KEY_SIZE,
                "SymCryptEckeySetValueIetfPublicKey should fail with incorrect size (curve %s)",
                params.pszCurveName,
            );

            scError = SymCryptEckeySetValueIetfPublicKey(&rgbEncodedPk, cbEncodedPk, params.format, SYMCRYPT_FLAG_ECKEY_ECDH, pEckeyDecoded);
            h.check3(
                scError == SYMCRYPT_NO_ERROR,
                "SymCryptEckeySetValueIetfPublicKey failed for curve %s",
                params.pszCurveName,
            );

            h.check(
                SymCryptEcpointIsEqual(pCurve, scTestEckeyGetPublicKey(pEckeyDecoded), scTestEckeyGetPublicKey(pEckey), 0, pbScratch, cbScratch) != 0,
                "Decoded public key does not match original",
            );

            scError = SymCryptEckeyGetValue(
                pEckey,
                &rgbEncodedSk,
                cbEncodedSk,
                null,
                0,
                privateNumFormat,
                privateEcPointFormat,
                0,
            );
            h.check3(
                scError == SYMCRYPT_NO_ERROR,
                "SymCryptEckeyGetValue private key failed for curve %s",
                params.pszCurveName,
            );

            scError = SymCryptEckeySetValueIetfPrivateKey(
                &rgbEncodedSk,
                cbEncodedSk + 1,
                params.privateFormat,
                SYMCRYPT_FLAG_ECKEY_ECDH,
                pEckeyDecoded,
            );
            h.check3(
                scError == SYMCRYPT_WRONG_KEY_SIZE,
                "SymCryptEckeySetValueIetfPrivateKey should fail with incorrect size (curve %s)",
                params.pszCurveName,
            );

            scError = SymCryptEckeySetValueIetfPrivateKey(
                &rgbEncodedSk,
                cbEncodedSk,
                params.privateFormat,
                SYMCRYPT_FLAG_ECKEY_ECDH,
                pEckeyDecoded,
            );
            h.check3(
                scError == SYMCRYPT_NO_ERROR,
                "SymCryptEckeySetValueIetfPrivateKey failed for curve %s",
                params.pszCurveName,
            );

            h.check(
                SymCryptEcpointIsEqual(pCurve, scTestEckeyGetPublicKey(pEckeyDecoded), scTestEckeyGetPublicKey(pEckey), 0, pbScratch, cbScratch) != 0,
                "Decoded private key public point does not match original",
            );
        }

        if (params.format == SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT_SEC1_UNCOMPRESSED) {
            scError = SymCryptEckeySetRandom(SYMCRYPT_FLAG_ECKEY_ECDH, pEckey);
            h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptEckeySetRandom failed");

            scError = SymCryptEckeyGetValueIetfPublicKey(pEckey, params.format, &rgbEncodedPk, cbEncodedPk);
            h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptEckeyGetValueIetfPublicKey failed");

            rgbEncodedPk[0] ^= 0x01;
            scError = SymCryptEckeySetValueIetfPublicKey(&rgbEncodedPk, cbEncodedPk, params.format, SYMCRYPT_FLAG_ECKEY_ECDH, pEckeyDecoded);
            h.check3(
                scError == SYMCRYPT_INVALID_BLOB,
                "SymCryptEckeySetValueIetfPublicKey should reject corrupted SEC1 tag (curve %s)",
                params.pszCurveName,
            );
        }

        scError = SymCryptEckeyGetValueIetfPublicKey(pEckey, SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT_NULL, &rgbEncodedPk, cbEncodedPk);
        h.check(
            scError == SYMCRYPT_INVALID_ARGUMENT,
            "SymCryptEckeyGetValueIetfPublicKey should reject NULL format",
        );

        scError = SymCryptEckeySetValueIetfPublicKey(&rgbEncodedPk, cbEncodedPk, SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT_NULL, SYMCRYPT_FLAG_ECKEY_ECDH, pEckeyDecoded);
        h.check(
            scError == SYMCRYPT_INVALID_ARGUMENT,
            "SymCryptEckeySetValueIetfPublicKey should reject NULL format",
        );

        scError = SymCryptEckeySetValueIetfPrivateKey(&rgbEncodedSk, cbEncodedSk, SYMCRYPT_ECKEY_IETF_PRIVATE_KEY_FORMAT_NULL, SYMCRYPT_FLAG_ECKEY_ECDH, pEckeyDecoded);
        h.check(
            scError == SYMCRYPT_INVALID_ARGUMENT,
            "SymCryptEckeySetValueIetfPrivateKey should reject NULL format",
        );

        SymCryptEckeyFree(pEckeyDecoded);
        SymCryptEckeyFree(pEckey);
        SymCryptWipe(pbScratch, cbScratch);
        SymCryptCallbackFree(pbScratch);
        SymCryptEcurveFree(pCurve);
    }
}

pub export fn testEcEncoding() callconv(.c) void {
    h.ziprint("    EC Encoding\n", .{});

    testEcIetfPublicKeyEncoding();

    const nOutstandingAllocs = @atomicLoad(i64, &cb.g_nOutstandingCheckedAllocs, .seq_cst);
    h.check3(nOutstandingAllocs == 0, "Memory leak, %d outstanding", nOutstandingAllocs);
}
