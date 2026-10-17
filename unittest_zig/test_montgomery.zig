// Copyright (c) Microsoft Corporation. Licensed under the MIT license.

const std = @import("std");
const h = @import("main_harness.zig");
const rng = @import("rng.zig");

const SYMCRYPT_NO_ERROR: u32 = 0;

const SYMCRYPT_NUMBER_FORMAT_LSB_FIRST: i32 = 1;
const SYMCRYPT_NUMBER_FORMAT_MSB_FIRST: i32 = 2;
const SYMCRYPT_ECPOINT_FORMAT_XY: i32 = 2;

const SYMCRYPT_FLAG_DATA_PUBLIC: u32 = 0x01;
const SYMCRYPT_FLAG_ECKEY_ECDSA: u32 = 0x1000;
const SYMCRYPT_FLAG_ECKEY_ECDH: u32 = 0x2000;
const NUM_OF_HIGH_BIT_RESTRICTION_ITERATIONS: u32 = 100;

extern fn SymCryptEcurveSizeofFieldElement(pCurve: ?*const anyopaque) callconv(.c) u32;
extern fn SymCryptEcurveDigitsofScalarMultiplier(pCurve: ?*const anyopaque) callconv(.c) u32;
extern fn SymCryptEcurveHighBitRestrictionNumOfBits(pCurve: ?*const anyopaque) callconv(.c) u32;
extern fn SymCryptEcurveHighBitRestrictionValue(pCurve: ?*const anyopaque) callconv(.c) u32;
extern fn SymCryptEcpointAllocate(pCurve: ?*const anyopaque) callconv(.c) ?*anyopaque;
extern fn SymCryptEcpointFree(pCurve: ?*const anyopaque, poDst: ?*anyopaque) callconv(.c) void;
extern fn SymCryptEcpointSetDistinguishedPoint(
    pCurve: ?*const anyopaque,
    poDst: ?*anyopaque,
    pbScratch: [*]u8,
    cbScratch: usize,
) callconv(.c) void;
extern fn SymCryptEcpointSetValue(
    pCurve: ?*const anyopaque,
    pbSrc: [*]const u8,
    cbSrc: usize,
    numFormat: i32,
    ecPointFormat: i32,
    poDst: ?*anyopaque,
    flags: u32,
    pbScratch: [*]u8,
    cbScratch: usize,
) callconv(.c) u32;
extern fn SymCryptEcpointGetValue(
    pCurve: ?*const anyopaque,
    poSrc: ?*const anyopaque,
    numFormat: i32,
    ecPointFormat: i32,
    pbDst: [*]u8,
    cbDst: usize,
    flags: u32,
    pbScratch: [*]u8,
    cbScratch: usize,
) callconv(.c) u32;
extern fn SymCryptEcpointScalarMul(
    pCurve: ?*const anyopaque,
    piScalar: ?*const anyopaque,
    poSrc: ?*const anyopaque,
    flags: u32,
    poDst: ?*anyopaque,
    pbScratch: [*]u8,
    cbScratch: usize,
) callconv(.c) u32;
extern fn SymCryptEcpointIsEqual(
    pCurve: ?*const anyopaque,
    poSrc1: ?*const anyopaque,
    poSrc2: ?*const anyopaque,
    flags: u32,
    pbScratch: [*]u8,
    cbScratch: usize,
) callconv(.c) u32;

extern fn SymCryptEckeyAllocate(pCurve: ?*const anyopaque) callconv(.c) ?*anyopaque;
extern fn SymCryptEckeyFree(pkObj: ?*anyopaque) callconv(.c) void;
extern fn SymCryptEckeySizeofPrivateKey(pkEckey: ?*const anyopaque) callconv(.c) u32;
extern fn SymCryptEckeySetRandom(flags: u32, pkDst: ?*anyopaque) callconv(.c) u32;
extern fn SymCryptEckeySetValue(
    pbPrivateKey: ?[*]const u8,
    cbPrivateKey: usize,
    pbPublicKey: ?[*]const u8,
    cbPublicKey: usize,
    numFormat: i32,
    ecPointFormat: i32,
    flags: u32,
    pkDst: ?*anyopaque,
) callconv(.c) u32;
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
extern fn SymCryptEcDhSecretAgreement(
    pkPrivate: ?*const anyopaque,
    pkPublic: ?*const anyopaque,
    numFormat: i32,
    flags: u32,
    pbAgreedSecret: [*]u8,
    cbAgreedSecret: usize,
) callconv(.c) u32;

extern fn SymCryptIntAllocate(nDigits: u32) callconv(.c) ?*anyopaque;
extern fn SymCryptIntFree(piObj: ?*anyopaque) callconv(.c) void;
extern fn SymCryptIntSetValue(pbSrc: [*]const u8, cbSrc: usize, format: i32, piDst: ?*anyopaque) callconv(.c) u32;
extern fn SymCryptIntIsEqual(piSrc1: ?*const anyopaque, piSrc2: ?*const anyopaque) callconv(.c) u32;

extern fn SymCryptCallbackAlloc(nBytes: usize) callconv(.c) ?*anyopaque;
extern fn SymCryptCallbackFree(ptr: ?*anyopaque) callconv(.c) void;
extern fn SymCryptWipe(pbData: [*]u8, cbData: usize) callconv(.c) void;

extern fn scTestEcurveScratchScalar(pCurve: ?*const anyopaque) callconv(.c) u32;
extern fn scTestEckeyGetPublicKey(pkEckey: ?*const anyopaque) callconv(.c) ?*anyopaque;
extern fn scTestEckeyGetPrivateKey(pkEckey: ?*const anyopaque) callconv(.c) ?*anyopaque;

const private_key_1 = [32]u8{
    0x6A, 0x2C, 0xB9, 0x1D, 0xA5, 0xFB, 0x77, 0xB1, 0x2A, 0x99, 0xC0, 0xEB, 0x87, 0x2F, 0x4C, 0xDF,
    0x45, 0x66, 0xB2, 0x51, 0x72, 0xC1, 0x16, 0x3C, 0x7D, 0xA5, 0x18, 0x73, 0x0A, 0x6D, 0x07, 0x70,
};

const public_key_1 = [32]u8{
    0x85, 0x20, 0xF0, 0x09, 0x89, 0x30, 0xA7, 0x54, 0x74, 0x8B, 0x7D, 0xDC, 0xB4, 0x3E, 0xF7, 0x5A,
    0x0D, 0xBF, 0x3A, 0x0D, 0x26, 0x38, 0x1A, 0xF4, 0xEB, 0xA4, 0xA9, 0x8E, 0xAA, 0x9B, 0x4E, 0x6A,
};

const public_key_1_xy = [64]u8{
    0x85, 0x20, 0xF0, 0x09, 0x89, 0x30, 0xA7, 0x54, 0x74, 0x8B, 0x7D, 0xDC, 0xB4, 0x3E, 0xF7, 0x5A,
    0x0D, 0xBF, 0x3A, 0x0D, 0x26, 0x38, 0x1A, 0xF4, 0xEB, 0xA4, 0xA9, 0x8E, 0xAA, 0x9B, 0x4E, 0x6A,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

const private_key_2 = [32]u8{
    0x6B, 0xE0, 0x88, 0xFF, 0x27, 0x8B, 0x2F, 0x1C, 0xFD, 0xB6, 0x18, 0x26, 0x29, 0xB1, 0x3B, 0x6F,
    0xE6, 0x0E, 0x80, 0x83, 0x8B, 0x7F, 0xE1, 0x79, 0x4B, 0x8A, 0x4A, 0x62, 0x7E, 0x08, 0xAB, 0x58,
};

const public_key_2 = [32]u8{
    0xDE, 0x9E, 0xDB, 0x7D, 0x7B, 0x7D, 0xC1, 0xB4, 0xD3, 0x5B, 0x61, 0xC2, 0xEC, 0xE4, 0x35, 0x37,
    0x3F, 0x83, 0x43, 0xC8, 0x5B, 0x78, 0x67, 0x4D, 0xAD, 0xFC, 0x7E, 0x14, 0x6F, 0x88, 0x2B, 0x4F,
};

const public_key_2_xy = [64]u8{
    0xDE, 0x9E, 0xDB, 0x7D, 0x7B, 0x7D, 0xC1, 0xB4, 0xD3, 0x5B, 0x61, 0xC2, 0xEC, 0xE4, 0x35, 0x37,
    0x3F, 0x83, 0x43, 0xC8, 0x5B, 0x78, 0x67, 0x4D, 0xAD, 0xFC, 0x7E, 0x14, 0x6F, 0x88, 0x2B, 0x4F,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

const shared_secret = [32]u8{
    0x4A, 0x5D, 0x9D, 0x5B, 0xA4, 0xCE, 0x2D, 0xE1, 0x72, 0x8E, 0x3B, 0xF4, 0x80, 0x35, 0x0F, 0x25,
    0xE0, 0x7E, 0x21, 0xC9, 0x47, 0xD1, 0x9E, 0x33, 0x76, 0xF0, 0x9B, 0x3C, 0x1E, 0x16, 0x17, 0x42,
};

fn testSymCryptMontgomeryPointScalarMul(
    pCurve: ?*const anyopaque,
    piScalar: ?*const anyopaque,
    poSrc: ?*const anyopaque,
    flags: u32,
    poDst: ?*anyopaque,
    pbResult: [*]const u8,
    cbResult: u32,
    pbScratch: [*]u8,
    cbScratch: usize,
) void {
    var pbX: [64]u8 = undefined;

    var scError = SymCryptEcpointScalarMul(
        pCurve,
        piScalar,
        poSrc,
        flags,
        poDst,
        pbScratch,
        cbScratch,
    );
    h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptMontgomeryPointScalarMul failed.\n");

    scError = SymCryptEcpointGetValue(
        pCurve,
        poDst,
        SYMCRYPT_NUMBER_FORMAT_LSB_FIRST,
        SYMCRYPT_ECPOINT_FORMAT_XY,
        &pbX,
        64,
        rng.scTestRngUint32(&rng.g_rng) & SYMCRYPT_FLAG_DATA_PUBLIC,
        pbScratch,
        cbScratch,
    );
    h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptEcpointGetValue failed.\n");
    h.check(std.mem.eql(u8, pbX[0..cbResult], pbResult[0..cbResult]), "Fail");

    h.vprint(h.g_verbose != 0, "Success\n", .{});
}

pub export fn testMontgomery(pCurve: ?*anyopaque) callconv(.c) void {
    var scError: u32 = SYMCRYPT_NO_ERROR;
    var msbCounter: u32 = NUM_OF_HIGH_BIT_RESTRICTION_ITERATIONS;
    var msbNumOfBits: u32 = 0;
    var msbValue: u32 = 0;
    var msbMask: u32 = 0;
    var msbActual: u32 = 0;

    const cbAgreedSecret: usize = SymCryptEcurveSizeofFieldElement(pCurve);
    const cbScratch: usize = scTestEcurveScratchScalar(pCurve);

    h.vprint(h.g_verbose != 0, "    ..................................................................................................\n", .{});
    h.vprint(h.g_verbose != 0, "    {s: <41}", .{"Operation"});
    h.vprint(h.g_verbose != 0, " {s: <40}", .{"Method"});
    h.vprint(h.g_verbose != 0, "Result\n", .{});
    h.vprint(h.g_verbose != 0, "    ..................................................................................................\n", .{});

    const cbWorkspace: usize = 2 * cbAgreedSecret + cbScratch;
    const pbWorkspaceRaw = SymCryptCallbackAlloc(cbWorkspace);
    if (pbWorkspaceRaw == null) {
        h.vprint(h.g_verbose != 0, " Memory allocation failed in Test.", .{});
        return;
    }
    const pbWorkspace: [*]u8 = @ptrCast(pbWorkspaceRaw.?);

    const pbAgreedSecret1: [*]u8 = pbWorkspace;
    const pbAgreedSecret2: [*]u8 = pbWorkspace + cbAgreedSecret;
    const pbScratch: [*]u8 = pbWorkspace + 2 * cbAgreedSecret;

    const piScalar = SymCryptIntAllocate(SymCryptEcurveDigitsofScalarMultiplier(pCurve));
    const poSrc = SymCryptEcpointAllocate(pCurve);
    const poDst = SymCryptEcpointAllocate(pCurve);
    const poDst2 = SymCryptEcpointAllocate(pCurve);
    const pkKey1 = SymCryptEckeyAllocate(pCurve);
    const pkKey2 = SymCryptEckeyAllocate(pCurve);

    h.vprint(h.g_verbose != 0, "    {s: <41}", .{"G_x * private_key_1"});
    h.vprint(h.g_verbose != 0, " {s: <40}", .{"SymCryptEcpointScalarMul"});
    _ = SymCryptIntSetValue(&private_key_1, 32, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, piScalar);
    SymCryptEcpointSetDistinguishedPoint(pCurve, poSrc, pbScratch, cbScratch);
    testSymCryptMontgomeryPointScalarMul(pCurve, piScalar, poSrc, 0, poDst, &public_key_1, 32, pbScratch, cbScratch);

    h.vprint(h.g_verbose != 0, "    {s: <41}", .{"G_x * private_key_2"});
    h.vprint(h.g_verbose != 0, " {s: <40}", .{"SymCryptEcpointScalarMul"});
    _ = SymCryptIntSetValue(&private_key_2, 32, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, piScalar);
    testSymCryptMontgomeryPointScalarMul(pCurve, piScalar, null, 0, poDst, &public_key_2, 32, pbScratch, cbScratch);

    h.vprint(h.g_verbose != 0, "    {s: <41}", .{"public_key_1 * private_key2"});
    h.vprint(h.g_verbose != 0, " {s: <40}", .{"SymCryptEcpointScalarMul"});
    _ = SymCryptIntSetValue(&private_key_2, 32, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, piScalar);
    _ = SymCryptEcpointSetValue(
        pCurve,
        &public_key_1_xy,
        64,
        SYMCRYPT_NUMBER_FORMAT_LSB_FIRST,
        SYMCRYPT_ECPOINT_FORMAT_XY,
        poSrc,
        rng.scTestRngUint32(&rng.g_rng) & SYMCRYPT_FLAG_DATA_PUBLIC,
        pbScratch,
        cbScratch,
    );
    testSymCryptMontgomeryPointScalarMul(pCurve, piScalar, poSrc, 0, poDst, &shared_secret, 32, pbScratch, cbScratch);

    h.vprint(h.g_verbose != 0, "    {s: <41}", .{"public_key_2 * private_key1"});
    h.vprint(h.g_verbose != 0, " {s: <40}", .{"SymCryptEcpointScalarMul"});
    _ = SymCryptIntSetValue(&private_key_1, 32, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, piScalar);
    _ = SymCryptEcpointSetValue(
        pCurve,
        &public_key_2_xy,
        64,
        SYMCRYPT_NUMBER_FORMAT_LSB_FIRST,
        SYMCRYPT_ECPOINT_FORMAT_XY,
        poSrc,
        rng.scTestRngUint32(&rng.g_rng) & SYMCRYPT_FLAG_DATA_PUBLIC,
        pbScratch,
        cbScratch,
    );
    testSymCryptMontgomeryPointScalarMul(pCurve, piScalar, poSrc, 0, poDst2, &shared_secret, 32, pbScratch, cbScratch);

    h.vprint(h.g_verbose != 0, "    {s: <41}", .{"public_key_1 * private_key2 == public_key_2 * private_key1"});
    h.vprint(h.g_verbose != 0, " {s: <40}", .{"SymCryptEcpointIsEqual"});
    h.check(SymCryptEcpointIsEqual(pCurve, poDst, poDst, 0, pbScratch, cbScratch) != 0, "poDst != poDst");
    h.check(SymCryptEcpointIsEqual(pCurve, poDst, poDst2, 0, pbScratch, cbScratch) != 0, "poDst != poDst2");
    h.check(SymCryptEcpointIsEqual(pCurve, poSrc, poDst, 0, pbScratch, cbScratch) == 0, "poSrc == poDst");

    h.vprint(h.g_verbose != 0, "    {s: <41}", .{"Set K1 to a uniformly random eckey"});
    h.vprint(h.g_verbose != 0, " {s: <40}", .{"SymCryptEckeySetRandom"});

    msbNumOfBits = SymCryptEcurveHighBitRestrictionNumOfBits(pCurve);
    h.check(msbNumOfBits < 33, "Invalid high bit restriction num of bits");
    if (msbNumOfBits != 0) {
        const shift: u5 = @intCast(32 - msbNumOfBits);
        msbMask = @as(u32, 0xffffffff) << shift;
        msbValue = SymCryptEcurveHighBitRestrictionValue(pCurve) << shift;
    }

    while (true) {
        scError = SymCryptEckeySetRandom(SYMCRYPT_FLAG_ECKEY_ECDH, pkKey1);
        h.check(scError == SYMCRYPT_NO_ERROR, "Set random key failed");

        scError = SymCryptEcpointScalarMul(pCurve, scTestEckeyGetPrivateKey(pkKey1), null, 0, poSrc, pbScratch, cbScratch);
        h.check(scError == SYMCRYPT_NO_ERROR, "Scalar Multiplying private key failed");

        scError = SymCryptEckeyGetValue(
            pkKey1,
            pbScratch,
            SymCryptEckeySizeofPrivateKey(pkKey1),
            null,
            0,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            SYMCRYPT_ECPOINT_FORMAT_XY,
            0,
        );
        h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptEckeyGetValue private key failed");

        msbActual = (@as(u32, pbScratch[0]) << 24) | (@as(u32, pbScratch[1]) << 16) | (@as(u32, pbScratch[2]) << 8) | @as(u32, pbScratch[3]);
        h.check5(
            (msbActual & msbMask) == msbValue,
            "High bit restriction failed. \n  Recvd: 0x%04X\n  Mask : 0x%04X\n  Bits : 0x%04X",
            msbActual,
            msbMask,
            msbValue,
        );

        scError = SymCryptEckeySetValue(
            pbScratch,
            SymCryptEckeySizeofPrivateKey(pkKey1),
            null,
            0,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            SYMCRYPT_ECPOINT_FORMAT_XY,
            SYMCRYPT_FLAG_ECKEY_ECDSA | SYMCRYPT_FLAG_ECKEY_ECDH,
            pkKey2,
        );
        h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptEckeySetValue private key failed");

        h.check(
            SymCryptIntIsEqual(scTestEckeyGetPrivateKey(pkKey1), scTestEckeyGetPrivateKey(pkKey2)) != 0,
            " pkKey1->piPrivateKey != pkKey2->piPrivateKey ",
        );
        h.check(
            SymCryptEcpointIsEqual(pCurve, scTestEckeyGetPublicKey(pkKey1), scTestEckeyGetPublicKey(pkKey2), 0, pbScratch, cbScratch) != 0,
            " pkKey1->poPublicKey != pkKey2->poPublicKey ",
        );

        msbCounter -= 1;
        if (!(msbCounter > 0 and msbNumOfBits > 0)) break;
    }

    h.vprint(h.g_verbose != 0, "Success\n", .{});

    scError = SymCryptEckeySetRandom(SYMCRYPT_FLAG_ECKEY_ECDH, pkKey2);
    h.check(scError == SYMCRYPT_NO_ERROR, "Set random key failed");

    h.vprint(h.g_verbose != 0, "    {s: <41}", .{"ECDH Algorithm"});
    h.vprint(h.g_verbose != 0, " {s: <40}", .{"SymCryptEcDhSecretAgreement"});
    scError = SymCryptEcDhSecretAgreement(
        pkKey1,
        pkKey2,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        0,
        pbAgreedSecret1,
        cbAgreedSecret,
    );
    h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptEcDhSecretAgreement failed");
    h.vprint(h.g_verbose != 0, "Success\n", .{});

    scError = SymCryptEcDhSecretAgreement(
        pkKey2,
        pkKey1,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        0,
        pbAgreedSecret2,
        cbAgreedSecret,
    );
    h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptEcDhSecretAgreement failed");
    h.vprint(h.g_verbose != 0, "Success\n", .{});

    h.check(
        std.mem.eql(u8, pbAgreedSecret1[0..cbAgreedSecret], pbAgreedSecret2[0..cbAgreedSecret]),
        "SymCryptEcDhSecretAgreement is inconsistent between two parties",
    );
    h.vprint(h.g_verbose != 0, "Success\n", .{});

    h.vprint(h.g_verbose != 0, "    {s: <41}", .{"Wiping and freeing stuff "});
    h.vprint(h.g_verbose != 0, " {s: <40}", .{"SymCryptWipe"});
    SymCryptIntFree(piScalar);
    SymCryptEcpointFree(pCurve, poSrc);
    SymCryptEcpointFree(pCurve, poDst);
    SymCryptEcpointFree(pCurve, poDst2);
    SymCryptEckeyFree(pkKey1);
    SymCryptEckeyFree(pkKey2);

    SymCryptWipe(pbWorkspace, cbWorkspace);
    SymCryptCallbackFree(pbWorkspace);
    h.vprint(h.g_verbose != 0, "Success\n", .{});
}
