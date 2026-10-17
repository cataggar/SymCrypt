// Copyright (c) Microsoft Corporation. Licensed under the MIT license.

const std = @import("std");
const h = @import("main_harness.zig");
const cb = @import("callback.zig");

const SYMCRYPT_NO_ERROR: u32 = 0;
const SYMCRYPT_WRONG_KEY_SIZE: u32 = 0x8001;
const SYMCRYPT_INVALID_BLOB: u32 = 0x800C;
const SYMCRYPT_BUFFER_TOO_SMALL: u32 = 0x800D;
const SYMCRYPT_INVALID_ARGUMENT: u32 = 0x800E;
const SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE: u32 = 0x8010;

const SYMCRYPT_CACHED_ECURVE_ID_NIST_P256: u32 = 0;
const SYMCRYPT_CACHED_ECURVE_ID_NIST_P384: u32 = 1;
const SYMCRYPT_CACHED_ECURVE_ID_CURVE_25519: u32 = 2;
const SYMCRYPT_CACHED_ECURVE_ID_NULL: u32 = 3;

const SYMCRYPT_FLAG_ECKEY_ECDH: u32 = 0x01;
const SYMCRYPT_FLAG_ECKEY_ECDSA: u32 = 0x02;

const SYMCRYPT_NUMBER_FORMAT_MSB_FIRST: u32 = 2;
const SYMCRYPT_SHA256_RESULT_SIZE: usize = 32;
const SYMCRYPT_SHA384_RESULT_SIZE: usize = 48;

const SYMCRYPT_ECURVE = opaque {};
const SYMCRYPT_ECKEY = opaque {};

extern fn SymCryptGetCachedEcurve(curveId: u32) callconv(.c) ?*const SYMCRYPT_ECURVE;
extern fn SymCryptEckeyAllocate(pCurve: *const SYMCRYPT_ECURVE) callconv(.c) ?*SYMCRYPT_ECKEY;
extern fn SymCryptEckeyFree(pkObj: *SYMCRYPT_ECKEY) callconv(.c) void;
extern fn SymCryptEckeySetRandom(flags: u32, pkObj: *SYMCRYPT_ECKEY) callconv(.c) u32;
extern fn SymCryptEckeyHasPrivateKey(pkEckey: *const SYMCRYPT_ECKEY) callconv(.c) u32;
extern fn SymCryptEckeySizeofPublicKey(pkEckey: *const SYMCRYPT_ECKEY, ecPointFormat: u32) callconv(.c) usize;
extern fn SymCryptEckeySizeofPrivateKey(pkEckey: *const SYMCRYPT_ECKEY) callconv(.c) usize;

extern fn SymCryptCompositeGetSizeOfEncodedEcSk(curveId: u32) callconv(.c) usize;
extern fn SymCryptCompositeGetSizeOfEncodedEcPk(curveId: u32) callconv(.c) usize;

extern fn SymCryptEckeySetValueCompositeEncodingSk(
    curveId: u32,
    pbEncodedEcSk: [*]const u8,
    cbEncodedEcSk: usize,
    flags: u32,
    pkEckey: *SYMCRYPT_ECKEY,
) callconv(.c) u32;

extern fn SymCryptEckeySetValueCompositeEncodingPk(
    curveId: u32,
    pbEncodedEcPk: [*]const u8,
    cbEncodedEcPk: usize,
    flags: u32,
    pkEckey: *SYMCRYPT_ECKEY,
) callconv(.c) u32;

extern fn SymCryptEckeyGetValueCompositeEncodingSk(
    pkEckey: *const SYMCRYPT_ECKEY,
    curveId: u32,
    pbEncodedEcSk: [*]u8,
    cbEncodedEcSk: usize,
) callconv(.c) u32;

extern fn SymCryptEckeyGetValueCompositeEncodingPk(
    pkEckey: *const SYMCRYPT_ECKEY,
    curveId: u32,
    pbEncodedEcPk: [*]u8,
    cbEncodedEcPk: usize,
) callconv(.c) u32;

extern fn SymCryptEcdsaSigValueCompositeEncode(
    pbSignature: [*]const u8,
    cbSignature: usize,
    pbEncodedSig: [*]u8,
    cbEncodedSig: usize,
    pcbEncodedSig: *usize,
) callconv(.c) u32;

extern fn SymCryptEcdsaSigValueCompositeDecode(
    pbEncodedSig: [*]const u8,
    cbEncodedSig: usize,
    pbSignature: [*]u8,
    cbSignature: usize,
) callconv(.c) u32;

extern fn SymCryptEcDsaSign(
    pkEckey: *const SYMCRYPT_ECKEY,
    pbHashValue: [*]const u8,
    cbHashValue: usize,
    format: u32,
    flags: u32,
    pbSignature: [*]u8,
    cbSignature: usize,
) callconv(.c) u32;

extern fn SymCryptEcDsaVerify(
    pkEckey: *const SYMCRYPT_ECKEY,
    pbHashValue: [*]const u8,
    cbHashValue: usize,
    pbSignature: [*]const u8,
    cbSignature: usize,
    format: u32,
    flags: u32,
) callconv(.c) u32;

const TEST_COMPOSITE_EC_CURVE_PARAMS = struct {
    curveId: u32,
    flags: u32,
};

const rgTestCompositeCurveParams = [_]TEST_COMPOSITE_EC_CURVE_PARAMS{
    .{
        .curveId = SYMCRYPT_CACHED_ECURVE_ID_NIST_P256,
        .flags = SYMCRYPT_FLAG_ECKEY_ECDH | SYMCRYPT_FLAG_ECKEY_ECDSA,
    },
    .{
        .curveId = SYMCRYPT_CACHED_ECURVE_ID_NIST_P384,
        .flags = SYMCRYPT_FLAG_ECKEY_ECDH | SYMCRYPT_FLAG_ECKEY_ECDSA,
    },
    .{
        .curveId = SYMCRYPT_CACHED_ECURVE_ID_CURVE_25519,
        .flags = SYMCRYPT_FLAG_ECKEY_ECDH,
    },
};

const MAX_ENCODED_EC_SK_SIZE: usize = 64;
const MAX_ENCODED_EC_PK_SIZE: usize = 97;

fn testEcKeyEncoding() void {
    var scError: u32 = SYMCRYPT_NO_ERROR;
    var pbEncodedSk1: [MAX_ENCODED_EC_SK_SIZE + 1]u8 = undefined;
    var pbEncodedSk2: [MAX_ENCODED_EC_SK_SIZE + 1]u8 = undefined;
    var pbEncodedPk1: [MAX_ENCODED_EC_PK_SIZE + 1]u8 = undefined;
    var pbEncodedPk2: [MAX_ENCODED_EC_PK_SIZE + 1]u8 = undefined;

    for (rgTestCompositeCurveParams) |curveParam| {
        const curveId = curveParam.curveId;
        const flags = curveParam.flags;

        const pCurve = SymCryptGetCachedEcurve(curveId);
        h.check(pCurve != null, "SymCryptGetCachedEcurve failed");

        const pkKey1 = SymCryptEckeyAllocate(pCurve.?);
        h.check(pkKey1 != null, "SymCryptEckeyAllocate failed for pkKey1");

        const pkKey2 = SymCryptEckeyAllocate(pCurve.?);
        h.check(pkKey2 != null, "SymCryptEckeyAllocate failed for pkKey2");

        const pkPubOnlyKey = SymCryptEckeyAllocate(pCurve.?);
        h.check(pkPubOnlyKey != null, "SymCryptEckeyAllocate failed for pkPubOnlyKey");

        scError = SymCryptEckeySetRandom(flags, pkKey1.?);
        h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptEckeySetRandom failed");

        const cbEncodedSk = SymCryptCompositeGetSizeOfEncodedEcSk(curveId);
        const cbEncodedPk = SymCryptCompositeGetSizeOfEncodedEcPk(curveId);
        h.check(cbEncodedSk <= MAX_ENCODED_EC_SK_SIZE, "cbEncodedSk exceeds max buffer size");
        h.check(cbEncodedPk <= MAX_ENCODED_EC_PK_SIZE, "cbEncodedPk exceeds max buffer size");

        // Export keys to buffers
        scError = SymCryptEckeyGetValueCompositeEncodingSk(pkKey1.?, curveId, &pbEncodedSk1, cbEncodedSk);
        h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptEckeyGetValueCompositeEncodingSk failed");

        scError = SymCryptEckeyGetValueCompositeEncodingPk(pkKey1.?, curveId, &pbEncodedPk1, cbEncodedPk);
        h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptEckeyGetValueCompositeEncodingPk failed");

        // Import secret key into pkKey2 and verify full equality (public + private)
        scError = SymCryptEckeySetValueCompositeEncodingSk(curveId, &pbEncodedSk1, cbEncodedSk, flags, pkKey2.?);
        h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptEckeySetValueCompositeEncodingSk failed");
        h.check(SymCryptEckeyHasPrivateKey(pkKey2.?) != 0, "pkKey2 should have private key");

        // Re-export from pkKey2 and verify byte-level match
        scError = SymCryptEckeyGetValueCompositeEncodingSk(pkKey2.?, curveId, &pbEncodedSk2, cbEncodedSk);
        h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptEckeyGetValueCompositeEncodingSk failed on pkKey2");
        h.check(std.mem.eql(u8, pbEncodedSk1[0..cbEncodedSk], pbEncodedSk2[0..cbEncodedSk]), "Re-exported SK mismatch");

        scError = SymCryptEckeyGetValueCompositeEncodingPk(pkKey2.?, curveId, &pbEncodedPk2, cbEncodedPk);
        h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptEckeyGetValueCompositeEncodingPk failed on pkKey2");
        h.check(std.mem.eql(u8, pbEncodedPk1[0..cbEncodedPk], pbEncodedPk2[0..cbEncodedPk]), "Re-exported PK mismatch");

        // Import public key into pkPubOnlyKey and verify public key equality
        scError = SymCryptEckeySetValueCompositeEncodingPk(curveId, &pbEncodedPk1, cbEncodedPk, flags, pkPubOnlyKey.?);
        h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptEckeySetValueCompositeEncodingPk failed");
        h.check(SymCryptEckeyHasPrivateKey(pkPubOnlyKey.?) == 0, "pkPubOnlyKey should not have private key");

        // Re-export public key from pkPubOnlyKey and verify byte-level match
        @memset(&pbEncodedPk2, 0);
        scError = SymCryptEckeyGetValueCompositeEncodingPk(pkPubOnlyKey.?, curveId, &pbEncodedPk2, cbEncodedPk);
        h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptEckeyGetValueCompositeEncodingPk failed on pkPubOnlyKey");
        h.check(std.mem.eql(u8, pbEncodedPk1[0..cbEncodedPk], pbEncodedPk2[0..cbEncodedPk]), "Re-exported PK from pub-only key mismatch");

        // Exporting secret key from public-only key should fail
        scError = SymCryptEckeyGetValueCompositeEncodingSk(pkPubOnlyKey.?, curveId, &pbEncodedSk2, cbEncodedSk);
        h.check(scError == SYMCRYPT_INVALID_ARGUMENT, "Expected SYMCRYPT_INVALID_ARGUMENT when getting SK from pub-only key");

        // Exporting with wrong buffer sizes should fail
        scError = SymCryptEckeyGetValueCompositeEncodingSk(pkKey1.?, curveId, &pbEncodedSk2, cbEncodedSk - 1);
        h.check(scError == SYMCRYPT_WRONG_KEY_SIZE, "Expected SYMCRYPT_WRONG_KEY_SIZE for SK export with small buffer");

        scError = SymCryptEckeyGetValueCompositeEncodingSk(pkKey1.?, curveId, &pbEncodedSk2, cbEncodedSk + 1);
        h.check(scError == SYMCRYPT_WRONG_KEY_SIZE, "Expected SYMCRYPT_WRONG_KEY_SIZE for SK export with large buffer");

        scError = SymCryptEckeyGetValueCompositeEncodingPk(pkKey1.?, curveId, &pbEncodedPk2, cbEncodedPk - 1);
        h.check(scError == SYMCRYPT_WRONG_KEY_SIZE, "Expected SYMCRYPT_WRONG_KEY_SIZE for PK export with small buffer");

        scError = SymCryptEckeyGetValueCompositeEncodingPk(pkKey1.?, curveId, &pbEncodedPk2, cbEncodedPk + 1);
        h.check(scError == SYMCRYPT_WRONG_KEY_SIZE, "Expected SYMCRYPT_WRONG_KEY_SIZE for PK export with large buffer");

        // Importing with wrong buffer sizes should fail
        scError = SymCryptEckeySetValueCompositeEncodingSk(curveId, &pbEncodedSk1, cbEncodedSk - 1, flags, pkKey2.?);
        h.check(scError == SYMCRYPT_WRONG_KEY_SIZE, "Expected SYMCRYPT_WRONG_KEY_SIZE for SK import with small buffer");

        scError = SymCryptEckeySetValueCompositeEncodingSk(curveId, &pbEncodedSk1, cbEncodedSk + 1, flags, pkKey2.?);
        h.check(scError == SYMCRYPT_WRONG_KEY_SIZE, "Expected SYMCRYPT_WRONG_KEY_SIZE for SK import with large buffer");

        scError = SymCryptEckeySetValueCompositeEncodingPk(curveId, &pbEncodedPk1, cbEncodedPk - 1, flags, pkPubOnlyKey.?);
        h.check(scError == SYMCRYPT_WRONG_KEY_SIZE, "Expected SYMCRYPT_WRONG_KEY_SIZE for PK import with small buffer");

        scError = SymCryptEckeySetValueCompositeEncodingPk(curveId, &pbEncodedPk1, cbEncodedPk + 1, flags, pkPubOnlyKey.?);
        h.check(scError == SYMCRYPT_WRONG_KEY_SIZE, "Expected SYMCRYPT_WRONG_KEY_SIZE for PK import with large buffer");

        // Importing with invalid curve ID should fail
        scError = SymCryptEckeySetValueCompositeEncodingSk(SYMCRYPT_CACHED_ECURVE_ID_NULL, &pbEncodedSk1, cbEncodedSk, flags, pkKey2.?);
        h.check(scError == SYMCRYPT_INVALID_ARGUMENT, "Expected SYMCRYPT_INVALID_ARGUMENT for SK import with NULL curve");

        scError = SymCryptEckeySetValueCompositeEncodingPk(SYMCRYPT_CACHED_ECURVE_ID_NULL, &pbEncodedPk1, cbEncodedPk, flags, pkPubOnlyKey.?);
        h.check(scError == SYMCRYPT_INVALID_ARGUMENT, "Expected SYMCRYPT_INVALID_ARGUMENT for PK import with NULL curve");

        scError = SymCryptEckeyGetValueCompositeEncodingSk(pkKey1.?, SYMCRYPT_CACHED_ECURVE_ID_NULL, &pbEncodedSk2, cbEncodedSk);
        h.check(scError == SYMCRYPT_INVALID_ARGUMENT, "Expected SYMCRYPT_INVALID_ARGUMENT for SK export with NULL curve");

        scError = SymCryptEckeyGetValueCompositeEncodingPk(pkKey1.?, SYMCRYPT_CACHED_ECURVE_ID_NULL, &pbEncodedPk2, cbEncodedPk);
        h.check(scError == SYMCRYPT_INVALID_ARGUMENT, "Expected SYMCRYPT_INVALID_ARGUMENT for PK export with NULL curve");

        // For NIST curves, test invalid public key prefix and corrupt secret key Version/OID
        if (curveId == SYMCRYPT_CACHED_ECURVE_ID_NIST_P256 or
            curveId == SYMCRYPT_CACHED_ECURVE_ID_NIST_P384)
        {
            @memcpy(pbEncodedPk2[0..cbEncodedPk], pbEncodedPk1[0..cbEncodedPk]);
            pbEncodedPk2[0] ^= 0xff; // Corrupt the 0x04 uncompressed point prefix
            scError = SymCryptEckeySetValueCompositeEncodingPk(curveId, &pbEncodedPk2, cbEncodedPk, flags, pkPubOnlyKey.?);
            h.check(scError == SYMCRYPT_INVALID_BLOB, "Expected SYMCRYPT_INVALID_BLOB for corrupted PK prefix");

            @memcpy(pbEncodedSk2[0..cbEncodedSk], pbEncodedSk1[0..cbEncodedSk]);
            pbEncodedSk2[0] ^= 0xff; // Corrupt the SEC1 header
            scError = SymCryptEckeySetValueCompositeEncodingSk(curveId, &pbEncodedSk2, cbEncodedSk, flags, pkKey2.?);
            h.check(scError == SYMCRYPT_INVALID_BLOB, "Expected SYMCRYPT_INVALID_BLOB for corrupted SK header");

            @memcpy(pbEncodedSk2[0..cbEncodedSk], pbEncodedSk1[0..cbEncodedSk]);
            pbEncodedSk2[cbEncodedSk - 1] ^= 0xff; // Corrupt the SEC1 OID trailer
            scError = SymCryptEckeySetValueCompositeEncodingSk(curveId, &pbEncodedSk2, cbEncodedSk, flags, pkKey2.?);
            h.check(scError == SYMCRYPT_INVALID_BLOB, "Expected SYMCRYPT_INVALID_BLOB for corrupted SK OID");
        }

        SymCryptEckeyFree(pkKey1.?);
        SymCryptEckeyFree(pkKey2.?);
        SymCryptEckeyFree(pkPubOnlyKey.?);
    }

    h.check(cb.g_nOutstandingCheckedAllocs == 0, "Memory leak in testEcKeyEncoding");
}

const DER_TAG_INTEGER: u8 = 0x02;
const DER_TAG_SEQUENCE: u8 = 0x30;
const MAX_SINGLE_BYTE_LENGTH: u8 = 0x7f;

const TEST_SIG_RAW_INTEGER_MAX_SIZE: usize = 61;
const TEST_SIG_RAW_TOTAL_MAX_SIZE: usize = TEST_SIG_RAW_INTEGER_MAX_SIZE * 2;
const TEST_SIG_ENCODED_INTEGER_MAX_SIZE: usize = 64;
const TEST_SIG_ENCODED_TOTAL_MAX_SIZE: usize = 2 + TEST_SIG_ENCODED_INTEGER_MAX_SIZE * 2;

const TEST_COMPOSITE_MLDSA_EC_SIG_DATA = struct {
    rgbRaw: [2][TEST_SIG_RAW_TOTAL_MAX_SIZE]u8,
    cbRaw: usize,
    rgbEncoded: [2][TEST_SIG_ENCODED_TOTAL_MAX_SIZE]u8,
    cbEncoded: usize,

    fn initBoth(
        comptime rgbRawInteger1: []const u8,
        comptime rgbRawInteger2: []const u8,
        comptime rgbEncodedSequence: []const u8,
        comptime rgbEncodedInteger1: []const u8,
        comptime rgbEncodedInteger2: []const u8,
    ) TEST_COMPOSITE_MLDSA_EC_SIG_DATA {
        comptime {
            std.debug.assert(rgbRawInteger1.len == rgbRawInteger2.len);
            std.debug.assert(rgbRawInteger1.len <= TEST_SIG_RAW_INTEGER_MAX_SIZE);
            std.debug.assert(rgbEncodedInteger1.len <= TEST_SIG_ENCODED_INTEGER_MAX_SIZE);
            std.debug.assert(rgbEncodedInteger2.len <= TEST_SIG_ENCODED_INTEGER_MAX_SIZE);
            std.debug.assert((rgbEncodedSequence.len + rgbEncodedInteger1.len + rgbEncodedInteger2.len) <= TEST_SIG_ENCODED_TOTAL_MAX_SIZE);
        }
        var res = TEST_COMPOSITE_MLDSA_EC_SIG_DATA{
            .rgbRaw = .{ @splat(0), @splat(0) },
            .cbRaw = rgbRawInteger1.len + rgbRawInteger2.len,
            .rgbEncoded = .{ @splat(0), @splat(0) },
            .cbEncoded = rgbEncodedSequence.len + rgbEncodedInteger1.len + rgbEncodedInteger2.len,
        };
        for (rgbRawInteger1, 0..) |b, i| {
            res.rgbRaw[0][i] = b;
            res.rgbRaw[1][rgbRawInteger2.len + i] = b;
        }
        for (rgbRawInteger2, 0..) |b, i| {
            res.rgbRaw[0][rgbRawInteger1.len + i] = b;
            res.rgbRaw[1][i] = b;
        }
        for (rgbEncodedSequence, 0..) |b, i| {
            res.rgbEncoded[0][i] = b;
            res.rgbEncoded[1][i] = b;
        }
        for (rgbEncodedInteger1, 0..) |b, i| {
            res.rgbEncoded[0][rgbEncodedSequence.len + i] = b;
            res.rgbEncoded[1][rgbEncodedSequence.len + rgbEncodedInteger2.len + i] = b;
        }
        for (rgbEncodedInteger2, 0..) |b, i| {
            res.rgbEncoded[0][rgbEncodedSequence.len + rgbEncodedInteger1.len + i] = b;
            res.rgbEncoded[1][rgbEncodedSequence.len + i] = b;
        }
        return res;
    }

    fn initEncodedOnly(
        comptime rgbEncodedSequence: []const u8,
        comptime rgbEncodedInteger1: []const u8,
        comptime rgbEncodedInteger2: []const u8,
    ) TEST_COMPOSITE_MLDSA_EC_SIG_DATA {
        comptime {
            std.debug.assert(rgbEncodedInteger1.len <= TEST_SIG_ENCODED_INTEGER_MAX_SIZE);
            std.debug.assert(rgbEncodedInteger2.len <= TEST_SIG_ENCODED_INTEGER_MAX_SIZE);
            std.debug.assert((rgbEncodedSequence.len + rgbEncodedInteger1.len + rgbEncodedInteger2.len) <= TEST_SIG_ENCODED_TOTAL_MAX_SIZE);
        }
        var res = TEST_COMPOSITE_MLDSA_EC_SIG_DATA{
            .rgbRaw = .{ @splat(0), @splat(0) },
            .cbRaw = 0,
            .rgbEncoded = .{ @splat(0), @splat(0) },
            .cbEncoded = rgbEncodedSequence.len + rgbEncodedInteger1.len + rgbEncodedInteger2.len,
        };
        for (rgbEncodedSequence, 0..) |b, i| {
            res.rgbEncoded[0][i] = b;
            res.rgbEncoded[1][i] = b;
        }
        for (rgbEncodedInteger1, 0..) |b, i| {
            res.rgbEncoded[0][rgbEncodedSequence.len + i] = b;
            res.rgbEncoded[1][rgbEncodedSequence.len + rgbEncodedInteger2.len + i] = b;
        }
        for (rgbEncodedInteger2, 0..) |b, i| {
            res.rgbEncoded[0][rgbEncodedSequence.len + rgbEncodedInteger1.len + i] = b;
            res.rgbEncoded[1][rgbEncodedSequence.len + i] = b;
        }
        return res;
    }
};

const g_rgSigTestsPassEncodeDecode = [_]TEST_COMPOSITE_MLDSA_EC_SIG_DATA{
    // Simple cases
    TEST_COMPOSITE_MLDSA_EC_SIG_DATA.initBoth(
        &.{0x7a},
        &.{0x7b},
        &.{ DER_TAG_SEQUENCE, 6 },
        &.{ DER_TAG_INTEGER, 1, 0x7a },
        &.{ DER_TAG_INTEGER, 1, 0x7b },
    ),
    TEST_COMPOSITE_MLDSA_EC_SIG_DATA.initBoth(
        &.{ 0x7a, 0x7b },
        &.{ 0x7c, 0x7d },
        &.{ DER_TAG_SEQUENCE, 8 },
        &.{ DER_TAG_INTEGER, 2, 0x7a, 0x7b },
        &.{ DER_TAG_INTEGER, 2, 0x7c, 0x7d },
    ),
    TEST_COMPOSITE_MLDSA_EC_SIG_DATA.initBoth(
        &.{ 0x7a, 0x7b, 0x7c },
        &.{ 0x7d, 0x7e, 0x7f },
        &.{ DER_TAG_SEQUENCE, 10 },
        &.{ DER_TAG_INTEGER, 3, 0x7a, 0x7b, 0x7c },
        &.{ DER_TAG_INTEGER, 3, 0x7d, 0x7e, 0x7f },
    ),

    // Pad with 0 to make integers unsigned
    TEST_COMPOSITE_MLDSA_EC_SIG_DATA.initBoth(
        &.{0x8a},
        &.{0x7a},
        &.{ DER_TAG_SEQUENCE, 7 },
        &.{ DER_TAG_INTEGER, 2, 0x00, 0x8a },
        &.{ DER_TAG_INTEGER, 1, 0x7a },
    ),
    TEST_COMPOSITE_MLDSA_EC_SIG_DATA.initBoth(
        &.{0x8a},
        &.{0x8b},
        &.{ DER_TAG_SEQUENCE, 8 },
        &.{ DER_TAG_INTEGER, 2, 0x00, 0x8a },
        &.{ DER_TAG_INTEGER, 2, 0x00, 0x8b },
    ),
    TEST_COMPOSITE_MLDSA_EC_SIG_DATA.initBoth(
        &.{ 0x00, 0x8a },
        &.{ 0x00, 0x8b },
        &.{ DER_TAG_SEQUENCE, 8 },
        &.{ DER_TAG_INTEGER, 2, 0x00, 0x8a },
        &.{ DER_TAG_INTEGER, 2, 0x00, 0x8b },
    ),
    TEST_COMPOSITE_MLDSA_EC_SIG_DATA.initBoth(
        &.{ 0x00, 0x8a },
        &.{ 0x7a, 0x8b },
        &.{ DER_TAG_SEQUENCE, 8 },
        &.{ DER_TAG_INTEGER, 2, 0x00, 0x8a },
        &.{ DER_TAG_INTEGER, 2, 0x7a, 0x8b },
    ),
    TEST_COMPOSITE_MLDSA_EC_SIG_DATA.initBoth(
        &.{ 0x7a, 0x7b },
        &.{ 0x8b, 0x7c },
        &.{ DER_TAG_SEQUENCE, 9 },
        &.{ DER_TAG_INTEGER, 2, 0x7a, 0x7b },
        &.{ DER_TAG_INTEGER, 3, 0x00, 0x8b, 0x7c },
    ),
    TEST_COMPOSITE_MLDSA_EC_SIG_DATA.initBoth(
        &.{ 0x7a, 0x7b },
        &.{ 0x8b, 0x8c },
        &.{ DER_TAG_SEQUENCE, 9 },
        &.{ DER_TAG_INTEGER, 2, 0x7a, 0x7b },
        &.{ DER_TAG_INTEGER, 3, 0x00, 0x8b, 0x8c },
    ),
    TEST_COMPOSITE_MLDSA_EC_SIG_DATA.initBoth(
        &.{ 0x8a, 0x7a },
        &.{ 0x8b, 0x7b },
        &.{ DER_TAG_SEQUENCE, 10 },
        &.{ DER_TAG_INTEGER, 3, 0x00, 0x8a, 0x7a },
        &.{ DER_TAG_INTEGER, 3, 0x00, 0x8b, 0x7b },
    ),
    TEST_COMPOSITE_MLDSA_EC_SIG_DATA.initBoth(
        &.{ 0x00, 0x8a, 0x7a },
        &.{ 0x00, 0x7b, 0x7c },
        &.{ DER_TAG_SEQUENCE, 9 },
        &.{ DER_TAG_INTEGER, 3, 0x00, 0x8a, 0x7a },
        &.{ DER_TAG_INTEGER, 2, 0x7b, 0x7c },
    ),
    TEST_COMPOSITE_MLDSA_EC_SIG_DATA.initBoth(
        &.{ 0x00, 0x8a, 0x7a },
        &.{ 0x00, 0x7b, 0x8b },
        &.{ DER_TAG_SEQUENCE, 9 },
        &.{ DER_TAG_INTEGER, 3, 0x00, 0x8a, 0x7a },
        &.{ DER_TAG_INTEGER, 2, 0x7b, 0x8b },
    ),
    TEST_COMPOSITE_MLDSA_EC_SIG_DATA.initBoth(
        &.{ 0x00, 0x8a, 0x7a },
        &.{ 0x00, 0x8b, 0x7b },
        &.{ DER_TAG_SEQUENCE, 10 },
        &.{ DER_TAG_INTEGER, 3, 0x00, 0x8a, 0x7a },
        &.{ DER_TAG_INTEGER, 3, 0x00, 0x8b, 0x7b },
    ),

    // Trim leading 0s but preserve unsigned
    TEST_COMPOSITE_MLDSA_EC_SIG_DATA.initBoth(
        &.{ 0x00, 0x7a },
        &.{ 0x00, 0x7b },
        &.{ DER_TAG_SEQUENCE, 6 },
        &.{ DER_TAG_INTEGER, 1, 0x7a },
        &.{ DER_TAG_INTEGER, 1, 0x7b },
    ),
    TEST_COMPOSITE_MLDSA_EC_SIG_DATA.initBoth(
        &.{ 0x00, 0x7a },
        &.{ 0x7b, 0x7c },
        &.{ DER_TAG_SEQUENCE, 7 },
        &.{ DER_TAG_INTEGER, 1, 0x7a },
        &.{ DER_TAG_INTEGER, 2, 0x7b, 0x7c },
    ),
    TEST_COMPOSITE_MLDSA_EC_SIG_DATA.initBoth(
        &.{ 0x00, 0x7a, 0x00 },
        &.{ 0x00, 0x7b, 0x00 },
        &.{ DER_TAG_SEQUENCE, 8 },
        &.{ DER_TAG_INTEGER, 2, 0x7a, 0x00 },
        &.{ DER_TAG_INTEGER, 2, 0x7b, 0x00 },
    ),
    TEST_COMPOSITE_MLDSA_EC_SIG_DATA.initBoth(
        &.{ 0x00, 0x8a, 0x7a, 0x00 },
        &.{ 0x00, 0x00, 0x7b, 0x00 },
        &.{ DER_TAG_SEQUENCE, 10 },
        &.{ DER_TAG_INTEGER, 4, 0x00, 0x8a, 0x7a, 0x00 },
        &.{ DER_TAG_INTEGER, 2, 0x7b, 0x00 },
    ),
    TEST_COMPOSITE_MLDSA_EC_SIG_DATA.initBoth(
        &.{ 0x00, 0x00, 0x00, 0x7a },
        &.{ 0x00, 0x00, 0x8a, 0x7b },
        &.{ DER_TAG_SEQUENCE, 8 },
        &.{ DER_TAG_INTEGER, 1, 0x7a },
        &.{ DER_TAG_INTEGER, 3, 0x00, 0x8a, 0x7b },
    ),

    // Maximum lengths
    TEST_COMPOSITE_MLDSA_EC_SIG_DATA.initBoth(
        &@as([61]u8, @splat(0x7a)),
        &@as([61]u8, @splat(0x7b)),
        &.{ DER_TAG_SEQUENCE, MAX_SINGLE_BYTE_LENGTH - 1 },
        &([_]u8{ DER_TAG_INTEGER, 61 } ++ @as([61]u8, @splat(0x7a))),
        &([_]u8{ DER_TAG_INTEGER, 61 } ++ @as([61]u8, @splat(0x7b))),
    ),
    TEST_COMPOSITE_MLDSA_EC_SIG_DATA.initBoth(
        &([_]u8{0x8a} ++ @as([60]u8, @splat(0x7a))),
        &@as([61]u8, @splat(0x7b)),
        &.{ DER_TAG_SEQUENCE, MAX_SINGLE_BYTE_LENGTH },
        &([_]u8{ DER_TAG_INTEGER, 62, 0x00, 0x8a } ++ @as([60]u8, @splat(0x7a))),
        &([_]u8{ DER_TAG_INTEGER, 61 } ++ @as([61]u8, @splat(0x7b))),
    ),
};

const g_rgSigTestsFailDecode = [_]TEST_COMPOSITE_MLDSA_EC_SIG_DATA{
    // Missing 0 padding
    TEST_COMPOSITE_MLDSA_EC_SIG_DATA.initBoth(
        &.{0x8a},
        &.{0x7a},
        &.{ DER_TAG_SEQUENCE, 6 },
        &.{ DER_TAG_INTEGER, 1, 0x8a },
        &.{ DER_TAG_INTEGER, 1, 0x7a },
    ),
    TEST_COMPOSITE_MLDSA_EC_SIG_DATA.initBoth(
        &.{ 0x00, 0x8a },
        &.{ 0x00, 0x7a },
        &.{ DER_TAG_SEQUENCE, 6 },
        &.{ DER_TAG_INTEGER, 1, 0x8a },
        &.{ DER_TAG_INTEGER, 1, 0x7a },
    ),
    TEST_COMPOSITE_MLDSA_EC_SIG_DATA.initBoth(
        &.{0x8a},
        &.{0x8b},
        &.{ DER_TAG_SEQUENCE, 6 },
        &.{ DER_TAG_INTEGER, 1, 0x8a },
        &.{ DER_TAG_INTEGER, 1, 0x8b },
    ),
    TEST_COMPOSITE_MLDSA_EC_SIG_DATA.initBoth(
        &.{ 0x00, 0x8a },
        &.{ 0x00, 0x8b },
        &.{ DER_TAG_SEQUENCE, 6 },
        &.{ DER_TAG_INTEGER, 1, 0x8a },
        &.{ DER_TAG_INTEGER, 1, 0x8b },
    ),
    TEST_COMPOSITE_MLDSA_EC_SIG_DATA.initBoth(
        &.{ 0x8a, 0x7a },
        &.{ 0x8b, 0x7b },
        &.{ DER_TAG_SEQUENCE, 8 },
        &.{ DER_TAG_INTEGER, 2, 0x8a, 0x7a },
        &.{ DER_TAG_INTEGER, 2, 0x8b, 0x7b },
    ),
    TEST_COMPOSITE_MLDSA_EC_SIG_DATA.initBoth(
        &.{ 0x8a, 0x7a },
        &.{ 0x8b, 0x8c },
        &.{ DER_TAG_SEQUENCE, 8 },
        &.{ DER_TAG_INTEGER, 2, 0x8a, 0x7a },
        &.{ DER_TAG_INTEGER, 2, 0x8b, 0x8c },
    ),
    TEST_COMPOSITE_MLDSA_EC_SIG_DATA.initBoth(
        &.{ 0x8a, 0x8b },
        &.{ 0x8c, 0x8d },
        &.{ DER_TAG_SEQUENCE, 8 },
        &.{ DER_TAG_INTEGER, 2, 0x8a, 0x8b },
        &.{ DER_TAG_INTEGER, 2, 0x8c, 0x8d },
    ),
    TEST_COMPOSITE_MLDSA_EC_SIG_DATA.initBoth(
        &.{ 0x00, 0x8a, 0x7a },
        &.{ 0x8b, 0x7b, 0x7c },
        &.{ DER_TAG_SEQUENCE, 10 },
        &.{ DER_TAG_INTEGER, 3, 0x00, 0x8a, 0x7a },
        &.{ DER_TAG_INTEGER, 3, 0x8b, 0x7b, 0x7c },
    ),

    // Un-trimmed leading 0s
    TEST_COMPOSITE_MLDSA_EC_SIG_DATA.initBoth(
        &.{ 0x00, 0x7a },
        &.{ 0x00, 0x7b },
        &.{ DER_TAG_SEQUENCE, 8 },
        &.{ DER_TAG_INTEGER, 2, 0x00, 0x7a },
        &.{ DER_TAG_INTEGER, 2, 0x00, 0x7b },
    ),
    TEST_COMPOSITE_MLDSA_EC_SIG_DATA.initBoth(
        &.{ 0x00, 0x8a },
        &.{ 0x00, 0x7a },
        &.{ DER_TAG_SEQUENCE, 8 },
        &.{ DER_TAG_INTEGER, 2, 0x00, 0x8a },
        &.{ DER_TAG_INTEGER, 2, 0x00, 0x7a },
    ),
    TEST_COMPOSITE_MLDSA_EC_SIG_DATA.initBoth(
        &.{ 0x00, 0x7a },
        &.{ 0x7b, 0x7c },
        &.{ DER_TAG_SEQUENCE, 8 },
        &.{ DER_TAG_INTEGER, 2, 0x00, 0x7a },
        &.{ DER_TAG_INTEGER, 2, 0x7b, 0x7c },
    ),
    TEST_COMPOSITE_MLDSA_EC_SIG_DATA.initBoth(
        &.{ 0x00, 0x7a, 0x00 },
        &.{ 0x00, 0x7b, 0x00 },
        &.{ DER_TAG_SEQUENCE, 10 },
        &.{ DER_TAG_INTEGER, 3, 0x00, 0x7a, 0x00 },
        &.{ DER_TAG_INTEGER, 3, 0x00, 0x7b, 0x00 },
    ),
    TEST_COMPOSITE_MLDSA_EC_SIG_DATA.initBoth(
        &.{ 0x00, 0x8a, 0x7a, 0x00 },
        &.{ 0x00, 0x00, 0x7b, 0x00 },
        &.{ DER_TAG_SEQUENCE, 12 },
        &.{ DER_TAG_INTEGER, 4, 0x00, 0x8a, 0x7a, 0x00 },
        &.{ DER_TAG_INTEGER, 4, 0x00, 0x00, 0x7b, 0x00 },
    ),
    TEST_COMPOSITE_MLDSA_EC_SIG_DATA.initBoth(
        &.{ 0x00, 0x00, 0x00, 0x7a },
        &.{ 0x00, 0x00, 0x8a, 0x7b },
        &.{ DER_TAG_SEQUENCE, 12 },
        &.{ DER_TAG_INTEGER, 4, 0x00, 0x00, 0x00, 0x7a },
        &.{ DER_TAG_INTEGER, 4, 0x00, 0x00, 0x8a, 0x7b },
    ),

    // 0 values
    TEST_COMPOSITE_MLDSA_EC_SIG_DATA.initBoth(
        &.{0x00},
        &.{0x00},
        &.{ DER_TAG_SEQUENCE, 6 },
        &.{ DER_TAG_INTEGER, 1, 0x00 },
        &.{ DER_TAG_INTEGER, 1, 0x00 },
    ),
    TEST_COMPOSITE_MLDSA_EC_SIG_DATA.initBoth(
        &.{ 0x00, 0x00 },
        &.{ 0x00, 0x00 },
        &.{ DER_TAG_SEQUENCE, 6 },
        &.{ DER_TAG_INTEGER, 1, 0x00 },
        &.{ DER_TAG_INTEGER, 1, 0x00 },
    ),
    TEST_COMPOSITE_MLDSA_EC_SIG_DATA.initBoth(
        &.{ 0x00, 0x00, 0x00 },
        &.{ 0x00, 0x00, 0x00 },
        &.{ DER_TAG_SEQUENCE, 6 },
        &.{ DER_TAG_INTEGER, 1, 0x00 },
        &.{ DER_TAG_INTEGER, 1, 0x00 },
    ),
    TEST_COMPOSITE_MLDSA_EC_SIG_DATA.initBoth(
        &.{ 0x00, 0x8a },
        &.{ 0x00, 0x00 },
        &.{ DER_TAG_SEQUENCE, 7 },
        &.{ DER_TAG_INTEGER, 2, 0x00, 0x8a },
        &.{ DER_TAG_INTEGER, 1, 0x00 },
    ),
    TEST_COMPOSITE_MLDSA_EC_SIG_DATA.initBoth(
        &.{ 0x00, 0x7a },
        &.{ 0x00, 0x00 },
        &.{ DER_TAG_SEQUENCE, 6 },
        &.{ DER_TAG_INTEGER, 1, 0x7a },
        &.{ DER_TAG_INTEGER, 1, 0x00 },
    ),

    // Incorrect DER tags
    TEST_COMPOSITE_MLDSA_EC_SIG_DATA.initEncodedOnly(
        &.{ DER_TAG_SEQUENCE, 6 },
        &.{ DER_TAG_INTEGER + 1, 1, 0x7a },
        &.{ DER_TAG_INTEGER, 1, 0x7b },
    ),
    TEST_COMPOSITE_MLDSA_EC_SIG_DATA.initEncodedOnly(
        &.{ DER_TAG_SEQUENCE + 1, 6 },
        &.{ DER_TAG_INTEGER + 1, 1, 0x7a },
        &.{ DER_TAG_INTEGER, 1, 0x7b },
    ),
    TEST_COMPOSITE_MLDSA_EC_SIG_DATA.initEncodedOnly(
        &.{ DER_TAG_SEQUENCE + 1, 6 },
        &.{ DER_TAG_INTEGER + 1, 1, 0x7a },
        &.{ DER_TAG_INTEGER + 1, 1, 0x7b },
    ),
    TEST_COMPOSITE_MLDSA_EC_SIG_DATA.initEncodedOnly(
        &.{ DER_TAG_SEQUENCE, 6 },
        &.{ DER_TAG_SEQUENCE, 1, 0x7a },
        &.{ DER_TAG_INTEGER, 1, 0x7b },
    ),
    TEST_COMPOSITE_MLDSA_EC_SIG_DATA.initEncodedOnly(
        &.{ DER_TAG_INTEGER, 6 },
        &.{ DER_TAG_INTEGER, 1, 0x7a },
        &.{ DER_TAG_INTEGER, 1, 0x7b },
    ),
    TEST_COMPOSITE_MLDSA_EC_SIG_DATA.initEncodedOnly(
        &.{ DER_TAG_INTEGER, 6 },
        &.{ DER_TAG_SEQUENCE, 1, 0x7a },
        &.{ DER_TAG_INTEGER, 1, 0x7b },
    ),

    // Lengths that are too small
    TEST_COMPOSITE_MLDSA_EC_SIG_DATA.initEncodedOnly(
        &.{ DER_TAG_SEQUENCE, 0 },
        &.{ DER_TAG_INTEGER, 1, 0x7a },
        &.{ DER_TAG_INTEGER, 1, 0x7b },
    ),
    TEST_COMPOSITE_MLDSA_EC_SIG_DATA.initEncodedOnly(
        &.{ DER_TAG_SEQUENCE, 5 },
        &.{ DER_TAG_INTEGER, 0 },
        &.{ DER_TAG_INTEGER, 1, 0x7b },
    ),
    TEST_COMPOSITE_MLDSA_EC_SIG_DATA.initEncodedOnly(
        &.{ DER_TAG_SEQUENCE, 5 },
        &.{ DER_TAG_INTEGER, 1, 0x7a },
        &.{ DER_TAG_INTEGER, 1, 0x7b },
    ),

    // Lengths that exceed buffer size
    TEST_COMPOSITE_MLDSA_EC_SIG_DATA.initEncodedOnly(
        &.{ DER_TAG_SEQUENCE, 7 },
        &.{ DER_TAG_INTEGER, 1, 0x7a },
        &.{ DER_TAG_INTEGER, 1, 0x7b },
    ),
    TEST_COMPOSITE_MLDSA_EC_SIG_DATA.initBoth(
        &.{0x7a},
        &.{0x7b},
        &.{ DER_TAG_SEQUENCE, 7 },
        &.{ DER_TAG_INTEGER, 1, 0x7a },
        &.{ DER_TAG_INTEGER, 1, 0x7b, 0x7c },
    ),
    TEST_COMPOSITE_MLDSA_EC_SIG_DATA.initEncodedOnly(
        &.{ DER_TAG_SEQUENCE, 6 },
        &.{ DER_TAG_INTEGER, 7, 0x7a },
        &.{ DER_TAG_INTEGER, 1, 0x7b },
    ),
    TEST_COMPOSITE_MLDSA_EC_SIG_DATA.initEncodedOnly(
        &.{ DER_TAG_SEQUENCE, 7 },
        &.{ DER_TAG_INTEGER, 7, 0x7a },
        &.{ DER_TAG_INTEGER, 1, 0x7b },
    ),
    TEST_COMPOSITE_MLDSA_EC_SIG_DATA.initEncodedOnly(
        &.{ DER_TAG_SEQUENCE, MAX_SINGLE_BYTE_LENGTH },
        &.{ DER_TAG_INTEGER, 1, 0x7a },
        &.{ DER_TAG_INTEGER, 1, 0x7b },
    ),
    TEST_COMPOSITE_MLDSA_EC_SIG_DATA.initEncodedOnly(
        &.{ DER_TAG_SEQUENCE, 6 },
        &.{ DER_TAG_INTEGER, MAX_SINGLE_BYTE_LENGTH, 0x7a },
        &.{ DER_TAG_INTEGER, 1, 0x7b },
    ),
    TEST_COMPOSITE_MLDSA_EC_SIG_DATA.initEncodedOnly(
        &.{ DER_TAG_SEQUENCE, MAX_SINGLE_BYTE_LENGTH },
        &.{ DER_TAG_INTEGER, MAX_SINGLE_BYTE_LENGTH, 0x7a },
        &.{ DER_TAG_INTEGER, 1, 0x7b },
    ),

    // Superfluous 0 padding (untrimmed leading 0) that exceeds the raw integer size
    TEST_COMPOSITE_MLDSA_EC_SIG_DATA.initBoth(
        &.{0x8a},
        &.{0x7a},
        &.{ DER_TAG_SEQUENCE, 8 },
        &.{ DER_TAG_INTEGER, 2, 0x00, 0x8a },
        &.{ DER_TAG_INTEGER, 2, 0x00, 0x7a },
    ),
    TEST_COMPOSITE_MLDSA_EC_SIG_DATA.initBoth(
        &.{0x7a},
        &.{0x7b},
        &.{ DER_TAG_SEQUENCE, 8 },
        &.{ DER_TAG_INTEGER, 2, 0x00, 0x7a },
        &.{ DER_TAG_INTEGER, 2, 0x00, 0x7b },
    ),
    TEST_COMPOSITE_MLDSA_EC_SIG_DATA.initBoth(
        &.{ 0x00, 0x8a },
        &.{ 0x00, 0x7a },
        &.{ DER_TAG_SEQUENCE, 9 },
        &.{ DER_TAG_INTEGER, 2, 0x00, 0x8a },
        &.{ DER_TAG_INTEGER, 3, 0x00, 0x00, 0x7a },
    ),

    // Lengths that exceed the maximum value that can be encoded in a single byte
    TEST_COMPOSITE_MLDSA_EC_SIG_DATA.initBoth(
        &([_]u8{0x8a} ++ @as([60]u8, @splat(0x7a))),
        &([_]u8{0x8b} ++ @as([60]u8, @splat(0x7b))),
        &.{ DER_TAG_SEQUENCE, MAX_SINGLE_BYTE_LENGTH + 1 },
        &([_]u8{ DER_TAG_INTEGER, 62, 0x00, 0x8a } ++ @as([60]u8, @splat(0x7a))),
        &([_]u8{ DER_TAG_INTEGER, 62, 0x00, 0x8b } ++ @as([60]u8, @splat(0x7b))),
    ),
};

fn testEcSignatureEncodingUnitPassEncodeDecode(
    pcbRawSignature: []const u8,
    pcbEncodedSignature: []const u8,
) void {
    var vbBuffer: [TEST_SIG_ENCODED_TOTAL_MAX_SIZE]u8 = undefined;
    var cbResult: usize = 0;

    var scError = SymCryptEcdsaSigValueCompositeEncode(
        pcbRawSignature.ptr,
        pcbRawSignature.len,
        &vbBuffer,
        pcbEncodedSignature.len,
        &cbResult,
    );
    h.check3(scError == SYMCRYPT_NO_ERROR, "SymCryptEcdsaSigValueCompositeEncode failed with {x}", scError);
    h.check(std.mem.eql(u8, vbBuffer[0..pcbEncodedSignature.len], pcbEncodedSignature), "SymCryptEcdsaSigValueCompositeEncode produced incorrect Ecdsa-Sig-Value");

    scError = SymCryptEcdsaSigValueCompositeDecode(
        pcbEncodedSignature.ptr,
        pcbEncodedSignature.len,
        &vbBuffer,
        pcbRawSignature.len,
    );
    h.check3(scError == SYMCRYPT_NO_ERROR, "SymCryptEcdsaSigValueCompositeDecode failed with {x}", scError);
    h.check(std.mem.eql(u8, vbBuffer[0..pcbRawSignature.len], pcbRawSignature), "SymCryptEcdsaSigValueCompositeDecode produced incorrect data");
}

fn testEcSignatureEncodingUnitFailDecode(
    cbRawSignature: usize,
    pcbEncodedSignature: []const u8,
) void {
    var vbBuffer: [TEST_SIG_RAW_TOTAL_MAX_SIZE]u8 = @splat(0);

    const scError = SymCryptEcdsaSigValueCompositeDecode(
        pcbEncodedSignature.ptr,
        pcbEncodedSignature.len,
        &vbBuffer,
        cbRawSignature,
    );
    h.check3(scError == SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE, "SymCryptEcdsaSigValueCompositeDecode did not fail as expected ({x})", scError);
}

fn testEcSignatureEncodingUnit() void {
    for (&g_rgSigTestsPassEncodeDecode) |*pTestCase| {
        for (0..pTestCase.rgbRaw.len) |j| {
            testEcSignatureEncodingUnitPassEncodeDecode(
                pTestCase.rgbRaw[j][0..pTestCase.cbRaw],
                pTestCase.rgbEncoded[j][0..pTestCase.cbEncoded],
            );
        }
    }

    for (&g_rgSigTestsFailDecode) |*pTestCase| {
        const cbRaw: usize = if (pTestCase.cbRaw == 0) TEST_SIG_RAW_TOTAL_MAX_SIZE else pTestCase.cbRaw;
        for (0..pTestCase.rgbRaw.len) |j| {
            testEcSignatureEncodingUnitFailDecode(
                cbRaw,
                pTestCase.rgbEncoded[j][0..pTestCase.cbEncoded],
            );
        }
    }

    const pTestCase = &g_rgSigTestsPassEncodeDecode[0];
    var cbResult: usize = 0;
    var vbBuffer: [TEST_SIG_ENCODED_TOTAL_MAX_SIZE]u8 = @splat(0);

    var scError = SymCryptEcdsaSigValueCompositeEncode(
        &pTestCase.rgbRaw[0],
        1,
        &vbBuffer,
        pTestCase.cbEncoded,
        &cbResult,
    );
    h.check(scError == SYMCRYPT_INVALID_ARGUMENT, "SymCryptEcdsaSigValueCompositeEncode failed to validate odd cbRawSignature");

    scError = SymCryptEcdsaSigValueCompositeEncode(
        &pTestCase.rgbRaw[0],
        TEST_SIG_RAW_TOTAL_MAX_SIZE + 2,
        &vbBuffer,
        pTestCase.cbEncoded,
        &cbResult,
    );
    h.check(scError == SYMCRYPT_INVALID_ARGUMENT, "SymCryptEcdsaSigValueCompositeEncode failed to validate large cbRawSignature");

    scError = SymCryptEcdsaSigValueCompositeEncode(
        &pTestCase.rgbRaw[0],
        pTestCase.cbRaw,
        &vbBuffer,
        pTestCase.cbEncoded - 1,
        &cbResult,
    );
    h.check(scError == SYMCRYPT_BUFFER_TOO_SMALL, "SymCryptEcdsaSigValueCompositeEncode failed to validate small cbEncodedSignature");

    scError = SymCryptEcdsaSigValueCompositeDecode(
        &pTestCase.rgbEncoded[0],
        pTestCase.cbEncoded,
        &vbBuffer,
        1,
    );
    h.check(scError == SYMCRYPT_INVALID_ARGUMENT, "SymCryptEcdsaSigValueCompositeDecode failed to validate odd cbRawSignature");

    scError = SymCryptEcdsaSigValueCompositeDecode(
        &pTestCase.rgbEncoded[0],
        pTestCase.cbEncoded,
        &vbBuffer,
        TEST_SIG_RAW_TOTAL_MAX_SIZE + 2,
    );
    h.check(scError == SYMCRYPT_INVALID_ARGUMENT, "SymCryptEcdsaSigValueCompositeDecode failed to validate large cbRawSignature");
}

fn testEcSignatureEncodingFunctional(
    curveId: u32,
    cbHash: usize,
) void {
    const pCurve = SymCryptGetCachedEcurve(curveId);
    h.check(pCurve != null, "SymCryptGetCachedEcurve failed");

    const pkKey = SymCryptEckeyAllocate(pCurve.?);
    h.check(pkKey != null, "SymCryptEckeyAllocate failed");

    var scError = SymCryptEckeySetRandom(SYMCRYPT_FLAG_ECKEY_ECDSA, pkKey.?);
    h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptEckeySetRandom failed");

    var vbHash: [SYMCRYPT_SHA384_RESULT_SIZE]u8 = undefined;
    h.GENRANDOM(&vbHash, @intCast(cbHash));

    const cbRawSig = SymCryptEckeySizeofPrivateKey(pkKey.?) * 2;
    var vbRawSig: [TEST_SIG_RAW_TOTAL_MAX_SIZE]u8 = undefined;
    var vbDecodedSig: [TEST_SIG_RAW_TOTAL_MAX_SIZE]u8 = undefined;
    var vbEncodedSig: [TEST_SIG_ENCODED_TOTAL_MAX_SIZE]u8 = undefined;

    for (0..32) |_| {
        scError = SymCryptEcDsaSign(
            pkKey.?,
            &vbHash,
            cbHash,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            0,
            &vbRawSig,
            cbRawSig,
        );
        h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptEcDsaSign failed");

        var cbEncodedSig: usize = 0;
        scError = SymCryptEcdsaSigValueCompositeEncode(
            &vbRawSig,
            cbRawSig,
            &vbEncodedSig,
            vbEncodedSig.len,
            &cbEncodedSig,
        );
        h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptEcdsaSigValueCompositeEncode failed");
        h.check(cbEncodedSig <= vbEncodedSig.len, "Encoded signature larger than max");

        scError = SymCryptEcdsaSigValueCompositeDecode(
            &vbEncodedSig,
            cbEncodedSig,
            &vbDecodedSig,
            cbRawSig,
        );
        h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptEcdsaSigValueCompositeDecode failed");
        h.check(std.mem.eql(u8, vbRawSig[0..cbRawSig], vbDecodedSig[0..cbRawSig]), "Decoded signature does not match original raw signature");

        scError = SymCryptEcDsaVerify(
            pkKey.?,
            &vbHash,
            cbHash,
            &vbDecodedSig,
            cbRawSig,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            0,
        );
        h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptEcDsaVerify failed on round-tripped signature");
    }

    SymCryptEckeyFree(pkKey.?);

    h.check(cb.g_nOutstandingCheckedAllocs == 0, "Memory leak in testEcSignatureEncodingFunctional");
}

fn testEcSignatureEncoding() void {
    testEcSignatureEncodingUnit();

    testEcSignatureEncodingFunctional(SYMCRYPT_CACHED_ECURVE_ID_NIST_P256, SYMCRYPT_SHA256_RESULT_SIZE);
    testEcSignatureEncodingFunctional(SYMCRYPT_CACHED_ECURVE_ID_NIST_P384, SYMCRYPT_SHA384_RESULT_SIZE);
}

pub export fn testCompositeHelpers() callconv(.c) void {
    if (!h.isAlgorithmPresent("CompositeHelpers", 0)) {
        return;
    }

    h.print("    compositeHelpers\n");

    testEcKeyEncoding();
    testEcSignatureEncoding();
}
