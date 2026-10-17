// Copyright (c) Microsoft Corporation. Licensed under the MIT license.

const std = @import("std");
const h = @import("main_harness.zig");
const sc = @import("sc_implementations.zig");
const tu = @import("testutil.zig");

const SYMCRYPT_OID = extern struct {
    cbOID: u32,
    pbOID: [*]const u8,
};

extern const SymCryptAesBlockCipher: u8;
extern const SymCrypt3DesBlockCipher: u8;
extern const SymCryptDesBlockCipher: u8;
extern const SymCryptDesxBlockCipher: u8;
extern const SymCryptRc2BlockCipher: u8;

extern const SymCryptEcurveParamsNistP192: u8;
extern const SymCryptEcurveParamsNistP224: u8;
extern const SymCryptEcurveParamsNistP256: u8;
extern const SymCryptEcurveParamsNistP384: u8;
extern const SymCryptEcurveParamsNistP521: u8;
extern const SymCryptEcurveParamsNumsP256t1: u8;
extern const SymCryptEcurveParamsNumsP384t1: u8;
extern const SymCryptEcurveParamsNumsP512t1: u8;
extern const SymCryptEcurveParamsCurve25519: u8;

extern const SymCryptMd2Algorithm: u8;
extern const SymCryptMd4Algorithm: u8;
extern const SymCryptMd5Algorithm: u8;
extern const SymCryptSha1Algorithm: u8;
extern const SymCryptSha224Algorithm: u8;
extern const SymCryptSha256Algorithm: u8;
extern const SymCryptSha384Algorithm: u8;
extern const SymCryptSha512Algorithm: u8;
extern const SymCryptSha512_224Algorithm: u8;
extern const SymCryptSha512_256Algorithm: u8;
extern const SymCryptSha3_224Algorithm: u8;
extern const SymCryptSha3_256Algorithm: u8;
extern const SymCryptSha3_384Algorithm: u8;
extern const SymCryptSha3_512Algorithm: u8;

extern const SymCryptHmacMd5Algorithm: u8;
extern const SymCryptHmacSha1Algorithm: u8;
extern const SymCryptHmacSha224Algorithm: u8;
extern const SymCryptHmacSha256Algorithm: u8;
extern const SymCryptHmacSha384Algorithm: u8;
extern const SymCryptHmacSha512Algorithm: u8;
extern const SymCryptHmacSha512_224Algorithm: u8;
extern const SymCryptHmacSha512_256Algorithm: u8;
extern const SymCryptHmacSha3_224Algorithm: u8;
extern const SymCryptHmacSha3_256Algorithm: u8;
extern const SymCryptHmacSha3_384Algorithm: u8;
extern const SymCryptHmacSha3_512Algorithm: u8;
extern const SymCryptAesCmacAlgorithm: u8;

extern const SymCryptMarvin32DefaultSeed: u8;

extern const SymCryptMd5OidList: [2]SYMCRYPT_OID;
extern const SymCryptSha1OidList: [4]SYMCRYPT_OID;
extern const SymCryptSha224OidList: [2]SYMCRYPT_OID;
extern const SymCryptSha256OidList: [2]SYMCRYPT_OID;
extern const SymCryptSha384OidList: [2]SYMCRYPT_OID;
extern const SymCryptSha512OidList: [2]SYMCRYPT_OID;
extern const SymCryptSha512_224OidList: [2]SYMCRYPT_OID;
extern const SymCryptSha512_256OidList: [2]SYMCRYPT_OID;
extern const SymCryptSha3_224OidList: [2]SYMCRYPT_OID;
extern const SymCryptSha3_256OidList: [2]SYMCRYPT_OID;
extern const SymCryptSha3_384OidList: [2]SYMCRYPT_OID;
extern const SymCryptSha3_512OidList: [2]SYMCRYPT_OID;
extern const SymCryptShake128OidList: [2]SYMCRYPT_OID;
extern const SymCryptShake256OidList: [2]SYMCRYPT_OID;

extern fn SymCryptGetBlockCipher(id: c_int) callconv(.c) ?*const anyopaque;
extern fn SymCryptGetEcurveParams(id: c_int) callconv(.c) ?*const anyopaque;
extern fn SymCryptGetHashAlgorithm(id: c_int) callconv(.c) ?*const anyopaque;
extern fn SymCryptGetMacAlgorithm(id: c_int) callconv(.c) ?*const anyopaque;
extern fn SymCryptGetMarvin32DefaultSeed() callconv(.c) ?*const anyopaque;
extern fn SymCryptGetOidList(id: c_int, pCount: ?*usize) callconv(.c) ?*const anyopaque;

extern fn scTestIsAlgorithmPresentCstr(name: [*:0]const u8, isPrefix: c_int) callconv(.c) c_int;
const scTestIsAlgorithmPresent = scTestIsAlgorithmPresentCstr;

fn testBlockCiphers() void {
    const Entry = struct { id: c_int, expected: ?*const anyopaque };
    const entries = [_]Entry{
        .{ .id = 0, .expected = null },
        .{ .id = 1, .expected = @ptrCast(&SymCryptAesBlockCipher) },
        .{ .id = 2, .expected = @ptrCast(&SymCrypt3DesBlockCipher) },
        .{ .id = 3, .expected = @ptrCast(&SymCryptDesBlockCipher) },
        .{ .id = 4, .expected = @ptrCast(&SymCryptDesxBlockCipher) },
        .{ .id = 5, .expected = @ptrCast(&SymCryptRc2BlockCipher) },
        .{ .id = 6, .expected = null },
    };

    for (entries) |entry| {
        const res = sc.callSymCrypt(
            "SymCryptGetBlockCipher",
            *const fn (c_int) callconv(.c) ?*const anyopaque,
            SymCryptGetBlockCipher,
            .{entry.id},
        );
        if (h.g_useDynamicFunctionsInTestCall != 0) {
            if (entry.expected != null) {
                h.check(res != null, "SymCryptGetBlockCipher dynamic call returned NULL");
            } else {
                h.check(res == null, "SymCryptGetBlockCipher dynamic call returned non-NULL");
            }
        } else {
            h.check(res == entry.expected, "SymCryptGetBlockCipher returned unexpected value");
        }
    }
}

fn testEcurveParams() void {
    const Entry = struct { id: c_int, expected: ?*const anyopaque };
    const entries = [_]Entry{
        .{ .id = 0, .expected = null },
        .{ .id = 1, .expected = @ptrCast(&SymCryptEcurveParamsNistP192) },
        .{ .id = 2, .expected = @ptrCast(&SymCryptEcurveParamsNistP224) },
        .{ .id = 3, .expected = @ptrCast(&SymCryptEcurveParamsNistP256) },
        .{ .id = 4, .expected = @ptrCast(&SymCryptEcurveParamsNistP384) },
        .{ .id = 5, .expected = @ptrCast(&SymCryptEcurveParamsNistP521) },
        .{ .id = 6, .expected = @ptrCast(&SymCryptEcurveParamsNumsP256t1) },
        .{ .id = 7, .expected = @ptrCast(&SymCryptEcurveParamsNumsP384t1) },
        .{ .id = 8, .expected = @ptrCast(&SymCryptEcurveParamsNumsP512t1) },
        .{ .id = 9, .expected = @ptrCast(&SymCryptEcurveParamsCurve25519) },
        .{ .id = 12, .expected = null },
    };

    for (entries) |entry| {
        const res = sc.callSymCrypt(
            "SymCryptGetEcurveParams",
            *const fn (c_int) callconv(.c) ?*const anyopaque,
            SymCryptGetEcurveParams,
            .{entry.id},
        );
        if (h.g_useDynamicFunctionsInTestCall != 0) {
            if (entry.expected != null) {
                h.check(res != null, "SymCryptGetEcurveParams dynamic call returned NULL");
            } else {
                h.check(res == null, "SymCryptGetEcurveParams dynamic call returned non-NULL");
            }
        } else {
            h.check(res == entry.expected, "SymCryptGetEcurveParams returned unexpected value");
        }
    }
}

fn testHashAlgorithms() void {
    const Entry = struct { id: c_int, expected: ?*const anyopaque };
    const entries = [_]Entry{
        .{ .id = 0, .expected = null },
        .{ .id = 1, .expected = @ptrCast(&SymCryptMd2Algorithm) },
        .{ .id = 2, .expected = @ptrCast(&SymCryptMd4Algorithm) },
        .{ .id = 3, .expected = @ptrCast(&SymCryptMd5Algorithm) },
        .{ .id = 4, .expected = @ptrCast(&SymCryptSha1Algorithm) },
        .{ .id = 5, .expected = @ptrCast(&SymCryptSha224Algorithm) },
        .{ .id = 6, .expected = @ptrCast(&SymCryptSha256Algorithm) },
        .{ .id = 7, .expected = @ptrCast(&SymCryptSha384Algorithm) },
        .{ .id = 8, .expected = @ptrCast(&SymCryptSha512Algorithm) },
        .{ .id = 9, .expected = @ptrCast(&SymCryptSha512_224Algorithm) },
        .{ .id = 10, .expected = @ptrCast(&SymCryptSha512_256Algorithm) },
        .{ .id = 11, .expected = @ptrCast(&SymCryptSha3_224Algorithm) },
        .{ .id = 12, .expected = @ptrCast(&SymCryptSha3_256Algorithm) },
        .{ .id = 13, .expected = @ptrCast(&SymCryptSha3_384Algorithm) },
        .{ .id = 14, .expected = @ptrCast(&SymCryptSha3_512Algorithm) },
        .{ .id = 15, .expected = null },
    };

    for (entries) |entry| {
        const res = sc.callSymCrypt(
            "SymCryptGetHashAlgorithm",
            *const fn (c_int) callconv(.c) ?*const anyopaque,
            SymCryptGetHashAlgorithm,
            .{entry.id},
        );
        if (h.g_useDynamicFunctionsInTestCall != 0) {
            if (entry.expected != null) {
                h.check(res != null, "SymCryptGetHashAlgorithm dynamic call returned NULL");
            } else {
                h.check(res == null, "SymCryptGetHashAlgorithm dynamic call returned non-NULL");
            }
        } else {
            h.check(res == entry.expected, "SymCryptGetHashAlgorithm returned unexpected value");
        }
    }
}

fn testMacAlgorithms() void {
    const Entry = struct { id: c_int, expected: ?*const anyopaque };
    const entries = [_]Entry{
        .{ .id = 0, .expected = null },
        .{ .id = 1, .expected = @ptrCast(&SymCryptHmacMd5Algorithm) },
        .{ .id = 2, .expected = @ptrCast(&SymCryptHmacSha1Algorithm) },
        .{ .id = 3, .expected = @ptrCast(&SymCryptHmacSha224Algorithm) },
        .{ .id = 4, .expected = @ptrCast(&SymCryptHmacSha256Algorithm) },
        .{ .id = 5, .expected = @ptrCast(&SymCryptHmacSha384Algorithm) },
        .{ .id = 6, .expected = @ptrCast(&SymCryptHmacSha512Algorithm) },
        .{ .id = 7, .expected = @ptrCast(&SymCryptHmacSha512_224Algorithm) },
        .{ .id = 8, .expected = @ptrCast(&SymCryptHmacSha512_256Algorithm) },
        .{ .id = 9, .expected = @ptrCast(&SymCryptHmacSha3_224Algorithm) },
        .{ .id = 10, .expected = @ptrCast(&SymCryptHmacSha3_256Algorithm) },
        .{ .id = 11, .expected = @ptrCast(&SymCryptHmacSha3_384Algorithm) },
        .{ .id = 12, .expected = @ptrCast(&SymCryptHmacSha3_512Algorithm) },
        .{ .id = 13, .expected = @ptrCast(&SymCryptAesCmacAlgorithm) },
        .{ .id = 14, .expected = null },
    };

    for (entries) |entry| {
        const res = sc.callSymCrypt(
            "SymCryptGetMacAlgorithm",
            *const fn (c_int) callconv(.c) ?*const anyopaque,
            SymCryptGetMacAlgorithm,
            .{entry.id},
        );
        if (h.g_useDynamicFunctionsInTestCall != 0) {
            if (entry.expected != null) {
                h.check(res != null, "SymCryptGetMacAlgorithm dynamic call returned NULL");
            } else {
                h.check(res == null, "SymCryptGetMacAlgorithm dynamic call returned non-NULL");
            }
        } else {
            h.check(res == entry.expected, "SymCryptGetMacAlgorithm returned unexpected value");
        }
    }
}

fn testMarvin32DefaultSeed() void {
    const res = sc.callSymCrypt(
        "SymCryptGetMarvin32DefaultSeed",
        *const fn () callconv(.c) ?*const anyopaque,
        SymCryptGetMarvin32DefaultSeed,
        .{},
    );
    if (h.g_useDynamicFunctionsInTestCall != 0) {
        h.check(res != null, "SymCryptGetMarvin32DefaultSeed dynamic call returned NULL");
    } else {
        h.check(
            res == @as(?*const anyopaque, @ptrCast(&SymCryptMarvin32DefaultSeed)),
            "SymCryptGetMarvin32DefaultSeed returned unexpected value",
        );
    }
}

fn testOidLists() void {
    const Entry = struct {
        id: c_int,
        expected: ?*const anyopaque,
        expectedCount: usize,
    };
    const entries = [_]Entry{
        .{ .id = 0, .expected = null, .expectedCount = 0 },
        .{ .id = 1, .expected = @ptrCast(&SymCryptMd5OidList[0]), .expectedCount = 2 },
        .{ .id = 2, .expected = @ptrCast(&SymCryptSha1OidList[0]), .expectedCount = 4 },
        .{ .id = 3, .expected = @ptrCast(&SymCryptSha224OidList[0]), .expectedCount = 2 },
        .{ .id = 4, .expected = @ptrCast(&SymCryptSha256OidList[0]), .expectedCount = 2 },
        .{ .id = 5, .expected = @ptrCast(&SymCryptSha384OidList[0]), .expectedCount = 2 },
        .{ .id = 6, .expected = @ptrCast(&SymCryptSha512OidList[0]), .expectedCount = 2 },
        .{ .id = 7, .expected = @ptrCast(&SymCryptSha512_224OidList[0]), .expectedCount = 2 },
        .{ .id = 8, .expected = @ptrCast(&SymCryptSha512_256OidList[0]), .expectedCount = 2 },
        .{ .id = 9, .expected = @ptrCast(&SymCryptSha3_224OidList[0]), .expectedCount = 2 },
        .{ .id = 10, .expected = @ptrCast(&SymCryptSha3_256OidList[0]), .expectedCount = 2 },
        .{ .id = 11, .expected = @ptrCast(&SymCryptSha3_384OidList[0]), .expectedCount = 2 },
        .{ .id = 12, .expected = @ptrCast(&SymCryptSha3_512OidList[0]), .expectedCount = 2 },
        .{ .id = 13, .expected = @ptrCast(&SymCryptShake128OidList[0]), .expectedCount = 2 },
        .{ .id = 14, .expected = @ptrCast(&SymCryptShake256OidList[0]), .expectedCount = 2 },
        .{ .id = 15, .expected = null, .expectedCount = 0 },
    };

    for (entries) |entry| {
        const res1 = sc.callSymCrypt(
            "SymCryptGetOidList",
            *const fn (c_int, ?*usize) callconv(.c) ?*const anyopaque,
            SymCryptGetOidList,
            .{ entry.id, null },
        );
        if (h.g_useDynamicFunctionsInTestCall != 0) {
            if (entry.expected != null) {
                h.check(res1 != null, "SymCryptGetOidList dynamic call returned NULL");
            } else {
                h.check(res1 == null, "SymCryptGetOidList dynamic call returned non-NULL");
            }
        } else {
            h.check(res1 == entry.expected, "SymCryptGetOidList returned unexpected value");
        }

        var count: usize = 0;
        const res2 = sc.callSymCrypt(
            "SymCryptGetOidList",
            *const fn (c_int, ?*usize) callconv(.c) ?*const anyopaque,
            SymCryptGetOidList,
            .{ entry.id, &count },
        );
        if (h.g_useDynamicFunctionsInTestCall != 0) {
            if (entry.expected != null) {
                h.check(res2 != null, "SymCryptGetOidList dynamic call returned NULL");
            } else {
                h.check(res2 == null, "SymCryptGetOidList dynamic call returned non-NULL");
            }
        } else {
            h.check(res2 == entry.expected, "SymCryptGetOidList returned unexpected value");
        }
        h.check(count == entry.expectedCount, "SymCryptGetOidList returned unexpected count");
    }
}

pub export fn testDataAccessors() callconv(.c) void {
    if (scTestIsAlgorithmPresent("DataAccessors", 1) == 0) {
        return;
    }

    h.ziprint("    DataAccessors\n", .{});

    if (tu.hasDispatchSym("SymCryptGetBlockCipher")) {
        testBlockCiphers();
    }
    if (tu.hasDispatchSym("SymCryptGetEcurveParams")) {
        testEcurveParams();
    }
    if (tu.hasDispatchSym("SymCryptGetHashAlgorithm")) {
        testHashAlgorithms();
    }
    if (tu.hasDispatchSym("SymCryptGetMacAlgorithm")) {
        testMacAlgorithms();
    }
    if (tu.hasDispatchSym("SymCryptGetMarvin32DefaultSeed")) {
        testMarvin32DefaultSeed();
    }
    if (tu.hasDispatchSym("SymCryptGetOidList")) {
        testOidLists();
    }
}
