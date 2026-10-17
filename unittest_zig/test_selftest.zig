// Copyright (c) Microsoft Corporation. Licensed under the MIT license.

const std = @import("std");
const h = @import("main_harness.zig");
const rng = @import("rng.zig");

pub const SelftestFn = *const fn () callconv(.c) void;
pub const SelftestAllocFn = *const fn () callconv(.c) void;

pub const SELFTEST_INFO = extern struct {
    f: ?*const anyopaque,
    name: ?[*:0]const u8,
};

extern fn SymCryptMd2Selftest() callconv(.c) void;
extern fn SymCryptMd4Selftest() callconv(.c) void;
extern fn SymCryptMd5Selftest() callconv(.c) void;
extern fn SymCryptSha1Selftest() callconv(.c) void;
extern fn SymCryptSha224Selftest() callconv(.c) void;
extern fn SymCryptSha256Selftest() callconv(.c) void;
extern fn SymCryptSha384Selftest() callconv(.c) void;
extern fn SymCryptSha512Selftest() callconv(.c) void;
extern fn SymCryptSha512_224Selftest() callconv(.c) void;
extern fn SymCryptSha512_256Selftest() callconv(.c) void;
extern fn SymCryptSha3_224Selftest() callconv(.c) void;
extern fn SymCryptSha3_256Selftest() callconv(.c) void;
extern fn SymCryptSha3_384Selftest() callconv(.c) void;
extern fn SymCryptSha3_512Selftest() callconv(.c) void;
extern fn SymCryptShake128Selftest() callconv(.c) void;
extern fn SymCryptShake256Selftest() callconv(.c) void;
extern fn SymCryptCShake128Selftest() callconv(.c) void;
extern fn SymCryptCShake256Selftest() callconv(.c) void;
extern fn SymCryptHmacMd5Selftest() callconv(.c) void;
extern fn SymCryptHmacSha1Selftest() callconv(.c) void;
extern fn SymCryptHmacSha224Selftest() callconv(.c) void;
extern fn SymCryptHmacSha256Selftest() callconv(.c) void;
extern fn SymCryptHmacSha384Selftest() callconv(.c) void;
extern fn SymCryptHmacSha512Selftest() callconv(.c) void;
extern fn SymCryptHmacSha512_224Selftest() callconv(.c) void;
extern fn SymCryptHmacSha512_256Selftest() callconv(.c) void;
extern fn SymCryptHmacSha3_224Selftest() callconv(.c) void;
extern fn SymCryptHmacSha3_256Selftest() callconv(.c) void;
extern fn SymCryptHmacSha3_384Selftest() callconv(.c) void;
extern fn SymCryptHmacSha3_512Selftest() callconv(.c) void;
extern fn SymCryptKmac128Selftest() callconv(.c) void;
extern fn SymCryptKmac256Selftest() callconv(.c) void;
extern fn SymCryptAesCmacSelftest() callconv(.c) void;
extern fn SymCryptMarvin32Selftest() callconv(.c) void;
extern fn SymCryptAesSelftest(flags: u32) callconv(.c) void;
extern fn SymCryptDesSelftest() callconv(.c) void;
extern fn SymCrypt3DesSelftest() callconv(.c) void;
extern fn SymCryptDesxSelftest() callconv(.c) void;
extern fn SymCryptRc2Selftest() callconv(.c) void;
extern fn SymCryptRc4Selftest() callconv(.c) void;
extern fn SymCryptCcmSelftest() callconv(.c) void;
extern fn SymCryptGcmSelftest() callconv(.c) void;
extern fn SymCryptChaCha20Selftest() callconv(.c) void;
extern fn SymCryptPoly1305Selftest() callconv(.c) void;
extern fn SymCryptChaCha20Poly1305Selftest() callconv(.c) void;
extern fn SymCryptRngAesInstantiateSelftest() callconv(.c) void;
extern fn SymCryptRngAesReseedSelftest() callconv(.c) void;
extern fn SymCryptRngAesGenerateSelftest() callconv(.c) void;
extern fn SymCryptXtsAesSelftest() callconv(.c) void;
extern fn SymCryptTlsPrf1_1SelfTest() callconv(.c) void;
extern fn SymCryptTlsPrf1_2SelfTest() callconv(.c) void;
extern fn SymCryptHkdfSelfTest() callconv(.c) void;
extern fn SymCryptSp800_108_HmacSha1SelfTest() callconv(.c) void;
extern fn SymCryptSp800_108_HmacSha256SelfTest() callconv(.c) void;
extern fn SymCryptSp800_108_HmacSha384SelfTest() callconv(.c) void;
extern fn SymCryptSp800_108_HmacSha512SelfTest() callconv(.c) void;
extern fn SymCryptPbkdf2_HmacSha1SelfTest() callconv(.c) void;
extern fn SymCryptPbkdf2_HmacSha256SelfTest() callconv(.c) void;
extern fn SymCryptSrtpKdfSelfTest() callconv(.c) void;
extern fn SymCryptSshKdfSha256SelfTest() callconv(.c) void;
extern fn SymCryptSshKdfSha512SelfTest() callconv(.c) void;
extern fn SymCryptSskdfSelfTest() callconv(.c) void;
extern fn SymCryptParallelSha256Selftest() callconv(.c) void;
extern fn SymCryptParallelSha384Selftest() callconv(.c) void;
extern fn SymCryptParallelSha512Selftest() callconv(.c) void;
extern fn SymCryptXmssSelftest() callconv(.c) void;
extern fn SymCryptLmsSelftest() callconv(.c) void;

extern fn SymCryptRsaSelftest() callconv(.c) void;
extern fn SymCryptDsaSelftest() callconv(.c) void;
extern fn SymCryptDhSecretAgreementSelftest() callconv(.c) void;
extern fn SymCryptEcDsaSelftest() callconv(.c) void;
extern fn SymCryptEcDhSecretAgreementSelftest() callconv(.c) void;
extern fn SymCryptMlKemSelftest() callconv(.c) void;
extern fn SymCryptMlDsaSelftest() callconv(.c) void;

extern var TestSelftestsEnabled: u8;
extern var TestFatalCount: u64;
extern var TestErrorInjectionCount: u64;
extern var TestErrorInjectionCalls: u64;
extern var TestErrorInjectionProb: u32;
extern var TestErrorInjectionSeed: [20]u8;

fn SymCryptAesAllModesSelftest() callconv(.c) void {
    SymCryptAesSelftest(0xF);
}

pub export const g_selfTests = [_]SELFTEST_INFO{
    .{ .f = @ptrCast(&SymCryptMd2Selftest), .name = "Md2" },
    .{ .f = @ptrCast(&SymCryptMd4Selftest), .name = "Md4" },
    .{ .f = @ptrCast(&SymCryptMd5Selftest), .name = "Md5" },
    .{ .f = @ptrCast(&SymCryptSha1Selftest), .name = "Sha1" },
    .{ .f = @ptrCast(&SymCryptSha224Selftest), .name = "Sha224" },
    .{ .f = @ptrCast(&SymCryptSha256Selftest), .name = "Sha256" },
    .{ .f = @ptrCast(&SymCryptSha384Selftest), .name = "Sha384" },
    .{ .f = @ptrCast(&SymCryptSha512Selftest), .name = "Sha512" },
    .{ .f = @ptrCast(&SymCryptSha512_224Selftest), .name = "Sha512-224" },
    .{ .f = @ptrCast(&SymCryptSha512_256Selftest), .name = "Sha512-256" },
    .{ .f = @ptrCast(&SymCryptSha3_224Selftest), .name = "Sha3-224" },
    .{ .f = @ptrCast(&SymCryptSha3_256Selftest), .name = "Sha3-256" },
    .{ .f = @ptrCast(&SymCryptSha3_384Selftest), .name = "Sha3-384" },
    .{ .f = @ptrCast(&SymCryptSha3_512Selftest), .name = "Sha3-512" },
    .{ .f = @ptrCast(&SymCryptShake128Selftest), .name = "Shake128" },
    .{ .f = @ptrCast(&SymCryptShake256Selftest), .name = "Shake256" },
    .{ .f = @ptrCast(&SymCryptCShake128Selftest), .name = "CShake128" },
    .{ .f = @ptrCast(&SymCryptCShake256Selftest), .name = "CShake256" },
    .{ .f = @ptrCast(&SymCryptKmac128Selftest), .name = "Kmac128" },
    .{ .f = @ptrCast(&SymCryptKmac256Selftest), .name = "Kmac256" },
    .{ .f = @ptrCast(&SymCryptHmacMd5Selftest), .name = "HmacMd5" },
    .{ .f = @ptrCast(&SymCryptHmacSha1Selftest), .name = "HmacSha1" },
    .{ .f = @ptrCast(&SymCryptHmacSha224Selftest), .name = "HmacSha224" },
    .{ .f = @ptrCast(&SymCryptHmacSha256Selftest), .name = "HmacSha256" },
    .{ .f = @ptrCast(&SymCryptHmacSha384Selftest), .name = "HmacSha384" },
    .{ .f = @ptrCast(&SymCryptHmacSha512Selftest), .name = "HmacSha512" },
    .{ .f = @ptrCast(&SymCryptHmacSha512_224Selftest), .name = "HmacSha512-224" },
    .{ .f = @ptrCast(&SymCryptHmacSha512_256Selftest), .name = "HmacSha512-256" },
    .{ .f = @ptrCast(&SymCryptHmacSha3_224Selftest), .name = "HmacSha3-224" },
    .{ .f = @ptrCast(&SymCryptHmacSha3_256Selftest), .name = "HmacSha3-256" },
    .{ .f = @ptrCast(&SymCryptHmacSha3_384Selftest), .name = "HmacSha3-384" },
    .{ .f = @ptrCast(&SymCryptHmacSha3_512Selftest), .name = "HmacSha3-512" },
    .{ .f = @ptrCast(&SymCryptAesCmacSelftest), .name = "AesCmac" },
    .{ .f = @ptrCast(&SymCryptMarvin32Selftest), .name = "Marvin32" },
    .{ .f = @ptrCast(&SymCryptAesAllModesSelftest), .name = "Aes" },
    .{ .f = @ptrCast(&SymCryptDesSelftest), .name = "Des" },
    .{ .f = @ptrCast(&SymCrypt3DesSelftest), .name = "3Des" },
    .{ .f = @ptrCast(&SymCryptDesxSelftest), .name = "Desx" },
    .{ .f = @ptrCast(&SymCryptRc2Selftest), .name = "Rc2" },
    .{ .f = @ptrCast(&SymCryptCcmSelftest), .name = "Ccm" },
    .{ .f = @ptrCast(&SymCryptGcmSelftest), .name = "Gcm" },
    .{ .f = @ptrCast(&SymCryptRc4Selftest), .name = "Rc4" },
    .{ .f = @ptrCast(&SymCryptChaCha20Selftest), .name = "ChaCha20" },
    .{ .f = @ptrCast(&SymCryptPoly1305Selftest), .name = "Poly1305" },
    .{ .f = @ptrCast(&SymCryptChaCha20Poly1305Selftest), .name = "ChaCha20Poly1305" },
    .{ .f = @ptrCast(&SymCryptRngAesInstantiateSelftest), .name = "AesCtrDrbgInstantiate" },
    .{ .f = @ptrCast(&SymCryptRngAesReseedSelftest), .name = "AesCtrDrbgReseed" },
    .{ .f = @ptrCast(&SymCryptRngAesGenerateSelftest), .name = "AesCtrDrbgGenerate" },
    .{ .f = @ptrCast(&SymCryptPbkdf2_HmacSha1SelfTest), .name = "Pbkdf2_HmacSha1" },
    .{ .f = @ptrCast(&SymCryptPbkdf2_HmacSha256SelfTest), .name = "Pbkdf2_HmacSha256" },
    .{ .f = @ptrCast(&SymCryptSp800_108_HmacSha1SelfTest), .name = "SP800-108_HmacSha1" },
    .{ .f = @ptrCast(&SymCryptSp800_108_HmacSha256SelfTest), .name = "SP800-108_HmacSha256" },
    .{ .f = @ptrCast(&SymCryptSp800_108_HmacSha384SelfTest), .name = "SP800-108_HmacSha384" },
    .{ .f = @ptrCast(&SymCryptSp800_108_HmacSha512SelfTest), .name = "SP800-108_HmacSha512" },
    .{ .f = @ptrCast(&SymCryptTlsPrf1_1SelfTest), .name = "TLS PRF 1.1" },
    .{ .f = @ptrCast(&SymCryptTlsPrf1_2SelfTest), .name = "TLS PRF 1.2" },
    .{ .f = @ptrCast(&SymCryptHkdfSelfTest), .name = "HKDF" },
    .{ .f = @ptrCast(&SymCryptXtsAesSelftest), .name = "Xts-Aes" },
    .{ .f = @ptrCast(&SymCryptParallelSha256Selftest), .name = "ParallelSha256" },
    .{ .f = @ptrCast(&SymCryptParallelSha384Selftest), .name = "ParallelSha384" },
    .{ .f = @ptrCast(&SymCryptParallelSha512Selftest), .name = "ParallelSha512" },
    .{ .f = @ptrCast(&SymCryptSrtpKdfSelfTest), .name = "SrtpKdf" },
    .{ .f = @ptrCast(&SymCryptSshKdfSha256SelfTest), .name = "SshKdfSha256" },
    .{ .f = @ptrCast(&SymCryptSshKdfSha512SelfTest), .name = "SshKdfSha512" },
    .{ .f = @ptrCast(&SymCryptSskdfSelfTest), .name = "Sskdf" },
    .{ .f = null, .name = null },
};

pub export const g_selfTests_allocating = [_]SELFTEST_INFO{
    .{ .f = @ptrCast(&SymCryptDhSecretAgreementSelftest), .name = "DHSecretAgreement" },
    .{ .f = @ptrCast(&SymCryptEcDhSecretAgreementSelftest), .name = "ECDHSecretAgreement" },
    .{ .f = @ptrCast(&SymCryptDsaSelftest), .name = "DSA" },
    .{ .f = @ptrCast(&SymCryptEcDsaSelftest), .name = "ECDSA" },
    .{ .f = @ptrCast(&SymCryptRsaSelftest), .name = "RSA" },
    .{ .f = @ptrCast(&SymCryptXmssSelftest), .name = "Xmss" },
    .{ .f = @ptrCast(&SymCryptLmsSelftest), .name = "Lms" },
    .{ .f = @ptrCast(&SymCryptMlKemSelftest), .name = "MlKem" },
    .{ .f = @ptrCast(&SymCryptMlDsaSelftest), .name = "MlDsa" },
    .{ .f = null, .name = null },
};

fn testSingleSelftest(f: ?SelftestFn, fAlloc: ?SelftestAllocFn, name: [*:0]const u8) void {
    h.check((f == null) != (fAlloc == null), "Invalid arguments");
    @memset(&TestErrorInjectionSeed, 0);
    const seedVal = rng.scTestRngSizet(&rng.g_rng, std.math.maxInt(usize)) | 1;
    std.mem.writeInt(usize, TestErrorInjectionSeed[0..@sizeOf(usize)], seedVal, .little);

    TestSelftestsEnabled = 1;

    var nInjectCalls = TestErrorInjectionCalls;
    TestErrorInjectionProb = 1;
    var fatalCount = TestFatalCount;

    if (f) |func| {
        func();
    } else if (fAlloc) |func| {
        func();
    }

    h.check3(
        TestFatalCount == fatalCount,
        "Executing {s} Selftest caused fatal failure when error injection was disabled",
        std.mem.span(name),
    );

    nInjectCalls = TestErrorInjectionCalls - nInjectCalls;
    h.check3(
        nInjectCalls > 0 and nInjectCalls < 10,
        "Expected at least 1 and fewer than 10 error injection calls in {s}",
        std.mem.span(name),
    );
    TestErrorInjectionProb = @as(u32, @intCast(nInjectCalls)) + 1;

    var nTests: u32 = 0;
    var nTestsFailed: u32 = 0;
    while (nTestsFailed < 10) : (nTests += 1) {
        fatalCount = TestFatalCount;
        const errorInjectionCount = TestErrorInjectionCount;

        if (f) |func| {
            func();
        } else if (fAlloc) |func| {
            func();
        }

        if (errorInjectionCount != TestErrorInjectionCount) {
            if (fatalCount == TestFatalCount) {
                h.fatal("Selftest {s} succeeded even when an error was injected", .{std.mem.span(name)});
            }
            nTestsFailed += 1;
        } else {
            if (fatalCount != TestFatalCount) {
                h.fatal("Selftest {s} failed even when no error was injected", .{std.mem.span(name)});
            }
        }
    }

    h.zvprint(
        h.g_verbose != 0,
        "    {s: <45} : {d: >2} inject call(s), {d: >3} tests were run in order to see {d: >2} injected errors catch the failure\n",
        .{ std.mem.span(name), nInjectCalls, nTests, nTestsFailed },
    );

    TestSelftestsEnabled = 0;
}

pub export fn testSelftest() callconv(.c) void {
    h.ziprint("    Selftests", .{});
    h.zvprint(h.g_verbose != 0, "\n", .{});

    var i: usize = 0;
    while (g_selfTests[i].f != null) : (i += 1) {
        const fnPtr: SelftestFn = @ptrCast(@alignCast(g_selfTests[i].f.?));
        testSingleSelftest(fnPtr, null, g_selfTests[i].name.?);
    }

    i = 0;
    while (g_selfTests_allocating[i].f != null) : (i += 1) {
        const fnPtr: SelftestAllocFn = @ptrCast(@alignCast(g_selfTests_allocating[i].f.?));
        testSingleSelftest(null, fnPtr, g_selfTests_allocating[i].name.?);
    }

    h.zvprint(h.g_verbose == 0, "\n", .{});
}
