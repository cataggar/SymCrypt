// Copyright (c) Microsoft Corporation. Licensed under the MIT license.

const std = @import("std");
const builtin = @import("builtin");
const h = @import("main_harness.zig");
const pt = @import("printtable.zig");
const rng = @import("rng.zig");

pub const PERF_BUFFER_SIZE: usize = 1 << 18;
pub const TEST_MEMORY_SIZE: usize = 1 << 24;
pub const PERF_WIPE_MAX_SIZE: usize = 64;
pub const PERF_WIPE_N_OFFSETS: usize = 16;

const PERF_KEY_FLAGS_MASK: usize = 0xff000000;
const PERF_KEY_SECRET: usize = 0x01000000;
const PERF_KEY_PUBLIC: usize = 0x02000000;
const PERF_KEY_PRIME: usize = 0x03000000;
const PERF_KEY_PUB_ODD: usize = 0x04000000;
const PERF_KEY_PUB_PM: usize = 0x05000000;
const PERF_KEY_PUB_NIST: usize = 0x06000000;

const PERF_KEY_XMSS: usize = 0x10000000;
const PERF_KEY_LMS: usize = 0x20000000;
const PERF_KEY_MLDSA: usize = 0x40000000;
const PERF_KEY_COMPOSITE_MLDSA: usize = 0x50000000;
const PERF_KEY_MLKEM: usize = 0x80000000;
const PERF_KEY_COMPOSITE_MLKEM: usize = 0x90000000;
const PERF_KEY_HPKE: usize = 0xa0000000;

const PERF_KEY_XTS_DATA_UNIT_256: usize = 0x10000000;
const PERF_KEY_XTS_DATA_UNIT_512: usize = 0x20000000;
const PERF_KEY_XTS_DATA_UNIT_4096: usize = 0x40000000;

const PERF_KEY_RSA_2K_100: usize = (256 << 8) | 100;
const PERF_KEY_RSA_2K_30: usize = (256 << 8) | 30;
const PERF_KEY_RSA_2K_10: usize = (256 << 8) | 10;
const PERF_KEY_RSA_2K_3: usize = (256 << 8) | 3;
const PERF_KEY_RSA_2K_1: usize = (256 << 8) | 1;
const PERF_KEY_RSA_2K_0: usize = (256 << 8) | 0;

const PERF_KEY_EC_SECP256R1: usize = 32;
const PERF_KEY_EC_SECP384R1: usize = 48;
const PERF_KEY_EC_SECP521R1: usize = 66;
const PERF_KEY_EC_CURVE25519: usize = 32 | 0x8000;
const PERF_KEY_EC_NUMSP256T1: usize = 32 | 0x4000;
const PERF_KEY_EC_NUMSP384T1: usize = 48 | 0x4000;
const PERF_KEY_EC_NUMSP512T1: usize = 64 | 0x4000;

const PERF_KEY_NIST_P256: usize = 0x01000000 | 32;
const PERF_KEY_NIST_P384: usize = 0x01000000 | 48;
const PERF_KEY_NIST_P521: usize = 0x01000000 | 66;
const PERF_KEY_NUMS_P256T1: usize = 0x02000000 | 32;
const PERF_KEY_NUMS_P384T1: usize = 0x02000000 | 48;
const PERF_KEY_NUMS_P512T1: usize = 0x02000000 | 64;
const PERF_KEY_C25519: usize = 0x03000000 | 32;
const PERF_KEY_SW_P256: usize = 0x04000000 | 32;
const PERF_KEY_W25519: usize = 0x05000000 | 32;
const PERF_KEY_W448: usize = 0x05000000 | 56;

const SYMCRYPT_XMSS_SHA2_10_256: usize = 0x00000001;
const SYMCRYPT_XMSS_SHA2_16_256: usize = 0x00000002;
const SYMCRYPT_XMSS_SHA2_20_256: usize = 0x00000003;
const SYMCRYPT_XMSS_SHA2_10_512: usize = 0x00000004;
const SYMCRYPT_XMSS_SHA2_16_512: usize = 0x00000005;
const SYMCRYPT_XMSS_SHA2_20_512: usize = 0x00000006;
const SYMCRYPT_XMSS_SHAKE256_10_256: usize = 0x00000010;
const SYMCRYPT_XMSS_SHAKE256_16_256: usize = 0x00000011;
const SYMCRYPT_XMSS_SHAKE256_20_256: usize = 0x00000012;

const SYMCRYPT_LMS_SHA256_M32_H5: usize = 5;
const SYMCRYPT_LMS_SHA256_M32_H10: usize = 6;
const SYMCRYPT_LMS_SHA256_M32_H15: usize = 7;
const SYMCRYPT_LMS_SHA256_M32_H20: usize = 8;
const SYMCRYPT_LMS_SHA256_M32_H25: usize = 9;
const SYMCRYPT_LMS_SHA256_M24_H5: usize = 10;
const SYMCRYPT_LMS_SHA256_M24_H10: usize = 11;
const SYMCRYPT_LMS_SHA256_M24_H15: usize = 12;
const SYMCRYPT_LMS_SHA256_M24_H20: usize = 13;
const SYMCRYPT_LMS_SHA256_M24_H25: usize = 14;
const SYMCRYPT_LMS_SHAKE_M32_H5: usize = 15;
const SYMCRYPT_LMS_SHAKE_M32_H10: usize = 16;
const SYMCRYPT_LMS_SHAKE_M32_H15: usize = 17;
const SYMCRYPT_LMS_SHAKE_M32_H20: usize = 18;
const SYMCRYPT_LMS_SHAKE_M32_H25: usize = 19;
const SYMCRYPT_LMS_SHAKE_M24_H5: usize = 20;
const SYMCRYPT_LMS_SHAKE_M24_H10: usize = 21;
const SYMCRYPT_LMS_SHAKE_M24_H15: usize = 22;
const SYMCRYPT_LMS_SHAKE_M24_H20: usize = 23;
const SYMCRYPT_LMS_SHAKE_M24_H25: usize = 24;

const SYMCRYPT_MLDSA_PARAMS_MLDSA44: usize = 1;
const SYMCRYPT_MLDSA_PARAMS_MLDSA65: usize = 2;
const SYMCRYPT_MLDSA_PARAMS_MLDSA87: usize = 3;

const SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA44_P256: usize = 1;
const SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA65_P256: usize = 2;
const SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA65_P384: usize = 3;
const SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA87_P384: usize = 4;

const SYMCRYPT_MLKEM_PARAMS_MLKEM512: usize = 1;
const SYMCRYPT_MLKEM_PARAMS_MLKEM768: usize = 2;
const SYMCRYPT_MLKEM_PARAMS_MLKEM1024: usize = 3;

const SYMCRYPT_COMPOSITE_MLKEM_PARAMS_MLKEM768_P256: usize = 1;
const SYMCRYPT_COMPOSITE_MLKEM_PARAMS_MLKEM768_X25519: usize = 2;
const SYMCRYPT_COMPOSITE_MLKEM_PARAMS_MLKEM1024_P384: usize = 3;

pub const PerfKeySizeSupportedFn = *const fn (keySize: usize) callconv(.c) c_int;
pub const PerfKeyFn = *const fn (buf1: [*]u8, buf2: [*]u8, buf3: [*]u8, keySize: usize) callconv(.c) void;
pub const PerfDataFn = *const fn (buf1: [*]u8, buf2: [*]u8, buf3: [*]u8, dataSize: usize) callconv(.c) void;
pub const PerfCleanFn = *const fn (buf1: [*]u8, buf2: [*]u8, buf3: [*]u8) callconv(.c) void;

// ============================================================================
// perfPrint implementation
// ============================================================================

var Output: [1 << 23]u8 = undefined;
var OutputOffset: usize = 0;

pub export fn scTestPrintAppend(ptr: [*]const u8, len: usize) callconv(.c) void {
    const avail = Output.len - 1 - OutputOffset;
    const copyLen = @min(len, avail);
    if (copyLen > 0) {
        @memcpy(Output[OutputOffset .. OutputOffset + copyLen], ptr[0..copyLen]);
        OutputOffset += copyLen;
        Output[OutputOffset] = 0;
    }
    if (OutputOffset >= Output.len - 10000) {
        printOutput(10);
    }
}

pub export fn scTestAddOutput(ptr: [*]const u8, len: usize) callconv(.c) void {
    scTestPrintAppend(ptr, len);
}

pub export fn scTestAddDirectOutput(ptr: [*]const u8, len: usize) callconv(.c) void {
    printOutput(0);
    scTestPrintAppend(ptr, len);
    printOutput(0);
}

pub export fn printOutput(delayMilliSeconds: c_int) callconv(.c) void {
    if (OutputOffset > 0) {
        Output[OutputOffset] = 0;
        _ = std.c.printf("%s", @as([*:0]const u8, @ptrCast(&Output)));
        OutputOffset = 0;
        if (delayMilliSeconds > 0) {
            scTestSleepMs(@intCast(delayMilliSeconds));
        }
    }
}

pub export fn printHex(pbData: [*]const u8, cbData: usize) callconv(.c) void {
    const hexDigits = "0123456789abcdef";
    var buf: [2]u8 = undefined;
    for (0..cbData) |i| {
        const b = pbData[i];
        buf[0] = hexDigits[b >> 4];
        buf[1] = hexDigits[b & 0x0f];
        scTestPrintAppend(&buf, 2);
    }
}

pub export fn scTestFormatNumber(v: f64, outBuf: [*]u8, outCap: usize) callconv(.c) usize {
    if (outCap == 0) return 0;
    var tmp: [64]u8 = undefined;
    const s = formatNumberSlice(&tmp, v);
    const n = @min(s.len, outCap - 1);
    @memcpy(outBuf[0..n], s[0..n]);
    outBuf[n] = 0;
    return n;
}

pub fn formatNumberSlice(buf: []u8, v_in: f64) []const u8 {
    if (v_in < 0) {
        var sub_buf: [64]u8 = undefined;
        const sub = formatNumberSlice(&sub_buf, -v_in);
        return std.fmt.bufPrint(buf, "-{s}", .{sub}) catch unreachable;
    }
    if (std.math.isNan(v_in)) {
        return std.fmt.bufPrint(buf, "NAN  ", .{}) catch unreachable;
    }
    h.check(v_in < 1e24, "Number too large");

    var v = v_in;
    const fSmallInt = @floor(v) == v and v < 10000.0;
    var s: usize = 0;
    while (v >= 10000.0) {
        v /= 1000.0;
        s += 1;
    }

    const suffixes = " kMGTPEZ";
    const suffix = suffixes[s];

    if (v < 1.0 and !fSmallInt) {
        const iv: u32 = @intFromFloat(1000.0 * v);
        return std.fmt.bufPrint(buf, " .{d:0>3}{c}", .{ iv, suffix }) catch unreachable;
    } else if (v < 10.0 and !fSmallInt) {
        const whole: u32 = @intFromFloat(@floor(v));
        const frac: u32 = @intFromFloat(100.0 * @mod(v, 1.0));
        return std.fmt.bufPrint(buf, " {d}.{d:0>2}{c}", .{ whole, frac, suffix }) catch unreachable;
    } else if (v < 100.0 and !fSmallInt) {
        const whole: u32 = @intFromFloat(@floor(v));
        const frac: u32 = @intFromFloat(10.0 * @mod(v, 1.0));
        return std.fmt.bufPrint(buf, " {d: >2}.{d:0>1}{c}", .{ whole, frac, suffix }) catch unreachable;
    } else if (v < 1000.0) {
        const whole: u32 = @intFromFloat(@floor(v));
        return std.fmt.bufPrint(buf, "  {d: >3}{c}", .{ whole, suffix }) catch unreachable;
    } else {
        const whole: u32 = @intFromFloat(@floor(v));
        return std.fmt.bufPrint(buf, " {d: >4}{c}", .{ whole, suffix }) catch unreachable;
    }
}

// ============================================================================
// perf globals & externs
// ============================================================================

pub export var g_wipePerf: [PERF_WIPE_MAX_SIZE + 1][PERF_WIPE_N_OFFSETS]f64 = @splat(@splat(0.0));
var g_perfUnitsStorage: [16]u8 = .{ 'c', 'y', 'c', 'l', 'e', 's', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
pub export var g_perfUnits: [*:0]u8 = @ptrCast(&g_perfUnitsStorage);

pub export var g_perfScaleFactor: f64 = 1.0;
pub export var g_perfMeasurementOverhead: f64 = 0.0;
pub export var g_perfStackOverhead: f64 = 0.0;
pub export var g_perfTimeScalingOverhead: f64 = 0.0;
pub export var g_perfDummy: u64 = 0;

var g_PerfBuffer: ?[]u8 = null;

extern var g_perfTestsRunning: c_int;
extern var g_profile: c_int;
extern var g_profile_iterations: u32;
extern var g_profile_key: u32;
extern var g_measure_specific_sizes: c_int;
extern var g_measure_sizes_start: u32;
extern var g_measure_sizes_end: u32;
extern var g_measure_sizes_increment: u32;
extern var g_measure_sizes_repetitions: u32;
pub export var g_tscFreq: f64 = 0.0;
extern var g_dynamicSymCryptModuleHandle: ?*anyopaque;
extern var TestSelftestsEnabled: u8;
extern var TestErrorInjectionProb: u32;

extern fn SymCryptWipe(pbData: [*]u8, cbData: usize) callconv(.c) void;
extern fn SymCryptSha1(pbData: [*]const u8, cbData: usize, pbResult: [*]u8) callconv(.c) void;
extern fn SymCryptLoadLsbFirstUint64(pbSrc: [*]const u8, cbSrc: usize) callconv(.c) u64;

const SYMCRYPT_RSA_PARAMS = extern struct {
    version: u32,
    nBitsOfModulus: u32,
    nPrimes: u32,
    nPubExp: u32,
};

extern fn SymCryptDigitsFromBits(nBits: u32) callconv(.c) u32;
extern fn SymCryptCreateTrialDivisionContext(nDigits: u32) callconv(.c) ?*const anyopaque;
extern fn SymCryptFreeTrialDivisionContext(pContext: *const anyopaque) callconv(.c) void;
extern fn SymCryptTestTrialdivisionMaxSmallPrime(pContext: *const anyopaque) callconv(.c) u32;
extern fn SymCryptRsakeyAllocate(pParams: *const SYMCRYPT_RSA_PARAMS, flags: u32) callconv(.c) ?*anyopaque;
extern fn SymCryptRsakeyFree(pkRsakey: *anyopaque) callconv(.c) void;
extern fn SymCryptRsakeyGenerate(pkRsakey: *anyopaque, pu64PubExp: ?[*]const u64, nPubExp: u32, flags: u32) callconv(.c) u32;

extern fn getDynamicSymbolPointerFromString(hModule: ?*anyopaque, pSymbolName: [*:0]const u8, symbolType: c_int) callconv(.c) ?*anyopaque;

extern fn scTestGetPerfClock() callconv(.c) u64;
extern fn scTestIsAlgorithmPresentCstr(name: [*:0]const u8, isPrefix: c_int) callconv(.c) c_int;
const scTestIsAlgorithmPresent = scTestIsAlgorithmPresentCstr;
extern fn scTestIsImpToTest(impNamePtr: [*]const u8, impNameLen: usize) callconv(.c) c_int;
extern fn scTestGetAlgImpCount() callconv(.c) usize;
extern fn scTestGetAlgImpAt(idx: usize) callconv(.c) *anyopaque;
extern fn scTestAlgImpGetAlgName(pImp: *anyopaque, outPtr: *[*]const u8) callconv(.c) usize;
extern fn scTestAlgImpGetModeName(pImp: *anyopaque, outPtr: *[*]const u8) callconv(.c) usize;
extern fn scTestAlgImpGetImpName(pImp: *anyopaque, outPtr: *[*]const u8) callconv(.c) usize;
extern fn scTestAlgImpGetPerfFunctions(
    pImp: *anyopaque,
    pKeySizeSupported: *?PerfKeySizeSupportedFn,
    pKeyFn: *?PerfKeyFn,
    pDataFn: *?PerfDataFn,
    pDecryptFn: *?PerfDataFn,
    pCleanFn: *?PerfCleanFn,
) callconv(.c) void;
extern fn scTestAlgImpAddPerfInfo(
    pImp: *anyopaque,
    keySize: usize,
    dataSize: usize,
    strPostfixPtr: [*]const u8,
    strPostfixLen: usize,
    cPerByte: f64,
    cOverhead: f64,
    cRange: f64,
) callconv(.c) void;
extern fn scTestAlgImpGetPerfInfoCount(pImp: *anyopaque) callconv(.c) usize;
extern fn scTestAlgImpGetPerfInfoAt(
    pImp: *anyopaque,
    idx: usize,
    pKeySize: *usize,
    pDataSize: *usize,
    outPostfixPtr: *[*]const u8,
    outPostfixLen: *usize,
    pCpb: *f64,
    pOverhead: *f64,
    pRange: *f64,
) callconv(.c) void;
extern fn scTestGetMeasureSizesStringPrefix(outPtr: *[*]const u8) callconv(.c) usize;
extern fn scTestSleepMs(ms: u32) callconv(.c) void;

const Timespec = extern struct {
    tv_sec: isize,
    tv_nsec: isize,
};
extern fn clock_gettime(clk_id: c_int, tp: *Timespec) callconv(.c) c_int;

fn getMonotonicNs() i128 {
    var ts: Timespec = .{ .tv_sec = 0, .tv_nsec = 0 };
    _ = clock_gettime(1, &ts);
    return @as(i128, ts.tv_sec) * 1_000_000_000 + @as(i128, ts.tv_nsec);
}

const AlgMeasureParams = struct {
    algName: []const u8,
    modeName: []const u8,
    keySizes: [32]usize,
    dataSizes: [10]usize,
};

fn makeKeySizes(comptime slice: []const usize) [32]usize {
    @setEvalBranchQuota(10000);
    var arr: [32]usize = @splat(0);
    for (slice, 0..) |v, i| arr[i] = v;
    return arr;
}

fn makeDataSizes(comptime slice: []const usize) [10]usize {
    @setEvalBranchQuota(10000);
    var arr: [10]usize = @splat(0);
    for (slice, 0..) |v, i| arr[i] = v;
    return arr;
}

const g_algMeasureParams = [_]AlgMeasureParams{
    .{ .algName = "Md2", .modeName = "", .keySizes = makeKeySizes(&.{0}), .dataSizes = makeDataSizes(&.{ 1, 32, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "Md4", .modeName = "", .keySizes = makeKeySizes(&.{0}), .dataSizes = makeDataSizes(&.{ 1, 32, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "Md5", .modeName = "", .keySizes = makeKeySizes(&.{0}), .dataSizes = makeDataSizes(&.{ 1, 32, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "Sha1", .modeName = "", .keySizes = makeKeySizes(&.{0}), .dataSizes = makeDataSizes(&.{ 1, 32, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "Sha224", .modeName = "", .keySizes = makeKeySizes(&.{0}), .dataSizes = makeDataSizes(&.{ 1, 32, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "Sha256", .modeName = "", .keySizes = makeKeySizes(&.{0}), .dataSizes = makeDataSizes(&.{ 1, 32, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "Sha384", .modeName = "", .keySizes = makeKeySizes(&.{0}), .dataSizes = makeDataSizes(&.{ 1, 32, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "Sha512", .modeName = "", .keySizes = makeKeySizes(&.{0}), .dataSizes = makeDataSizes(&.{ 1, 32, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "Sha512-224", .modeName = "", .keySizes = makeKeySizes(&.{0}), .dataSizes = makeDataSizes(&.{ 1, 32, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "Sha512-256", .modeName = "", .keySizes = makeKeySizes(&.{0}), .dataSizes = makeDataSizes(&.{ 1, 32, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "Sha3-224", .modeName = "", .keySizes = makeKeySizes(&.{0}), .dataSizes = makeDataSizes(&.{ 1, 32, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "Sha3-256", .modeName = "", .keySizes = makeKeySizes(&.{0}), .dataSizes = makeDataSizes(&.{ 1, 32, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "Sha3-384", .modeName = "", .keySizes = makeKeySizes(&.{0}), .dataSizes = makeDataSizes(&.{ 1, 32, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "Sha3-512", .modeName = "", .keySizes = makeKeySizes(&.{0}), .dataSizes = makeDataSizes(&.{ 1, 32, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "Shake128", .modeName = "", .keySizes = makeKeySizes(&.{0}), .dataSizes = makeDataSizes(&.{ 1, 32, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "Shake256", .modeName = "", .keySizes = makeKeySizes(&.{0}), .dataSizes = makeDataSizes(&.{ 1, 32, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "CShake128", .modeName = "", .keySizes = makeKeySizes(&.{0}), .dataSizes = makeDataSizes(&.{ 1, 32, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "CShake256", .modeName = "", .keySizes = makeKeySizes(&.{0}), .dataSizes = makeDataSizes(&.{ 1, 32, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "Kmac128", .modeName = "", .keySizes = makeKeySizes(&.{32}), .dataSizes = makeDataSizes(&.{ 1, 32, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "Kmac256", .modeName = "", .keySizes = makeKeySizes(&.{64}), .dataSizes = makeDataSizes(&.{ 1, 32, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "ParSha256", .modeName = "", .keySizes = makeKeySizes(&.{0}), .dataSizes = makeDataSizes(&.{ 8 * 1, 8 * 32, 8 * 128, 8 << 10, 8 << 14 }) },
    .{ .algName = "ParSha384", .modeName = "", .keySizes = makeKeySizes(&.{0}), .dataSizes = makeDataSizes(&.{ 8 * 1, 8 * 32, 8 * 128, 8 << 10, 8 << 14 }) },
    .{ .algName = "ParSha512", .modeName = "", .keySizes = makeKeySizes(&.{0}), .dataSizes = makeDataSizes(&.{ 8 * 1, 8 * 32, 8 * 128, 8 << 10, 8 << 14 }) },
    .{ .algName = "HmacMd5", .modeName = "", .keySizes = makeKeySizes(&.{16}), .dataSizes = makeDataSizes(&.{ 1, 32, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "HmacSha1", .modeName = "", .keySizes = makeKeySizes(&.{20}), .dataSizes = makeDataSizes(&.{ 1, 32, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "HmacSha224", .modeName = "", .keySizes = makeKeySizes(&.{28}), .dataSizes = makeDataSizes(&.{ 1, 32, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "HmacSha256", .modeName = "", .keySizes = makeKeySizes(&.{32}), .dataSizes = makeDataSizes(&.{ 1, 32, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "HmacSha384", .modeName = "", .keySizes = makeKeySizes(&.{48}), .dataSizes = makeDataSizes(&.{ 1, 32, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "HmacSha512", .modeName = "", .keySizes = makeKeySizes(&.{64}), .dataSizes = makeDataSizes(&.{ 1, 32, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "HmacSha512-224", .modeName = "", .keySizes = makeKeySizes(&.{28}), .dataSizes = makeDataSizes(&.{ 1, 32, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "HmacSha512-256", .modeName = "", .keySizes = makeKeySizes(&.{32}), .dataSizes = makeDataSizes(&.{ 1, 32, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "HmacSha3-224", .modeName = "", .keySizes = makeKeySizes(&.{28}), .dataSizes = makeDataSizes(&.{ 1, 32, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "HmacSha3-256", .modeName = "", .keySizes = makeKeySizes(&.{32}), .dataSizes = makeDataSizes(&.{ 1, 32, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "HmacSha3-384", .modeName = "", .keySizes = makeKeySizes(&.{48}), .dataSizes = makeDataSizes(&.{ 1, 32, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "HmacSha3-512", .modeName = "", .keySizes = makeKeySizes(&.{64}), .dataSizes = makeDataSizes(&.{ 1, 32, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "AesCmac", .modeName = "", .keySizes = makeKeySizes(&.{ 16, 24, 32 }), .dataSizes = makeDataSizes(&.{ 1, 32, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "Marvin32", .modeName = "", .keySizes = makeKeySizes(&.{8}), .dataSizes = makeDataSizes(&.{ 1, 2, 3, 4, 8, 32, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "Poly1305", .modeName = "", .keySizes = makeKeySizes(&.{32}), .dataSizes = makeDataSizes(&.{ 1, 32, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "Aes", .modeName = "Ecb", .keySizes = makeKeySizes(&.{ 16, 24, 32 }), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "Aes", .modeName = "Cbc", .keySizes = makeKeySizes(&.{ 16, 24, 32 }), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "Aes", .modeName = "Cfb", .keySizes = makeKeySizes(&.{ 16, 24, 32 }), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "Aes", .modeName = "Ccm", .keySizes = makeKeySizes(&.{ 16, 24, 32 }), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "Aes", .modeName = "Gcm", .keySizes = makeKeySizes(&.{ 16, 24, 32 }), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "Des", .modeName = "Ecb", .keySizes = makeKeySizes(&.{8}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "Des", .modeName = "Cbc", .keySizes = makeKeySizes(&.{8}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "Des", .modeName = "Cfb", .keySizes = makeKeySizes(&.{8}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "Des2", .modeName = "Ecb", .keySizes = makeKeySizes(&.{16}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "Des2", .modeName = "Cbc", .keySizes = makeKeySizes(&.{16}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "Des2", .modeName = "Cfb", .keySizes = makeKeySizes(&.{16}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "Des3", .modeName = "Ecb", .keySizes = makeKeySizes(&.{24}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "Des3", .modeName = "Cbc", .keySizes = makeKeySizes(&.{24}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "Des3", .modeName = "Cfb", .keySizes = makeKeySizes(&.{24}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "Desx", .modeName = "Ecb", .keySizes = makeKeySizes(&.{24}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "Desx", .modeName = "Cbc", .keySizes = makeKeySizes(&.{24}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "Desx", .modeName = "Cfb", .keySizes = makeKeySizes(&.{24}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "Rc2", .modeName = "Ecb", .keySizes = makeKeySizes(&.{16}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "Rc2", .modeName = "Cbc", .keySizes = makeKeySizes(&.{16}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "Rc2", .modeName = "Cfb", .keySizes = makeKeySizes(&.{16}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "Rc4", .modeName = "", .keySizes = makeKeySizes(&.{4}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "ChaCha20", .modeName = "", .keySizes = makeKeySizes(&.{32}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "ChaCha20Poly1305", .modeName = "", .keySizes = makeKeySizes(&.{32}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "AesCtrDrbg", .modeName = "", .keySizes = makeKeySizes(&.{0}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "AesCtrF142", .modeName = "", .keySizes = makeKeySizes(&.{0}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "Pbkdf2", .modeName = "HmacMd5", .keySizes = makeKeySizes(&.{16}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 15 }) },
    .{ .algName = "Pbkdf2", .modeName = "HmacSha1", .keySizes = makeKeySizes(&.{20}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 15 }) },
    .{ .algName = "Pbkdf2", .modeName = "HmacSha256", .keySizes = makeKeySizes(&.{32}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 15 }) },
    .{ .algName = "Pbkdf2", .modeName = "HmacSha384", .keySizes = makeKeySizes(&.{48}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 15 }) },
    .{ .algName = "Pbkdf2", .modeName = "HmacSha512", .keySizes = makeKeySizes(&.{64}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 15 }) },
    .{ .algName = "Pbkdf2", .modeName = "HmacSha3-256", .keySizes = makeKeySizes(&.{32}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 15 }) },
    .{ .algName = "Pbkdf2", .modeName = "HmacSha3-384", .keySizes = makeKeySizes(&.{48}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 15 }) },
    .{ .algName = "Pbkdf2", .modeName = "HmacSha3-512", .keySizes = makeKeySizes(&.{64}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 15 }) },
    .{ .algName = "Pbkdf2", .modeName = "AesCmac", .keySizes = makeKeySizes(&.{ 16, 24, 32 }), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 15 }) },
    .{ .algName = "Sp800_108", .modeName = "HmacMd5", .keySizes = makeKeySizes(&.{16}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "Sp800_108", .modeName = "HmacSha1", .keySizes = makeKeySizes(&.{20}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "Sp800_108", .modeName = "HmacSha256", .keySizes = makeKeySizes(&.{32}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "Sp800_108", .modeName = "HmacSha384", .keySizes = makeKeySizes(&.{48}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "Sp800_108", .modeName = "HmacSha512", .keySizes = makeKeySizes(&.{64}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "Sp800_108", .modeName = "HmacSha3-256", .keySizes = makeKeySizes(&.{32}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "Sp800_108", .modeName = "HmacSha3-384", .keySizes = makeKeySizes(&.{48}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "Sp800_108", .modeName = "HmacSha3-512", .keySizes = makeKeySizes(&.{64}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "Sp800_108", .modeName = "AesCmac", .keySizes = makeKeySizes(&.{ 16, 24, 32 }), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "TlsPrf1_1", .modeName = "", .keySizes = makeKeySizes(&.{32}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "TlsPrf1_2", .modeName = "HmacSha256", .keySizes = makeKeySizes(&.{32}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "TlsPrf1_2", .modeName = "HmacSha384", .keySizes = makeKeySizes(&.{48}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "TlsPrf1_2", .modeName = "HmacSha512", .keySizes = makeKeySizes(&.{64}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "Hkdf", .modeName = "HmacSha1", .keySizes = makeKeySizes(&.{20}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 255 * 20 }) },
    .{ .algName = "Hkdf", .modeName = "HmacSha256", .keySizes = makeKeySizes(&.{32}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 255 * 32 }) },
    .{ .algName = "Hkdf", .modeName = "HmacSha384", .keySizes = makeKeySizes(&.{48}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 255 * 48 }) },
    .{ .algName = "Hkdf", .modeName = "HmacSha512", .keySizes = makeKeySizes(&.{64}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 255 * 64 }) },
    .{ .algName = "Hkdf", .modeName = "HmacSha3-256", .keySizes = makeKeySizes(&.{32}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 255 * 32 }) },
    .{ .algName = "Hkdf", .modeName = "HmacSha3-384", .keySizes = makeKeySizes(&.{48}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 255 * 48 }) },
    .{ .algName = "Hkdf", .modeName = "HmacSha3-512", .keySizes = makeKeySizes(&.{64}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 255 * 64 }) },
    .{ .algName = "SshKdf", .modeName = "Sha1", .keySizes = makeKeySizes(&.{20}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "SshKdf", .modeName = "Sha256", .keySizes = makeKeySizes(&.{32}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "SshKdf", .modeName = "Sha384", .keySizes = makeKeySizes(&.{48}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "SshKdf", .modeName = "Sha512", .keySizes = makeKeySizes(&.{64}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "SrtpKdf", .modeName = "", .keySizes = makeKeySizes(&.{ 16, 24, 32 }), .dataSizes = makeDataSizes(&.{ 16, 32, 64, 128 }) },
    .{ .algName = "SskdfMac", .modeName = "HmacSha1", .keySizes = makeKeySizes(&.{20}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "SskdfMac", .modeName = "HmacSha224", .keySizes = makeKeySizes(&.{28}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "SskdfMac", .modeName = "HmacSha256", .keySizes = makeKeySizes(&.{32}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "SskdfMac", .modeName = "HmacSha384", .keySizes = makeKeySizes(&.{48}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "SskdfMac", .modeName = "HmacSha512", .keySizes = makeKeySizes(&.{64}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "SskdfMac", .modeName = "HmacSha512-224", .keySizes = makeKeySizes(&.{28}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "SskdfMac", .modeName = "HmacSha512-256", .keySizes = makeKeySizes(&.{32}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "SskdfMac", .modeName = "HmacSha3-224", .keySizes = makeKeySizes(&.{28}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "SskdfMac", .modeName = "HmacSha3-256", .keySizes = makeKeySizes(&.{32}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "SskdfMac", .modeName = "HmacSha3-384", .keySizes = makeKeySizes(&.{48}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "SskdfMac", .modeName = "HmacSha3-512", .keySizes = makeKeySizes(&.{64}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "SskdfMac", .modeName = "Kmac128", .keySizes = makeKeySizes(&.{16}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "SskdfMac", .modeName = "Kmac256", .keySizes = makeKeySizes(&.{32}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "SskdfHash", .modeName = "Sha1", .keySizes = makeKeySizes(&.{20}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "SskdfHash", .modeName = "Sha224", .keySizes = makeKeySizes(&.{28}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "SskdfHash", .modeName = "Sha256", .keySizes = makeKeySizes(&.{32}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "SskdfHash", .modeName = "Sha384", .keySizes = makeKeySizes(&.{48}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "SskdfHash", .modeName = "Sha512", .keySizes = makeKeySizes(&.{64}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "SskdfHash", .modeName = "Sha512-224", .keySizes = makeKeySizes(&.{28}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "SskdfHash", .modeName = "Sha512-256", .keySizes = makeKeySizes(&.{32}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "SskdfHash", .modeName = "Sha3-224", .keySizes = makeKeySizes(&.{28}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "SskdfHash", .modeName = "Sha3-256", .keySizes = makeKeySizes(&.{32}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "SskdfHash", .modeName = "Sha3-384", .keySizes = makeKeySizes(&.{48}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "SskdfHash", .modeName = "Sha3-512", .keySizes = makeKeySizes(&.{64}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "SskdfHash", .modeName = "Shake128", .keySizes = makeKeySizes(&.{16}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "SskdfHash", .modeName = "Shake256", .keySizes = makeKeySizes(&.{32}), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{
        .algName = "XtsAes",
        .modeName = "",
        .keySizes = makeKeySizes(&.{
            32 | PERF_KEY_XTS_DATA_UNIT_512,
            64 | PERF_KEY_XTS_DATA_UNIT_512,
            32 | PERF_KEY_XTS_DATA_UNIT_4096,
            64 | PERF_KEY_XTS_DATA_UNIT_4096,
        }),
        .dataSizes = makeDataSizes(&.{ 512, 4096, 1 << 16 }),
    },
    .{ .algName = "AesKw", .modeName = "", .keySizes = makeKeySizes(&.{ 16, 24, 32 }), .dataSizes = makeDataSizes(&.{ 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "AesKwp", .modeName = "", .keySizes = makeKeySizes(&.{ 16, 24, 32 }), .dataSizes = makeDataSizes(&.{ 1, 16, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "TlsCbcHmacSha1", .modeName = "", .keySizes = makeKeySizes(&.{ 16, 24, 32 }), .dataSizes = makeDataSizes(&.{ 64, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "TlsCbcHmacSha256", .modeName = "", .keySizes = makeKeySizes(&.{ 16, 24, 32 }), .dataSizes = makeDataSizes(&.{ 64, 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "TlsCbcHmacSha384", .modeName = "", .keySizes = makeKeySizes(&.{ 16, 24, 32 }), .dataSizes = makeDataSizes(&.{ 128, 1 << 10, 1 << 16 }) },
    .{ .algName = "IntAdd", .modeName = "", .keySizes = makeKeySizes(&.{0}), .dataSizes = makeDataSizes(&.{ 32, 48, 64, 96, 128, 256, 384, 512, 1024 }) },
    .{ .algName = "IntSub", .modeName = "", .keySizes = makeKeySizes(&.{0}), .dataSizes = makeDataSizes(&.{ 32, 48, 64, 96, 128, 256, 384, 512, 1024 }) },
    .{ .algName = "IntMul", .modeName = "", .keySizes = makeKeySizes(&.{0}), .dataSizes = makeDataSizes(&.{ 32, 48, 64, 96, 128, 256, 384, 512, 1024 }) },
    .{ .algName = "IntSquare", .modeName = "", .keySizes = makeKeySizes(&.{0}), .dataSizes = makeDataSizes(&.{ 32, 48, 64, 96, 128, 256, 384, 512, 1024 }) },
    .{ .algName = "IntDivMod", .modeName = "", .keySizes = makeKeySizes(&.{ PERF_KEY_PUBLIC | 32, PERF_KEY_PUBLIC | 48, PERF_KEY_PUBLIC | 64, PERF_KEY_PUBLIC | 96, PERF_KEY_PUBLIC | 128, PERF_KEY_PUBLIC | 256, PERF_KEY_PUBLIC | 384, PERF_KEY_PUBLIC | 512, PERF_KEY_PUBLIC | 1024 }), .dataSizes = makeDataSizes(&.{0}) },
    .{ .algName = "ModAdd", .modeName = "", .keySizes = makeKeySizes(&.{ PERF_KEY_PUB_ODD | 32, PERF_KEY_PUB_ODD | 48, PERF_KEY_PUB_ODD | 64, PERF_KEY_PUB_PM | 32, PERF_KEY_PUB_PM | 48, PERF_KEY_PUB_PM | 64, PERF_KEY_PUB_NIST | 32, PERF_KEY_PUB_NIST | 48, PERF_KEY_PUB_NIST | 68, PERF_KEY_PUBLIC | 128, PERF_KEY_PUBLIC | 256, PERF_KEY_PUBLIC | 384, PERF_KEY_PUBLIC | 512, PERF_KEY_PUBLIC | 1024 }), .dataSizes = makeDataSizes(&.{0}) },
    .{ .algName = "ModSub", .modeName = "", .keySizes = makeKeySizes(&.{ PERF_KEY_PUB_ODD | 32, PERF_KEY_PUB_ODD | 48, PERF_KEY_PUB_ODD | 64, PERF_KEY_PUB_PM | 32, PERF_KEY_PUB_PM | 48, PERF_KEY_PUB_PM | 64, PERF_KEY_PUB_NIST | 32, PERF_KEY_PUB_NIST | 48, PERF_KEY_PUB_NIST | 68, PERF_KEY_PUBLIC | 128, PERF_KEY_PUBLIC | 256, PERF_KEY_PUBLIC | 384, PERF_KEY_PUBLIC | 512, PERF_KEY_PUBLIC | 1024 }), .dataSizes = makeDataSizes(&.{0}) },
    .{ .algName = "ModMul", .modeName = "", .keySizes = makeKeySizes(&.{ PERF_KEY_PUB_ODD | 32, PERF_KEY_PUB_ODD | 48, PERF_KEY_PUB_ODD | 64, PERF_KEY_PUB_PM | 32, PERF_KEY_PUB_PM | 48, PERF_KEY_PUB_PM | 64, PERF_KEY_PUB_NIST | 32, PERF_KEY_PUB_NIST | 48, PERF_KEY_PUB_NIST | 68, PERF_KEY_PUBLIC | 32, PERF_KEY_PUBLIC | 64, PERF_KEY_PUB_ODD | 96, PERF_KEY_PUB_ODD | 128, PERF_KEY_PUB_ODD | 256, PERF_KEY_PUB_ODD | 384, PERF_KEY_PUB_ODD | 512, PERF_KEY_PUB_ODD | 1024 }), .dataSizes = makeDataSizes(&.{0}) },
    .{ .algName = "ModSquare", .modeName = "", .keySizes = makeKeySizes(&.{ PERF_KEY_PUB_ODD | 32, PERF_KEY_PUB_ODD | 48, PERF_KEY_PUB_ODD | 64, PERF_KEY_PUB_PM | 32, PERF_KEY_PUB_PM | 48, PERF_KEY_PUB_PM | 64, PERF_KEY_PUB_NIST | 32, PERF_KEY_PUB_NIST | 48, PERF_KEY_PUB_NIST | 68, PERF_KEY_PUBLIC | 32, PERF_KEY_PUBLIC | 64, PERF_KEY_PUB_ODD | 96, PERF_KEY_PUB_ODD | 128, PERF_KEY_PUB_ODD | 256, PERF_KEY_PUB_ODD | 384, PERF_KEY_PUB_ODD | 512, PERF_KEY_PUB_ODD | 1024 }), .dataSizes = makeDataSizes(&.{0}) },
    .{ .algName = "ModInv", .modeName = "", .keySizes = makeKeySizes(&.{ PERF_KEY_PRIME | 32, PERF_KEY_PRIME | 48, PERF_KEY_PRIME | 64, PERF_KEY_PRIME | 96, PERF_KEY_PRIME | 128, PERF_KEY_PRIME | 256, PERF_KEY_PRIME | 384, PERF_KEY_PRIME | 512, PERF_KEY_PRIME | 1024 }), .dataSizes = makeDataSizes(&.{0}) },
    .{ .algName = "ModExp", .modeName = "", .keySizes = makeKeySizes(&.{ PERF_KEY_PUB_ODD | 32, PERF_KEY_PUB_ODD | 64, PERF_KEY_PUB_ODD | 96, PERF_KEY_PUB_ODD | 128, PERF_KEY_PUB_ODD | 256, PERF_KEY_PUB_ODD | 384, PERF_KEY_PUB_ODD | 512, PERF_KEY_PUB_ODD | 1024 }), .dataSizes = makeDataSizes(&.{0}) },
    .{ .algName = "ScsTable", .modeName = "", .keySizes = makeKeySizes(&.{ 16, 32, 64 }), .dataSizes = makeDataSizes(&.{ 32, 64, 128 }) },
    .{ .algName = "TrialDivision", .modeName = "", .keySizes = makeKeySizes(&.{0}), .dataSizes = makeDataSizes(&.{ 32, 64, 128, 256, 512 }) },
    .{ .algName = "TrialDivisionContext", .modeName = "", .keySizes = makeKeySizes(&.{0}), .dataSizes = makeDataSizes(&.{ 32, 64, 128, 256, 512 }) },
    .{ .algName = "IEEE802_11SaeCustom", .modeName = "", .keySizes = makeKeySizes(&.{0}), .dataSizes = makeDataSizes(&.{ 32, 48, 66 }) },
    .{ .algName = "RsaEncRaw", .modeName = "", .keySizes = makeKeySizes(&.{ 128, 256, 384, 512, 1024 }), .dataSizes = makeDataSizes(&.{0}) },
    .{ .algName = "RsaEncPkcs1", .modeName = "", .keySizes = makeKeySizes(&.{ 128, 256, 384, 512, 1024 }), .dataSizes = makeDataSizes(&.{0}) },
    .{ .algName = "RsaEncOaep", .modeName = "", .keySizes = makeKeySizes(&.{ 128, 256, 384, 512, 1024 }), .dataSizes = makeDataSizes(&.{0}) },
    .{ .algName = "RsaSignPkcs1", .modeName = "", .keySizes = makeKeySizes(&.{ 128, 256, 384, 512, 1024 }), .dataSizes = makeDataSizes(&.{0}) },
    .{ .algName = "RsaSignPss", .modeName = "", .keySizes = makeKeySizes(&.{ 128, 256, 384, 512, 1024 }), .dataSizes = makeDataSizes(&.{0}) },
    .{ .algName = "RsakeySetValue", .modeName = "", .keySizes = makeKeySizes(&.{ 128, 256, 384, 512, 1024 }), .dataSizes = makeDataSizes(&.{0}) },
    .{ .algName = "RsakeySetValueFromPrivateExponent", .modeName = "", .keySizes = makeKeySizes(&.{ 128, 256, 384, 512, 1024 }), .dataSizes = makeDataSizes(&.{0}) },
    .{ .algName = "DsaSign", .modeName = "", .keySizes = makeKeySizes(&.{ 64, 128, 256 }), .dataSizes = makeDataSizes(&.{0}) },
    .{ .algName = "DsaVerify", .modeName = "", .keySizes = makeKeySizes(&.{ 64, 128, 256 }), .dataSizes = makeDataSizes(&.{0}) },
    .{ .algName = "Dh", .modeName = "", .keySizes = makeKeySizes(&.{ 64, 128, 256 }), .dataSizes = makeDataSizes(&.{0}) },
    .{ .algName = "EcurveAllocateAndFree", .modeName = "", .keySizes = makeKeySizes(&.{ PERF_KEY_NIST_P256, PERF_KEY_NIST_P384, PERF_KEY_NIST_P521, PERF_KEY_NUMS_P256T1, PERF_KEY_NUMS_P384T1, PERF_KEY_NUMS_P512T1, PERF_KEY_C25519, PERF_KEY_SW_P256, PERF_KEY_W25519, PERF_KEY_W448 }), .dataSizes = makeDataSizes(&.{0}) },
    .{ .algName = "EckeySetRandom", .modeName = "", .keySizes = makeKeySizes(&.{ PERF_KEY_NIST_P256, PERF_KEY_NIST_P384, PERF_KEY_NIST_P521, PERF_KEY_NUMS_P256T1, PERF_KEY_NUMS_P384T1, PERF_KEY_NUMS_P512T1, PERF_KEY_C25519, PERF_KEY_SW_P256, PERF_KEY_W25519, PERF_KEY_W448 }), .dataSizes = makeDataSizes(&.{0}) },
    .{ .algName = "EcpointSetZero", .modeName = "", .keySizes = makeKeySizes(&.{ PERF_KEY_NIST_P256, PERF_KEY_NIST_P384, PERF_KEY_NIST_P521, PERF_KEY_NUMS_P256T1, PERF_KEY_NUMS_P384T1, PERF_KEY_NUMS_P512T1, PERF_KEY_C25519, PERF_KEY_SW_P256, PERF_KEY_W25519, PERF_KEY_W448 }), .dataSizes = makeDataSizes(&.{0}) },
    .{ .algName = "EcpointSetDistinguished", .modeName = "", .keySizes = makeKeySizes(&.{ PERF_KEY_NIST_P256, PERF_KEY_NIST_P384, PERF_KEY_NIST_P521, PERF_KEY_NUMS_P256T1, PERF_KEY_NUMS_P384T1, PERF_KEY_NUMS_P512T1, PERF_KEY_C25519, PERF_KEY_SW_P256, PERF_KEY_W25519, PERF_KEY_W448 }), .dataSizes = makeDataSizes(&.{0}) },
    .{ .algName = "EcpointSetRandom", .modeName = "", .keySizes = makeKeySizes(&.{ PERF_KEY_NIST_P256, PERF_KEY_NIST_P384, PERF_KEY_NIST_P521, PERF_KEY_NUMS_P256T1, PERF_KEY_NUMS_P384T1, PERF_KEY_NUMS_P512T1, PERF_KEY_C25519, PERF_KEY_SW_P256, PERF_KEY_W25519, PERF_KEY_W448 }), .dataSizes = makeDataSizes(&.{0}) },
    .{ .algName = "EcpointIsEqual", .modeName = "", .keySizes = makeKeySizes(&.{ PERF_KEY_NIST_P256, PERF_KEY_NIST_P384, PERF_KEY_NIST_P521, PERF_KEY_NUMS_P256T1, PERF_KEY_NUMS_P384T1, PERF_KEY_NUMS_P512T1, PERF_KEY_C25519, PERF_KEY_SW_P256, PERF_KEY_W25519, PERF_KEY_W448 }), .dataSizes = makeDataSizes(&.{0}) },
    .{ .algName = "EcpointIsZero", .modeName = "", .keySizes = makeKeySizes(&.{ PERF_KEY_NIST_P256, PERF_KEY_NIST_P384, PERF_KEY_NIST_P521, PERF_KEY_NUMS_P256T1, PERF_KEY_NUMS_P384T1, PERF_KEY_NUMS_P512T1, PERF_KEY_C25519, PERF_KEY_SW_P256, PERF_KEY_W25519, PERF_KEY_W448 }), .dataSizes = makeDataSizes(&.{0}) },
    .{ .algName = "EcpointOnCurve", .modeName = "", .keySizes = makeKeySizes(&.{ PERF_KEY_NIST_P256, PERF_KEY_NIST_P384, PERF_KEY_NIST_P521, PERF_KEY_NUMS_P256T1, PERF_KEY_NUMS_P384T1, PERF_KEY_NUMS_P512T1, PERF_KEY_SW_P256, PERF_KEY_W25519, PERF_KEY_W448 }), .dataSizes = makeDataSizes(&.{0}) },
    .{ .algName = "EcpointAdd", .modeName = "", .keySizes = makeKeySizes(&.{ PERF_KEY_NIST_P256, PERF_KEY_NIST_P384, PERF_KEY_NIST_P521, PERF_KEY_NUMS_P256T1, PERF_KEY_NUMS_P384T1, PERF_KEY_NUMS_P512T1, PERF_KEY_SW_P256, PERF_KEY_W25519, PERF_KEY_W448 }), .dataSizes = makeDataSizes(&.{0}) },
    .{ .algName = "EcpointAddDiffNz", .modeName = "", .keySizes = makeKeySizes(&.{ PERF_KEY_NIST_P256, PERF_KEY_NIST_P384, PERF_KEY_NIST_P521, PERF_KEY_NUMS_P256T1, PERF_KEY_NUMS_P384T1, PERF_KEY_NUMS_P512T1, PERF_KEY_SW_P256, PERF_KEY_W25519, PERF_KEY_W448 }), .dataSizes = makeDataSizes(&.{0}) },
    .{ .algName = "EcpointDouble", .modeName = "", .keySizes = makeKeySizes(&.{ PERF_KEY_NIST_P256, PERF_KEY_NIST_P384, PERF_KEY_NIST_P521, PERF_KEY_NUMS_P256T1, PERF_KEY_NUMS_P384T1, PERF_KEY_NUMS_P512T1, PERF_KEY_SW_P256, PERF_KEY_W25519, PERF_KEY_W448 }), .dataSizes = makeDataSizes(&.{0}) },
    .{ .algName = "EcpointScalarMul", .modeName = "", .keySizes = makeKeySizes(&.{ PERF_KEY_NIST_P256, PERF_KEY_NIST_P384, PERF_KEY_NIST_P521, PERF_KEY_NUMS_P256T1, PERF_KEY_NUMS_P384T1, PERF_KEY_NUMS_P512T1, PERF_KEY_C25519, PERF_KEY_SW_P256, PERF_KEY_W25519, PERF_KEY_W448 }), .dataSizes = makeDataSizes(&.{0}) },
    .{ .algName = "EcdsaSign", .modeName = "", .keySizes = makeKeySizes(&.{ PERF_KEY_NIST_P256, PERF_KEY_NIST_P384, PERF_KEY_NIST_P521, PERF_KEY_NUMS_P256T1, PERF_KEY_NUMS_P384T1, PERF_KEY_NUMS_P512T1, PERF_KEY_SW_P256, PERF_KEY_W25519, PERF_KEY_W448 }), .dataSizes = makeDataSizes(&.{0}) },
    .{ .algName = "EcdsaVerify", .modeName = "", .keySizes = makeKeySizes(&.{ PERF_KEY_NIST_P256, PERF_KEY_NIST_P384, PERF_KEY_NIST_P521, PERF_KEY_NUMS_P256T1, PERF_KEY_NUMS_P384T1, PERF_KEY_NUMS_P512T1, PERF_KEY_SW_P256, PERF_KEY_W25519, PERF_KEY_W448 }), .dataSizes = makeDataSizes(&.{0}) },
    .{ .algName = "Ecdh", .modeName = "", .keySizes = makeKeySizes(&.{ PERF_KEY_NIST_P256, PERF_KEY_NIST_P384, PERF_KEY_NIST_P521, PERF_KEY_NUMS_P256T1, PERF_KEY_NUMS_P384T1, PERF_KEY_NUMS_P512T1, PERF_KEY_C25519, PERF_KEY_SW_P256, PERF_KEY_W25519, PERF_KEY_W448 }), .dataSizes = makeDataSizes(&.{0}) },
    .{ .algName = "EckeySetValue", .modeName = "", .keySizes = makeKeySizes(&.{ PERF_KEY_NIST_P256, PERF_KEY_NIST_P384, PERF_KEY_NIST_P521, PERF_KEY_NUMS_P256T1, PERF_KEY_NUMS_P384T1, PERF_KEY_NUMS_P512T1, PERF_KEY_C25519, PERF_KEY_SW_P256, PERF_KEY_W25519, PERF_KEY_W448 }), .dataSizes = makeDataSizes(&.{0}) },
    .{ .algName = "Xmss", .modeName = "", .keySizes = makeKeySizes(&.{ PERF_KEY_XMSS | SYMCRYPT_XMSS_SHA2_10_256, PERF_KEY_XMSS | SYMCRYPT_XMSS_SHA2_16_256, PERF_KEY_XMSS | SYMCRYPT_XMSS_SHA2_20_256, PERF_KEY_XMSS | SYMCRYPT_XMSS_SHA2_10_512, PERF_KEY_XMSS | SYMCRYPT_XMSS_SHA2_16_512, PERF_KEY_XMSS | SYMCRYPT_XMSS_SHA2_20_512, PERF_KEY_XMSS | SYMCRYPT_XMSS_SHAKE256_10_256, PERF_KEY_XMSS | SYMCRYPT_XMSS_SHAKE256_16_256, PERF_KEY_XMSS | SYMCRYPT_XMSS_SHAKE256_20_256 }), .dataSizes = makeDataSizes(&.{128}) },
    .{ .algName = "Lms", .modeName = "", .keySizes = makeKeySizes(&.{ PERF_KEY_LMS | SYMCRYPT_LMS_SHA256_M32_H5, PERF_KEY_LMS | SYMCRYPT_LMS_SHA256_M32_H10, PERF_KEY_LMS | SYMCRYPT_LMS_SHA256_M32_H15, PERF_KEY_LMS | SYMCRYPT_LMS_SHA256_M32_H20, PERF_KEY_LMS | SYMCRYPT_LMS_SHA256_M32_H25, PERF_KEY_LMS | SYMCRYPT_LMS_SHA256_M24_H5, PERF_KEY_LMS | SYMCRYPT_LMS_SHA256_M24_H10, PERF_KEY_LMS | SYMCRYPT_LMS_SHA256_M24_H15, PERF_KEY_LMS | SYMCRYPT_LMS_SHA256_M24_H20, PERF_KEY_LMS | SYMCRYPT_LMS_SHA256_M24_H25, PERF_KEY_LMS | SYMCRYPT_LMS_SHAKE_M32_H5, PERF_KEY_LMS | SYMCRYPT_LMS_SHAKE_M32_H10, PERF_KEY_LMS | SYMCRYPT_LMS_SHAKE_M32_H15, PERF_KEY_LMS | SYMCRYPT_LMS_SHAKE_M32_H20, PERF_KEY_LMS | SYMCRYPT_LMS_SHAKE_M32_H25, PERF_KEY_LMS | SYMCRYPT_LMS_SHAKE_M24_H5, PERF_KEY_LMS | SYMCRYPT_LMS_SHAKE_M24_H10, PERF_KEY_LMS | SYMCRYPT_LMS_SHAKE_M24_H15, PERF_KEY_LMS | SYMCRYPT_LMS_SHAKE_M24_H20, PERF_KEY_LMS | SYMCRYPT_LMS_SHAKE_M24_H25 }), .dataSizes = makeDataSizes(&.{128}) },
    .{ .algName = "MlKem", .modeName = "", .keySizes = makeKeySizes(&.{ PERF_KEY_MLKEM | SYMCRYPT_MLKEM_PARAMS_MLKEM512, PERF_KEY_MLKEM | SYMCRYPT_MLKEM_PARAMS_MLKEM768, PERF_KEY_MLKEM | SYMCRYPT_MLKEM_PARAMS_MLKEM1024 }), .dataSizes = makeDataSizes(&.{0}) },
    .{ .algName = "MlKemkeySetValue", .modeName = "", .keySizes = makeKeySizes(&.{ PERF_KEY_MLKEM | SYMCRYPT_MLKEM_PARAMS_MLKEM512, PERF_KEY_MLKEM | SYMCRYPT_MLKEM_PARAMS_MLKEM768, PERF_KEY_MLKEM | SYMCRYPT_MLKEM_PARAMS_MLKEM1024 }), .dataSizes = makeDataSizes(&.{0}) },
    .{ .algName = "CompositeMlKem", .modeName = "", .keySizes = makeKeySizes(&.{ PERF_KEY_COMPOSITE_MLKEM | SYMCRYPT_COMPOSITE_MLKEM_PARAMS_MLKEM768_P256, PERF_KEY_COMPOSITE_MLKEM | SYMCRYPT_COMPOSITE_MLKEM_PARAMS_MLKEM768_X25519, PERF_KEY_COMPOSITE_MLKEM | SYMCRYPT_COMPOSITE_MLKEM_PARAMS_MLKEM1024_P384 }), .dataSizes = makeDataSizes(&.{0}) },
    .{ .algName = "CompositeMlKemkeySetValue", .modeName = "", .keySizes = makeKeySizes(&.{ PERF_KEY_COMPOSITE_MLKEM | SYMCRYPT_COMPOSITE_MLKEM_PARAMS_MLKEM768_P256, PERF_KEY_COMPOSITE_MLKEM | SYMCRYPT_COMPOSITE_MLKEM_PARAMS_MLKEM768_X25519, PERF_KEY_COMPOSITE_MLKEM | SYMCRYPT_COMPOSITE_MLKEM_PARAMS_MLKEM1024_P384 }), .dataSizes = makeDataSizes(&.{0}) },
    .{ .algName = "MlDsa", .modeName = "", .keySizes = makeKeySizes(&.{ PERF_KEY_MLDSA | SYMCRYPT_MLDSA_PARAMS_MLDSA44, PERF_KEY_MLDSA | SYMCRYPT_MLDSA_PARAMS_MLDSA65, PERF_KEY_MLDSA | SYMCRYPT_MLDSA_PARAMS_MLDSA87 }), .dataSizes = makeDataSizes(&.{32}) },
    .{ .algName = "MlDsakeySetValue", .modeName = "", .keySizes = makeKeySizes(&.{ PERF_KEY_MLDSA | SYMCRYPT_MLDSA_PARAMS_MLDSA44, PERF_KEY_MLDSA | SYMCRYPT_MLDSA_PARAMS_MLDSA65, PERF_KEY_MLDSA | SYMCRYPT_MLDSA_PARAMS_MLDSA87 }), .dataSizes = makeDataSizes(&.{0}) },
    .{ .algName = "CompositeMlDsa", .modeName = "", .keySizes = makeKeySizes(&.{ PERF_KEY_COMPOSITE_MLDSA | SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA44_P256, PERF_KEY_COMPOSITE_MLDSA | SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA65_P256, PERF_KEY_COMPOSITE_MLDSA | SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA65_P384, PERF_KEY_COMPOSITE_MLDSA | SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA87_P384 }), .dataSizes = makeDataSizes(&.{32}) },
    .{ .algName = "CompositeMlDsakeySetValue", .modeName = "", .keySizes = makeKeySizes(&.{ PERF_KEY_COMPOSITE_MLDSA | SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA44_P256, PERF_KEY_COMPOSITE_MLDSA | SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA65_P256, PERF_KEY_COMPOSITE_MLDSA | SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA65_P384, PERF_KEY_COMPOSITE_MLDSA | SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA87_P384 }), .dataSizes = makeDataSizes(&.{0}) },
    .{ .algName = "Hpke", .modeName = "", .keySizes = makeKeySizes(&.{ PERF_KEY_HPKE | (0x0010 << 8) | 0x01, PERF_KEY_HPKE | (0x0011 << 8) | 0x02, PERF_KEY_HPKE | (0x0012 << 8) | 0x03, PERF_KEY_HPKE | (0x0020 << 8) | 0x01, PERF_KEY_HPKE | (0x0041 << 8) | 0x11, PERF_KEY_HPKE | (0x647a << 8) | 0x11, PERF_KEY_HPKE | (0x0050 << 8) | 0x01, PERF_KEY_HPKE | (0x0051 << 8) | 0x02 }), .dataSizes = makeDataSizes(&.{64}) },
    .{ .algName = "TlsHandshake", .modeName = "", .keySizes = makeKeySizes(&.{ PERF_KEY_RSA_2K_100, PERF_KEY_RSA_2K_30, PERF_KEY_RSA_2K_10, PERF_KEY_RSA_2K_3, PERF_KEY_RSA_2K_1, PERF_KEY_RSA_2K_0, PERF_KEY_EC_SECP256R1, PERF_KEY_EC_SECP384R1, PERF_KEY_EC_SECP521R1, PERF_KEY_EC_CURVE25519, PERF_KEY_EC_NUMSP256T1, PERF_KEY_EC_NUMSP384T1, PERF_KEY_EC_NUMSP512T1 }), .dataSizes = makeDataSizes(&.{0}) },
    .{ .algName = "DeveloperTest", .modeName = "", .keySizes = makeKeySizes(&.{0}), .dataSizes = makeDataSizes(&.{0}) },
};

fn nullPerfFunction(_: [*]u8, _: [*]u8, _: [*]u8, _: usize) callconv(.c) void {}

fn fixedTimeLoopPerfFunction(_: [*]u8, _: [*]u8, _: [*]u8, _: usize) callconv(.c) void {
    var t: u64 = 1;
    var i: usize = 0;
    while (i < 500) : (i += 1) {
        if (comptime (builtin.cpu.arch == .x86_64 or builtin.cpu.arch == .x86)) {
            asm volatile (
                \\imulq %[t], %[t]
                \\imulq %[t], %[t]
                \\imulq %[t], %[t]
                \\imulq %[t], %[t]
                \\imulq %[t], %[t]
                \\imulq %[t], %[t]
                \\imulq %[t], %[t]
                \\imulq %[t], %[t]
                \\imulq %[t], %[t]
                \\imulq %[t], %[t]
                : [t] "+r" (t),
                :
                : .{ .cc = true });
        } else if (comptime builtin.cpu.arch == .aarch64) {
            asm volatile (
                \\mul %[t], %[t], %[t]
                \\mul %[t], %[t], %[t]
                \\mul %[t], %[t], %[t]
                \\mul %[t], %[t], %[t]
                \\mul %[t], %[t], %[t]
                \\mul %[t], %[t], %[t]
                \\mul %[t], %[t], %[t]
                \\mul %[t], %[t], %[t]
                \\mul %[t], %[t], %[t]
                \\mul %[t], %[t], %[t]
                : [t] "+r" (t),
            );
        } else {
            var j: usize = 0;
            while (j < 10) : (j += 1) {
                t = @as(*volatile u64, @ptrCast(&t)).* *% t;
            }
        }
    }
    @as(*volatile u64, @ptrCast(&g_perfDummy)).* = t;
}

noinline fn moveStackAndMeasurePerfData(
    stackMove: usize,
    df: PerfDataFn,
    buf1: [*]u8,
    buf2: [*]u8,
    buf3: [*]u8,
    dataSize: usize,
    nTries: usize,
) u64 {
    var stackPad: [4096]u8 = undefined;
    if (stackMove > 0) {
        const idx = @min(stackMove, stackPad.len - 1);
        @as(*volatile u8, @ptrCast(&stackPad[idx])).* = 1;
    }

    const start = scTestGetPerfClock();
    for (0..nTries) |_| {
        df(buf1, buf2, buf3, dataSize);
    }
    const stop = scTestGetPerfClock();

    return stop -% start;
}

fn measureOverhead() void {
    var dummyBuf: [16]u8 = @splat(0);
    var minTicks: u64 = std.math.maxInt(u64);

    for (0..100) |_| {
        const ticks = moveStackAndMeasurePerfData(0, &nullPerfFunction, &dummyBuf, &dummyBuf, &dummyBuf, 0, 1000);
        if (ticks < minTicks) {
            minTicks = ticks;
        }
    }

    g_perfMeasurementOverhead = @as(f64, @floatFromInt(minTicks)) / 1000.0;

    var minLoopTicks: u64 = std.math.maxInt(u64);
    for (0..20) |_| {
        const ticks = moveStackAndMeasurePerfData(0, &fixedTimeLoopPerfFunction, &dummyBuf, &dummyBuf, &dummyBuf, 0, 10);
        if (ticks < minLoopTicks) {
            minLoopTicks = ticks;
        }
    }

    const loopTicksPerCall = (@as(f64, @floatFromInt(minLoopTicks)) / 10.0) - g_perfMeasurementOverhead;
    if (loopTicksPerCall > 0.0) {
        g_perfTimeScalingOverhead = loopTicksPerCall;
        g_perfScaleFactor = 15000.0 / loopTicksPerCall;
    } else {
        g_perfScaleFactor = 1.0;
    }
}

fn measurePerfDataFunction(
    df: PerfDataFn,
    cf: ?PerfCleanFn,
    buf1: [*]u8,
    buf2: [*]u8,
    buf3: [*]u8,
    dataSize: usize,
    nTries: usize,
) f64 {
    const stackMove = rng.scTestRngSizet(&rng.g_rng, 2048);
    const ticks = moveStackAndMeasurePerfData(stackMove, df, buf1, buf2, buf3, dataSize, nTries);
    if (cf) |cleanFn| {
        cleanFn(buf1, buf2, buf3);
    }
    const scaled = (@as(f64, @floatFromInt(ticks)) * g_perfScaleFactor) / @as(f64, @floatFromInt(nTries));
    return @max(0.0, scaled - g_perfMeasurementOverhead * g_perfScaleFactor);
}

fn measurePerfOneSize(
    kf: ?PerfKeyFn,
    df: PerfDataFn,
    cf: ?PerfCleanFn,
    keySize: usize,
    dataSize: usize,
    pOverhead: *f64,
    pRange: *f64,
) void {
    const perfBuf = g_PerfBuffer.?;
    var results: [31]f64 = undefined;

    for (0..results.len) |i| {
        const off1 = (rng.scTestRngSizet(&rng.g_rng, 256)) * 64;
        const off2 = PERF_BUFFER_SIZE * 2 + (rng.scTestRngSizet(&rng.g_rng, 256)) * 64;
        const off3 = PERF_BUFFER_SIZE * 4 + (rng.scTestRngSizet(&rng.g_rng, 256)) * 64;

        const b1 = perfBuf[off1..].ptr;
        const b2 = perfBuf[off2..].ptr;
        const b3 = perfBuf[off3..].ptr;

        if (kf) |keyFn| {
            keyFn(b1, b2, b3, keySize);
        }

        // Warmup call
        df(b1, b2, b3, dataSize);

        const t1 = scTestGetPerfClock();
        df(b1, b2, b3, dataSize);
        const t2 = scTestGetPerfClock();
        const estTicks = @max(1, t2 -% t1);
        const nTries = std.math.clamp(10000 / estTicks, 1, 200);

        results[i] = measurePerfDataFunction(df, cf, b1, b2, b3, dataSize, @intCast(nTries));
    }

    std.mem.sort(f64, &results, {}, std.sort.asc(f64));
    // P20..P80 average
    var sum: f64 = 0.0;
    const idx20 = 6;
    const idx80 = 24;
    for (idx20..idx80 + 1) |i| {
        sum += results[i];
    }
    pOverhead.* = sum / @as(f64, @floatFromInt(idx80 - idx20 + 1));
    pRange.* = (results[idx80] - results[idx20]) / 2.0;
}

fn formatKeySizePostfix(buf: []u8, algName: []const u8, keySize: usize) []const u8 {
    _ = algName;
    if (keySize == 0) return "";
    const rawSize = keySize & ~PERF_KEY_FLAGS_MASK;
    const flags = keySize & PERF_KEY_FLAGS_MASK;
    return switch (flags) {
        PERF_KEY_SECRET => std.fmt.bufPrint(buf, "s{d}", .{rawSize}) catch unreachable,
        PERF_KEY_PUBLIC => std.fmt.bufPrint(buf, "p{d}", .{rawSize}) catch unreachable,
        PERF_KEY_PRIME => std.fmt.bufPrint(buf, "q{d}", .{rawSize}) catch unreachable,
        PERF_KEY_PUB_ODD => std.fmt.bufPrint(buf, "o{d}", .{rawSize}) catch unreachable,
        PERF_KEY_PUB_PM => std.fmt.bufPrint(buf, "m{d}", .{rawSize}) catch unreachable,
        PERF_KEY_PUB_NIST => std.fmt.bufPrint(buf, "n{d}", .{rawSize}) catch unreachable,
        else => std.fmt.bufPrint(buf, "{d}", .{rawSize}) catch unreachable,
    };
}

fn measurePerfOneKey(
    pImp: *anyopaque,
    algName: []const u8,
    kf: ?PerfKeyFn,
    df: ?PerfDataFn,
    decf: ?PerfDataFn,
    cf: ?PerfCleanFn,
    keySize: usize,
    dataSizes: *const [10]usize,
) void {
    var postfixBuf: [64]u8 = undefined;
    const basePostfix = formatKeySizePostfix(&postfixBuf, algName, keySize);

    // Measure key setup cost if kf != null and df == null (or measure key setup separately)
    if (kf != null and df == null) {
        var cost: f64 = 0.0;
        var range: f64 = 0.0;
        measurePerfOneSize(null, kf.?, cf, 0, keySize, &cost, &range);
        scTestAlgImpAddPerfInfo(pImp, keySize, 0, basePostfix.ptr, basePostfix.len, 0.0, cost, range);
        return;
    }

    if (df == null) return;

    var nSizes: usize = 0;
    var costs: [10]f64 = @splat(0.0);
    var ranges: [10]f64 = @splat(0.0);
    var sizes: [10]usize = @splat(0);

    for (dataSizes) |ds| {
        if (ds == 0 and nSizes > 0) break;
        sizes[nSizes] = ds;
        measurePerfOneSize(kf, df.?, cf, keySize, ds, &costs[nSizes], &ranges[nSizes]);
        nSizes += 1;
        if (ds == 0) break;
    }

    if (nSizes == 1) {
        scTestAlgImpAddPerfInfo(pImp, keySize, sizes[0], basePostfix.ptr, basePostfix.len, 0.0, costs[0], ranges[0]);
    } else if (nSizes > 1) {
        const minSize = sizes[0];
        const maxSize = sizes[nSizes - 1];
        const cpb = if (maxSize > minSize) (costs[nSizes - 1] - costs[0]) / @as(f64, @floatFromInt(maxSize - minSize)) else 0.0;
        const overhead = @max(0.0, costs[0] - cpb * @as(f64, @floatFromInt(minSize)));
        scTestAlgImpAddPerfInfo(pImp, keySize, 0, basePostfix.ptr, basePostfix.len, cpb, overhead, ranges[0]);
    }

    if (decf) |decryptFn| {
        var decPostfixBuf: [80]u8 = undefined;
        const decPostfix = std.fmt.bufPrint(&decPostfixBuf, "{s}d", .{basePostfix}) catch unreachable;
        if (nSizes == 1) {
            var dCost: f64 = 0.0;
            var dRange: f64 = 0.0;
            measurePerfOneSize(kf, decryptFn, cf, keySize, sizes[0], &dCost, &dRange);
            scTestAlgImpAddPerfInfo(pImp, keySize, sizes[0], decPostfix.ptr, decPostfix.len, 0.0, dCost, dRange);
        } else if (nSizes > 1) {
            var dCost0: f64 = 0.0;
            var dRange0: f64 = 0.0;
            var dCostN: f64 = 0.0;
            var dRangeN: f64 = 0.0;
            measurePerfOneSize(kf, decryptFn, cf, keySize, sizes[0], &dCost0, &dRange0);
            measurePerfOneSize(kf, decryptFn, cf, keySize, sizes[nSizes - 1], &dCostN, &dRangeN);
            const minSize = sizes[0];
            const maxSize = sizes[nSizes - 1];
            const cpb = if (maxSize > minSize) (dCostN - dCost0) / @as(f64, @floatFromInt(maxSize - minSize)) else 0.0;
            const overhead = @max(0.0, dCost0 - cpb * @as(f64, @floatFromInt(minSize)));
            scTestAlgImpAddPerfInfo(pImp, keySize, 0, decPostfix.ptr, decPostfix.len, cpb, overhead, dRange0);
        }
    }
}

fn measurePerfOfAlg(pImp: *anyopaque) void {
    var algNamePtr: [*]const u8 = undefined;
    const algNameLen = scTestAlgImpGetAlgName(pImp, &algNamePtr);
    const algName = algNamePtr[0..algNameLen];

    var modeNamePtr: [*]const u8 = undefined;
    const modeNameLen = scTestAlgImpGetModeName(pImp, &modeNamePtr);
    const modeName = modeNamePtr[0..modeNameLen];

    var kssFn: ?PerfKeySizeSupportedFn = null;
    var keyFn: ?PerfKeyFn = null;
    var dataFn: ?PerfDataFn = null;
    var decFn: ?PerfDataFn = null;
    var cleanFn: ?PerfCleanFn = null;
    scTestAlgImpGetPerfFunctions(pImp, &kssFn, &keyFn, &dataFn, &decFn, &cleanFn);

    for (&g_algMeasureParams) |*params| {
        if (std.mem.eql(u8, params.algName, algName) and std.mem.eql(u8, params.modeName, modeName)) {
            for (params.keySizes, 0..) |ks, idx| {
                if (ks == 0 and idx > 0) break;
                if (kssFn) |kss| {
                    if (kss(ks) == 0) continue;
                }
                measurePerfOneKey(pImp, algName, keyFn, dataFn, decFn, cleanFn, ks, &params.dataSizes);
                if (ks == 0) break;
            }
            return;
        }
    }
}

fn wipePerfDataFn(buf1: [*]u8, _: [*]u8, _: [*]u8, dataSize: usize) callconv(.c) void {
    SymCryptWipe(buf1, dataSize);
}

fn measurePerfOfWipe() void {
    for (0..PERF_WIPE_MAX_SIZE + 1) |size| {
        for (0..PERF_WIPE_N_OFFSETS) |offset| {
            const bufPtr = g_PerfBuffer.?[offset..].ptr;
            const cost = measurePerfDataFunction(&wipePerfDataFn, null, bufPtr, bufPtr, bufPtr, size, 100);
            g_wipePerf[size][offset] = cost;
        }
    }
}

pub export fn measurePerf() callconv(.c) void {
    g_perfTestsRunning = 1;
    defer g_perfTestsRunning = 0;

    initPerfSystem();
    measureOverhead();

    h.ziprint(
        "Performance measurement overhead = {d:.1} {s}, Scale factor = {d:.2}\n",
        .{ g_perfMeasurementOverhead, std.mem.span(g_perfUnits), g_perfScaleFactor },
    );

    const startClock = scTestGetPerfClock();
    const startTimeNs = getMonotonicNs();

    const nAlgs = scTestGetAlgImpCount();
    for (0..nAlgs) |i| {
        const pImp = scTestGetAlgImpAt(i);
        measurePerfOfAlg(pImp);
    }

    measurePerfOfWipe();

    const stopClock = scTestGetPerfClock();
    const stopTimeNs = getMonotonicNs();
    const elapsedSec = @as(f64, @floatFromInt(stopTimeNs - startTimeNs)) / 1e9;
    if (elapsedSec > 0.0) {
        g_tscFreq = (@as(f64, @floatFromInt(stopClock -% startClock)) * g_perfScaleFactor) / elapsedSec;
    }
}

pub export fn runProfiling() callconv(.c) void {
    g_perfTestsRunning = 1;
    defer g_perfTestsRunning = 0;

    const perfBuf = g_PerfBuffer.?;
    const b1 = perfBuf[0..].ptr;
    const b2 = perfBuf[PERF_BUFFER_SIZE * 2 ..].ptr;
    const b3 = perfBuf[PERF_BUFFER_SIZE * 4 ..].ptr;

    const nAlgs = scTestGetAlgImpCount();
    for (0..nAlgs) |i| {
        const pImp = scTestGetAlgImpAt(i);

        var algNamePtr: [*]const u8 = undefined;
        const algNameLen = scTestAlgImpGetAlgName(pImp, &algNamePtr);
        const algName = algNamePtr[0..algNameLen];

        var modeNamePtr: [*]const u8 = undefined;
        const modeNameLen = scTestAlgImpGetModeName(pImp, &modeNamePtr);
        const modeName = modeNamePtr[0..modeNameLen];

        var kssFn: ?PerfKeySizeSupportedFn = null;
        var keyFn: ?PerfKeyFn = null;
        var dataFn: ?PerfDataFn = null;
        var decFn: ?PerfDataFn = null;
        var cleanFn: ?PerfCleanFn = null;
        scTestAlgImpGetPerfFunctions(pImp, &kssFn, &keyFn, &dataFn, &decFn, &cleanFn);

        for (&g_algMeasureParams) |*params| {
            if (std.mem.eql(u8, params.algName, algName) and std.mem.eql(u8, params.modeName, modeName)) {
                for (params.keySizes, 0..) |ks, idx| {
                    if (ks == 0 and idx > 0) break;
                    if (g_profile_key != 0 and (ks & ~PERF_KEY_FLAGS_MASK) != g_profile_key) continue;
                    if (kssFn) |kss| {
                        if (kss(ks) == 0) continue;
                    }

                    if (keyFn) |kf| {
                        kf(b1, b2, b3, ks);
                    }
                    if (dataFn) |df| {
                        var maxDs: usize = params.dataSizes[0];
                        for (params.dataSizes) |ds| {
                            if (ds > maxDs) maxDs = ds;
                        }
                        for (0..g_profile_iterations) |_| {
                            df(b1, b2, b3, maxDs);
                        }
                    }
                    if (cleanFn) |cf| {
                        cf(b1, b2, b3);
                    }
                    if (ks == 0) break;
                }
            }
        }
    }
}

pub export fn initPerfSystem() callconv(.c) void {
    const buf = std.heap.c_allocator.alloc(u8, TEST_MEMORY_SIZE) catch h.fatal("Could not allocate memory for performance testing", .{});
    g_PerfBuffer = buf;

    var state: [24]u8 = @splat(0);
    var p = buf.ptr;
    const pEnd = buf.ptr + TEST_MEMORY_SIZE;
    while (@intFromPtr(p) < @intFromPtr(pEnd)) : (p += 20) {
        SymCryptSha1(&state, 24, &state);
        @memcpy(p[0..20], state[0..20]);
        const v = SymCryptLoadLsbFirstUint64(state[20..].ptr, 4) +% 1;
        std.mem.writeInt(u64, state[16..24], v, .little);
    }

    measureOverhead();
}
