// Copyright (c) Microsoft Corporation. Licensed under the MIT license.

const std = @import("std");
const builtin = @import("builtin");
const rng = @import("rng.zig");
const cb = @import("callback.zig");
const testutil = @import("testutil.zig");

pub extern fn print(format: [*:0]const u8, ...) callconv(.c) void;
pub extern fn iprint(format: [*:0]const u8, ...) callconv(.c) void;
pub extern fn dprint(format: [*:0]const u8, ...) callconv(.c) void;
pub const printOutput = @import("perf.zig").printOutput;
extern fn scTestGenRandom(pbBuf: [*]u8, cbBuf: usize) callconv(.c) c_int;
extern fn scTestSleepMs(ms: u32) callconv(.c) void;
extern fn scTestIsAlgorithmPresent(name_ptr: [*]const u8, name_len: usize, isPrefix: u32) callconv(.c) u32;

pub fn fillRandom(buf: []u8) error{RandomFailed}!void {
    if (buf.len == 0) return;
    if (scTestGenRandom(buf.ptr, buf.len) != 0) return error.RandomFailed;
}

pub fn GENRANDOM(pbBuf: [*]u8, cbBuf: usize) void {
    if (cbBuf == 0) return;
    _ = scTestGenRandom(pbBuf, cbBuf);
}

pub fn fmtBufZ(buf: []u8, comptime fmt: []const u8, args: anytype) [*:0]const u8 {
    const s = std.fmt.bufPrint(buf[0 .. buf.len - 1], fmt, args) catch blk: {
        break :blk buf[0 .. buf.len - 1];
    };
    buf[s.len] = 0;
    return @ptrCast(buf.ptr);
}

pub fn zprint(comptime fmt: []const u8, args: anytype) void {
    var buf: [4096]u8 = undefined;
    print("%s", fmtBufZ(&buf, fmt, args));
}

pub fn ziprint(comptime fmt: []const u8, args: anytype) void {
    var buf: [4096]u8 = undefined;
    iprint("%s", fmtBufZ(&buf, fmt, args));
}

pub fn zdprint(comptime fmt: []const u8, args: anytype) void {
    var buf: [4096]u8 = undefined;
    dprint("%s", fmtBufZ(&buf, fmt, args));
}

pub fn vprint(cond: bool, comptime fmt: []const u8, args: anytype) void {
    if (cond) {
        zprint(fmt, args);
    }
}

pub const zvprint = vprint;

pub fn fatal(comptime fmt: []const u8, args: anytype) noreturn {
    var buf: [2048]u8 = undefined;
    fatalImpl(fmtBufZ(&buf, fmt, args));
}

pub const fatalFmt = fatal;
pub const g_rng = &rng.g_rng;

extern fn snprintf(str: [*]u8, size: usize, format: [*:0]const u8, ...) callconv(.c) c_int;

pub fn check(cond: bool, msg: [*:0]const u8) void {
    if (!cond) {
        fatalImpl(msg);
    }
}

pub fn check3(cond: bool, comptime fmt: [:0]const u8, a: anytype) void {
    if (!cond) {
        if (comptime std.mem.indexOfScalar(u8, fmt, '{') != null) {
            fatal(fmt, .{a});
        } else {
            var buf: [2048]u8 = undefined;
            _ = snprintf(&buf, buf.len, fmt.ptr, a);
            buf[buf.len - 1] = 0;
            fatalImpl(@ptrCast(&buf));
        }
    }
}

pub fn check4(cond: bool, comptime fmt: [:0]const u8, a: anytype, b: anytype) void {
    if (!cond) {
        if (comptime std.mem.indexOfScalar(u8, fmt, '{') != null) {
            fatal(fmt, .{ a, b });
        } else {
            var buf: [2048]u8 = undefined;
            _ = snprintf(&buf, buf.len, fmt.ptr, a, b);
            buf[buf.len - 1] = 0;
            fatalImpl(@ptrCast(&buf));
        }
    }
}

pub fn check5(cond: bool, comptime fmt: [:0]const u8, a: anytype, b: anytype, c: anytype) void {
    if (!cond) {
        if (comptime std.mem.indexOfScalar(u8, fmt, '{') != null) {
            fatal(fmt, .{ a, b, c });
        } else {
            var buf: [2048]u8 = undefined;
            _ = snprintf(&buf, buf.len, fmt.ptr, a, b, c);
            buf[buf.len - 1] = 0;
            fatalImpl(@ptrCast(&buf));
        }
    }
}

pub fn check6(cond: bool, comptime fmt: []const u8, arg1: anytype, arg2: anytype, arg3: anytype, arg4: anytype) void {
    if (!cond) {
        fatal(fmt, .{ arg1, arg2, arg3, arg4 });
    }
}

pub export fn isAlgorithmPresent(algName: [*]const u8, isPrefix: c_int) callconv(.c) bool {
    const cstr: [*:0]const u8 = @ptrCast(algName);
    const slice = std.mem.span(cstr);
    return scTestIsAlgorithmPresent(slice.ptr, slice.len, if (isPrefix != 0) 1 else 0) != 0;
}

pub export fn scTestIsAlgorithmPresentCstr(name: [*:0]const u8, isPrefix: c_int) callconv(.c) c_int {
    const slice = std.mem.span(name);
    return if (scTestIsAlgorithmPresent(slice.ptr, slice.len, if (isPrefix != 0) 1 else 0) != 0) 1 else 0;
}

const kat_mod = @import("kat.zig");

pub const DataResource = struct {
    name: []const u8,
    pbData: [*]const u8,
    cbData: usize,
};

pub fn findDataItem(name: []const u8) ?DataResource {
    return kat_mod.findEmbeddedResource(name);
}
pub export var g_rc2EffectiveKeyLength: u32 = 0;
pub export var g_modeCfbShiftParam: usize = 1;
pub export var g_modifiedCpuFeatures: u32 = 0;
pub export var g_failRegisterSave: u32 = 0;
pub export var g_runRsaAverageKeyPerf: u32 = 0;
pub export var g_osVersion: u32 = 0;
pub export var g_rngSeed: u32 = 0;
pub export var g_nTotalErrors: u64 = 0;
pub export var g_disabledOnCommandLine: u32 = 0;

pub export var g_dynamicSymCryptModuleHandle: ?*anyopaque = null;
pub export var g_useDynamicFunctionsInTestCall: u32 = 0;

pub export var g_showPerfRangeInfo: u32 = 0;
pub export var g_verbose: u32 = 0;
pub export var g_noPerfTests: u32 = 0;
pub export var g_profile: u32 = 0;
pub export var g_profile_iterations: u32 = 0;
pub export var g_profile_key: u32 = 0;

pub export var g_measure_specific_sizes: u32 = 0;
pub export var g_measure_sizes_start: u32 = 0;
pub export var g_measure_sizes_end: u32 = 0;
pub export var g_measure_sizes_increment: u32 = 1;
pub export var g_measure_sizes_repetitions: u32 = 1;

pub export var g_perfTestsRunning: u32 = 0;
pub export var g_printStatusIndicator: u32 = 0;
pub export var g_devTest: u32 = 0;
pub export var g_sgx: u32 = 0;

extern var TestSaveXmmEnabled: u8;
extern var TestSaveYmmEnabled: u8;
extern var TestSaveZmmEnabled: u8;

pub export var g_algorithmNames = [_]?[*:0]const u8{
    "Md2",
    "Md4",
    "Md5",
    "Sha1",
    "Sha224",
    "Sha256",
    "Sha384",
    "Sha512",
    "Sha512-224",
    "Sha512-256",
    "Sha3-224",
    "Sha3-256",
    "Sha3-384",
    "Sha3-512",
    "Shake128",
    "Shake256",
    "CShake128",
    "CShake256",
    "Kmac128",
    "Kmac256",
    "HmacMd5",
    "HmacSha1",
    "HmacSha224",
    "HmacSha256",
    "HmacSha384",
    "HmacSha512",
    "HmacSha512-224",
    "HmacSha512-256",
    "HmacSha3-224",
    "HmacSha3-256",
    "HmacSha3-384",
    "HmacSha3-512",
    "AesCmac",
    "Marvin32",
    "Aes",
    "Des",
    "2Des",
    "3Des",
    "Desx",
    "Rc2",
    "Rc4",
    "ChaCha20",
    "Poly1305",
    "ChaCha20Poly1305",
    "AesCtrDrbg",
    "AesCtrF142",
    "DynamicRandom",
    "ParSha256",
    "ParSha384",
    "ParSha512",
    "Pbkdf2",
    "Sp800_108",
    "TlsPrf1_1",
    "TlsPrf1_2",
    "SshKdf",
    "SrtpKdf",
    "Hkdf",
    "SskdfMac",
    "SskdfHash",
    "XtsAes",
    "AesKw",
    "AesKwp",
    "TlsCbcHmacSha1",
    "TlsCbcHmacSha256",
    "TlsCbcHmacSha384",
    "IntAdd",
    "IntSub",
    "IntMul",
    "IntSquare",
    "IntDivMod",
    "ModAdd",
    "ModSub",
    "ModMul",
    "ModSquare",
    "ModInv",
    "ModExp",
    "ScsTable",
    "IEEE802_11SaeCustom",
    "TrialDivision",
    "TrialDivisionContext",
    "Wipe",
    "RsaEncRaw",
    "RsaEncPkcs1",
    "RsaEncOaep",
    "RsaSignPkcs1",
    "RsaSignPss",
    "RsakeySetValue",
    "RsakeySetValueFromPrivateExponent",
    "DsaSign",
    "DsaVerify",
    "Dh",
    "Dsa",
    "EcurveAllocateAndFree",
    "EckeySetRandom",
    "EcpointSetZero",
    "EcpointSetDistinguished",
    "EcpointSetRandom",
    "EcpointIsEqual",
    "EcpointIsZero",
    "EcpointOnCurve",
    "EcpointAdd",
    "EcpointAddDiffNz",
    "EcpointDouble",
    "EcpointScalarMul",
    "EcdsaSign",
    "EcdsaVerify",
    "Ecdh",
    "EckeySetValue",
    "TlsHandshake",
    "Xmss",
    "Lms",
    "MlKem",
    "MlKemkeySetValue",
    "MlDsa",
    "MlDsakeySetValue",
    "CompositeMlDsa",
    "CompositeMlDsakeySetValue",
    "CompositeMlKem",
    "CompositeMlKemkeySetValue",
    "Hpke",
    "DeveloperTest",
    null,
};

pub export var g_modeNames = [_]?[*:0]const u8{
    "Ecb",
    "Cbc",
    "Cfb",
    "Ccm",
    "Gcm",
    "",
    null,
};

const NameSet = struct {
    items: std.ArrayListUnmanaged([]u8) = .empty,

    fn insert(self: *NameSet, s: []const u8) void {
        for (self.items.items) |existing| {
            if (std.mem.eql(u8, existing, s)) return;
        }
        const copy = std.heap.c_allocator.dupe(u8, s) catch fatalFmt("Out of memory", .{});
        self.items.append(std.heap.c_allocator, copy) catch fatalFmt("Out of memory", .{});
    }

    fn erase(self: *NameSet, s: []const u8) void {
        var i: usize = 0;
        while (i < self.items.items.len) {
            if (std.mem.eql(u8, self.items.items[i], s)) {
                const removed = self.items.orderedRemove(i);
                std.heap.c_allocator.free(removed);
                return;
            }
            i += 1;
        }
    }

    fn containsPrefix(self: *const NameSet, str: []const u8) bool {
        if (self.items.items.len == 0) {
            return true;
        }
        for (self.items.items) |prefix| {
            if (str.len >= prefix.len and std.ascii.eqlIgnoreCase(prefix, str[0..prefix.len])) {
                return true;
            }
        }
        return false;
    }
};

var g_algorithmsToTestZig: NameSet = .{};
var g_implementationsToTestZig: NameSet = .{};

fn updateNameSet(names: [*:null]const ?[*:0]const u8, set: *NameSet, op: u8, name: []const u8) bool {
    if (name.len == 0) return false;
    var nameMatch = false;

    var i: usize = 0;
    while (names[i]) |entry_cstr| : (i += 1) {
        const entry = std.mem.span(entry_cstr);
        if (op == '+') {
            const prefixLen = @min(entry.len, name.len);
            if (std.ascii.eqlIgnoreCase(name[0..prefixLen], entry[0..prefixLen])) {
                nameMatch = true;
                set.insert(name);
                break;
            }
        } else {
            if (entry.len >= name.len and std.ascii.eqlIgnoreCase(name, entry[0..name.len])) {
                if (set.items.items.len == 0) {
                    var j: usize = 0;
                    while (names[j]) |all_cstr| : (j += 1) {
                        set.insert(std.mem.span(all_cstr));
                    }
                }
                set.erase(entry);
                nameMatch = true;
            }
        }
    }
    return nameMatch;
}

pub export fn scTestSetContainsPrefixAlg(str_ptr: [*]const u8, str_len: usize) callconv(.c) u32 {
    return if (g_algorithmsToTestZig.containsPrefix(str_ptr[0..str_len])) 1 else 0;
}

pub export fn scTestSetContainsPrefixImp(str_ptr: [*]const u8, str_len: usize) callconv(.c) u32 {
    return if (g_implementationsToTestZig.containsPrefix(str_ptr[0..str_len])) 1 else 0;
}

pub fn printHex(data: []const u8) void {
    for (data) |b| {
        zprint("{x:0>2}", .{b});
    }
}

extern var g_SymCryptCpuFeaturesNotPresent: u32;
extern const SymCryptBuildString: [*:0]const u8;
extern const g_implementationNames: [16]?[*:0]const u8;

extern fn SymCryptInit() callconv(.c) void;
extern fn SymCryptCpuFeaturesNeverPresent() callconv(.c) u32;
extern fn SymCryptFipsGetSelftestsPerformed() callconv(.c) u32;
extern fn SymCryptGetCachedEcurve(curve_id: u32) callconv(.c) ?*anyopaque;
extern fn SymCryptRdrandStatus() callconv(.c) u32;
extern fn SymCryptRdrandGet(pbBuffer: [*]u8, cbBuffer: usize, pbResult: [*]u8) callconv(.c) void;
extern fn SymCryptRdseedStatus() callconv(.c) u32;
extern fn SymCryptRdseedGet(pbResult: [*]u8, cbResult: usize) callconv(.c) void;

extern fn scTestCheckAsmOffsets() callconv(.c) void;
extern fn scTestSetMeasureSizesPrefix(ptr: [*]const u8, len: usize) callconv(.c) void;
extern fn scTestSetDynamicModulePath(ptr: [*]const u8, len: usize) callconv(.c) void;
extern fn scTestGetDynamicModulePath() callconv(.c) ?[*:0]const u8;
extern fn scTestSummarizeFunctionalResults(pTotalErrors: *u64) callconv(.c) void;
extern fn scTestRunPerfTestsCpp() callconv(.c) void;
extern fn scTestClearAndFreeAlgImps() callconv(.c) void;

extern fn initVectorRegisters() callconv(.c) void;
extern fn verifyVectorRegisters() callconv(.c) void;
extern fn loadDynamicModuleFromPath(dynamicModulePath: [*:0]const u8) callconv(.c) ?*anyopaque;
extern fn getDynamicSymbolPointerFromString(hDynamicModule: ?*anyopaque, pSymbolName: [*:0]const u8, symbolType: u32) callconv(.c) ?*anyopaque;
extern fn SctestDisableCpuFeatures(disable: u32) callconv(.c) u32;

extern fn scTestRunSingleLayerCppTests() callconv(.c) void;
extern fn scTestRunMultiImpCppTests() callconv(.c) void;
extern fn scTestRunStatusAndServiceIndicatorTests(printIndicator: u32) callconv(.c) void;

pub export fn developertest() callconv(.c) void {}

const SYMCRYPT_CPU_FEATURE_SSE2: u32 = 0x0001;
const SYMCRYPT_CPU_FEATURE_SSSE3: u32 = 0x0002;
const SYMCRYPT_CPU_FEATURE_AESNI: u32 = 0x0004;
const SYMCRYPT_CPU_FEATURE_PCLMULQDQ: u32 = 0x0008;
const SYMCRYPT_CPU_FEATURE_AVX2: u32 = 0x0010;
const SYMCRYPT_CPU_FEATURE_SAVEXMM_NOFAIL: u32 = 0x0020;
const SYMCRYPT_CPU_FEATURE_SHANI: u32 = 0x0040;
const SYMCRYPT_CPU_FEATURE_BMI2: u32 = 0x0080;
const SYMCRYPT_CPU_FEATURE_ADX: u32 = 0x0100;
const SYMCRYPT_CPU_FEATURE_RDRAND: u32 = 0x0200;
const SYMCRYPT_CPU_FEATURE_RDSEED: u32 = 0x0400;
const SYMCRYPT_CPU_FEATURE_VAES: u32 = 0x0800;
const SYMCRYPT_CPU_FEATURE_AVX512: u32 = 0x1000;
const SYMCRYPT_CPU_FEATURE_CMPXCHG16B: u32 = 0x2000;

const SYMCRYPT_CPU_FEATURE_NEON: u32 = 0x01;
const SYMCRYPT_CPU_FEATURE_NEON_AES: u32 = 0x02;
const SYMCRYPT_CPU_FEATURE_NEON_PMULL: u32 = 0x04;
const SYMCRYPT_CPU_FEATURE_NEON_SHA256: u32 = 0x08;

const CpuFeatureData = struct {
    name: []const u8,
    mask: u32,
};

const g_cpuFeatureData = if (builtin.cpu.arch == .x86 or builtin.cpu.arch == .x86_64) [_]CpuFeatureData{
    .{ .name = "sse2", .mask = SYMCRYPT_CPU_FEATURE_SSE2 },
    .{ .name = "ssse3", .mask = SYMCRYPT_CPU_FEATURE_SSSE3 },
    .{ .name = "aesni", .mask = SYMCRYPT_CPU_FEATURE_AESNI },
    .{ .name = "pclmulqdq", .mask = SYMCRYPT_CPU_FEATURE_PCLMULQDQ },
    .{ .name = "rdrand", .mask = SYMCRYPT_CPU_FEATURE_RDRAND },
    .{ .name = "rdseed", .mask = SYMCRYPT_CPU_FEATURE_RDSEED },
    .{ .name = "avx2", .mask = SYMCRYPT_CPU_FEATURE_AVX2 },
    .{ .name = "savexmmnofail", .mask = SYMCRYPT_CPU_FEATURE_SAVEXMM_NOFAIL },
    .{ .name = "shani", .mask = SYMCRYPT_CPU_FEATURE_SHANI },
    .{ .name = "adx", .mask = SYMCRYPT_CPU_FEATURE_ADX },
    .{ .name = "bmi2", .mask = SYMCRYPT_CPU_FEATURE_BMI2 },
    .{ .name = "vaes", .mask = SYMCRYPT_CPU_FEATURE_VAES },
    .{ .name = "avx512", .mask = SYMCRYPT_CPU_FEATURE_AVX512 },
    .{ .name = "cmpxchg16b", .mask = SYMCRYPT_CPU_FEATURE_CMPXCHG16B },
} else if (builtin.cpu.arch == .aarch64) [_]CpuFeatureData{
    .{ .name = "neon", .mask = SYMCRYPT_CPU_FEATURE_NEON },
    .{ .name = "i_aes", .mask = SYMCRYPT_CPU_FEATURE_NEON_AES },
    .{ .name = "i_pmull", .mask = SYMCRYPT_CPU_FEATURE_NEON_PMULL },
    .{ .name = "i_sha256", .mask = SYMCRYPT_CPU_FEATURE_NEON_SHA256 },
} else if (builtin.cpu.arch == .arm) [_]CpuFeatureData{
    .{ .name = "neon", .mask = SYMCRYPT_CPU_FEATURE_NEON },
} else [_]CpuFeatureData{
    .{ .name = "aesni", .mask = 0 },
};

fn printSymCryptCpuInfo(text: []const u8, notPresent: u32) void {
    var sep: u8 = ' ';
    zprint("{s}: ", .{text});
    for (g_cpuFeatureData) |entry| {
        if ((notPresent & entry.mask) == 0) {
            zprint("{c}{s}", .{ sep, entry.name });
            sep = ',';
        }
    }
    zprint("\n", .{});
}

fn printTestVectorSaveOptions() void {
    var sep: u8 = ' ';
    zprint("\nTest Vector Save/Restore options:", .{});
    if (TestSaveXmmEnabled != 0) {
        zprint("{c}TestSaveXmmEnabled", .{sep});
        sep = ',';
    }
    if (TestSaveYmmEnabled != 0) {
        zprint("{c}TestSaveYmmEnabled", .{sep});
        sep = ',';
    }
    if (TestSaveZmmEnabled != 0) {
        zprint("{c}TestSaveZmmEnabled", .{sep});
        sep = ',';
    }
    if (sep == ' ') {
        zprint(" None", .{});
    }
    zprint("\n", .{});
}

const SCTEST_DYNSYM_FUNCTION_PTR: u32 = 1;

fn printSymCryptFipsGetSelftestsPerformed() void {
    const fipsSelfTestsPerformed = SymCryptFipsGetSelftestsPerformed();
    zprint("static  SymCryptFipsGetSelftestsPerformed() {x}\n", .{fipsSelfTestsPerformed});

    if (g_dynamicSymCryptModuleHandle) |handle| {
        const sym = getDynamicSymbolPointerFromString(handle, "SymCryptFipsGetSelftestsPerformed", SCTEST_DYNSYM_FUNCTION_PTR);
        if (sym) |fn_ptr| {
            const dynFn: *const fn () callconv(.c) u32 = @ptrCast(@alignCast(fn_ptr));
            zprint("dynamic SymCryptFipsGetSelftestsPerformed() {x}\n", .{dynFn()});
        }
    }
}

fn usage() void {
    ziprint(
        "\n\n" ++
            "USAGE: symcryptunittest <option>...\n" ++
            "Each option is a '+' or '-' followed by a string\n" ++
            "Options:\n" ++
            "  +<cpufeature>     ensure that cpu feature is present in CPU\n" ++
            "  -<cpufeature>     disable CPU feature for SymCrypt.\n" ++
            "                    \"-aesni\" also disables AES-NI usage for RSA32\n" ++
            " +<impl. prefix>    run only those implementations that match the prefix\n" ++
            " -<impl. prefix>    do not run the implementations that match the prefix\n" ++
            " +<alg. prefix>     run only those algorithms that match the prefix\n" ++
            " -<alg. prefix>     do not run algorithms that match the prefix\n" ++
            "  showrange         show 90-percentile range on the deviation of individual \n" ++
            "                    performance measurement from the linear performance data\n" ++
            "  osversion=xxxx    Use Capi/Cng calling conventions for OS version xxxx\n" ++
            "                    XP = <tbd>, Vista = 0600, Win7 = 0601, Win8 = 0602, Blue=0603\n" ++
            "  rngseed=xxxxxxxx  Set seed for test RNG algorithm, default = 0 = random\n" ++
            "  sizes:<startSize>,<endSize>,<sizeIncrement>,<numberOfRepetitions>\n" ++
            "                    Run algorithms for dataSizes specified at the command line, rather\n" ++
            "                    than using the sizes built into the unit tests and performing\n" ++
            "                    a linear regression. All parameters are unsigned decimal integers.\n" ++
            "                    Only a prefix of the parameters needs to be specified - i.e. sizes:1024\n" ++
            "                    tests specified algorithms/implementations at only a dataSize of 1024\n" ++
            "  sizeprefix:<prefix>      Only applies when sizes: parameter is also specified. Prefixes\n" ++
            "                           output of test command with a specific string. This can enable\n" ++
            "                           easier concatenation of many test runs on differing platforms into\n" ++
            "                           a single .csv for postprocessing.\n" ++
            "  verbose           Print detailed information for some algorithms\n" ++
            "  noperftests       Skip running the performance tests - only run functional tests\n" ++
            "  profile:xxx [key=yyy]    Run one or more algorithms in a tight loop, xxx times for\n" ++
            "                           each key/datasize combination. The algorithms to run are specified\n" ++
            "                           by the +/- options. The optional key parameter can specify\n" ++
            "                           that only the key size with the hex code yyy will be run.\n" ++
            "                           Note: If you don't know the desired key, run profiling without\n" ++
            "                               the key parameter and all possible codes will get printed.\n" ++
            "  rsakgp            Run perf measurement of RSA key generation.\n" ++
            "  sgx               Run CNG and symcrypt test implementations against BCrypt in SGX enclave.\n" ++
            "                    This option is only valid for win8_1 version and newer of the tests.\n" ++
            "  testSaveYmm       This option enables the unit tests to test the save/restore logic for\n" ++
            "                    Ymm registers. Has no effect on Windows as there is no way to configure\n" ++
            "                    the C runtime to not overwrite YMM registers on Windows.\n" ++
            "  testSaveZmm       This option enables the unit tests to test the save/restore logic for\n" ++
            "                    Zmm registers. Has no effect on Windows as there is no way to configure\n" ++
            "                    the C runtime to not overwrite ZMM registers on Windows.\n" ++
            "  dynamic:<path_to_module>\n" ++
            "                    This option instructs the unit tests to load <path_to_module> as another\n" ++
            "                    external implementation of the SymCrypt APIs, which will be added as an\n" ++
            "                    implementation called SymCryptDynamic. By default, all calls to SymCrypt\n" ++
            "                    are passed to both the statically and dynamically linked SymCrypt versions\n" ++
            " statusindicator    Print FIPS status indicator string\n" ++
            " devtest            Run developer test (normally empty)\n" ++
            "\n",
        .{},
    );

    if (builtin.cpu.arch == .x86 or builtin.cpu.arch == .x86_64) {
        ziprint(" CPU feature:       aesni, pclmulqdq, sse2, sse3, ssse3, avx2,\n                    rdrand, rdseed, savexmmnofail, shani, adx, bmi2\n", .{});
    } else if (builtin.cpu.arch == .aarch64) {
        ziprint(" CPU feature:       neon, i_sha1, i_sha256, i_aes, i_pmull\n", .{});
    } else if (builtin.cpu.arch == .arm) {
        ziprint(" CPU feature:       neon\n", .{});
    }

    var sep: []const u8 = " Implementations:   ";
    var i: usize = 0;
    while (g_implementationNames[i]) |imp_cstr| : (i += 1) {
        ziprint("{s}{s}", .{ sep, std.mem.span(imp_cstr) });
        sep = ", ";
    }
    ziprint("\n", .{});

    sep = " Algorithm names:   ";
    var col: usize = 0;
    i = 0;
    while (g_algorithmNames[i]) |alg_cstr| : (i += 1) {
        const alg = std.mem.span(alg_cstr);
        if (col + sep.len + alg.len > 77) {
            ziprint("{s}\n                    ", .{sep});
            col = 20;
            sep = "";
        }
        ziprint("{s}{s}", .{ sep, alg });
        col += sep.len + alg.len;
        sep = ", ";
    }
    ziprint("\n", .{});

    sep = " Mode names:        ";
    i = 0;
    while (g_modeNames[i]) |mode_cstr| : (i += 1) {
        ziprint("{s}{s}", .{ sep, std.mem.span(mode_cstr) });
        sep = ", ";
    }
    ziprint("\n", .{});
}

fn processSingleOption(option_cstr: [*:0]u8) void {
    const option = std.mem.span(option_cstr);
    var optionHandled = false;

    if (option.len > 0 and (option[0] == '+' or option[0] == '-')) {
        const body = option[1..];
        for (g_cpuFeatureData) |entry| {
            if (std.ascii.eqlIgnoreCase(body, entry.name)) {
                if (option[0] == '-') {
                    g_SymCryptCpuFeaturesNotPresent |= entry.mask;
                    g_disabledOnCommandLine |= entry.mask;
                    g_modifiedCpuFeatures = 1;
                } else {
                    const disabled = g_SymCryptCpuFeaturesNotPresent | SymCryptCpuFeaturesNeverPresent();
                    if ((entry.mask & disabled) != 0) {
                        fatalFmt("CPU feature not available: {s}", .{option});
                    }
                }
                optionHandled = true;
                break;
            }
        }
    } else {
        if (std.ascii.eqlIgnoreCase(option, "showrange")) {
            g_showPerfRangeInfo = 1;
            optionHandled = true;
        }
        if (std.ascii.eqlIgnoreCase(option, "verbose")) {
            g_verbose = 1;
            optionHandled = true;
        }
        if (std.ascii.eqlIgnoreCase(option, "noperftests")) {
            g_noPerfTests = 1;
            optionHandled = true;
        }
        if (std.ascii.startsWithIgnoreCase(option, "profile:")) {
            const num_str = option[8..];
            g_profile = 1;
            g_profile_iterations = std.fmt.parseInt(u32, num_str, 0) catch 0;
            if (g_profile_iterations == 0) {
                fatalFmt("Number of profile iterations must be greater than zero.", .{});
            }
            optionHandled = true;
        }
        if (std.ascii.startsWithIgnoreCase(option, "key=")) {
            if (g_profile == 0) {
                fatalFmt("Key parameter present without profile parameter \"{s}\"", .{option});
            }
            g_profile_key = std.fmt.parseInt(u32, option[4..], 16) catch 0;
            optionHandled = true;
        }
        if (std.ascii.startsWithIgnoreCase(option, "sizes:")) {
            g_measure_specific_sizes = 1;
            var it = std.mem.splitScalar(u8, option[6..], ',');
            g_measure_sizes_start = if (it.next()) |s| (std.fmt.parseInt(u32, s, 0) catch 0) else 0;
            g_measure_sizes_end = if (it.next()) |s| (std.fmt.parseInt(u32, s, 0) catch 0) else 0;
            g_measure_sizes_increment = if (it.next()) |s| (std.fmt.parseInt(u32, s, 0) catch 0) else 0;
            g_measure_sizes_repetitions = if (it.next()) |s| (std.fmt.parseInt(u32, s, 0) catch 0) else 0;

            if (g_measure_sizes_end == 0) {
                g_measure_sizes_end = g_measure_sizes_start;
            }
            if (g_measure_sizes_increment == 0) {
                g_measure_sizes_increment = if (g_measure_sizes_start >= g_measure_sizes_end) 1 else (g_measure_sizes_end - g_measure_sizes_start);
            }
            if (g_measure_sizes_repetitions == 0) {
                g_measure_sizes_repetitions = 1;
            }
            optionHandled = true;
        }
        if (std.ascii.startsWithIgnoreCase(option, "sizeprefix:")) {
            const pfx = option[11..];
            scTestSetMeasureSizesPrefix(pfx.ptr, pfx.len);
            optionHandled = true;
        }
        if (std.ascii.eqlIgnoreCase(option, "rsakgp")) {
            g_runRsaAverageKeyPerf = 1;
            optionHandled = true;
        }
        if (std.ascii.startsWithIgnoreCase(option, "osversion=")) {
            const ver_str = option[10..];
            g_osVersion = std.fmt.parseInt(u32, ver_str, 16) catch 0;
            if (ver_str.len != 4 or g_osVersion < 0x0500 or g_osVersion > 0x0800) {
                fatalFmt("Invalid OS version \"{s}\"", .{ver_str});
            }
            optionHandled = true;
            g_modifiedCpuFeatures = 1;
        }
        if (std.ascii.startsWithIgnoreCase(option, "rngseed=")) {
            g_rngSeed = std.fmt.parseInt(u32, option[8..], 16) catch 0;
            optionHandled = true;
        }
        if (std.ascii.eqlIgnoreCase(option, "sgx")) {
            g_sgx = 1;
            optionHandled = true;
        }
        if (std.ascii.eqlIgnoreCase(option, "testSaveYmm")) {
            TestSaveYmmEnabled = 1;
            optionHandled = true;
        }
        if (std.ascii.eqlIgnoreCase(option, "testSaveZmm")) {
            TestSaveZmmEnabled = 1;
            optionHandled = true;
        }
        if (std.ascii.startsWithIgnoreCase(option, "dynamic:")) {
            const dyn_path = option[8..];
            scTestSetDynamicModulePath(dyn_path.ptr, dyn_path.len);
            optionHandled = true;
        }
        if (std.ascii.eqlIgnoreCase(option, "statusindicator")) {
            g_printStatusIndicator = 1;
            optionHandled = true;
        }
        if (std.ascii.eqlIgnoreCase(option, "devtest")) {
            g_devTest = 1;
            optionHandled = true;
        }
    }

    if (!optionHandled) {
        zprint("\nUnknown option \"{s}\"", .{option});
        usage();
        std.c.exit(-1);
    }
}

fn processOptions(argc: c_int, argv: [*][*:0]u8) void {
    var sepchar: u8 = ' ';
    ziprint("\nOptions:", .{});

    const count: usize = @intCast(argc);
    const alg_ptr: [*:null]const ?[*:0]const u8 = @ptrCast(&g_algorithmNames);
    var i: usize = 1;
    while (i < count) : (i += 1) {
        const arg = std.mem.span(argv[i]);
        ziprint("{c} {s}", .{ sepchar, arg });
        sepchar = ',';

        var optionHandled = false;
        if (arg.len > 0 and (arg[0] == '+' or arg[0] == '-')) {
            const op = arg[0];
            const name = arg[1..];

            if (updateNameSet(alg_ptr, &g_algorithmsToTestZig, op, name)) {
                optionHandled = true;
            }
            if (!optionHandled and updateNameSet(@ptrCast(&g_implementationNames), &g_implementationsToTestZig, op, name)) {
                optionHandled = true;
            }
        }
        if (!optionHandled) {
            processSingleOption(argv[i]);
        }
    }

    ziprint("\n", .{});
}

var alreadyFatal: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);

extern fn fflush(stream: ?*anyopaque) callconv(.c) c_int;

pub export fn fatalImpl(message: [*:0]const u8) callconv(.c) noreturn {
    if (alreadyFatal.swap(true, .seq_cst)) {
        while (true) {
            scTestSleepMs(10000);
        }
    }

    _ = std.c.printf("%s", message);
    _ = fflush(null);
    printOutput(0);
    _ = fflush(null);

    std.c._exit(-1);
}

fn printPlatformInformation(text: []const u8) void {
    const arch = switch (builtin.cpu.arch) {
        .x86 => "x86",
        .x86_64 => "amd64",
        .aarch64 => "arm64",
        .arm => "arm",
        else => "generic",
    };
    const flavor = if (builtin.mode == .debug) "Debug" else "Release";

    var uts: std.posix.utsname = undefined;
    const rc = std.posix.system.uname(&uts);
    if (rc == 0) {
        const sysname = std.mem.sliceTo(&uts.sysname, 0);
        const release = std.mem.sliceTo(&uts.release, 0);
        ziprint("\n{s} {s} {s} {s} {s}\n", .{ text, arch, flavor, sysname, release });
    } else {
        ziprint("\n{s} {s} {s} Unknown platform\n", .{ text, arch, flavor });
    }
}

fn initCachedEcurves() void {
    const nOutstandingAllocs = @atomicLoad(i64, &cb.g_nOutstandingCheckedAllocs, .seq_cst);
    var i: u32 = 0;
    while (i < 6) : (i += 1) {
        _ = SymCryptGetCachedEcurve(i);
    }
    @atomicStore(i64, &cb.g_nOutstandingCheckedAllocs, nOutstandingAllocs, .seq_cst);
}

const SYMCRYPT_CODE_VERSION_API: u32 = 103;
const SYMCRYPT_CODE_VERSION_MINOR: u32 = 13;

pub export fn initTestInfrastructure(argc: c_int, argv: [*][*:0]u8) callconv(.c) void {
    ziprint(
        "SymCrypt unit test program, Library version {s}\nCopyright (c) Microsoft Corporation. Licensed under the MIT license.\n",
        .{std.mem.span(SymCryptBuildString)},
    );

    scTestCheckAsmOffsets();

    SymCryptInit();

    printPlatformInformation("System information:");
    printSymCryptCpuInfo("Hardware CPU features", g_SymCryptCpuFeaturesNotPresent);

    processOptions(argc, argv);

    if (g_modifiedCpuFeatures != 0) {
        printPlatformInformation("Modified System information for this test");
        printSymCryptCpuInfo("Modified CPU features for this test", g_SymCryptCpuFeaturesNotPresent);
    }

    printTestVectorSaveOptions();

    if (scTestGetDynamicModulePath()) |dynPath| {
        const dynSlice = std.mem.span(dynPath);
        if (dynSlice.len > 0) {
            g_dynamicSymCryptModuleHandle = loadDynamicModuleFromPath(dynPath);
            check(g_dynamicSymCryptModuleHandle != null, "Failed to load dynamic module. Is the path correct?");

            ziprint("\nLoaded {s} to {x}\n", .{ dynSlice, @intFromPtr(g_dynamicSymCryptModuleHandle) });

            const pSymCryptModuleInit = getDynamicSymbolPointerFromString(
                g_dynamicSymCryptModuleHandle,
                "SymCryptModuleInit",
                SCTEST_DYNSYM_FUNCTION_PTR,
            );
            check(pSymCryptModuleInit != null, "Could not find SymCryptModuleInit Function");
            const fnModuleInit: *const fn (u32, u32) callconv(.c) void = @ptrCast(@alignCast(pSymCryptModuleInit.?));
            fnModuleInit(SYMCRYPT_CODE_VERSION_API, SYMCRYPT_CODE_VERSION_MINOR);

            const pDisable = getDynamicSymbolPointerFromString(
                g_dynamicSymCryptModuleHandle,
                "SctestDisableCpuFeatures",
                SCTEST_DYNSYM_FUNCTION_PTR,
            );
            if (pDisable) |fn_ptr| {
                const fnDisable: *const fn (u32) callconv(.c) u32 = @ptrCast(@alignCast(fn_ptr));
                printSymCryptCpuInfo("Dynamic Hardware CPU features", fnDisable(g_disabledOnCommandLine));
            }
        }
    }

    printSymCryptFipsGetSelftestsPerformed();

    if (g_rngSeed == 0) {
        fillRandom(std.mem.asBytes(&g_rngSeed)) catch fatalFmt("Failed to get random seed", .{});
    }
    rng.scTestRngReset(&rng.g_rng, std.mem.asBytes(&g_rngSeed).ptr, @sizeOf(u32));
    ziprint("\nTest Rng seed = {x:0>8}\n", .{g_rngSeed});

    if (g_algorithmsToTestZig.items.items.len > 0) {
        zprint("\nAlgorithms to test:\n", .{});
        for (g_algorithmsToTestZig.items.items) |alg| {
            zprint("    {s}\n", .{alg});
        }
    }

    if (g_implementationsToTestZig.items.items.len > 0) {
        zprint("\nImplementations to test:\n", .{});
        for (g_implementationsToTestZig.items.items) |imp| {
            zprint("    {s}\n", .{imp});
        }
    } else {
        _ = updateNameSet(@ptrCast(&g_implementationNames), &g_implementationsToTestZig, '-', "rsa32b");
    }

    cb.AllocWithChecksInit();

    initCachedEcurves();

    printOutput(0);
}

pub export fn rdrandTest() callconv(.c) void {
    if (builtin.cpu.arch != .x86 and builtin.cpu.arch != .x86_64) {
        return;
    }

    if (g_useDynamicFunctionsInTestCall != 0) {
        if (getDynamicSymbolPointerFromString(g_dynamicSymCryptModuleHandle, "SymCryptRdrandStatus", SCTEST_DYNSYM_FUNCTION_PTR) == null or
            getDynamicSymbolPointerFromString(g_dynamicSymCryptModuleHandle, "SymCryptRdrandGet", SCTEST_DYNSYM_FUNCTION_PTR) == null or
            getDynamicSymbolPointerFromString(g_dynamicSymCryptModuleHandle, "SymCryptRdseedStatus", SCTEST_DYNSYM_FUNCTION_PTR) == null or
            getDynamicSymbolPointerFromString(g_dynamicSymCryptModuleHandle, "SymCryptRdseedGet", SCTEST_DYNSYM_FUNCTION_PTR) == null)
        {
            zprint("    rdrandTest skipped\n", .{});
            return;
        }
    }

    const rdrandStatus = if (g_useDynamicFunctionsInTestCall != 0) blk: {
        const fn_ptr: *const fn () callconv(.c) u32 = @ptrCast(@alignCast(getDynamicSymbolPointerFromString(g_dynamicSymCryptModuleHandle, "SymCryptRdrandStatus", SCTEST_DYNSYM_FUNCTION_PTR).?));
        break :blk fn_ptr();
    } else blk: {
        initVectorRegisters();
        const r = SymCryptRdrandStatus();
        verifyVectorRegisters();
        break :blk r;
    };

    var buf: [64]u8 = undefined;
    const reseed_size: usize = 3 * (1 << 13);

    if (rdrandStatus == 0) {
        const p = std.heap.c_allocator.alloc(u8, reseed_size) catch fatalFmt("Out of memory in rdrandTest()", .{});
        defer std.heap.c_allocator.free(p);

        if (g_useDynamicFunctionsInTestCall != 0) {
            const fn_ptr: *const fn ([*]u8, usize, [*]u8) callconv(.c) void = @ptrCast(@alignCast(getDynamicSymbolPointerFromString(g_dynamicSymCryptModuleHandle, "SymCryptRdrandGet", SCTEST_DYNSYM_FUNCTION_PTR).?));
            fn_ptr(p.ptr, reseed_size, &buf);
        } else {
            initVectorRegisters();
            SymCryptRdrandGet(p.ptr, reseed_size, &buf);
            verifyVectorRegisters();
        }
        zprint("RDRAND present {c}\n", .{@as(u8, '0') + (buf[3] % 45)});
    }

    const rdseedStatus = if (g_useDynamicFunctionsInTestCall != 0) blk: {
        const fn_ptr: *const fn () callconv(.c) u32 = @ptrCast(@alignCast(getDynamicSymbolPointerFromString(g_dynamicSymCryptModuleHandle, "SymCryptRdseedStatus", SCTEST_DYNSYM_FUNCTION_PTR).?));
        break :blk fn_ptr();
    } else blk: {
        initVectorRegisters();
        const r = SymCryptRdseedStatus();
        verifyVectorRegisters();
        break :blk r;
    };

    if (rdseedStatus == 0) {
        if (g_useDynamicFunctionsInTestCall != 0) {
            const fn_ptr: *const fn ([*]u8, usize) callconv(.c) void = @ptrCast(@alignCast(getDynamicSymbolPointerFromString(g_dynamicSymCryptModuleHandle, "SymCryptRdseedGet", SCTEST_DYNSYM_FUNCTION_PTR).?));
            fn_ptr(&buf, buf.len);
        } else {
            initVectorRegisters();
            SymCryptRdseedGet(&buf, buf.len);
            verifyVectorRegisters();
        }
        zprint("RDSEED present {c}\n", .{@as(u8, '0') + (buf[3] % 45)});
    }
}

pub export fn runFunctionalTests() callconv(.c) void {
    zprint("\n\nFunctional tests:\n", .{});

    if (g_devTest != 0) {
        developertest();
    }

    const modes = [_]u32{ 0, 1 };
    for (modes) |useDynamic| {
        g_useDynamicFunctionsInTestCall = useDynamic;
        if (g_useDynamicFunctionsInTestCall != 0 and g_dynamicSymCryptModuleHandle == null) {
            break;
        }

        const kind_str = if (g_useDynamicFunctionsInTestCall != 0) "dynamic" else "static";
        ziprint("SymCrypt {s} function tests\n", .{kind_str});

        rdrandTest();
        testutil.testUtil();
        testutil.testModuleInitEx();
        scTestRunSingleLayerCppTests();
    }

    ziprint("Multi-implementation tests\n", .{});
    g_useDynamicFunctionsInTestCall = 0;

    scTestRunMultiImpCppTests();

    printSymCryptFipsGetSelftestsPerformed();

    scTestRunStatusAndServiceIndicatorTests(g_printStatusIndicator);

    ziprint("Functional testing done.\n", .{});

    scTestSummarizeFunctionalResults(&g_nTotalErrors);

    printOutput(0);
}

pub export fn runPerfTests() callconv(.c) void {
    if (g_noPerfTests != 0) {
        return;
    }

    g_perfTestsRunning = 1;
    scTestRunPerfTestsCpp();
    g_perfTestsRunning = 0;
}

pub export fn exitTestInfrastructure() callconv(.c) void {
    scTestClearAndFreeAlgImps();

    check(g_nTotalErrors == 0, "Errors detected in algorithms, see tables above for details.");

    zprint("\n...SymCrypt unit test done\n", .{});
    printOutput(0);
}

pub export fn printHexArray(pData: [*]const u8, nElements: usize, elementSize: usize) callconv(.c) void {
    var ptr = pData;
    for (0..nElements) |i| {
        zprint("{d: >2}: ", .{i});
        for (0..elementSize) |j| {
            zprint("{x:0>2}", .{ptr[0]});
            ptr += 1;
            if (j % 4 == 3) {
                zprint(" ", .{});
            }
        }
        zprint("\n", .{});
    }
}

extern fn fprintf(stream: *anyopaque, format: [*:0]const u8, ...) callconv(.c) c_int;

pub export fn fprintHex(f: *anyopaque, pbData: [*]const u8, cbData: usize) callconv(.c) void {
    for (0..cbData) |i| {
        _ = fprintf(f, "%02x", @as(c_uint, pbData[i]));
    }
    _ = fprintf(f, "\n");
}

pub export fn ReverseMemCopy(pbDst: [*]u8, pbSrc: [*]const u8, cbSrc: usize) callconv(.c) void {
    for (0..cbSrc) |i| {
        pbDst[cbSrc - 1 - i] = pbSrc[i];
    }
}
