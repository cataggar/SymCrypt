// Copyright (c) Microsoft Corporation. Licensed under the MIT license.

const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");
const h = @import("main_harness.zig");
const cpp_bridge = @import("cpp_bridge.zig");

const SYMCRYPT_API_VERSION: u32 = (@as(u32, @intCast(build_options.symcrypt_version.major)) << 16) |
    @as(u32, @intCast(build_options.symcrypt_version.minor));

const SYMCRYPT_FLAG_LIB_INITIALIZED: u32 = 1;

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
const SYMCRYPT_CPU_FEATURE_SAVEYMM_NOFAIL: u32 = 0x4000;
const SYMCRYPT_CPU_FEATURE_SAVEZMM_NOFAIL: u32 = 0x8000;

const SYMCRYPT_CPU_FEATURE_NEON: u32 = 0x01;

const SYMCRYPT_CPUID_DETECT_FLAG_CHECK_OS_SUPPORT_FOR_YMM: u32 = 1;

pub const SCTEST_DYNSYM_FUNCTION_PTR: u32 = 1;
pub const SCTEST_DYNSYM_DATA_PTR: u32 = 2;
pub const SCTEST_DYNSYM_ARRAY: u32 = 3;

const is_amd64_asm = (builtin.cpu.arch == .x86_64) and build_options.use_asm;
const is_x86_or_amd64_asm = (builtin.cpu.arch == .x86 or builtin.cpu.arch == .x86_64) and build_options.use_asm;
const is_arm64_asm = (builtin.cpu.arch == .aarch64) and build_options.use_asm;
const is_arm_asm = (builtin.cpu.arch == .arm) and build_options.use_asm;

pub export const g_SymCryptInformativeProductString: [26:0]u8 = "SymCrypt_Unittest_103.12.0".*;

pub export var TestSaveXmmEnabled: u8 = 0;
pub export var TestSaveYmmEnabled: u8 = 0;
pub export var TestSaveZmmEnabled: u8 = 0;

pub export var TestSelftestsEnabled: u8 = 0;
pub export var TestFatalCount: u64 = 0;
pub export var TestErrorInjectionCount: u64 = 0;
pub export var TestErrorInjectionCalls: u64 = 0;
pub export var TestErrorInjectionProb: u32 = 0;
pub export var TestErrorInjectionSeed: [20]u8 = @splat(0);

pub export var g_nSaves: u32 = 0;
pub export var SctestDisableCpuFeatures: u32 = 0;

pub export var g_implementationNames: [2:null]?[*:0]const u8 = .{ "SymCrypt", "Ref" };

extern var g_SymCryptFlags: u32;
extern var g_SymCryptCpuFeaturesNotPresent: u32;

extern fn SymCryptInitEnvCommon(version: u32) callconv(.c) void;
extern fn SymCryptSha1(pbData: ?[*]const u8, cbData: usize, pbResult: [*]u8) callconv(.c) void;
extern fn SymCryptMarvin32(pSeed: *const anyopaque, pbData: [*]const u8, cbData: usize, pbResult: [*]u8) callconv(.c) void;
extern const SymCryptMarvin32DefaultSeed: *const anyopaque;

extern fn SymCryptDetectCpuFeaturesByCpuid(flags: u32) callconv(.c) void;
extern fn SymCryptDetectCpuFeaturesFromIsProcessorFeaturePresent() callconv(.c) void;
extern fn SymCryptCpuidExFuncEnvGeneric(cpuInfo: *[4]c_int, function_id: c_int, subfunction_id: c_int) callconv(.c) void;

extern fn SymCryptEnvUmSaveYmmRegistersAsm(buffer: [*]u8) callconv(.c) void;
extern fn SymCryptEnvUmRestoreYmmRegistersAsm(buffer: [*]const u8) callconv(.c) void;
extern fn SymCryptEnvUmSaveZmmRegistersAsm(buffer: [*]u8) callconv(.c) void;
extern fn SymCryptEnvUmRestoreZmmRegistersAsm(buffer: [*]const u8) callconv(.c) void;

inline fn multiCharConstant(comptime str: *const [4]u8) u32 {
    return (@as(u32, str[0]) << 24) |
        (@as(u32, str[1]) << 16) |
        (@as(u32, str[2]) << 8) |
        @as(u32, str[3]);
}

inline fn cpuFeaturesPresent(mask: u32) bool {
    return ((mask & SymCryptCpuFeaturesNeverPresentEnvUnittest()) == 0) and
        ((mask & g_SymCryptCpuFeaturesNotPresent) == 0);
}

pub export fn SymCryptCpuFeaturesNeverPresentEnvUnittest() callconv(.c) u32 {
    return 0;
}

pub export fn SymCryptCpuFeaturesNeverPresent() callconv(.c) u32 {
    return SymCryptCpuFeaturesNeverPresentEnvUnittest();
}

pub export fn SymCryptFatalEnvUnittest(fatalCode: u32) callconv(.c) void {
    if (TestSelftestsEnabled != 0) {
        TestFatalCount += 1;
        return;
    }

    h.zprint("\n***SymCrypt fatal error ", .{});
    var codeString = true;
    for (0..4) |i| {
        const c: u8 = @truncate(fatalCode >> @intCast(8 * i));
        if (!((c >= 'a' and c <= 'z') or (c >= '0' and c <= '9'))) {
            codeString = false;
        }
    }

    if (codeString) {
        const c0: u8 = @truncate(fatalCode >> 24);
        const c1: u8 = @truncate(fatalCode >> 16);
        const c2: u8 = @truncate(fatalCode >> 8);
        const c3: u8 = @truncate(fatalCode);
        h.zprint("'{c}{c}{c}{c}'\n", .{ c0, c1, c2, c3 });
    } else {
        h.zprint("0x{x:0>8}\n", .{fatalCode});
    }

    h.printOutput(0);
    std.c.exit(@bitCast(fatalCode));
}

pub export fn SymCryptFatal(fatalCode: u32) callconv(.c) void {
    SymCryptFatalEnvUnittest(fatalCode);
}

pub export fn SymCryptTestInjectErrorEnvUnittest(pbBuf: ?[*]u8, cbBuf: usize) callconv(.c) void {
    if (TestSelftestsEnabled != 0) {
        TestErrorInjectionCalls += 1;
        if (TestErrorInjectionSeed[10] % TestErrorInjectionProb == 1) {
            const bitNo: usize = @as(usize, @truncate(std.mem.readInt(u64, TestErrorInjectionSeed[0..8], .little))) % (8 * cbBuf);
            pbBuf.?[bitNo / 8] ^= (@as(u8, 1) << @as(u3, @truncate(bitNo % 8)));

            TestErrorInjectionCount += 1;
        }
        SymCryptSha1(&TestErrorInjectionSeed, TestErrorInjectionSeed.len, &TestErrorInjectionSeed);
    }
}

pub export fn SymCryptInjectError(pbBuf: ?[*]u8, cbBuf: usize) callconv(.c) void {
    SymCryptTestInjectErrorEnvUnittest(pbBuf, cbBuf);
}

// ============================================================================
// Vector Register Verification & Save/Restore State (x86_64 ASM)
// ============================================================================

const RegistersStruct = extern struct {
    savedState: [32 * 64]u8 align(64) = @splat(0),
};

var g_Regs: RegistersStruct align(64) = .{};

pub export fn initVectorRegisters() callconv(.c) void {
    if (comptime is_amd64_asm) {
        var isZmm: bool = false;
        if (cpuFeaturesPresent(SYMCRYPT_CPU_FEATURE_AVX512)) {
            isZmm = true;
            SymCryptEnvUmSaveZmmRegistersAsm(&g_Regs.savedState);
        } else if (cpuFeaturesPresent(SYMCRYPT_CPU_FEATURE_AVX2)) {
            SymCryptEnvUmSaveYmmRegistersAsm(&g_Regs.savedState);
        } else {
            return;
        }

        const numHighVectorSubregisters: u32 = if (isZmm) (16 * 3 + 16 * 4) else 16;
        for (0..numHighVectorSubregisters) |i| {
            var buf: [2 * @sizeOf(u32)]u8 = undefined;
            std.mem.writeInt(u32, buf[0..4], @intCast(i), .little);
            std.mem.writeInt(u32, buf[4..8], @truncate(@intFromPtr(&g_Regs.savedState)), .little);
            const dest = g_Regs.savedState[i * 16 ..][0..16];
            SymCryptMarvin32(SymCryptMarvin32DefaultSeed, &buf, buf.len, dest.ptr);
            SymCryptMarvin32(SymCryptMarvin32DefaultSeed, dest.ptr, 8, dest[8..16].ptr);
        }

        if (isZmm) {
            SymCryptEnvUmRestoreZmmRegistersAsm(&g_Regs.savedState);
        } else {
            SymCryptEnvUmRestoreYmmRegistersAsm(&g_Regs.savedState);
        }
    }
}

pub export fn verifyVectorRegisters() callconv(.c) void {
    if (comptime is_amd64_asm) {
        var currentState: RegistersStruct align(64) = .{};
        if (cpuFeaturesPresent(SYMCRYPT_CPU_FEATURE_AVX512) and TestSaveZmmEnabled == 0) {
            SymCryptEnvUmSaveZmmRegistersAsm(&currentState.savedState);
            if (!std.mem.eql(u8, &currentState.savedState, &g_Regs.savedState)) {
                SymCryptFatalEnvUnittest(multiCharConstant("zmmx"));
            }
        } else if (cpuFeaturesPresent(SYMCRYPT_CPU_FEATURE_AVX2) and TestSaveYmmEnabled == 0) {
            SymCryptEnvUmSaveYmmRegistersAsm(&currentState.savedState);
            if (!std.mem.eql(u8, currentState.savedState[0..256], g_Regs.savedState[0..256])) {
                SymCryptFatalEnvUnittest(multiCharConstant("ymmx"));
            }
        }
    }
}

pub export fn cleanVectorRegisters() callconv(.c) void {
    if (comptime is_amd64_asm) {
        @memset(&g_Regs.savedState, 0);
        if (cpuFeaturesPresent(SYMCRYPT_CPU_FEATURE_AVX512)) {
            SymCryptEnvUmRestoreZmmRegistersAsm(&g_Regs.savedState);
        } else if (cpuFeaturesPresent(SYMCRYPT_CPU_FEATURE_AVX2)) {
            SymCryptEnvUmRestoreYmmRegistersAsm(&g_Regs.savedState);
        }
    }
}

const ExtendedSaveData = extern struct {
    interlock: i32 align(64),
    data: [32 * 64]u8 align(64),
    magic: usize,
};

inline fn computeMagic(ptr: anytype) usize {
    return @intFromPtr(ptr) +% (@as(usize, multiCharConstant("S1mv")) +% @as(usize, SYMCRYPT_API_VERSION));
}

pub export fn SymCryptSaveXmmEnvUnittest(pSaveData: ?*anyopaque) callconv(.c) u32 {
    _ = pSaveData;
    return 0;
}

pub export fn SymCryptSaveXmm(pSaveData: ?*anyopaque) callconv(.c) u32 {
    return SymCryptSaveXmmEnvUnittest(pSaveData);
}

pub export fn SymCryptRestoreXmmEnvUnittest(pSaveData: ?*anyopaque) callconv(.c) void {
    _ = pSaveData;
}

pub export fn SymCryptRestoreXmm(pSaveData: ?*anyopaque) callconv(.c) void {
    SymCryptRestoreXmmEnvUnittest(pSaveData);
}

pub export fn SymCryptSaveYmmEnvUnittest(pSaveDataPtr: ?*anyopaque) callconv(.c) u32 {
    if (comptime is_amd64_asm) {
        const pSaveData: *ExtendedSaveData = @ptrCast(@alignCast(pSaveDataPtr.?));
        if (!cpuFeaturesPresent(SYMCRYPT_CPU_FEATURE_AVX2)) {
            SymCryptFatalEnvUnittest(multiCharConstant("save"));
        }

        if (TestSaveYmmEnabled != 0) {
            if (@cmpxchgStrong(i32, &g_nYmmSaves, 0, 1, .seq_cst, .seq_cst) != null) {
                SymCryptFatalEnvUnittest(multiCharConstant("ymms"));
            }
            pSaveData.interlock = 0;
            SymCryptEnvUmSaveYmmRegistersAsm(&pSaveData.data);
            pSaveData.magic = computeMagic(pSaveData);
        } else {
            var currentRegs: RegistersStruct align(64) = .{};
            SymCryptEnvUmSaveYmmRegistersAsm(&currentRegs.savedState);
            if (!std.mem.eql(u8, currentRegs.savedState[0..256], g_Regs.savedState[0..256])) {
                SymCryptFatalEnvUnittest(multiCharConstant("ymmx"));
            }
            @memcpy(pSaveData.data[0..256], currentRegs.savedState[0..256]);
            pSaveData.magic = computeMagic(pSaveData);
        }

        _ = @atomicRmw(u32, &g_nSaves, .Add, 1, .seq_cst);
    }
    return 0;
}

var g_nYmmSaves: i32 = 0;
var g_nZmmSaves: i32 = 0;

pub export fn SymCryptSaveYmm(pSaveDataPtr: ?*anyopaque) callconv(.c) u32 {
    return SymCryptSaveYmmEnvUnittest(pSaveDataPtr);
}

pub export fn SymCryptRestoreYmmEnvUnittest(pSaveDataPtr: ?*anyopaque) callconv(.c) void {
    if (comptime is_amd64_asm) {
        const pSaveData: *ExtendedSaveData = @ptrCast(@alignCast(pSaveDataPtr.?));
        if (pSaveData.magic != computeMagic(pSaveData)) {
            SymCryptFatalEnvUnittest(multiCharConstant("magc"));
        }

        if (TestSaveYmmEnabled != 0) {
            if (@cmpxchgStrong(i32, &g_nYmmSaves, 1, 0, .seq_cst, .seq_cst) != null) {
                SymCryptFatalEnvUnittest(multiCharConstant("ymms"));
            }
            SymCryptEnvUmRestoreYmmRegistersAsm(&pSaveData.data);
        } else {
            if (!std.mem.eql(u8, pSaveData.data[0..256], g_Regs.savedState[0..256])) {
                SymCryptFatalEnvUnittest(multiCharConstant("ymmx"));
            }
            SymCryptEnvUmRestoreYmmRegistersAsm(&g_Regs.savedState);
        }
        pSaveData.magic = 0;
    }
}

pub export fn SymCryptRestoreYmm(pSaveDataPtr: ?*anyopaque) callconv(.c) void {
    SymCryptRestoreYmmEnvUnittest(pSaveDataPtr);
}

pub export fn SymCryptSaveZmmEnvUnittest(pSaveDataPtr: ?*anyopaque) callconv(.c) u32 {
    if (comptime is_amd64_asm) {
        const pSaveData: *ExtendedSaveData = @ptrCast(@alignCast(pSaveDataPtr.?));
        if (!cpuFeaturesPresent(SYMCRYPT_CPU_FEATURE_AVX512)) {
            SymCryptFatalEnvUnittest(multiCharConstant("save"));
        }

        if (TestSaveZmmEnabled != 0) {
            if (@cmpxchgStrong(i32, &g_nZmmSaves, 0, 1, .seq_cst, .seq_cst) != null) {
                SymCryptFatalEnvUnittest(multiCharConstant("zmms"));
            }
            pSaveData.interlock = 0;
            SymCryptEnvUmSaveZmmRegistersAsm(&pSaveData.data);
            pSaveData.magic = computeMagic(pSaveData);
        } else {
            var currentRegs: RegistersStruct align(64) = .{};
            SymCryptEnvUmSaveZmmRegistersAsm(&currentRegs.savedState);
            if (!std.mem.eql(u8, &currentRegs.savedState, &g_Regs.savedState)) {
                SymCryptFatalEnvUnittest(multiCharConstant("zmmx"));
            }
            @memcpy(&pSaveData.data, &currentRegs.savedState);
            pSaveData.magic = computeMagic(pSaveData);
        }

        _ = @atomicRmw(u32, &g_nSaves, .Add, 1, .seq_cst);
    }
    return 0;
}

pub export fn SymCryptSaveZmm(pSaveDataPtr: ?*anyopaque) callconv(.c) u32 {
    return SymCryptSaveZmmEnvUnittest(pSaveDataPtr);
}

pub export fn SymCryptRestoreZmmEnvUnittest(pSaveDataPtr: ?*anyopaque) callconv(.c) void {
    if (comptime is_amd64_asm) {
        const pSaveData: *ExtendedSaveData = @ptrCast(@alignCast(pSaveDataPtr.?));
        if (pSaveData.magic != computeMagic(pSaveData)) {
            SymCryptFatalEnvUnittest(multiCharConstant("magc"));
        }

        if (TestSaveZmmEnabled != 0) {
            if (@cmpxchgStrong(i32, &g_nZmmSaves, 1, 0, .seq_cst, .seq_cst) != null) {
                SymCryptFatalEnvUnittest(multiCharConstant("zmms"));
            }
            SymCryptEnvUmRestoreZmmRegistersAsm(&pSaveData.data);
        } else {
            if (!std.mem.eql(u8, &pSaveData.data, &g_Regs.savedState)) {
                SymCryptFatalEnvUnittest(multiCharConstant("zmmx"));
            }
            SymCryptEnvUmRestoreZmmRegistersAsm(&g_Regs.savedState);
        }
        pSaveData.magic = 0;
    }
}

pub export fn SymCryptRestoreZmm(pSaveDataPtr: ?*anyopaque) callconv(.c) void {
    SymCryptRestoreZmmEnvUnittest(pSaveDataPtr);
}

pub export fn SymCryptCpuidExFuncEnvUnittest(
    cpuInfo: *[4]c_int,
    function_id: c_int,
    subfunction_id: c_int,
) callconv(.c) void {
    if (comptime is_x86_or_amd64_asm) {
        SymCryptCpuidExFuncEnvGeneric(cpuInfo, function_id, subfunction_id);
    } else {
        cpuInfo.* = .{ 0, 0, 0, 0 };
    }
}

pub export fn SymCryptCpuidExFunc(
    cpuInfo: *[4]c_int,
    function_id: c_int,
    subfunction_id: c_int,
) callconv(.c) void {
    SymCryptCpuidExFuncEnvUnittest(cpuInfo, function_id, subfunction_id);
}

pub export fn SymCryptInitEnvUnittest(version: u32) callconv(.c) void {
    if ((g_SymCryptFlags & SYMCRYPT_FLAG_LIB_INITIALIZED) != 0) {
        return;
    }

    if (comptime is_x86_or_amd64_asm) {
        SymCryptDetectCpuFeaturesByCpuid(SYMCRYPT_CPUID_DETECT_FLAG_CHECK_OS_SUPPORT_FOR_YMM);

        g_SymCryptCpuFeaturesNotPresent &= ~SYMCRYPT_CPU_FEATURE_SAVEXMM_NOFAIL;
        g_SymCryptCpuFeaturesNotPresent &= ~SYMCRYPT_CPU_FEATURE_SAVEYMM_NOFAIL;
        g_SymCryptCpuFeaturesNotPresent &= ~SYMCRYPT_CPU_FEATURE_SAVEZMM_NOFAIL;

        initVectorRegisters();
    } else if (comptime is_arm_asm) {
        g_SymCryptCpuFeaturesNotPresent = ~SYMCRYPT_CPU_FEATURE_NEON;
    } else if (comptime is_arm64_asm) {
        SymCryptDetectCpuFeaturesFromIsProcessorFeaturePresent();
    } else {
        g_SymCryptCpuFeaturesNotPresent = ~@as(u32, 0);
    }

    g_SymCryptCpuFeaturesNotPresent |= SctestDisableCpuFeatures;

    SymCryptInitEnvCommon(version);
}

pub export fn SymCryptInit() callconv(.c) void {
    SymCryptInitEnvUnittest(SYMCRYPT_API_VERSION);
}

// ============================================================================
// Dynamic Module Loading & Entropy (from main_exe.cpp)
// ============================================================================

pub export fn loadDynamicModuleFromPath(dynamicModulePath: [*:0]const u8) callconv(.c) ?*anyopaque {
    if (comptime builtin.os.tag != .windows) {
        const hDynamicModule = std.c.dlopen(dynamicModulePath, .{ .LAZY = true });
        if (hDynamicModule == null) {
            if (std.c.dlerror()) |errStr| {
                h.zprint("dlopen failed with message: {s}\n", .{std.mem.span(errStr)});
            } else {
                h.zprint("dlopen failed\n", .{});
            }
        }
        return hDynamicModule;
    }
    return null;
}

pub export fn getDynamicSymbolPointerFromString(
    hDynamicModule: ?*anyopaque,
    pSymbolName: [*:0]const u8,
    symbolType: u32,
) callconv(.c) ?*anyopaque {
    if (comptime builtin.os.tag != .windows) {
        const symbolPointer = std.c.dlsym(hDynamicModule, pSymbolName);
        if (symbolPointer == null) {
            return null;
        }

        switch (symbolType) {
            SCTEST_DYNSYM_FUNCTION_PTR, SCTEST_DYNSYM_ARRAY => return symbolPointer,
            SCTEST_DYNSYM_DATA_PTR => {
                if (std.mem.eql(u8, std.mem.span(pSymbolName), "SymCryptMarvin32DefaultSeed")) {
                    const ptr_to_ptr: *const ?*anyopaque = @ptrCast(@alignCast(symbolPointer));
                    return ptr_to_ptr.*;
                }
                const fnPtr: *const fn () callconv(.c) ?*anyopaque = @ptrCast(@alignCast(symbolPointer));
                return fnPtr();
            },
            else => return null,
        }
    }
    return null;
}

const c_stdio = struct {
    extern "c" fn fopen(path: [*:0]const u8, mode: [*:0]const u8) ?*anyopaque;
    extern "c" fn fread(ptr: [*]u8, size: usize, nmemb: usize, stream: ?*anyopaque) usize;
    extern "c" fn fclose(stream: ?*anyopaque) c_int;
};

pub export fn oe_sgx_get_additional_host_entropy(data: [*]u8, size: usize) callconv(.c) c_int {
    if (comptime builtin.os.tag != .windows) {
        const f = c_stdio.fopen("/dev/urandom", "rb") orelse {
            SymCryptFatalEnvUnittest(multiCharConstant("rndf"));
            return 0;
        };
        defer _ = c_stdio.fclose(f);

        const bytesRead = c_stdio.fread(data, 1, size, f);
        if (bytesRead != size) {
            SymCryptFatalEnvUnittest(multiCharConstant("rndr"));
            return 0;
        }
        return 1;
    }
    return 0;
}

// ============================================================================
// Unittest Entry Point Helper (from main_exe_common.cpp)
// ============================================================================

const perf = @import("perf.zig");
const selftest = @import("test_selftest.zig");

pub export fn scTestCppMain(argc: c_int, argv: [*][*:0]u8) callconv(.c) c_int {
    h.initTestInfrastructure(argc, argv);

    cpp_bridge.addAllAlgs();

    if (h.g_profile == 0 and h.g_measure_specific_sizes == 0) {
        h.runFunctionalTests();
    }

    TestSaveXmmEnabled = 0;
    TestSaveYmmEnabled = 0;
    cleanVectorRegisters();

    if (h.g_profile != 0) {
        perf.runProfiling();
    } else {
        h.runPerfTests();

        if (h.g_measure_specific_sizes == 0) {
            selftest.testSelftest();
        }
    }

    h.exitTestInfrastructure();

    return 0;
}
