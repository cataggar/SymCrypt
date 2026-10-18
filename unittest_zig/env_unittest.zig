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

threadlocal var t_ymmStartState: [16 * 32]u8 align(32) = @splat(0);
threadlocal var t_ymmTestState: [16 * 32]u8 align(32) = @splat(0);
// Extra space in ZMM buffers for k0-k7 mask registers (8 * 8 bytes = one extra 64-byte slot)
threadlocal var t_zmmStartState: [33 * 64]u8 align(64) = @splat(0);
threadlocal var t_zmmTestState: [33 * 64]u8 align(64) = @splat(0);

inline fn rdtsc() u64 {
    if (comptime is_amd64_asm) {
        var low: u32 = undefined;
        var high: u32 = undefined;
        asm volatile ("rdtsc"
            : [low] "={eax}" (low),
              [high] "={edx}" (high),
        );
        return (@as(u64, high) << 32) | @as(u64, low);
    }
    return 0;
}

pub export fn verifyVectorRegisters() callconv(.c) void {
    if (comptime is_amd64_asm) {
        if (TestSaveZmmEnabled != 0 and cpuFeaturesPresent(SYMCRYPT_CPU_FEATURE_AVX512)) {
            SymCryptEnvUmSaveZmmRegistersAsm(&t_zmmTestState);

            var i: usize = 16 * 64;
            while (i < 32 * 64) : (i += 1) {
                if (t_zmmStartState[i] != t_zmmTestState[i]) {
                    h.fatal("Zmm registers modified without proper save/restore Zmm{d}[{d}]", .{ i / 64, i % 64 });
                }
            }

            i = 0;
            while (i < 8 * 8) : (i += 1) {
                if (t_zmmStartState[32 * 64 + i] != t_zmmTestState[32 * 64 + i]) {
                    h.fatal("Mask register modified without proper save/restore k{d}[{d}]", .{ i / 8, i % 8 });
                }
            }
        } else if (TestSaveYmmEnabled != 0 and cpuFeaturesPresent(SYMCRYPT_CPU_FEATURE_AVX2)) {
            SymCryptEnvUmSaveYmmRegistersAsm(&t_ymmTestState);

            for (0..t_ymmStartState.len) |i| {
                if (t_ymmStartState[i] != t_ymmTestState[i] and ((i & 16) == 16)) {
                    h.fatal("Ymm registers modified without proper save/restore Ymm{d}[{d}]", .{ i >> 5, i & 31 });
                }
            }
        }
    }
}

pub export fn initVectorRegisters() callconv(.c) void {
    if (comptime is_amd64_asm) {
        if (TestSaveZmmEnabled != 0 and cpuFeaturesPresent(SYMCRYPT_CPU_FEATURE_AVX512)) {
            @memset(&t_zmmTestState, 17);
            const fill: u8 = @as(u8, @truncate(rdtsc())) ^ 0x42;
            @memset(&t_zmmStartState, fill);
            SymCryptEnvUmRestoreZmmRegistersAsm(&t_zmmStartState);
            verifyVectorRegisters();
        } else if (TestSaveYmmEnabled != 0) {
            @memset(&t_ymmTestState, 17);
            const fill: u8 = @as(u8, @truncate(rdtsc())) ^ 0x42;
            @memset(&t_ymmStartState, fill);
            SymCryptEnvUmRestoreYmmRegistersAsm(&t_ymmStartState);
            verifyVectorRegisters();
        }
    }
}

pub export fn cleanVectorRegisters() callconv(.c) void {
    if (comptime is_amd64_asm) {
        if (!cpuFeaturesPresent(SYMCRYPT_CPU_FEATURE_AVX2)) {
            return;
        }
        var zero_ymm: [16 * 32]u8 align(32) = @splat(0);
        SymCryptEnvUmRestoreYmmRegistersAsm(&zero_ymm);
    }
}

const SYMCRYPT_NO_ERROR: u32 = 0;
const SYMCRYPT_EXTERNAL_FAILURE: u32 = 0x8015;
const SYMCRYPT_SAVE_YMM_FAIL_PROB: u64 = 31;
const SYMCRYPT_SAVE_ZMM_FAIL_PROB: u64 = 31;

threadlocal var t_saveInProgressTypes: [16]u8 = @splat(0);
threadlocal var t_savesInProgress: usize = 0;
threadlocal var t_savePtrs: [16]?*anyopaque = @splat(null);

const YmmSaveDataRegs = extern struct {
    ymm: [16 * 32]u8 align(32),
    magic: usize,
};

const YmmSaveData = extern struct {
    pRegs: ?*YmmSaveDataRegs,
    magic: usize,
};

const ZmmSaveDataRegs = extern struct {
    zmm: [32 * 64]u8 align(64),
    kmask: [8]u64,
    magic: usize,
};

const ZmmSaveData = extern struct {
    pRegs: ?*ZmmSaveDataRegs,
    magic: usize,
};

fn mallocAlign(comptime alignment: usize, size: usize) ?[*]align(alignment) u8 {
    const raw = std.c.malloc(size + 8 + (alignment - 1)) orelse return null;
    const base_addr = @intFromPtr(raw);
    const aligned_addr = (base_addr + 8 + (alignment - 1)) & ~(alignment - 1);
    const prev_ptr: *usize = @ptrFromInt(aligned_addr - 8);
    prev_ptr.* = base_addr;
    return @ptrFromInt(aligned_addr);
}

fn freeAlign(comptime alignment: usize, p: *anyopaque) void {
    const addr = @intFromPtr(p);
    h.check((addr & (alignment - 1)) == 0, "?");
    const prev_ptr: *const usize = @ptrFromInt(addr - 8);
    std.c.free(@ptrFromInt(prev_ptr.*));
}

inline fn computeMagic(ptr: anytype) usize {
    return @intFromPtr(ptr) +% (@as(usize, multiCharConstant("S1mv")) +% @as(usize, SYMCRYPT_API_VERSION));
}

pub export fn SymCryptSaveXmmEnvUnittest(pSaveData: ?*anyopaque) callconv(.c) u32 {
    _ = pSaveData;
    return SYMCRYPT_NO_ERROR;
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
        const p: *YmmSaveData = @ptrCast(@alignCast(pSaveDataPtr.?));
        h.check(cpuFeaturesPresent(SYMCRYPT_CPU_FEATURE_AVX2), "?");

        if (TestSaveYmmEnabled != 0) {
            if ((rdtsc() % SYMCRYPT_SAVE_YMM_FAIL_PROB) == 0) {
                return SYMCRYPT_EXTERNAL_FAILURE;
            }

            var regs: [16 * 32]u8 align(32) = undefined;
            SymCryptEnvUmSaveYmmRegistersAsm(&regs);

            const mem = mallocAlign(32, @sizeOf(YmmSaveDataRegs)) orelse return SYMCRYPT_EXTERNAL_FAILURE;
            const pRegs: *YmmSaveDataRegs = @ptrCast(mem);
            @memcpy(&pRegs.ymm, &regs);
            pRegs.magic = computeMagic(pRegs);
            p.pRegs = pRegs;
            p.magic = computeMagic(p);

            h.check(t_savesInProgress < t_saveInProgressTypes.len, "Too many nested saves!");
            t_saveInProgressTypes[t_savesInProgress] = 'Y';
            t_savePtrs[t_savesInProgress] = pSaveDataPtr;
            t_savesInProgress += 1;
        }
    }
    return SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptSaveYmm(pSaveDataPtr: ?*anyopaque) callconv(.c) u32 {
    return SymCryptSaveYmmEnvUnittest(pSaveDataPtr);
}

pub export fn SymCryptRestoreYmmEnvUnittest(pSaveDataPtr: ?*anyopaque) callconv(.c) void {
    if (comptime is_amd64_asm) {
        const p: *YmmSaveData = @ptrCast(@alignCast(pSaveDataPtr.?));
        h.check(cpuFeaturesPresent(SYMCRYPT_CPU_FEATURE_AVX2), "?");

        if (TestSaveYmmEnabled != 0) {
            h.check(p.magic == computeMagic(p), "SaveData magic mismatch");
            const pRegs = p.pRegs.?;
            h.check(pRegs.magic == computeMagic(pRegs), "SaveDataRegs magic mismatch");

            h.check(t_savesInProgress > 0, "No saves in progress!");
            t_savesInProgress -= 1;
            h.check(t_saveInProgressTypes[t_savesInProgress] == 'Y', "YMM not saved");
            h.check(t_savePtrs[t_savesInProgress] == pSaveDataPtr, "?");

            var regs: [16 * 32]u8 align(32) = undefined;
            @memcpy(&regs, &pRegs.ymm);
            pRegs.magic = 0;
            freeAlign(32, pRegs);
            p.pRegs = null;
            p.magic = 0;

            SymCryptEnvUmRestoreYmmRegistersAsm(&regs);
        }
    }
}

pub export fn SymCryptRestoreYmm(pSaveDataPtr: ?*anyopaque) callconv(.c) void {
    SymCryptRestoreYmmEnvUnittest(pSaveDataPtr);
}

pub export fn SymCryptSaveZmmEnvUnittest(pSaveDataPtr: ?*anyopaque) callconv(.c) u32 {
    if (comptime is_amd64_asm) {
        const p: *ZmmSaveData = @ptrCast(@alignCast(pSaveDataPtr.?));
        h.check(cpuFeaturesPresent(SYMCRYPT_CPU_FEATURE_AVX512), "?");

        if (TestSaveZmmEnabled == 0 and TestSaveYmmEnabled != 0) {
            return SYMCRYPT_EXTERNAL_FAILURE;
        }

        if (TestSaveZmmEnabled != 0) {
            if ((rdtsc() % SYMCRYPT_SAVE_ZMM_FAIL_PROB) == 0) {
                return SYMCRYPT_EXTERNAL_FAILURE;
            }

            var regs: [33 * 64]u8 align(64) = undefined;
            SymCryptEnvUmSaveZmmRegistersAsm(&regs);

            const mem = mallocAlign(64, @sizeOf(ZmmSaveDataRegs)) orelse return SYMCRYPT_EXTERNAL_FAILURE;
            const pRegs: *ZmmSaveDataRegs = @ptrCast(mem);
            @memcpy(&pRegs.zmm, regs[0 .. 32 * 64]);
            @memcpy(std.mem.asBytes(&pRegs.kmask), regs[32 * 64 ..][0 .. 8 * 8]);
            pRegs.magic = computeMagic(pRegs);
            p.pRegs = pRegs;
            p.magic = computeMagic(p);

            h.check(t_savesInProgress < t_saveInProgressTypes.len, "Too many nested saves!");
            t_saveInProgressTypes[t_savesInProgress] = 'Z';
            t_savePtrs[t_savesInProgress] = pSaveDataPtr;
            t_savesInProgress += 1;
        }
    }
    return SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptSaveZmm(pSaveDataPtr: ?*anyopaque) callconv(.c) u32 {
    return SymCryptSaveZmmEnvUnittest(pSaveDataPtr);
}

pub export fn SymCryptRestoreZmmEnvUnittest(pSaveDataPtr: ?*anyopaque) callconv(.c) void {
    if (comptime is_amd64_asm) {
        const p: *ZmmSaveData = @ptrCast(@alignCast(pSaveDataPtr.?));
        h.check(cpuFeaturesPresent(SYMCRYPT_CPU_FEATURE_AVX512), "?");

        if (TestSaveZmmEnabled != 0) {
            h.check(p.magic == computeMagic(p), "SaveData magic mismatch");
            const pRegs = p.pRegs.?;
            h.check(pRegs.magic == computeMagic(pRegs), "SaveDataRegs magic mismatch");

            h.check(t_savesInProgress > 0, "No saves in progress!");
            t_savesInProgress -= 1;
            h.check(t_saveInProgressTypes[t_savesInProgress] == 'Z', "ZMM not saved");
            h.check(t_savePtrs[t_savesInProgress] == pSaveDataPtr, "?");

            var regs: [33 * 64]u8 align(64) = undefined;
            @memcpy(regs[0 .. 32 * 64], &pRegs.zmm);
            @memcpy(regs[32 * 64 ..][0 .. 8 * 8], std.mem.asBytes(&pRegs.kmask));
            pRegs.magic = 0;
            freeAlign(64, pRegs);
            p.pRegs = null;
            p.magic = 0;

            SymCryptEnvUmRestoreZmmRegistersAsm(&regs);
        }
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
                const ptr_to_ptr: *const ?*anyopaque = @ptrCast(@alignCast(symbolPointer));
                return ptr_to_ptr.*;
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
