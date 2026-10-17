//
// env.zig
// Platform-specific environment implementations:
// - Generic (env_generic.c)
// - Posix UserMode (env_posixUserMode.c)
// - Windows UserMode Win8.1+ (env_windowsUserModeWin8_1.c)
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

const builtin = @import("builtin");
const types = @import("types.zig");
const macros = @import("macros.zig");
const libmain = @import("libmain.zig");
const cpuid = @import("cpuid.zig");

pub extern fn SymCryptFatalIntercept(fatalCode: types.UINT32) callconv(types.SYMCRYPT_CALL) void;

inline fn executeCpuidEx(cpuInfo: *[4]c_int, function_id: c_int, subfunction_id: c_int) void {
    var eax: u32 = undefined;
    var ebx: u32 = undefined;
    var ecx: u32 = undefined;
    var edx: u32 = undefined;
    asm volatile ("cpuid"
        : [eax] "={eax}" (eax),
          [ebx] "={ebx}" (ebx),
          [ecx] "={ecx}" (ecx),
          [edx] "={edx}" (edx),
        : [fn_id] "{eax}" (@as(u32, @bitCast(function_id))),
          [sub_id] "{ecx}" (@as(u32, @bitCast(subfunction_id))),
    );
    cpuInfo[0] = @bitCast(eax);
    cpuInfo[1] = @bitCast(ebx);
    cpuInfo[2] = @bitCast(ecx);
    cpuInfo[3] = @bitCast(edx);
}

inline fn forceNullWrite(fatalCode: types.UINT32) void {
    const null_ptr: *allowzero volatile types.UINT32 = @ptrFromInt(0);
    null_ptr.* = fatalCode;
}

// ==============================================================================================
// Generic Environment (env_generic.c)
// ==============================================================================================

pub export fn SymCryptCpuFeaturesNeverPresentEnvGeneric() callconv(types.SYMCRYPT_CALL) types.SYMCRYPT_CPU_FEATURES {
    if (types.CPU_X86 or types.CPU_AMD64) {
        return ~(types.SYMCRYPT_CPU_FEATURE_RDRAND | types.SYMCRYPT_CPU_FEATURE_RDSEED);
    } else {
        return ~@as(types.SYMCRYPT_CPU_FEATURES, 0);
    }
}

pub export fn SymCryptInitEnvGeneric(version: types.UINT32) callconv(types.SYMCRYPT_CALL) void {
    if ((libmain.g_SymCryptFlags & types.SYMCRYPT_FLAG_LIB_INITIALIZED) != 0) {
        return;
    }

    if (types.CPU_X86 or types.CPU_AMD64) {
        cpuid.SymCryptDetectCpuFeaturesByCpuid(0);
    }

    libmain.SymCryptInitEnvCommon(version);
}

pub export fn SymCryptFatalEnvGeneric(fatalCode: types.UINT32) callconv(types.SYMCRYPT_CALL) noreturn {
    var fatalCodeVar: types.UINT32 = 0;

    SymCryptFatalIntercept(fatalCode);
    macros.SYMCRYPT_FORCE_WRITE32(&fatalCodeVar, fatalCode);
    forceNullWrite(fatalCode);
    libmain.SymCryptFatalHang(fatalCode);
}

pub export fn SymCryptTestInjectErrorEnvGeneric(
    pbBuf: ?[*]types.BYTE,
    cbBuf: types.SIZE_T,
) callconv(types.SYMCRYPT_CALL) void {
    _ = pbBuf;
    _ = cbBuf;
}

pub fn SymCryptSaveXmmEnvGeneric(pSaveArea: ?*anyopaque) callconv(types.SYMCRYPT_CALL) types.SYMCRYPT_ERROR {
    _ = pSaveArea;
    macros.SymCryptFatal(macros.multiCharConstant("mmxs"));
    return .SYMCRYPT_EXTERNAL_FAILURE;
}

pub fn SymCryptRestoreXmmEnvGeneric(pSaveArea: ?*anyopaque) callconv(types.SYMCRYPT_CALL) void {
    _ = pSaveArea;
    macros.SymCryptFatal(macros.multiCharConstant("mmxs"));
}

pub fn SymCryptSaveYmmEnvGeneric(pSaveArea: ?*anyopaque) callconv(types.SYMCRYPT_CALL) types.SYMCRYPT_ERROR {
    _ = pSaveArea;
    macros.SymCryptFatal(macros.multiCharConstant("mmys"));
    return .SYMCRYPT_EXTERNAL_FAILURE;
}

pub fn SymCryptRestoreYmmEnvGeneric(pSaveArea: ?*anyopaque) callconv(types.SYMCRYPT_CALL) void {
    _ = pSaveArea;
    macros.SymCryptFatal(macros.multiCharConstant("mmxs"));
}

pub fn SymCryptSaveZmmEnvGeneric(pSaveArea: ?*anyopaque) callconv(types.SYMCRYPT_CALL) types.SYMCRYPT_ERROR {
    _ = pSaveArea;
    macros.SymCryptFatal(macros.multiCharConstant("mmzs"));
    return .SYMCRYPT_EXTERNAL_FAILURE;
}

pub fn SymCryptRestoreZmmEnvGeneric(pSaveArea: ?*anyopaque) callconv(types.SYMCRYPT_CALL) void {
    _ = pSaveArea;
    macros.SymCryptFatal(macros.multiCharConstant("mmzs"));
}

pub fn SymCryptCpuidExFuncEnvGeneric(
    cpuInfo: *[4]c_int,
    function_id: c_int,
    subfunction_id: c_int,
) callconv(types.SYMCRYPT_CALL) void {
    executeCpuidEx(cpuInfo, function_id, subfunction_id);
}

comptime {
    if (types.CPU_AMD64 or types.CPU_X86) {
        @export(&SymCryptSaveXmmEnvGeneric, .{ .name = "SymCryptSaveXmmEnvGeneric" });
        @export(&SymCryptRestoreXmmEnvGeneric, .{ .name = "SymCryptRestoreXmmEnvGeneric" });
        @export(&SymCryptSaveYmmEnvGeneric, .{ .name = "SymCryptSaveYmmEnvGeneric" });
        @export(&SymCryptRestoreYmmEnvGeneric, .{ .name = "SymCryptRestoreYmmEnvGeneric" });
        @export(&SymCryptSaveZmmEnvGeneric, .{ .name = "SymCryptSaveZmmEnvGeneric" });
        @export(&SymCryptRestoreZmmEnvGeneric, .{ .name = "SymCryptRestoreZmmEnvGeneric" });
        @export(&SymCryptCpuidExFuncEnvGeneric, .{ .name = "SymCryptCpuidExFuncEnvGeneric" });
    }
}

// ==============================================================================================
// Posix UserMode Environment (env_posixUserMode.c)
// ==============================================================================================

pub fn SymCryptCpuFeaturesNeverPresentEnvPosixUsermode() callconv(types.SYMCRYPT_CALL) types.SYMCRYPT_CPU_FEATURES {
    return 0;
}

pub fn SymCryptInitEnvPosixUsermode(version: types.UINT32) callconv(types.SYMCRYPT_CALL) void {
    if ((libmain.g_SymCryptFlags & types.SYMCRYPT_FLAG_LIB_INITIALIZED) != 0) {
        return;
    }

    if (types.CPU_X86 or types.CPU_AMD64) {
        cpuid.SymCryptDetectCpuFeaturesByCpuid(cpuid.SYMCRYPT_CPUID_DETECT_FLAG_CHECK_OS_SUPPORT_FOR_YMM);

        libmain.g_SymCryptCpuFeaturesNotPresent &= ~types.SYMCRYPT_CPU_FEATURE_SAVEXMM_NOFAIL;
        libmain.g_SymCryptCpuFeaturesNotPresent &= ~types.SYMCRYPT_CPU_FEATURE_SAVEYMM_NOFAIL;
        libmain.g_SymCryptCpuFeaturesNotPresent &= ~types.SYMCRYPT_CPU_FEATURE_SAVEZMM_NOFAIL;
    } else if (types.CPU_ARM) {
        libmain.g_SymCryptCpuFeaturesNotPresent = ~types.SYMCRYPT_CPU_FEATURE_NEON;
    } else if (types.CPU_ARM64) {
        cpuid.SymCryptDetectCpuFeaturesFromIsProcessorFeaturePresent();
    }

    libmain.SymCryptInitEnvCommon(version);
}

pub fn SymCryptFatalEnvPosixUsermode(fatalCode: types.UINT32) callconv(types.SYMCRYPT_CALL) noreturn {
    var fatalCodeVar: types.UINT32 = 0;

    SymCryptFatalIntercept(fatalCode);
    macros.SYMCRYPT_FORCE_WRITE32(&fatalCodeVar, fatalCode);
    forceNullWrite(fatalCode);
    libmain.SymCryptFatalHang(fatalCode);
}

pub fn SymCryptSaveXmmEnvPosixUsermode(pSaveData: ?*anyopaque) callconv(types.SYMCRYPT_CALL) types.SYMCRYPT_ERROR {
    _ = pSaveData;
    return .SYMCRYPT_NO_ERROR;
}

pub fn SymCryptRestoreXmmEnvPosixUsermode(pSaveData: ?*anyopaque) callconv(types.SYMCRYPT_CALL) void {
    _ = pSaveData;
}

pub fn SymCryptSaveYmmEnvPosixUsermode(pSaveData: ?*anyopaque) callconv(types.SYMCRYPT_CALL) types.SYMCRYPT_ERROR {
    _ = pSaveData;
    return .SYMCRYPT_NO_ERROR;
}

pub fn SymCryptRestoreYmmEnvPosixUsermode(pSaveData: ?*anyopaque) callconv(types.SYMCRYPT_CALL) void {
    _ = pSaveData;
}

pub fn SymCryptSaveZmmEnvPosixUsermode(pSaveData: ?*anyopaque) callconv(types.SYMCRYPT_CALL) types.SYMCRYPT_ERROR {
    _ = pSaveData;
    return .SYMCRYPT_NO_ERROR;
}

pub fn SymCryptRestoreZmmEnvPosixUsermode(pSaveData: ?*anyopaque) callconv(types.SYMCRYPT_CALL) void {
    _ = pSaveData;
}

pub fn SymCryptCpuidExFuncEnvPosixUsermode(
    cpuInfo: *[4]c_int,
    function_id: c_int,
    subfunction_id: c_int,
) callconv(types.SYMCRYPT_CALL) void {
    executeCpuidEx(cpuInfo, function_id, subfunction_id);
}

pub fn SymCryptTestInjectErrorEnvPosixUsermode(
    pbBuf: ?[*]types.BYTE,
    cbBuf: types.SIZE_T,
) callconv(types.SYMCRYPT_CALL) void {
    _ = pbBuf;
    _ = cbBuf;
}

comptime {
    if (builtin.os.tag != .windows) {
        @export(&SymCryptCpuFeaturesNeverPresentEnvPosixUsermode, .{ .name = "SymCryptCpuFeaturesNeverPresentEnvPosixUsermode" });
        @export(&SymCryptInitEnvPosixUsermode, .{ .name = "SymCryptInitEnvPosixUsermode" });
        @export(&SymCryptFatalEnvPosixUsermode, .{ .name = "SymCryptFatalEnvPosixUsermode" });
        @export(&SymCryptTestInjectErrorEnvPosixUsermode, .{ .name = "SymCryptTestInjectErrorEnvPosixUsermode" });

        if (types.CPU_AMD64 or types.CPU_X86) {
            @export(&SymCryptSaveXmmEnvPosixUsermode, .{ .name = "SymCryptSaveXmmEnvPosixUsermode" });
            @export(&SymCryptRestoreXmmEnvPosixUsermode, .{ .name = "SymCryptRestoreXmmEnvPosixUsermode" });
            @export(&SymCryptSaveYmmEnvPosixUsermode, .{ .name = "SymCryptSaveYmmEnvPosixUsermode" });
            @export(&SymCryptRestoreYmmEnvPosixUsermode, .{ .name = "SymCryptRestoreYmmEnvPosixUsermode" });
            @export(&SymCryptSaveZmmEnvPosixUsermode, .{ .name = "SymCryptSaveZmmEnvPosixUsermode" });
            @export(&SymCryptRestoreZmmEnvPosixUsermode, .{ .name = "SymCryptRestoreZmmEnvPosixUsermode" });
            @export(&SymCryptCpuidExFuncEnvPosixUsermode, .{ .name = "SymCryptCpuidExFuncEnvPosixUsermode" });
        }
    }
}

// ==============================================================================================
// Windows UserMode Win8.1+ Environment (env_windowsUserModeWin8_1.c)
// ==============================================================================================

const FAST_FAIL_CRYPTO_LIBRARY: u32 = 22;
const XSTATE_MASK_AVX: u64 = 4;
const XSTATE_MASK_AVX512: u64 = 0xe0;

extern "kernel32" fn GetEnabledXStateFeatures() callconv(.winapi) u64;
extern "kernel32" fn GetCurrentProcess() callconv(.winapi) ?*anyopaque;
extern "kernel32" fn TerminateProcess(hProcess: ?*anyopaque, uExitCode: u32) callconv(.winapi) c_int;

inline fn fastfail(code: u32) void {
    switch (builtin.cpu.arch) {
        .x86, .x86_64 => {
            asm volatile ("int $0x29"
                :
                : [code] "{ecx}" (code),
            );
        },
        .aarch64 => {
            asm volatile ("brk #0xf003"
                :
                : [code] "{x0}" (@as(u64, code)),
            );
        },
        .arm => {
            asm volatile ("udf #0xfb"
                :
                : [code] "{r0}" (code),
            );
        },
        else => {},
    }
}

pub fn SymCryptCpuFeaturesNeverPresentEnvWindowsUsermodeWin8_1nLater() callconv(types.SYMCRYPT_CALL) types.SYMCRYPT_CPU_FEATURES {
    return 0;
}

pub fn SymCryptInitEnvWindowsUsermodeWin8_1nLater(version: types.UINT32) callconv(types.SYMCRYPT_CALL) void {
    if ((libmain.g_SymCryptFlags & types.SYMCRYPT_FLAG_LIB_INITIALIZED) != 0) {
        return;
    }

    if (types.CPU_X86 or types.CPU_AMD64) {
        cpuid.SymCryptDetectCpuFeaturesByCpuid(cpuid.SYMCRYPT_CPUID_DETECT_FLAG_CHECK_OS_SUPPORT_FOR_YMM);

        const featureMask = GetEnabledXStateFeatures();
        if ((featureMask & XSTATE_MASK_AVX) == 0) {
            libmain.g_SymCryptCpuFeaturesNotPresent |= types.SYMCRYPT_CPU_FEATURE_AVX2;
        }
        if ((featureMask & XSTATE_MASK_AVX512) == 0) {
            libmain.g_SymCryptCpuFeaturesNotPresent |= types.SYMCRYPT_CPU_FEATURE_AVX512;
        }

        libmain.g_SymCryptCpuFeaturesNotPresent &= ~types.SYMCRYPT_CPU_FEATURE_SAVEXMM_NOFAIL;
        libmain.g_SymCryptCpuFeaturesNotPresent &= ~types.SYMCRYPT_CPU_FEATURE_SAVEYMM_NOFAIL;
        libmain.g_SymCryptCpuFeaturesNotPresent &= ~types.SYMCRYPT_CPU_FEATURE_SAVEZMM_NOFAIL;
    } else if (types.CPU_ARM) {
        libmain.g_SymCryptCpuFeaturesNotPresent = ~types.SYMCRYPT_CPU_FEATURE_NEON;
    } else if (types.CPU_ARM64) {
        cpuid.SymCryptDetectCpuFeaturesFromIsProcessorFeaturePresent();
    }

    libmain.SymCryptInitEnvCommon(version);
}

pub fn SymCryptFatalEnvWindowsUsermodeWin8_1nLater(fatalCode: types.UINT32) callconv(types.SYMCRYPT_CALL) noreturn {
    var fatalCodeVar: types.UINT32 = 0;

    SymCryptFatalIntercept(fatalCode);
    macros.SYMCRYPT_FORCE_WRITE32(&fatalCodeVar, fatalCode);
    fastfail(FAST_FAIL_CRYPTO_LIBRARY);
    forceNullWrite(fatalCode);
    _ = TerminateProcess(GetCurrentProcess(), fatalCode);
    libmain.SymCryptFatalHang(fatalCode);
}

pub fn SymCryptSaveXmmEnvWindowsUsermodeWin8_1nLater(pSaveArea: ?*anyopaque) callconv(types.SYMCRYPT_CALL) types.SYMCRYPT_ERROR {
    _ = pSaveArea;
    return .SYMCRYPT_NO_ERROR;
}

pub fn SymCryptRestoreXmmEnvWindowsUsermodeWin8_1nLater(pSaveArea: ?*anyopaque) callconv(types.SYMCRYPT_CALL) void {
    _ = pSaveArea;
}

pub fn SymCryptSaveYmmEnvWindowsUsermodeWin8_1nLater(pSaveArea: ?*anyopaque) callconv(types.SYMCRYPT_CALL) types.SYMCRYPT_ERROR {
    _ = pSaveArea;
    return .SYMCRYPT_NO_ERROR;
}

pub fn SymCryptRestoreYmmEnvWindowsUsermodeWin8_1nLater(pSaveArea: ?*anyopaque) callconv(types.SYMCRYPT_CALL) void {
    _ = pSaveArea;
}

pub fn SymCryptSaveZmmEnvWindowsUsermodeWin8_1nLater(pSaveArea: ?*anyopaque) callconv(types.SYMCRYPT_CALL) types.SYMCRYPT_ERROR {
    _ = pSaveArea;
    return .SYMCRYPT_NO_ERROR;
}

pub fn SymCryptRestoreZmmEnvWindowsUsermodeWin8_1nLater(pSaveArea: ?*anyopaque) callconv(types.SYMCRYPT_CALL) void {
    _ = pSaveArea;
}

pub fn SymCryptTestInjectErrorEnvWindowsUsermodeWin8_1nLater(
    pbBuf: ?[*]types.BYTE,
    cbBuf: types.SIZE_T,
) callconv(types.SYMCRYPT_CALL) void {
    _ = pbBuf;
    _ = cbBuf;
}

pub fn SymCryptCpuidExFuncEnvWindowsUsermodeWin8_1nLater(
    cpuInfo: *[4]c_int,
    function_id: c_int,
    subfunction_id: c_int,
) callconv(types.SYMCRYPT_CALL) void {
    executeCpuidEx(cpuInfo, function_id, subfunction_id);
}

comptime {
    if (builtin.os.tag == .windows) {
        @export(&SymCryptCpuFeaturesNeverPresentEnvWindowsUsermodeWin8_1nLater, .{ .name = "SymCryptCpuFeaturesNeverPresentEnvWindowsUsermodeWin8_1nLater" });
        @export(&SymCryptInitEnvWindowsUsermodeWin8_1nLater, .{ .name = "SymCryptInitEnvWindowsUsermodeWin8_1nLater" });
        @export(&SymCryptFatalEnvWindowsUsermodeWin8_1nLater, .{ .name = "SymCryptFatalEnvWindowsUsermodeWin8_1nLater" });
        @export(&SymCryptTestInjectErrorEnvWindowsUsermodeWin8_1nLater, .{ .name = "SymCryptTestInjectErrorEnvWindowsUsermodeWin8_1nLater" });

        if (types.CPU_AMD64 or types.CPU_X86) {
            @export(&SymCryptSaveXmmEnvWindowsUsermodeWin8_1nLater, .{ .name = "SymCryptSaveXmmEnvWindowsUsermodeWin8_1nLater" });
            @export(&SymCryptRestoreXmmEnvWindowsUsermodeWin8_1nLater, .{ .name = "SymCryptRestoreXmmEnvWindowsUsermodeWin8_1nLater" });
            @export(&SymCryptSaveYmmEnvWindowsUsermodeWin8_1nLater, .{ .name = "SymCryptSaveYmmEnvWindowsUsermodeWin8_1nLater" });
            @export(&SymCryptRestoreYmmEnvWindowsUsermodeWin8_1nLater, .{ .name = "SymCryptRestoreYmmEnvWindowsUsermodeWin8_1nLater" });
            @export(&SymCryptSaveZmmEnvWindowsUsermodeWin8_1nLater, .{ .name = "SymCryptSaveZmmEnvWindowsUsermodeWin8_1nLater" });
            @export(&SymCryptRestoreZmmEnvWindowsUsermodeWin8_1nLater, .{ .name = "SymCryptRestoreZmmEnvWindowsUsermodeWin8_1nLater" });
            @export(&SymCryptCpuidExFuncEnvWindowsUsermodeWin8_1nLater, .{ .name = "SymCryptCpuidExFuncEnvWindowsUsermodeWin8_1nLater" });
        }
    }
}
