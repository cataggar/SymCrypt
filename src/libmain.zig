//
// libmain.zig
// General routines for the SymCrypt library
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

const std = @import("std");
const types = @import("types.zig");
const macros = @import("macros.zig");

// ==============================================================================================
// ASM Structure Offset Constants (matching inc/C_asm_shared.inc)
// ==============================================================================================

pub const SymCryptModulusNdigitsOffsetAmd64: usize = 4;
pub const SymCryptModulusInv64OffsetAmd64: usize = 24;
pub const SymCryptModulusValueOffsetAmd64: usize = 128;
pub const SymCryptNegDivisorSingleDigitOffsetAmd64: usize = 256;

pub const SymCryptModulusNdigitsOffsetX86: usize = 4;
pub const SymCryptModulusInv64OffsetX86: usize = 24;
pub const SymCryptModulusValueOffsetX86: usize = 96;

pub const SymCryptModulusNdigitsOffsetArm64: usize = 4;
pub const SymCryptModulusInv64OffsetArm64: usize = 24;
pub const SymCryptModulusValueOffsetArm64: usize = 128;

pub const SymCryptModulusNdigitsOffsetArm: usize = 4;
pub const SymCryptModulusInv64OffsetArm: usize = 24;
pub const SymCryptModulusValueOffsetArm: usize = 96;

// ==============================================================================================
// Global Library State & Build String
// ==============================================================================================

pub export var g_SymCryptFlags: types.UINT32 = 0;

pub export var g_SymCryptCpuFeaturesNotPresent: types.SYMCRYPT_CPU_FEATURES = ~@as(types.SYMCRYPT_CPU_FEATURES, 0);
pub export var g_SymCryptCpuFeaturesPresentCheck: types.SYMCRYPT_CPU_FEATURES = 0;

const build_string_literal: [:0]const u8 = std.fmt.comptimePrint(
    "v{d}.{d}.{d}_zig_zig-build_1970-01-01T00:00:00",
    .{
        types.CODE_VERSION_API,
        types.CODE_VERSION_MINOR,
        types.CODE_VERSION_PATCH,
    },
);

pub export const SymCryptBuildString: [*:0]const types.CHAR = build_string_literal.ptr;

pub extern fn SymCryptCpuFeaturesNeverPresent() callconv(types.SYMCRYPT_CALL) types.SYMCRYPT_CPU_FEATURES;

pub inline fn SYMCRYPT_CPU_FEATURES_PRESENT(x: types.SYMCRYPT_CPU_FEATURES) bool {
    return ((x & SymCryptCpuFeaturesNeverPresent()) == 0) and ((x & g_SymCryptCpuFeaturesNotPresent) == 0);
}

// ==============================================================================================
// Library Initialization & Fatal Hang
// ==============================================================================================

pub noinline fn SymCryptLibraryWasNotInitialized() callconv(types.SYMCRYPT_CALL) void {
    macros.SymCryptFatal(macros.multiCharConstant("init"));
}

comptime {
    if (types.DEBUG) {
        @export(&SymCryptLibraryWasNotInitialized, .{ .name = "SymCryptLibraryWasNotInitialized" });
    }
}

pub inline fn SymCryptCheckLibraryInitialized() void {
    if (types.DEBUG) {
        if ((g_SymCryptFlags & types.SYMCRYPT_FLAG_LIB_INITIALIZED) == 0) {
            SymCryptLibraryWasNotInitialized();
        }
    }
}

pub export fn SymCryptInitEnvCommon(version: types.UINT32) callconv(types.SYMCRYPT_CALL) void {
    var tmp: types.UINT32 = 0;

    if (version != types.SYMCRYPT_API_VERSION) {
        macros.SymCryptFatal(macros.multiCharConstant("apiv"));
    }

    _ = @atomicRmw(types.UINT32, &g_SymCryptFlags, .Or, types.SYMCRYPT_FLAG_LIB_INITIALIZED, .monotonic);

    macros.SYMCRYPT_FORCE_WRITE32(&tmp, types.SYMCRYPT_API_VERSION);

    var p: [*:0]const u8 = SymCryptBuildString;
    while (p[0] != 0) : (p += 1) {
        macros.SYMCRYPT_FORCE_WRITE8(&tmp, p[0]);
    }

    macros.SYMCRYPT_FORCE_WRITE32(&g_SymCryptCpuFeaturesPresentCheck, ~g_SymCryptCpuFeaturesNotPresent);
}

pub noinline fn SymCryptFatalHang(fatalCode: types.UINT32) callconv(types.SYMCRYPT_CALL) noreturn {
    var fcode: types.UINT32 = 0;
    while (true) {
        macros.SYMCRYPT_FORCE_WRITE32(&fcode, fatalCode);
    }
}

comptime {
    @export(&SymCryptFatalHang, .{ .name = "SymCryptFatalHang" });
}

// ==============================================================================================
// SymCryptWipe & SymCryptWipeKnownSize
// ==============================================================================================

extern fn SymCryptWipeAsm(pbData: types.PVOID, cbData: types.SIZE_T) callconv(types.SYMCRYPT_CALL) void;

pub export fn SymCryptWipe(pbData: types.PVOID, cbData: types.SIZE_T) callconv(types.SYMCRYPT_CALL) void {
    if (types.CPU_X86 or types.CPU_AMD64 or types.CPU_ARM or types.CPU_ARM64) {
        SymCryptWipeAsm(pbData, cbData);
    } else {
        if (cbData == 0) return;
        if (pbData) |ptr| {
            const p: [*]volatile u8 = @ptrCast(ptr);
            var i: usize = 0;
            while (i < cbData) : (i += 1) {
                p[i] = 0;
            }
        }
    }
}

pub const SYMCRYPT_WIPE_FUNCTION_LIMIT: usize = if (types.CPU_X86 or types.CPU_ARM)
    32
else if (types.CPU_AMD64 or types.CPU_ARM64)
    64
else
    0;

pub inline fn SymCryptWipeKnownSize(pbData: types.PVOID, cbData: types.SIZE_T) void {
    if (types.CPU_X86 or types.CPU_AMD64 or types.CPU_ARM or types.CPU_ARM64) {
        if (cbData > SYMCRYPT_WIPE_FUNCTION_LIMIT) {
            SymCryptWipe(pbData, cbData);
        } else if (pbData) |ptr| {
            const pb: [*]u8 = @ptrCast(ptr);
            var cb = cbData;
            if ((cb & 1) != 0) {
                cb -= 1;
                macros.SYMCRYPT_FORCE_WRITE8(pb + cb, 0);
            }
            if ((cb & 2) != 0) {
                cb -= 2;
                macros.SYMCRYPT_FORCE_WRITE16(pb + cb, 0);
            }
            if ((cb & 4) != 0) {
                cb -= 4;
                macros.SYMCRYPT_FORCE_WRITE32(pb + cb, 0);
            }
            if ((cb & 8) != 0) {
                cb -= 8;
                macros.SYMCRYPT_FORCE_WRITE64(pb + cb, 0);
            }
            if ((cb & 16) != 0) {
                cb -= 16;
                macros.SYMCRYPT_FORCE_WRITE64(pb + cb, 0);
                macros.SYMCRYPT_FORCE_WRITE64(pb + cb + 8, 0);
            }
            if ((cb & 32) != 0) {
                cb -= 32;
                macros.SYMCRYPT_FORCE_WRITE64(pb + cb, 0);
                macros.SYMCRYPT_FORCE_WRITE64(pb + cb + 8, 0);
                macros.SYMCRYPT_FORCE_WRITE64(pb + cb + 16, 0);
                macros.SYMCRYPT_FORCE_WRITE64(pb + cb + 24, 0);
            }
            if (SYMCRYPT_WIPE_FUNCTION_LIMIT >= 64) {
                if ((cb & 64) != 0) {
                    cb -= 64;
                    macros.SYMCRYPT_FORCE_WRITE64(pb + cb, 0);
                    macros.SYMCRYPT_FORCE_WRITE64(pb + cb + 8, 0);
                    macros.SYMCRYPT_FORCE_WRITE64(pb + cb + 16, 0);
                    macros.SYMCRYPT_FORCE_WRITE64(pb + cb + 24, 0);
                    macros.SYMCRYPT_FORCE_WRITE64(pb + cb + 32, 0);
                    macros.SYMCRYPT_FORCE_WRITE64(pb + cb + 40, 0);
                    macros.SYMCRYPT_FORCE_WRITE64(pb + cb + 48, 0);
                    macros.SYMCRYPT_FORCE_WRITE64(pb + cb + 56, 0);
                }
            }
        }
    } else {
        SymCryptWipe(pbData, cbData);
    }
}

// ==============================================================================================
// SymCryptXorBytes
// ==============================================================================================

pub export fn SymCryptXorBytes(
    pbSrc1_opt: ?[*]const u8,
    pbSrc2_opt: ?[*]const u8,
    pbResult_opt: ?[*]u8,
    cbBytes: types.SIZE_T,
) callconv(types.SYMCRYPT_CALL) void {
    if (cbBytes == 0) return;
    var pbSrc1 = pbSrc1_opt.?;
    var pbSrc2 = pbSrc2_opt.?;
    var pbResult = pbResult_opt.?;
    var rem = cbBytes;

    if (types.CPU_AMD64 or types.CPU_ARM64) {
        if (rem == 16) {
            const s1: [*]align(1) const u64 = @ptrCast(pbSrc1);
            const s2: [*]align(1) const u64 = @ptrCast(pbSrc2);
            const d: [*]align(1) u64 = @ptrCast(pbResult);
            d[0] = s1[0] ^ s2[0];
            d[1] = s1[1] ^ s2[1];
        } else {
            while (rem >= 8) {
                const s1: *align(1) const u64 = @ptrCast(pbSrc1);
                const s2: *align(1) const u64 = @ptrCast(pbSrc2);
                const d: *align(1) u64 = @ptrCast(pbResult);
                d.* = s1.* ^ s2.*;
                pbSrc1 += 8;
                pbSrc2 += 8;
                pbResult += 8;
                rem -= 8;
            }
            while (rem > 0) {
                pbResult[0] = pbSrc1[0] ^ pbSrc2[0];
                pbResult += 1;
                pbSrc1 += 1;
                pbSrc2 += 1;
                rem -= 1;
            }
        }
    } else if (types.CPU_X86 or types.CPU_ARM) {
        if (rem == 16) {
            const s1: [*]align(1) const u32 = @ptrCast(pbSrc1);
            const s2: [*]align(1) const u32 = @ptrCast(pbSrc2);
            const d: [*]align(1) u32 = @ptrCast(pbResult);
            d[0] = s1[0] ^ s2[0];
            d[1] = s1[1] ^ s2[1];
            d[2] = s1[2] ^ s2[2];
            d[3] = s1[3] ^ s2[3];
        } else {
            var i: usize = 0;
            while (i + 3 < rem) : (i += 4) {
                const s1: *align(1) const u32 = @ptrCast(pbSrc1 + i);
                const s2: *align(1) const u32 = @ptrCast(pbSrc2 + i);
                const d: *align(1) u32 = @ptrCast(pbResult + i);
                d.* = s1.* ^ s2.*;
            }
            while (i < rem) : (i += 1) {
                pbResult[i] = pbSrc1[i] ^ pbSrc2[i];
            }
        }
    } else {
        for (0..rem) |i| {
            pbResult[i] = pbSrc1[i] ^ pbSrc2[i];
        }
    }
}

// ==============================================================================================
// Variable-size Uint32 / Uint64 Bit/Byte Size & Load/Store Functions
// ==============================================================================================

pub export fn SymCryptUint32Bitsize(value: types.UINT32) callconv(.c) types.UINT32 {
    var v = value;
    var res: types.UINT32 = 0;
    while (v != 0) {
        res += 1;
        v >>= 1;
    }
    return res;
}

pub export fn SymCryptUint64Bitsize(value: types.UINT64) callconv(.c) types.UINT32 {
    const upper: types.UINT32 = @truncate(value >> 32);
    if (upper == 0) {
        return SymCryptUint32Bitsize(@truncate(value));
    } else {
        return 32 + SymCryptUint32Bitsize(upper);
    }
}

pub export fn SymCryptUint32Bytesize(value: types.UINT32) callconv(.c) types.UINT32 {
    if (value == 0) return 0;
    if (value < 0x100) return 1;
    if (value < 0x10000) return 2;
    if (value < 0x1000000) return 3;
    return 4;
}

pub export fn SymCryptUint64Bytesize(value: types.UINT64) callconv(.c) types.UINT32 {
    const upper: types.UINT32 = @truncate(value >> 32);
    if (upper == 0) {
        return SymCryptUint32Bytesize(@truncate(value));
    } else {
        return 4 + SymCryptUint32Bytesize(upper);
    }
}

pub export fn SymCryptLoadLsbFirstUint64(
    pbSrc_opt: ?[*]const u8,
    cbSrc: types.SIZE_T,
    pDst: *types.UINT64,
) callconv(types.SYMCRYPT_CALL) types.SYMCRYPT_ERROR {
    var v: types.UINT64 = 0;
    if (cbSrc > 0) {
        const pbSrc = pbSrc_opt.?;
        var rem = cbSrc;
        while (rem > 8) {
            rem -= 1;
            if (pbSrc[rem] != 0) {
                return .SYMCRYPT_VALUE_TOO_LARGE;
            }
        }
        while (rem > 0) {
            rem -= 1;
            v = (v << 8) | @as(types.UINT64, pbSrc[rem]);
        }
    }
    pDst.* = v;
    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptLoadLsbFirstUint32(
    pbSrc_opt: ?[*]const u8,
    cbSrc: types.SIZE_T,
    pDst: *types.UINT32,
) callconv(types.SYMCRYPT_CALL) types.SYMCRYPT_ERROR {
    var v64: types.UINT64 = 0;
    const scError = SymCryptLoadLsbFirstUint64(pbSrc_opt, cbSrc, &v64);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }
    const v32: types.UINT32 = @truncate(v64);
    if (@as(types.UINT64, v32) != v64) {
        return .SYMCRYPT_VALUE_TOO_LARGE;
    }
    pDst.* = v32;
    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptLoadMsbFirstUint64(
    pbSrc_opt: ?[*]const u8,
    cbSrc: types.SIZE_T,
    pDst: *types.UINT64,
) callconv(types.SYMCRYPT_CALL) types.SYMCRYPT_ERROR {
    var v: types.UINT64 = 0;
    if (cbSrc > 0) {
        var pbSrc = pbSrc_opt.?;
        var rem = cbSrc;
        while (rem > 8) : (rem -= 1) {
            if (pbSrc[0] != 0) {
                return .SYMCRYPT_VALUE_TOO_LARGE;
            }
            pbSrc += 1;
        }
        while (rem > 0) : (rem -= 1) {
            v = (v << 8) | @as(types.UINT64, pbSrc[0]);
            pbSrc += 1;
        }
    }
    pDst.* = v;
    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptLoadMsbFirstUint32(
    pbSrc_opt: ?[*]const u8,
    cbSrc: types.SIZE_T,
    pDst: *types.UINT32,
) callconv(types.SYMCRYPT_CALL) types.SYMCRYPT_ERROR {
    var v64: types.UINT64 = 0;
    const scError = SymCryptLoadMsbFirstUint64(pbSrc_opt, cbSrc, &v64);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }
    const v32: types.UINT32 = @truncate(v64);
    if (@as(types.UINT64, v32) != v64) {
        return .SYMCRYPT_VALUE_TOO_LARGE;
    }
    pDst.* = v32;
    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptStoreLsbFirstUint64(
    src: types.UINT64,
    pbDst_opt: ?[*]u8,
    cbDst: types.SIZE_T,
) callconv(types.SYMCRYPT_CALL) types.SYMCRYPT_ERROR {
    var v = src;
    if (cbDst > 0) {
        const pbDst = pbDst_opt.?;
        for (0..cbDst) |i| {
            pbDst[i] = @truncate(v);
            v >>= 8;
        }
    }
    if (v != 0) {
        return .SYMCRYPT_VALUE_TOO_LARGE;
    }
    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptStoreLsbFirstUint32(
    src: types.UINT32,
    pbDst_opt: ?[*]u8,
    cbDst: types.SIZE_T,
) callconv(types.SYMCRYPT_CALL) types.SYMCRYPT_ERROR {
    return SymCryptStoreLsbFirstUint64(src, pbDst_opt, cbDst);
}

pub export fn SymCryptStoreMsbFirstUint64(
    src: types.UINT64,
    pbDst_opt: ?[*]u8,
    cbDst: types.SIZE_T,
) callconv(types.SYMCRYPT_CALL) types.SYMCRYPT_ERROR {
    var v = src;
    if (cbDst > 0) {
        const pbDst = pbDst_opt.?;
        var rem = cbDst;
        while (rem > 0) {
            rem -= 1;
            pbDst[rem] = @truncate(v);
            v >>= 8;
        }
    }
    if (v != 0) {
        return .SYMCRYPT_VALUE_TOO_LARGE;
    }
    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptStoreMsbFirstUint32(
    src: types.UINT32,
    pbDst_opt: ?[*]u8,
    cbDst: types.SIZE_T,
) callconv(types.SYMCRYPT_CALL) types.SYMCRYPT_ERROR {
    return SymCryptStoreMsbFirstUint64(src, pbDst_opt, cbDst);
}
