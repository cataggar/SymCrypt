//
// rdseed.zig
// Support for RdSeed instruction (ports lib/rdseed.c)
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

const types = @import("types.zig");
const macros = @import("macros.zig");
const libmain = @import("libmain.zig");

inline fn rdseedStep(p: *align(1) usize) u8 {
    var val: usize = undefined;
    var ok: u8 = undefined;
    asm volatile (
        \\rdseed %[val]
        \\setc %[ok]
        : [val] "=r" (val),
          [ok] "=r" (ok),
        :
        : .{ .cc = true });
    p.* = val;
    return ok;
}

inline fn SymCryptRdseedSizet(p: *align(1) usize) types.SYMCRYPT_ERROR {
    var i: usize = 0;
    while (i < 10000000) : (i += 1) {
        if (rdseedStep(p) != 0) {
            return .SYMCRYPT_NO_ERROR;
        }
    }
    return .SYMCRYPT_HARDWARE_FAILURE;
}

pub fn SymCryptRdseedStatus() callconv(types.SYMCRYPT_CALL) types.SYMCRYPT_ERROR {
    libmain.SymCryptCheckLibraryInitialized();

    if (libmain.SYMCRYPT_CPU_FEATURES_PRESENT(types.SYMCRYPT_CPU_FEATURE_RDSEED)) {
        return .SYMCRYPT_NO_ERROR;
    } else {
        return .SYMCRYPT_NOT_IMPLEMENTED;
    }
}

pub fn SymCryptRdseedGetBytes(
    pbResult: [*]u8,
    cbResult: types.SIZE_T,
) callconv(types.SYMCRYPT_CALL) types.SYMCRYPT_ERROR {
    if (SymCryptRdseedStatus() != .SYMCRYPT_NO_ERROR or (cbResult & 0xf) != 0) {
        macros.SymCryptFatal(macros.multiCharConstant("rdsd"));
    }

    const pBuf: [*]align(1) usize = @ptrCast(pbResult);
    const nBuf: usize = cbResult / @sizeOf(usize);
    var scError: types.SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;

    for (0..nBuf) |i| {
        scError = SymCryptRdseedSizet(&pBuf[i]);
        if (scError != .SYMCRYPT_NO_ERROR) {
            break;
        }
    }

    return scError;
}

pub fn SymCryptRdseedGet(
    pbResult: [*]u8,
    cbResult: types.SIZE_T,
) callconv(types.SYMCRYPT_CALL) void {
    if (SymCryptRdseedGetBytes(pbResult, cbResult) != .SYMCRYPT_NO_ERROR) {
        macros.SymCryptFatal(macros.multiCharConstant("rdsx"));
    }
}

comptime {
    if (types.CPU_X86 or types.CPU_AMD64) {
        @export(&SymCryptRdseedStatus, .{ .name = "SymCryptRdseedStatus" });
        @export(&SymCryptRdseedGetBytes, .{ .name = "SymCryptRdseedGetBytes" });
        @export(&SymCryptRdseedGet, .{ .name = "SymCryptRdseedGet" });
    }
}
