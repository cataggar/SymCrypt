//
// rdrand.zig
// Support for RdRand instruction (ports lib/rdrand.c)
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

const types = @import("types.zig");
const macros = @import("macros.zig");
const libmain = @import("libmain.zig");

extern fn SymCryptSha512(
    pbData: ?[*]const u8,
    cbData: types.SIZE_T,
    pbResult: [*]u8,
) callconv(types.SYMCRYPT_CALL) void;

inline fn rdrandStep(p: *align(1) usize) u8 {
    var val: usize = undefined;
    var ok: u8 = undefined;
    asm volatile (
        \\rdrand %[val]
        \\setc %[ok]
        : [val] "=r" (val),
          [ok] "=r" (ok),
        :
        : .{ .cc = true });
    p.* = val;
    return ok;
}

inline fn SymCryptRdrandSizet(p: *align(1) usize) types.SYMCRYPT_ERROR {
    var i: usize = 0;
    while (i < 1000000) : (i += 1) {
        if (rdrandStep(p) != 0) {
            return .SYMCRYPT_NO_ERROR;
        }
    }
    return .SYMCRYPT_HARDWARE_FAILURE;
}

pub fn SymCryptRdrandStatus() callconv(types.SYMCRYPT_CALL) types.SYMCRYPT_ERROR {
    libmain.SymCryptCheckLibraryInitialized();

    if (libmain.SYMCRYPT_CPU_FEATURES_PRESENT(types.SYMCRYPT_CPU_FEATURE_RDRAND)) {
        return .SYMCRYPT_NO_ERROR;
    } else {
        return .SYMCRYPT_NOT_IMPLEMENTED;
    }
}

pub fn SymCryptRdrandGetBytes(
    pbBuffer: [*]u8,
    cbBuffer: types.SIZE_T,
    pbResult: [*]u8,
) callconv(types.SYMCRYPT_CALL) types.SYMCRYPT_ERROR {
    if (SymCryptRdrandStatus() != .SYMCRYPT_NO_ERROR or (cbBuffer & 0xf) != 0) {
        macros.SymCryptFatal(macros.multiCharConstant("rdrn"));
    }

    const pBuf: [*]align(1) usize = @ptrCast(pbBuffer);
    const nBuf: usize = cbBuffer / @sizeOf(usize);
    var scError: types.SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;

    for (0..nBuf) |i| {
        scError = SymCryptRdrandSizet(&pBuf[i]);
        if (scError != .SYMCRYPT_NO_ERROR) {
            break;
        }
    }

    if (scError == .SYMCRYPT_NO_ERROR) {
        SymCryptSha512(pbBuffer, cbBuffer, pbResult);
    }

    libmain.SymCryptWipe(@ptrCast(pbBuffer), cbBuffer);

    return scError;
}

pub fn SymCryptRdrandGet(
    pbBuffer: [*]u8,
    cbBuffer: types.SIZE_T,
    pbResult: [*]u8,
) callconv(types.SYMCRYPT_CALL) void {
    if (SymCryptRdrandGetBytes(pbBuffer, cbBuffer, pbResult) != .SYMCRYPT_NO_ERROR) {
        macros.SymCryptFatal(macros.multiCharConstant("rdrx"));
    }
}

comptime {
    if (types.CPU_X86 or types.CPU_AMD64) {
        @export(&SymCryptRdrandStatus, .{ .name = "SymCryptRdrandStatus" });
        @export(&SymCryptRdrandGetBytes, .{ .name = "SymCryptRdrandGetBytes" });
        @export(&SymCryptRdrandGet, .{ .name = "SymCryptRdrandGet" });
    }
}
