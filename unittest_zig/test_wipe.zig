// Copyright (c) Microsoft Corporation. Licensed under the MIT license.

const builtin = @import("builtin");
const h = @import("main_harness.zig");
const sc = @import("sc_implementations.zig");

extern fn SymCryptWipe(pbData: [*]u8, cbData: usize) callconv(.c) void;

inline fn forceWrite8(ptr: [*]volatile u8, val: u8) void {
    const p: *align(1) volatile u8 = @ptrCast(ptr);
    p.* = val;
}

inline fn forceWrite16(ptr: [*]volatile u8, val: u16) void {
    const p: *align(1) volatile u16 = @ptrCast(ptr);
    p.* = val;
}

inline fn forceWrite32(ptr: [*]volatile u8, val: u32) void {
    const p: *align(1) volatile u32 = @ptrCast(ptr);
    p.* = val;
}

inline fn forceWrite64(ptr: [*]volatile u8, val: u64) void {
    if (builtin.cpu.arch == .arm) {
        forceWrite32(ptr, @truncate(val));
        forceWrite32(ptr + 4, @truncate(val >> 32));
        return;
    }
    const p: *align(1) volatile u64 = @ptrCast(ptr);
    p.* = val;
}

const SYMCRYPT_WIPE_FUNCTION_LIMIT: usize = if (builtin.cpu.arch == .x86_64 or builtin.cpu.arch == .aarch64) 64 else 32;

pub fn symCryptWipeKnownSize(pbData: [*]u8, cbDataInput: usize) void {
    if (builtin.cpu.arch == .x86 or builtin.cpu.arch == .x86_64 or builtin.cpu.arch == .arm or builtin.cpu.arch == .aarch64) {
        var cbData = cbDataInput;
        const pb: [*]volatile u8 = @ptrCast(pbData);
        if (cbData > SYMCRYPT_WIPE_FUNCTION_LIMIT) {
            SymCryptWipe(pbData, cbData);
        } else {
            if ((cbData & 1) != 0) {
                cbData -= 1;
                forceWrite8(pb + cbData, 0);
            }
            if ((cbData & 2) != 0) {
                cbData -= 2;
                forceWrite16(pb + cbData, 0);
            }
            if ((cbData & 4) != 0) {
                cbData -= 4;
                forceWrite32(pb + cbData, 0);
            }
            if ((cbData & 8) != 0) {
                cbData -= 8;
                forceWrite64(pb + cbData, 0);
            }
            if ((cbData & 16) != 0) {
                cbData -= 16;
                forceWrite64(pb + cbData, 0);
                forceWrite64(pb + cbData + 8, 0);
            }
            if ((cbData & 32) != 0) {
                cbData -= 32;
                forceWrite64(pb + cbData, 0);
                forceWrite64(pb + cbData + 8, 0);
                forceWrite64(pb + cbData + 16, 0);
                forceWrite64(pb + cbData + 24, 0);
            }
            if (SYMCRYPT_WIPE_FUNCTION_LIMIT >= 64) {
                if ((cbData & 64) != 0) {
                    cbData -= 64;
                    forceWrite64(pb + cbData, 0);
                    forceWrite64(pb + cbData + 8, 0);
                    forceWrite64(pb + cbData + 16, 0);
                    forceWrite64(pb + cbData + 24, 0);
                    forceWrite64(pb + cbData + 32, 0);
                    forceWrite64(pb + cbData + 40, 0);
                    forceWrite64(pb + cbData + 48, 0);
                    forceWrite64(pb + cbData + 56, 0);
                }
            }
        }
    } else {
        SymCryptWipe(pbData, cbDataInput);
    }
}

pub export fn testWipe() callconv(.c) void {
    var buf: [256]u8 = undefined;

    for (0..128) |len| {
        for (0..128 - len) |i| {
            @memset(&buf, '*');
            sc.callSymCrypt(
                "SymCryptWipe",
                *const fn ([*]u8, usize) callconv(.c) void,
                SymCryptWipe,
                .{ buf[i..].ptr, len },
            );

            for (0..i) |j| {
                h.check(buf[j] == '*', "Overwrite before buffer");
            }
            for (i..i + len) |j| {
                h.check(buf[j] == 0, "Incomplete wipe");
            }
            for (i + len..buf.len) |j| {
                h.check(buf[j] == '*', "Overwrite after buffer");
            }

            @memset(&buf, '*');
            symCryptWipeKnownSize(buf[i..].ptr, len);

            for (0..i) |j| {
                h.check(buf[j] == '*', "Overwrite before buffer");
            }
            for (i..i + len) |j| {
                h.check(buf[j] == 0, "Incomplete wipe");
            }
            for (i + len..buf.len) |j| {
                h.check(buf[j] == '*', "Overwrite after buffer");
            }
        }
    }
}
