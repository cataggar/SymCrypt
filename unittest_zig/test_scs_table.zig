// Copyright (c) Microsoft Corporation. Licensed under the MIT license.

const std = @import("std");
const h = @import("main_harness.zig");
const cb = @import("callback.zig");
const rng = @import("rng.zig");
const sc = @import("sc_implementations.zig");

pub const SYMCRYPT_SCSTABLE = extern struct {
    groupSize: u32,
    interleaveSize: u32,
    nElements: u32,
    elementSize: u32,
    pbTableData: [*]u8,
    cbTableData: u32,
};

extern fn SymCryptScsTableInit(pScsTable: *SYMCRYPT_SCSTABLE, nElements: u32, elementSize: u32) callconv(.c) u32;
extern fn SymCryptScsTableSetBuffer(pScsTable: *SYMCRYPT_SCSTABLE, pbTableData: [*]u8, cbTableData: u32) callconv(.c) void;
extern fn SymCryptScsTableStore(pScsTable: *SYMCRYPT_SCSTABLE, iIndex: u32, pbSrc: [*]const u8, cbSrc: u32) callconv(.c) void;
extern fn SymCryptScsTableLoad(pScsTable: *const SYMCRYPT_SCSTABLE, iIndex: u32, pbDst: [*]u8, cbDst: u32) callconv(.c) void;
extern fn SymCryptScsTableWipe(pScsTable: *SYMCRYPT_SCSTABLE) callconv(.c) void;

extern fn scTestIsAlgorithmPresentCstr(name: [*:0]const u8, isPrefix: c_int) callconv(.c) c_int;
const scTestIsAlgorithmPresent = scTestIsAlgorithmPresentCstr;

const builtin = @import("builtin");

const testScsTableElementSizes = if (builtin.cpu.arch == .x86_64 or builtin.cpu.arch == .aarch64)
    [_]u32{ 32, 64, 128, 192, 256, 1024 }
else
    [_]u32{ 16, 48, 32, 64, 128, 192, 256, 1024 };

const testScsTableNElements = [_]u32{ 8, 16, 24, 32, 64 };

pub fn testScsTableOneSize(nElements: u32, elementSize: u32) void {
    var scsTable: SYMCRYPT_SCSTABLE = undefined;

    const cbBuffer = sc.callSymCrypt(
        "SymCryptScsTableInit",
        *const fn (*SYMCRYPT_SCSTABLE, u32, u32) callconv(.c) u32,
        SymCryptScsTableInit,
        .{ &scsTable, nElements, elementSize },
    );

    const pbTableBuffer: [*]u8 = @ptrCast(cb.AllocWithChecksSc(cbBuffer).?);
    defer cb.FreeWithChecksSc(pbTableBuffer);

    sc.callSymCrypt(
        "SymCryptScsTableSetBuffer",
        *const fn (*SYMCRYPT_SCSTABLE, [*]u8, u32) callconv(.c) void,
        SymCryptScsTableSetBuffer,
        .{ &scsTable, pbTableBuffer, cbBuffer },
    );

    const pbRef: [*]u8 = @ptrCast(cb.AllocWithChecksSc(@as(usize, nElements) * elementSize).?);
    defer cb.FreeWithChecksSc(pbRef);

    const pbTest: [*]u8 = @ptrCast(cb.AllocWithChecksSc(elementSize).?);
    defer cb.FreeWithChecksSc(pbTest);

    h.GENRANDOM(pbRef, @as(usize, nElements) * elementSize);

    var i: u32 = 0;
    while (i < nElements) : (i += 1) {
        sc.callSymCrypt(
            "SymCryptScsTableStore",
            *const fn (*SYMCRYPT_SCSTABLE, u32, [*]const u8, u32) callconv(.c) void,
            SymCryptScsTableStore,
            .{ &scsTable, i, pbRef + @as(usize, i) * elementSize, elementSize },
        );
    }

    for (0..10 * @as(usize, nElements)) |_| {
        i = @intCast(rng.scTestRngSizet(&rng.g_rng, nElements));
        sc.callSymCrypt(
            "SymCryptScsTableLoad",
            *const fn (*const SYMCRYPT_SCSTABLE, u32, [*]u8, u32) callconv(.c) void,
            SymCryptScsTableLoad,
            .{ &scsTable, i, pbTest, elementSize },
        );
        const refSlice = (pbRef + @as(usize, i) * elementSize)[0..elementSize];
        h.check5(
            std.mem.eql(u8, pbTest[0..elementSize], refSlice),
            "Mismatch in ScsTable ({d}, {d}, {d})",
            nElements,
            elementSize,
            i,
        );

        i = @intCast(rng.scTestRngSizet(&rng.g_rng, nElements));
        h.GENRANDOM(pbRef + @as(usize, i) * elementSize, elementSize);
        sc.callSymCrypt(
            "SymCryptScsTableStore",
            *const fn (*SYMCRYPT_SCSTABLE, u32, [*]const u8, u32) callconv(.c) void,
            SymCryptScsTableStore,
            .{ &scsTable, i, pbRef + @as(usize, i) * elementSize, elementSize },
        );
    }

    sc.callSymCrypt(
        "SymCryptScsTableWipe",
        *const fn (*SYMCRYPT_SCSTABLE) callconv(.c) void,
        SymCryptScsTableWipe,
        .{&scsTable},
    );
    var d: u8 = 0;
    for (0..cbBuffer) |j| {
        d |= pbTableBuffer[j];
    }
    h.check4(d == 0, "SymCryptScsTableWipe error ({d}, {d})", nElements, elementSize);

    @memset(pbTest[0..elementSize], 0);
    @memset(pbRef[0 .. @as(usize, nElements) * elementSize], 0);
}

pub export fn testScsTable() callconv(.c) void {
    if (scTestIsAlgorithmPresent("ScsTable", 0) == 0) {
        return;
    }

    h.zprint("    ScsTable\n", .{});
    for (testScsTableElementSizes) |elementSize| {
        for (testScsTableNElements) |nElements| {
            testScsTableOneSize(nElements, elementSize);
        }
    }
}
