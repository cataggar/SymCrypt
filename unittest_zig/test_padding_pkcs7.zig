// Copyright (c) Microsoft Corporation. Licensed under the MIT license.

const std = @import("std");
const h = @import("main_harness.zig");
const sc_imp = @import("sc_implementations.zig");

const types = struct {
    pub const SYMCRYPT_CALL: std.builtin.CallingConvention = .c;
    pub const SYMCRYPT_ERROR = enum(c_int) {
        SYMCRYPT_NO_ERROR = 0,
        SYMCRYPT_BUFFER_TOO_SMALL = 0x800d,
        SYMCRYPT_INVALID_ARGUMENT = 0x800e,
        _,
    };
};

const check = h.check;
const print = h.print;

const MAX_BUFFER_SIZE: u32 = 10000;
const MAX_PKCS7_BLOCK_SIZE: usize = 128;
const MAX_DEST_BUFFER_SIZE: u32 = 2 * (MAX_BUFFER_SIZE + MAX_PKCS7_BLOCK_SIZE);

extern fn scTestGenRandom(pbBuf: *anyopaque, cbBuf: usize) callconv(.c) c_int;
extern fn SymCryptRoundUpPow2Sizet(v: usize) callconv(types.SYMCRYPT_CALL) usize;

extern fn SymCryptPaddingPkcs7Add(
    cbBlockSize: usize,
    pbSrc: [*]const u8,
    cbSrc: usize,
    pbDst: [*]u8,
    cbDst: usize,
    pcbResult: *usize,
) callconv(types.SYMCRYPT_CALL) void;

extern fn SymCryptPaddingPkcs7Remove(
    cbBlockSize: usize,
    pbSrc: [*]const u8,
    cbSrc: usize,
    pbDst: [*]u8,
    cbDst: usize,
    pcbResult: *usize,
) callconv(types.SYMCRYPT_CALL) types.SYMCRYPT_ERROR;

fn verifyAddPadding(cbBlockSize: usize, pbSrc: [*]const u8, cbSrc: u32, pbDst: [*]u8, cbDst: u32) usize {
    var cbResult: usize = cbSrc;

    const pbDstCpy = std.heap.c_allocator.alloc(u8, @max(cbDst, 1)) catch unreachable;
    defer std.heap.c_allocator.free(pbDstCpy);
    @memcpy(pbDstCpy[0..cbDst], pbDst[0..cbDst]);

    const cbPadVal: u32 = @intCast(cbBlockSize - (cbSrc % cbBlockSize));
    const cbPredictedResult: u32 = cbSrc + cbPadVal;

    sc_imp.callSymCrypt(
        "SymCryptPaddingPkcs7Add",
        @TypeOf(&SymCryptPaddingPkcs7Add),
        &SymCryptPaddingPkcs7Add,
        .{ cbBlockSize, pbSrc, cbSrc, pbDst, cbDst, &cbResult },
    );

    check(cbResult == cbPredictedResult, "testPaddingPkcs7Add : cbResult is incorrect.");

    for (0..cbDst) |i| {
        if (i < cbSrc) {
            check(pbSrc[i] == pbDst[i], "testPaddingPkcs7Add: message was not copied to destination as expected!");
            continue;
        }
        if (i < cbResult) {
            check(@as(u8, @truncate(cbPadVal)) == pbDst[i], "testPaddingPkcs7Add: invalid padded value!");
            continue;
        }
        check(pbDst[i] == pbDstCpy[i], "testPaddingPkcs7Add: data after padding was changed!");
    }

    return cbResult;
}

fn verifyRemovePadding(cbBlockSize: usize, pbSrc: [*]const u8, cbSrc: u32, pbDst: [*]u8, cbDst: u32) void {
    var cbResult: usize = cbSrc;
    const cbPadVal: u32 = pbSrc[cbSrc - 1];
    const cbMsg: u32 = cbSrc - @as(u32, @intCast(cbPadVal % (cbBlockSize + 1)));

    var validPadding: bool = (cbPadVal != 0 and cbPadVal <= cbBlockSize);
    const bufferTooSmall: bool = (cbDst < cbSrc - cbBlockSize);
    const validBuffer: bool = (cbDst >= cbMsg);

    const pbDstCpy = std.heap.c_allocator.alloc(u8, @max(cbDst, 1)) catch unreachable;
    defer std.heap.c_allocator.free(pbDstCpy);
    @memcpy(pbDstCpy[0..cbDst], pbDst[0..cbDst]);

    const err = sc_imp.callSymCrypt(
        "SymCryptPaddingPkcs7Remove",
        @TypeOf(&SymCryptPaddingPkcs7Remove),
        &SymCryptPaddingPkcs7Remove,
        .{ cbBlockSize, pbSrc, cbSrc, pbDst, cbDst, &cbResult },
    );

    if (!bufferTooSmall) {
        var i: u32 = cbMsg;
        while (i < cbSrc) : (i += 1) {
            if (pbSrc[i] != cbPadVal) {
                validPadding = false;
            }
        }
    } else {
        if (!validPadding) {
            check(
                (err == .SYMCRYPT_BUFFER_TOO_SMALL) or (err == .SYMCRYPT_INVALID_ARGUMENT),
                "SymCryptPaddingPkcs7Remove: not the expected error was returned.",
            );
        } else {
            check(err == .SYMCRYPT_BUFFER_TOO_SMALL, "testPaddingPkcs7Remove: not the expected error was returned.");
        }
    }

    if (validBuffer and validPadding) {
        check(err == .SYMCRYPT_NO_ERROR, "SymCryptPaddingPkcs7Remove: not the expected error was returned.");
        check(cbResult == cbMsg, "testPaddingPkcs7Remove: cbResult is incorrect.");

        for (0..cbDst) |i| {
            if (i < cbMsg) {
                check(pbSrc[i] == pbDst[i], "testPaddingPkcs7Remove: message was not copied to destination as expected!");
                continue;
            }
            check(pbDstCpy[i] == pbDst[i], "testPaddingPkcs7Remove: data after padding was changed!");
        }
    } else if (validBuffer and !validPadding) {
        check(err == .SYMCRYPT_INVALID_ARGUMENT, "SymCryptPaddingPkcs7Remove: not the expected error was returned.");
    } else if (!validBuffer and validPadding) {
        check(err == .SYMCRYPT_BUFFER_TOO_SMALL, "SymCryptPaddingPkcs7Remove: not the expected error was returned.");
    } else if (!validBuffer and !validPadding) {
        check(
            (err == .SYMCRYPT_BUFFER_TOO_SMALL) or (err == .SYMCRYPT_INVALID_ARGUMENT),
            "SymCryptPaddingPkcs7Remove: not the expected error was returned.",
        );
    }
}

pub export fn testPaddingPkcs7() callconv(.c) void {
    var cbMsg: u32 = 0;
    var cbAddPad: u32 = 0;
    var cbRemovePad: u32 = 0;

    if (h.g_useDynamicFunctionsInTestCall != 0) {
        if (sc_imp.lookupDynamicSymbol(*const anyopaque, "SymCryptPaddingPkcs7Add", .function_ptr) == null or
            sc_imp.lookupDynamicSymbol(*const anyopaque, "SymCryptPaddingPkcs7Remove", .function_ptr) == null)
        {
            print("    testPaddingPkcs7 skipped\n");
            return;
        }
    }

    var cbBlockSize: usize = 0;
    _ = scTestGenRandom(&cbBlockSize, @sizeOf(usize));
    cbBlockSize = SymCryptRoundUpPow2Sizet(1 + (cbBlockSize % MAX_PKCS7_BLOCK_SIZE));

    _ = scTestGenRandom(&cbMsg, @sizeOf(u32));
    cbMsg = cbMsg % MAX_BUFFER_SIZE;

    _ = scTestGenRandom(&cbRemovePad, @sizeOf(u32));
    cbRemovePad = cbRemovePad % MAX_BUFFER_SIZE;

    _ = scTestGenRandom(&cbAddPad, @sizeOf(u32));
    cbAddPad = cbAddPad % MAX_DEST_BUFFER_SIZE;
    cbAddPad = cbAddPad + (cbMsg + @as(u32, @intCast(cbBlockSize)) - (cbMsg % @as(u32, @intCast(cbBlockSize))));

    const pbMsg = std.heap.c_allocator.alloc(u8, @max(cbMsg, 1)) catch unreachable;
    defer std.heap.c_allocator.free(pbMsg);
    const pbAddPad = std.heap.c_allocator.alloc(u8, @max(cbAddPad, 1)) catch unreachable;
    defer std.heap.c_allocator.free(pbAddPad);
    const pbRemovePad = std.heap.c_allocator.alloc(u8, @max(cbRemovePad, 1)) catch unreachable;
    defer std.heap.c_allocator.free(pbRemovePad);

    _ = scTestGenRandom(pbMsg.ptr, cbMsg);
    _ = scTestGenRandom(pbAddPad.ptr, cbAddPad);
    _ = scTestGenRandom(pbRemovePad.ptr, cbRemovePad);

    const cbResult: u32 = @intCast(verifyAddPadding(cbBlockSize, pbMsg.ptr, cbMsg, pbAddPad.ptr, cbAddPad));

    verifyRemovePadding(cbBlockSize, pbAddPad.ptr, cbResult, pbRemovePad.ptr, cbRemovePad);

    var cbPadValDummy: u32 = 0;
    _ = scTestGenRandom(&cbPadValDummy, @sizeOf(u32));
    if (MAX_PKCS7_BLOCK_SIZE <= cbPadValDummy) {
        cbPadValDummy = cbPadValDummy % @as(u32, @intCast(MAX_PKCS7_BLOCK_SIZE));
    }
    const cbPadVal: u32 = cbResult - cbMsg;
    var rndPadPos: u32 = cbMsg;
    if (cbPadVal != 0) {
        rndPadPos = rndPadPos + (cbPadValDummy % cbPadVal);
    }
    const cbSrcDummy: u32 = cbResult;
    const pbSrcDummy = std.heap.c_allocator.alloc(u8, @max(cbSrcDummy, 1)) catch unreachable;
    defer std.heap.c_allocator.free(pbSrcDummy);
    @memcpy(pbSrcDummy[0..cbResult], pbAddPad[0..cbResult]);
    pbSrcDummy[rndPadPos] = @truncate(cbPadValDummy);

    var cbDstDummy: u32 = 0;
    _ = scTestGenRandom(&cbDstDummy, @sizeOf(u32));
    cbDstDummy = cbDstDummy % MAX_BUFFER_SIZE;
    const pbDstDummy = std.heap.c_allocator.alloc(u8, @max(cbDstDummy, 1)) catch unreachable;
    defer std.heap.c_allocator.free(pbDstDummy);
    _ = scTestGenRandom(pbDstDummy.ptr, cbDstDummy);

    verifyRemovePadding(cbBlockSize, pbSrcDummy.ptr, cbSrcDummy, pbDstDummy.ptr, cbDstDummy);
}
