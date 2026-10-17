// Copyright (c) Microsoft Corporation. Licensed under the MIT license.

const std = @import("std");
const h = @import("main_harness.zig");
const cb = @import("callback.zig");
const kat = @import("kat.zig");
const rng = @import("rng.zig");

const STATUS_SUCCESS: i32 = 0;

const SYMCRYPT_NO_ERROR: u32 = 0;
const SYMCRYPT_HBS_NO_OTS_KEYS_LEFT: u32 = 0x8014;

const SYMCRYPT_SHA256_RESULT_SIZE: u32 = 32;
const SYMCRYPT_SHA512_RESULT_SIZE: u32 = 64;

const SYMCRYPT_XMSS_SHA2_10_256: u32 = 0x00000001;
const SYMCRYPT_XMSSKEY_TYPE_PUBLIC: u32 = 1;
const SYMCRYPT_XMSSKEY_TYPE_PRIVATE: u32 = 2;

const SYMCRYPT_LMS_SHA256_M32_H5: u32 = 0x00000005;
const SYMCRYPT_LMS_OTS_SHA256_N32_W8: u32 = 0x00000004;
const SYMCRYPT_LMSKEY_TYPE_PUBLIC: u32 = 1;
const SYMCRYPT_LMSKEY_TYPE_PRIVATE: u32 = 2;

const SYMCRYPT_XMSS_PARAMS = extern struct {
    hash: ?*const anyopaque align(16),
    id: u32,
    cbHashOutput: u32,
    nWinternitzWidth: u32,
    nTotalTreeHeight: u32,
    nLayers: u32,
    cbPrefix: u32,
    len1: u32,
    len2: u32,
    len: u32,
    nLayerHeight: u32,
    cbIdx: u32,
    nLeftShift32: u32,
    Reserved: [16]u8,
};

const SYMCRYPT_LMS_PARAMS = extern struct {
    lmsAlgID: u32 align(16),
    lmsOtsAlgID: u32,
    pLmsHashFunction: ?*const anyopaque,
    nTreeHeight: u32,
    cbHashOutput: u32,
    nWinternitzChainWidth: u32,
    nByteStringCount: u32,
    nChecksumLShiftBits: u32,
};

const SYMCRYPT_XMSS_KEY = opaque {};
const SYMCRYPT_LMS_KEY = opaque {};

extern const SymCryptSha256Algorithm: *const anyopaque;

extern fn SymCryptWipe(pbData: [*]u8, cbData: usize) callconv(.c) void;

extern fn SymCryptHbsGetWinternitzLengths(
    n: u32,
    w: u32,
    puLen1: *u32,
    puLen2: *u32,
) callconv(.c) void;

extern fn SymCryptXmssParamsFromAlgId(
    id: u32,
    pParams: *SYMCRYPT_XMSS_PARAMS,
) callconv(.c) u32;

extern fn SymCryptXmssSetParams(
    pParams: *SYMCRYPT_XMSS_PARAMS,
    id: u32,
    pHash: *const anyopaque,
    cbHashOutput: u32,
    nWinternitzWidth: u32,
    nTotalTreeHeight: u32,
    nLayers: u32,
    cbPrefix: u32,
) callconv(.c) u32;

extern fn SymCryptXmssSizeofKeyBlobFromParams(
    pParams: *const SYMCRYPT_XMSS_PARAMS,
    keyType: u32,
    pcbKey: *usize,
) callconv(.c) u32;

extern fn SymCryptXmssSizeofSignatureFromParams(
    pParams: *const SYMCRYPT_XMSS_PARAMS,
) callconv(.c) usize;

extern fn SymCryptXmsskeyAllocate(
    pParams: *const SYMCRYPT_XMSS_PARAMS,
    flags: u32,
) callconv(.c) ?*SYMCRYPT_XMSS_KEY;

extern fn SymCryptXmsskeyFree(
    pKey: *SYMCRYPT_XMSS_KEY,
) callconv(.c) void;

extern fn SymCryptXmsskeyGenerate(
    pKey: *SYMCRYPT_XMSS_KEY,
    flags: u32,
) callconv(.c) u32;

extern fn SymCryptXmsskeySetValue(
    pbSrc: [*]const u8,
    cbSrc: usize,
    keyType: u32,
    flags: u32,
    pKey: *SYMCRYPT_XMSS_KEY,
) callconv(.c) u32;

extern fn SymCryptXmsskeyGetValue(
    pKey: *const SYMCRYPT_XMSS_KEY,
    keyType: u32,
    flags: u32,
    pbOutput: [*]u8,
    cbOutput: usize,
) callconv(.c) u32;

extern fn SymCryptXmssSign(
    pKey: *SYMCRYPT_XMSS_KEY,
    pbInput: [*]const u8,
    cbInput: usize,
    flags: u32,
    pbSignature: [*]u8,
    cbSignature: usize,
) callconv(.c) u32;

extern fn SymCryptXmssVerify(
    pKey: *const SYMCRYPT_XMSS_KEY,
    pbInput: [*]const u8,
    cbInput: usize,
    flags: u32,
    pbSignature: [*]const u8,
    cbSignature: usize,
) callconv(.c) u32;

extern fn SymCryptLmsParamsFromAlgId(
    lmsAlgID: u32,
    lmsOtsAlgID: u32,
    pParams: *SYMCRYPT_LMS_PARAMS,
) callconv(.c) u32;

extern fn SymCryptLmsSetParams(
    pParams: *SYMCRYPT_LMS_PARAMS,
    lmsAlgID: u32,
    lmsOtsAlgID: u32,
    pLmsHashFunction: *const anyopaque,
    cbHashOutput: u32,
    nTreeHeight: u32,
    nWinternitzChainWidth: u32,
) callconv(.c) u32;

extern fn SymCryptLmsSizeofSignatureFromParams(
    pParams: *const SYMCRYPT_LMS_PARAMS,
) callconv(.c) usize;

extern fn SymCryptLmskeyAllocate(
    pParams: *const SYMCRYPT_LMS_PARAMS,
    flags: u32,
) callconv(.c) ?*SYMCRYPT_LMS_KEY;

extern fn SymCryptLmskeyFree(
    pKey: *SYMCRYPT_LMS_KEY,
) callconv(.c) void;

extern fn SymCryptLmskeyGenerate(
    pKey: *SYMCRYPT_LMS_KEY,
    flags: u32,
) callconv(.c) u32;

extern fn SymCryptLmskeySetValue(
    pbInput: [*]const u8,
    cbInput: usize,
    keyType: u32,
    flags: u32,
    pKey: *SYMCRYPT_LMS_KEY,
) callconv(.c) u32;

extern fn SymCryptLmskeyGetValue(
    pKey: *const SYMCRYPT_LMS_KEY,
    keyType: u32,
    flags: u32,
    pbOutput: [*]u8,
    cbOutput: usize,
) callconv(.c) u32;

extern fn SymCryptLmsSign(
    pKey: *SYMCRYPT_LMS_KEY,
    pbInput: [*]const u8,
    cbInput: usize,
    flags: u32,
    pbSignature: [*]u8,
    cbSignature: usize,
) callconv(.c) u32;

extern fn SymCryptLmsVerify(
    pKey: *const SYMCRYPT_LMS_KEY,
    pbInput: [*]const u8,
    cbInput: usize,
    flags: u32,
    pbSignature: [*]const u8,
    cbSignature: usize,
) callconv(.c) u32;

extern fn scTestHbsMultiImpCreate(algName: [*:0]const u8) callconv(.c) ?*anyopaque;
extern fn scTestHbsMultiImpDestroy(pMultiImp: *anyopaque) callconv(.c) void;
extern fn scTestHbsMultiImpGetCount(pMultiImp: *anyopaque) callconv(.c) usize;

extern fn scTestHbsImpSetKey(
    pImp: *anyopaque,
    algId: u32,
    otsAlgId: u32,
    fMultitree: c_int,
    pbSrc: ?[*]const u8,
    cbSrc: usize,
    fVerifyRoot: c_int,
) callconv(.c) i32;

extern fn scTestHbsImpVerify(
    pImp: *anyopaque,
    pbMsg: [*]const u8,
    cbMsg: usize,
    flags: u32,
    pbSig: [*]const u8,
    cbSig: usize,
) callconv(.c) i32;

extern fn scTestHbsImpSign(
    pImp: *anyopaque,
    pbMsg: [*]const u8,
    cbMsg: usize,
    flags: u32,
    pbSig: [*]u8,
    cbSig: usize,
) callconv(.c) i32;

const TEST_WINTERNITZ_LENGTHS = struct {
    n: u32,
    w: u32,
    len1: u32,
    len2: u32,
};

const rgTestWinternitzLengths = [_]TEST_WINTERNITZ_LENGTHS{
    .{
        .n = 24,
        .w = 1,
        .len1 = 192,
        .len2 = 8,
    },
    .{
        .n = 24,
        .w = 2,
        .len1 = 96,
        .len2 = 5,
    },
    .{
        .n = 24,
        .w = 4,
        .len1 = 48,
        .len2 = 3,
    },
    .{
        .n = 24,
        .w = 8,
        .len1 = 24,
        .len2 = 2,
    },
    .{
        .n = SYMCRYPT_SHA256_RESULT_SIZE,
        .w = 1,
        .len1 = 256,
        .len2 = 9,
    },
    .{
        .n = SYMCRYPT_SHA256_RESULT_SIZE,
        .w = 2,
        .len1 = 128,
        .len2 = 5,
    },
    .{
        .n = SYMCRYPT_SHA256_RESULT_SIZE,
        .w = 4,
        .len1 = 64,
        .len2 = 3,
    },
    .{
        .n = SYMCRYPT_SHA256_RESULT_SIZE,
        .w = 8,
        .len1 = 32,
        .len2 = 2,
    },
    .{
        .n = SYMCRYPT_SHA512_RESULT_SIZE,
        .w = 1,
        .len1 = 512,
        .len2 = 10,
    },
    .{
        .n = SYMCRYPT_SHA512_RESULT_SIZE,
        .w = 2,
        .len1 = 256,
        .len2 = 5,
    },
    .{
        .n = SYMCRYPT_SHA512_RESULT_SIZE,
        .w = 4,
        .len1 = 128,
        .len2 = 3,
    },
    .{
        .n = SYMCRYPT_SHA512_RESULT_SIZE,
        .w = 8,
        .len1 = 64,
        .len2 = 2,
    },
};

fn testWinternitzLengths() void {
    var len1: u32 = 0;
    var len2: u32 = 0;

    for (rgTestWinternitzLengths) |item| {
        SymCryptHbsGetWinternitzLengths(
            item.n,
            item.w,
            &len1,
            &len2,
        );

        h.check6(len1 == item.len1, "Unexpected len1 values when n={d}, w={d} (expected {d}, got {d})", item.n, item.w, item.len1, len1);
        h.check6(len2 == item.len2, "Unexpected len2 values when n={d}, w={d} (expected {d}, got {d})", item.n, item.w, item.len2, len2);
    }
}

fn testHbsVerify(
    pHbs: *anyopaque,
    algId: u32,
    otsAlgId: u32,
    fMultitree: bool,
    pbMsg: []const u8,
    pbPubkey: []const u8,
    pbSig: []const u8,
    line: i64,
) void {
    _ = line;

    var status = scTestHbsImpSetKey(pHbs, algId, otsAlgId, if (fMultitree) 1 else 0, pbPubkey.ptr, pbPubkey.len, 0);
    h.check3(status == STATUS_SUCCESS, "Hbs setKey failed for algid = {d}", algId);

    status = scTestHbsImpVerify(pHbs, pbMsg.ptr, pbMsg.len, 0, pbSig.ptr, pbSig.len);
    h.check3(status == STATUS_SUCCESS, "Hbs verify failed for algid = {d}", algId);

    // Modify one random byte in the signature and check verification failure
    const pbSigModified = std.heap.page_allocator.alloc(u8, pbSig.len) catch unreachable;
    defer std.heap.page_allocator.free(pbSigModified);
    @memcpy(pbSigModified, pbSig);
    const nModifyPos: usize = @intCast(rng.g_rng.uint32() % @as(u32, @intCast(pbSig.len)));
    pbSigModified[nModifyPos] ^= 1;

    status = scTestHbsImpVerify(pHbs, pbMsg.ptr, pbMsg.len, 0, pbSigModified.ptr, pbSigModified.len);
    h.check3(status != STATUS_SUCCESS, "Hbs verify succeeded for modified signature (algid = {d})", algId);

    // Modify the message if it is non-empty and check verification failure
    if (pbMsg.len > 0) {
        const pbMsgModified = std.heap.page_allocator.alloc(u8, pbMsg.len) catch unreachable;
        defer std.heap.page_allocator.free(pbMsgModified);
        @memcpy(pbMsgModified, pbMsg);
        pbMsgModified[0] ^= 1;

        status = scTestHbsImpVerify(pHbs, pbMsgModified.ptr, pbMsgModified.len, 0, pbSig.ptr, pbSig.len);
        h.check3(status != STATUS_SUCCESS, "Hbs verify succeeded for modified message (algid = {d})", algId);
    }

    h.check(scTestHbsImpSetKey(pHbs, 0, 0, 0, null, 0, 0) == STATUS_SUCCESS, "Failed to clear key");
}

fn testHbsSign(
    pHbs: *anyopaque,
    algId: u32,
    otsAlgId: u32,
    fMultitree: bool,
    pbMsg: []const u8,
    pbPrvkey: []const u8,
    pbSig: []const u8,
    line: i64,
) void {
    var status = scTestHbsImpSetKey(pHbs, algId, otsAlgId, if (fMultitree) 1 else 0, pbPrvkey.ptr, pbPrvkey.len, 0);
    h.check3(status == STATUS_SUCCESS, "Hbs setKey failed for algid = {d}", algId);

    const pbComputedSig = std.heap.page_allocator.alloc(u8, pbSig.len) catch unreachable;
    defer std.heap.page_allocator.free(pbComputedSig);

    status = scTestHbsImpSign(pHbs, pbMsg.ptr, pbMsg.len, 0, pbComputedSig.ptr, pbSig.len);
    h.check3(status == STATUS_SUCCESS, "Hbs sign failed for algid = {d}", algId);

    if (!std.mem.eql(u8, pbComputedSig, pbSig)) {
        h.zprint("HBS Signature mismatch at line {d}\n", .{line});
        h.check(false, "HBS Signature mismatch");
    }

    h.check(scTestHbsImpSetKey(pHbs, 0, 0, 0, null, 0, 0) == STATUS_SUCCESS, "Failed to clear key");
}

fn testHbsKeygen(
    pHbs: *anyopaque,
    algId: u32,
    otsAlgId: u32,
    fMultitree: bool,
    pbPrvkey: []const u8,
    line: i64,
) void {
    _ = line;

    const status = scTestHbsImpSetKey(pHbs, algId, otsAlgId, if (fMultitree) 1 else 0, pbPrvkey.ptr, pbPrvkey.len, 1);
    h.check3(status == STATUS_SUCCESS, "Hbs setKey failed for algid = {d}", algId);

    h.check(scTestHbsImpSetKey(pHbs, 0, 0, 0, null, 0, 0) == STATUS_SUCCESS, "Failed to clear key");
}

fn testHbsKats() void {
    var katHbs = kat.ZigKatReader.init("kat_hbs.dat");
    var katItem: kat.ZigKatItem = .{};
    defer katItem.deinit();

    var skipData: bool = true;
    var sep: []const u8 = "    ";
    var doneAnything: bool = false;

    var pHbsMultiImp: ?*anyopaque = null;
    defer if (pHbsMultiImp) |p| scTestHbsMultiImpDestroy(p);

    while (true) {
        katHbs.getKatItem(&katItem);

        if (katItem.type == kat.KAT_TYPE_END) {
            break;
        }

        if (katItem.type == kat.KAT_TYPE_CATEGORY) {
            if (pHbsMultiImp) |p| {
                scTestHbsMultiImpDestroy(p);
                pHbsMultiImp = null;
            }

            var catBuf: [128]u8 = @splat(0);
            const catLen = @min(katItem.categoryName.len, catBuf.len - 1);
            @memcpy(catBuf[0..catLen], katItem.categoryName[0..catLen]);
            catBuf[catLen] = 0;
            const catZ: [*:0]const u8 = @ptrCast(&catBuf);

            pHbsMultiImp = scTestHbsMultiImpCreate(catZ);
            skipData = (pHbsMultiImp == null or scTestHbsMultiImpGetCount(pHbsMultiImp.?) == 0);

            if (!skipData) {
                h.ziprint("{s}{s}", .{ sep, katItem.categoryName });
                sep = ", ";
                doneAnything = true;
            }
        }

        if (skipData) {
            continue;
        }

        if (katItem.type == kat.KAT_TYPE_DATASET) {
            if (katItem.isFieldPresent("pubkey")) {
                var fMultitree: bool = false;
                var nExpectedItems: usize = 4;
                var otsAlgId: u32 = 0;

                if (katItem.isFieldPresent("multitree")) {
                    fMultitree = katItem.parseInteger("multitree") > 0;
                    nExpectedItems += 1;
                }

                if (katItem.isFieldPresent("otsalgid")) {
                    otsAlgId = @intCast(katItem.parseInteger("otsalgid"));
                    nExpectedItems += 1;
                }

                h.check3(katItem.dataItems.items.len == nExpectedItems, "Incorrect number of items in Hbs signature verification record ending at line {d}", katHbs.kat.m_line);

                const algId: u32 = @intCast(katItem.parseInteger("algid"));
                const katMsg = katItem.parseData("msg");
                defer std.heap.c_allocator.free(katMsg);
                const katPubkey = katItem.parseData("pubkey");
                defer std.heap.c_allocator.free(katPubkey);
                const katSig = katItem.parseData("sig");
                defer std.heap.c_allocator.free(katSig);

                testHbsVerify(
                    pHbsMultiImp.?,
                    algId,
                    otsAlgId,
                    fMultitree,
                    katMsg,
                    katPubkey,
                    katSig,
                    katHbs.kat.m_line,
                );

                continue;
            }

            if (katItem.isFieldPresent("prvkey")) {
                if (katItem.isFieldPresent("msg")) {
                    var fMultitree: bool = false;
                    var nExpectedItems: usize = 4;
                    var otsAlgId: u32 = 0;

                    if (katItem.isFieldPresent("multitree")) {
                        fMultitree = katItem.parseInteger("multitree") > 0;
                        nExpectedItems += 1;
                    }

                    if (katItem.isFieldPresent("otsalgid")) {
                        otsAlgId = @intCast(katItem.parseInteger("otsalgid"));
                        nExpectedItems += 1;
                    }

                    h.check3(katItem.dataItems.items.len == nExpectedItems, "Incorrect number of items in Hbs signature verification record ending at line {d}", katHbs.kat.m_line);

                    const algId: u32 = @intCast(katItem.parseInteger("algid"));
                    const katMsg = katItem.parseData("msg");
                    defer std.heap.c_allocator.free(katMsg);
                    const katPrvkey = katItem.parseData("prvkey");
                    defer std.heap.c_allocator.free(katPrvkey);
                    const katSig = katItem.parseData("sig");
                    defer std.heap.c_allocator.free(katSig);

                    testHbsSign(
                        pHbsMultiImp.?,
                        algId,
                        otsAlgId,
                        fMultitree,
                        katMsg,
                        katPrvkey,
                        katSig,
                        katHbs.kat.m_line,
                    );
                } else {
                    var fMultitree: bool = false;
                    var nExpectedItems: usize = 2;
                    var otsAlgId: u32 = 0;

                    if (katItem.isFieldPresent("multitree")) {
                        fMultitree = katItem.parseInteger("multitree") > 0;
                        nExpectedItems += 1;
                    }

                    if (katItem.isFieldPresent("otsalgid")) {
                        otsAlgId = @intCast(katItem.parseInteger("otsalgid"));
                        nExpectedItems += 1;
                    }

                    h.check3(katItem.dataItems.items.len == nExpectedItems, "Incorrect number of items in Hbs signature verification record ending at line {d}", katHbs.kat.m_line);

                    const algId: u32 = @intCast(katItem.parseInteger("algid"));
                    const katPrvkey = katItem.parseData("prvkey");
                    defer std.heap.c_allocator.free(katPrvkey);

                    testHbsKeygen(
                        pHbsMultiImp.?,
                        algId,
                        otsAlgId,
                        fMultitree,
                        katPrvkey,
                        katHbs.kat.m_line,
                    );
                }

                continue;
            }

            h.fatal("Unknown data record ending at line {d}", .{katHbs.kat.m_line});
        }
    }

    if (doneAnything) {
        h.print("\n");
    }
}

fn testXmssCustomParameters() void {
    var params: SYMCRYPT_XMSS_PARAMS = undefined;
    var scError: u32 = SYMCRYPT_NO_ERROR;
    const msg = [_]u8{ 0x00, 0x01, 0x03, 0x04 };
    const pHash = SymCryptSha256Algorithm;

    var w: u8 = 1;
    while (w <= 8) : (w <<= 1) {
        var treeH: u8 = 1;
        while (treeH <= 4) : (treeH += 1) {
            SymCryptWipe(@ptrCast(&params), @sizeOf(SYMCRYPT_XMSS_PARAMS));

            scError = SymCryptXmssSetParams(
                &params,
                0,
                pHash,
                SYMCRYPT_SHA256_RESULT_SIZE,
                w,
                treeH,
                1,
                SYMCRYPT_SHA256_RESULT_SIZE,
            );
            h.check(scError == SYMCRYPT_NO_ERROR, "?");

            const pKey = SymCryptXmsskeyAllocate(&params, 0);
            h.check(pKey != null, "?");

            scError = SymCryptXmsskeyGenerate(pKey.?, 0);
            h.check(scError == SYMCRYPT_NO_ERROR, "?");

            const cbSignature = SymCryptXmssSizeofSignatureFromParams(&params);
            const pbSignature = std.heap.page_allocator.alloc(u8, cbSignature) catch unreachable;
            defer std.heap.page_allocator.free(pbSignature);

            const numKeys: u32 = @as(u32, 1) << @intCast(treeH);
            for (0..numKeys) |_| {
                scError = SymCryptXmssSign(pKey.?, &msg, msg.len, 0, pbSignature.ptr, cbSignature);
                h.check(scError == SYMCRYPT_NO_ERROR, "?");

                scError = SymCryptXmssVerify(pKey.?, &msg, msg.len, 0, pbSignature.ptr, cbSignature);
                h.check(scError == SYMCRYPT_NO_ERROR, "?");

                const nModifyPos: usize = @intCast(rng.g_rng.uint32() % @as(u32, @intCast(cbSignature)));
                pbSignature[nModifyPos] ^= 1;

                scError = SymCryptXmssVerify(pKey.?, &msg, msg.len, 0, pbSignature.ptr, cbSignature);
                h.check(scError != SYMCRYPT_NO_ERROR, "?");
            }

            scError = SymCryptXmssSign(pKey.?, &msg, msg.len, 0, pbSignature.ptr, cbSignature);
            h.check(scError == SYMCRYPT_HBS_NO_OTS_KEYS_LEFT, "?");

            SymCryptXmsskeyFree(pKey.?);
        }
    }
}

fn testLmsCustomParameters() void {
    var params: SYMCRYPT_LMS_PARAMS = undefined;
    var scError: u32 = SYMCRYPT_NO_ERROR;
    const msg = [_]u8{ 0x61, 0x62, 0x63 };
    const pHash = SymCryptSha256Algorithm;

    var w: u8 = 1;
    while (w <= 8) : (w <<= 1) {
        var u: u32 = 0;
        var v: u32 = 0;
        SymCryptHbsGetWinternitzLengths(
            SYMCRYPT_SHA256_RESULT_SIZE,
            w,
            &u,
            &v,
        );

        var treeH: u8 = 1;
        while (treeH <= 4) : (treeH += 1) {
            SymCryptWipe(@ptrCast(&params), @sizeOf(SYMCRYPT_LMS_PARAMS));
            scError = SymCryptLmsSetParams(
                &params,
                0,
                0,
                pHash,
                SYMCRYPT_SHA256_RESULT_SIZE,
                treeH,
                w,
            );
            h.check(scError == SYMCRYPT_NO_ERROR, "?");

            const pKey = SymCryptLmskeyAllocate(&params, 0);
            h.check(pKey != null, "?");

            scError = SymCryptLmskeyGenerate(pKey.?, 0);
            h.check(scError == SYMCRYPT_NO_ERROR, "?");

            const cbSignature = SymCryptLmsSizeofSignatureFromParams(&params);
            const pbSignature = std.heap.page_allocator.alloc(u8, cbSignature) catch unreachable;
            defer std.heap.page_allocator.free(pbSignature);

            const numKeys: u32 = @as(u32, 1) << @intCast(treeH);
            for (0..numKeys) |_| {
                scError = SymCryptLmsSign(pKey.?, &msg, msg.len, 0, pbSignature.ptr, cbSignature);
                h.check(scError == SYMCRYPT_NO_ERROR, "?");

                scError = SymCryptLmsVerify(pKey.?, &msg, msg.len, 0, pbSignature.ptr, cbSignature);
                h.check(scError == SYMCRYPT_NO_ERROR, "?");

                const nModifyPos: usize = @intCast(rng.g_rng.uint32() % @as(u32, @intCast(cbSignature)));
                pbSignature[nModifyPos] ^= 1;

                scError = SymCryptLmsVerify(pKey.?, &msg, msg.len, 0, pbSignature.ptr, cbSignature);
                h.check(scError != SYMCRYPT_NO_ERROR, "?");
            }

            scError = SymCryptLmsSign(pKey.?, &msg, msg.len, 0, pbSignature.ptr, cbSignature);
            h.check(scError == SYMCRYPT_HBS_NO_OTS_KEYS_LEFT, "?");

            SymCryptLmskeyFree(pKey.?);
        }
    }
}

fn testXmssImportExport() void {
    var params: SYMCRYPT_XMSS_PARAMS = undefined;
    var cbPrivateKey: usize = 0;
    var cbPublicKey: usize = 0;
    const msg = [_]u8{0x01};

    var scError = SymCryptXmssParamsFromAlgId(SYMCRYPT_XMSS_SHA2_10_256, &params);
    h.check(scError == SYMCRYPT_NO_ERROR, "?");

    var pKeyPrivate = SymCryptXmsskeyAllocate(&params, 0);
    h.check(pKeyPrivate != null, "?");
    scError = SymCryptXmsskeyGenerate(pKeyPrivate.?, 0);
    h.check(scError == SYMCRYPT_NO_ERROR, "?");

    scError = SymCryptXmssSizeofKeyBlobFromParams(&params, SYMCRYPT_XMSSKEY_TYPE_PUBLIC, &cbPublicKey);
    h.check(scError == SYMCRYPT_NO_ERROR, "?");

    scError = SymCryptXmssSizeofKeyBlobFromParams(&params, SYMCRYPT_XMSSKEY_TYPE_PRIVATE, &cbPrivateKey);
    h.check(scError == SYMCRYPT_NO_ERROR, "?");

    const pbPrivateKeyBlob = std.heap.page_allocator.alloc(u8, cbPrivateKey) catch unreachable;
    defer std.heap.page_allocator.free(pbPrivateKeyBlob);
    scError = SymCryptXmsskeyGetValue(pKeyPrivate.?, SYMCRYPT_XMSSKEY_TYPE_PRIVATE, 0, pbPrivateKeyBlob.ptr, cbPrivateKey);
    h.check(scError == SYMCRYPT_NO_ERROR, "?");

    const pbPublicKeyBlob = std.heap.page_allocator.alloc(u8, cbPublicKey) catch unreachable;
    defer std.heap.page_allocator.free(pbPublicKeyBlob);
    scError = SymCryptXmsskeyGetValue(pKeyPrivate.?, SYMCRYPT_XMSSKEY_TYPE_PUBLIC, 0, pbPublicKeyBlob.ptr, cbPublicKey);
    h.check(scError == SYMCRYPT_NO_ERROR, "?");

    const cbSignature = SymCryptXmssSizeofSignatureFromParams(&params);
    const pbSignature = std.heap.page_allocator.alloc(u8, cbSignature) catch unreachable;
    defer std.heap.page_allocator.free(pbSignature);

    scError = SymCryptXmssSign(pKeyPrivate.?, &msg, msg.len, 0, pbSignature.ptr, cbSignature);
    h.check(scError == SYMCRYPT_NO_ERROR, "?");
    scError = SymCryptXmssVerify(pKeyPrivate.?, &msg, msg.len, 0, pbSignature.ptr, cbSignature);
    h.check(scError == SYMCRYPT_NO_ERROR, "?");

    SymCryptXmsskeyFree(pKeyPrivate.?);

    pKeyPrivate = SymCryptXmsskeyAllocate(&params, 0);
    h.check(pKeyPrivate != null, "?");
    scError = SymCryptXmsskeySetValue(pbPrivateKeyBlob.ptr, cbPrivateKey, SYMCRYPT_XMSSKEY_TYPE_PRIVATE, 0, pKeyPrivate.?);
    h.check(scError == SYMCRYPT_NO_ERROR, "?");

    const pbSignature2 = std.heap.page_allocator.alloc(u8, cbSignature) catch unreachable;
    defer std.heap.page_allocator.free(pbSignature2);

    scError = SymCryptXmssSign(pKeyPrivate.?, &msg, msg.len, 0, pbSignature2.ptr, cbSignature);
    h.check(scError == SYMCRYPT_NO_ERROR, "?");
    h.check(std.mem.eql(u8, pbSignature, pbSignature2), "?");

    SymCryptXmsskeyFree(pKeyPrivate.?);

    const pKeyPublic = SymCryptXmsskeyAllocate(&params, 0);
    h.check(pKeyPublic != null, "?");
    scError = SymCryptXmsskeySetValue(pbPublicKeyBlob.ptr, cbPublicKey, SYMCRYPT_XMSSKEY_TYPE_PUBLIC, 0, pKeyPublic.?);
    h.check(scError == SYMCRYPT_NO_ERROR, "?");

    scError = SymCryptXmssVerify(pKeyPublic.?, &msg, msg.len, 0, pbSignature.ptr, cbSignature);
    h.check(scError == SYMCRYPT_NO_ERROR, "?");

    SymCryptXmsskeyFree(pKeyPublic.?);
}

fn testLmsImportExport() void {
    var params: SYMCRYPT_LMS_PARAMS = undefined;
    const msg = [_]u8{0x01};

    var scError = SymCryptLmsParamsFromAlgId(SYMCRYPT_LMS_SHA256_M32_H5, SYMCRYPT_LMS_OTS_SHA256_N32_W8, &params);
    h.check(scError == SYMCRYPT_NO_ERROR, "?");

    var pKeyPrivate = SymCryptLmskeyAllocate(&params, 0);
    h.check(pKeyPrivate != null, "?");
    scError = SymCryptLmskeyGenerate(pKeyPrivate.?, 0);
    h.check(scError == SYMCRYPT_NO_ERROR, "?");

    const cbPublicKey: usize = 24 + params.cbHashOutput;
    const cbPrivateKey: usize = 28 + 2 * params.cbHashOutput;

    const pbPrivateKeyBlob = std.heap.page_allocator.alloc(u8, cbPrivateKey) catch unreachable;
    defer std.heap.page_allocator.free(pbPrivateKeyBlob);
    scError = SymCryptLmskeyGetValue(pKeyPrivate.?, SYMCRYPT_LMSKEY_TYPE_PRIVATE, 0, pbPrivateKeyBlob.ptr, cbPrivateKey);
    h.check(scError == SYMCRYPT_NO_ERROR, "?");

    const pbPublicKeyBlob = std.heap.page_allocator.alloc(u8, cbPublicKey) catch unreachable;
    defer std.heap.page_allocator.free(pbPublicKeyBlob);
    scError = SymCryptLmskeyGetValue(pKeyPrivate.?, SYMCRYPT_LMSKEY_TYPE_PUBLIC, 0, pbPublicKeyBlob.ptr, cbPublicKey);
    h.check(scError == SYMCRYPT_NO_ERROR, "?");

    const cbSignature = SymCryptLmsSizeofSignatureFromParams(&params);
    const pbSignature = std.heap.page_allocator.alloc(u8, cbSignature) catch unreachable;
    defer std.heap.page_allocator.free(pbSignature);

    scError = SymCryptLmsSign(pKeyPrivate.?, &msg, msg.len, 0, pbSignature.ptr, cbSignature);
    h.check(scError == SYMCRYPT_NO_ERROR, "?");
    scError = SymCryptLmsVerify(pKeyPrivate.?, &msg, msg.len, 0, pbSignature.ptr, cbSignature);
    h.check(scError == SYMCRYPT_NO_ERROR, "?");

    SymCryptLmskeyFree(pKeyPrivate.?);

    pKeyPrivate = SymCryptLmskeyAllocate(&params, 0);
    h.check(pKeyPrivate != null, "?");
    scError = SymCryptLmskeySetValue(pbPrivateKeyBlob.ptr, cbPrivateKey, SYMCRYPT_LMSKEY_TYPE_PRIVATE, 0, pKeyPrivate.?);
    h.check(scError == SYMCRYPT_NO_ERROR, "?");

    const pbSignature2 = std.heap.page_allocator.alloc(u8, cbSignature) catch unreachable;
    defer std.heap.page_allocator.free(pbSignature2);

    scError = SymCryptLmsSign(pKeyPrivate.?, &msg, msg.len, 0, pbSignature2.ptr, cbSignature);
    h.check(scError == SYMCRYPT_NO_ERROR, "?");

    SymCryptLmskeyFree(pKeyPrivate.?);

    const pKeyPublic = SymCryptLmskeyAllocate(&params, 0);
    h.check(pKeyPublic != null, "?");
    scError = SymCryptLmskeySetValue(pbPublicKeyBlob.ptr, cbPublicKey, SYMCRYPT_LMSKEY_TYPE_PUBLIC, 0, pKeyPublic.?);
    h.check(scError == SYMCRYPT_NO_ERROR, "?");

    scError = SymCryptLmsVerify(pKeyPublic.?, &msg, msg.len, 0, pbSignature.ptr, cbSignature);
    h.check(scError == SYMCRYPT_NO_ERROR, "?");

    SymCryptLmskeyFree(pKeyPublic.?);
}

fn testXmssMultitree() void {
    var params: SYMCRYPT_XMSS_PARAMS = undefined;
    var scError: u32 = SYMCRYPT_NO_ERROR;
    const msg = [_]u8{ 0x00, 0x01, 0x03, 0x04 };
    const pHash = SymCryptSha256Algorithm;
    const H: u8 = 6;
    const LayerHeights = [_]u8{ 1, 2, 3 };

    for (LayerHeights) |lh| {
        scError = SymCryptXmssSetParams(
            &params,
            0,
            pHash,
            SYMCRYPT_SHA256_RESULT_SIZE,
            4,
            H,
            H / lh,
            SYMCRYPT_SHA256_RESULT_SIZE,
        );
        h.check(scError == SYMCRYPT_NO_ERROR, "?");

        const pKey = SymCryptXmsskeyAllocate(&params, 0);
        h.check(pKey != null, "?");

        scError = SymCryptXmsskeyGenerate(pKey.?, 0);
        h.check(scError == SYMCRYPT_NO_ERROR, "?");

        const cbSignature = SymCryptXmssSizeofSignatureFromParams(&params);
        const pbSignature = std.heap.page_allocator.alloc(u8, cbSignature) catch unreachable;
        defer std.heap.page_allocator.free(pbSignature);

        const numKeys: u32 = @as(u32, 1) << H;
        for (0..numKeys) |_| {
            scError = SymCryptXmssSign(pKey.?, &msg, msg.len, 0, pbSignature.ptr, cbSignature);
            h.check(scError == SYMCRYPT_NO_ERROR, "?");

            scError = SymCryptXmssVerify(pKey.?, &msg, msg.len, 0, pbSignature.ptr, cbSignature);
            h.check(scError == SYMCRYPT_NO_ERROR, "?");

            const nModifyPos: usize = @intCast(rng.g_rng.uint32() % @as(u32, @intCast(cbSignature)));
            pbSignature[nModifyPos] ^= 1;

            scError = SymCryptXmssVerify(pKey.?, &msg, msg.len, 0, pbSignature.ptr, cbSignature);
            h.check(scError != SYMCRYPT_NO_ERROR, "?");
        }

        scError = SymCryptXmssSign(pKey.?, &msg, msg.len, 0, pbSignature.ptr, cbSignature);
        h.check(scError == SYMCRYPT_HBS_NO_OTS_KEYS_LEFT, "?");

        SymCryptXmsskeyFree(pKey.?);
    }
}

fn testXmssMultitreeLargeTotalHeight() void {
    var params: SYMCRYPT_XMSS_PARAMS = undefined;
    var scError: u32 = SYMCRYPT_NO_ERROR;
    const msg = [_]u8{ 0x00, 0x01, 0x03, 0x04 };
    const pHash = SymCryptSha256Algorithm;

    scError = SymCryptXmssSetParams(
        &params,
        0,
        pHash,
        SYMCRYPT_SHA256_RESULT_SIZE,
        4,
        32,
        32,
        SYMCRYPT_SHA256_RESULT_SIZE,
    );
    h.check(scError == SYMCRYPT_NO_ERROR, "?");

    const pKey = SymCryptXmsskeyAllocate(&params, 0);
    h.check(pKey != null, "?");

    scError = SymCryptXmsskeyGenerate(pKey.?, 0);
    h.check(scError == SYMCRYPT_NO_ERROR, "?");

    const cbSignature = SymCryptXmssSizeofSignatureFromParams(&params);
    const pbSignature = std.heap.page_allocator.alloc(u8, cbSignature) catch unreachable;
    defer std.heap.page_allocator.free(pbSignature);

    scError = SymCryptXmssSign(pKey.?, &msg, msg.len, 0, pbSignature.ptr, cbSignature);
    h.check(scError == SYMCRYPT_NO_ERROR, "?");

    scError = SymCryptXmssVerify(pKey.?, &msg, msg.len, 0, pbSignature.ptr, cbSignature);
    h.check(scError == SYMCRYPT_NO_ERROR, "?");

    const nModifyPos: usize = @intCast(rng.g_rng.uint32() % @as(u32, @intCast(cbSignature)));
    pbSignature[nModifyPos] ^= 1;

    scError = SymCryptXmssVerify(pKey.?, &msg, msg.len, 0, pbSignature.ptr, cbSignature);
    h.check(scError != SYMCRYPT_NO_ERROR, "?");

    SymCryptXmsskeyFree(pKey.?);
}

fn testXmss() void {
    testWinternitzLengths();

    testXmssCustomParameters();

    testXmssMultitree();

    testXmssMultitreeLargeTotalHeight();

    testXmssImportExport();
}

fn testLms() void {
    testWinternitzLengths();

    testLmsCustomParameters();

    testLmsImportExport();
}

pub export fn testHbs() callconv(.c) void {
    if (!h.isAlgorithmPresent("Xmss", 0) and !h.isAlgorithmPresent("Lms", 0)) {
        return;
    }

    testXmss();
    h.check3(cb.g_nOutstandingCheckedAllocs == 0, "Memory leak {d} outstanding", cb.g_nOutstandingCheckedAllocs);

    testLms();
    h.check3(cb.g_nOutstandingCheckedAllocs == 0, "Memory leak {d} outstanding", cb.g_nOutstandingCheckedAllocs);

    testHbsKats();
    h.check3(cb.g_nOutstandingCheckedAllocs == 0, "Memory leak {d} outstanding", cb.g_nOutstandingCheckedAllocs);
}
