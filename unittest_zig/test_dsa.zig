// Copyright (c) Microsoft Corporation. Licensed under the MIT license.

const std = @import("std");
const h = @import("main_harness.zig");
const rng = @import("rng.zig");
const kat = @import("kat.zig");
const rm = @import("result_merge.zig");
const dh = @import("test_dh.zig");

const DLKEY_MAXKEYSIZE = dh.DLKEY_MAXKEYSIZE;
const MAX_DSA_SIG_SIZE: usize = 2 * DLKEY_MAXKEYSIZE;

const STATUS_SUCCESS: u32 = 0;
const STATUS_NOT_SUPPORTED: u32 = 0xC00000BB;
const STATUS_INVALID_SIGNATURE: u32 = 0xC000A000;

const SYMCRYPT_DLGROUP_FIPS_NONE: i32 = 0;

extern fn SymCryptWipe(pbData: [*]u8, cbData: usize) callconv(.c) void;
extern fn SymCryptCallbackRandom(pbBuffer: [*]u8, cbBuffer: usize) callconv(.c) void;

extern fn scTestGetAllImplementations(
    algNamePtr: [*]const u8,
    algNameLen: usize,
    outImps: [*]*anyopaque,
    maxImps: usize,
) callconv(.c) usize;
extern fn scTestImpIncResults(impPtr: *anyopaque) callconv(.c) void;
extern fn scTestResultMergeAddAlgImp(
    handle: *rm.ResultMerge,
    impPtr: *anyopaque,
    pbData: [*]const u8,
    cbData: usize,
) callconv(.c) void;
extern fn scTestDsaImpSetKey(impPtr: *anyopaque, pcKeyBlob: ?*const dh.DlkeyTestBlob) callconv(.c) u32;
extern fn scTestDsaImpSign(
    impPtr: *anyopaque,
    pbHash: [*]const u8,
    cbHash: usize,
    pbSig: [*]u8,
    cbSig: usize,
) callconv(.c) u32;
extern fn scTestDsaImpVerify(
    impPtr: *anyopaque,
    pbHash: [*]const u8,
    cbHash: usize,
    pbSig: [*]const u8,
    cbSig: usize,
) callconv(.c) u32;

const DsaMultiImp = struct {
    comps: [16]*anyopaque = undefined,
    n_comps: usize = 0,
    imps: [16]*anyopaque = undefined,
    n_imps: usize = 0,

    fn init(algName: []const u8) ?DsaMultiImp {
        if (!h.isAlgorithmPresent(algName.ptr, 0)) {
            return null;
        }
        var self = DsaMultiImp{};
        self.n_comps = scTestGetAllImplementations(algName.ptr, algName.len, &self.comps, self.comps.len);
        if (self.n_comps == 0) {
            return null;
        }
        return self;
    }

    fn deinit(self: *DsaMultiImp) void {
        for (self.comps[0..self.n_comps]) |imp| {
            scTestImpIncResults(imp);
        }
    }

    fn setKey(self: *DsaMultiImp, pcKeyBlob: ?*const dh.DlkeyTestBlob) u32 {
        self.n_imps = 0;
        for (self.comps[0..self.n_comps]) |imp| {
            if (scTestDsaImpSetKey(imp, pcKeyBlob) == STATUS_SUCCESS) {
                self.imps[self.n_imps] = imp;
                self.n_imps += 1;
            }
        }
        return if (self.n_imps == 0) STATUS_NOT_SUPPORTED else STATUS_SUCCESS;
    }

    fn sign(self: *DsaMultiImp, pbHash: [*]const u8, cbHash: usize, pbSig: [*]u8, cbSig: usize) u32 {
        var sig: [MAX_DSA_SIG_SIZE]u8 = undefined;
        var nSigs: u32 = 0;

        for (self.imps[0..self.n_imps]) |imp| {
            const status = scTestDsaImpSign(imp, pbHash, cbHash, &sig, cbSig);
            if (status == STATUS_NOT_SUPPORTED) {
                continue;
            }
            h.check(status == STATUS_SUCCESS, "Failure during DSA Sign");
            for (self.imps[0..self.n_imps]) |imp_v| {
                const v_status = scTestDsaImpVerify(imp_v, pbHash, cbHash, &sig, cbSig);
                if (v_status == STATUS_NOT_SUPPORTED) {
                    continue;
                }
                h.check(v_status == STATUS_SUCCESS, "DSA sig verification failure");
            }
            nSigs += 1;
            if ((rng.scTestRngUint32(&rng.g_rng) % nSigs) == 0) {
                @memcpy(pbSig[0..cbSig], sig[0..cbSig]);
            }
        }
        return STATUS_SUCCESS;
    }

    fn verify(self: *DsaMultiImp, pbHash: [*]const u8, cbHash: usize, pbSig: [*]const u8, cbSig: usize) u32 {
        var bBuf: [MAX_DSA_SIG_SIZE]u8 = undefined;
        const res = rm.scTestResultMergeCreate() orelse h.fatal("OOM", .{});
        defer rm.scTestResultMergeDestroy(res);

        for (self.imps[0..self.n_imps]) |imp| {
            SymCryptWipe(&bBuf, bBuf.len);
            const status = scTestDsaImpVerify(imp, pbHash, cbHash, pbSig, cbSig);
            scTestResultMergeAddAlgImp(res, imp, @ptrCast(&status), @sizeOf(u32));
        }

        rm.scTestResultMergeGetResult(res, &bBuf, @sizeOf(u32), 1);
        return std.mem.bytesToValue(u32, bBuf[0..4]);
    }
};

fn testDsaVerify(
    pDsa: *DsaMultiImp,
    pKey: *const dh.DlkeyTestBlob,
    pbHash: [*]const u8,
    cbHash: usize,
    pbSig: [*]const u8,
    cbSig: usize,
    line: i64,
) void {
    var abSig: [MAX_DSA_SIG_SIZE]u8 = undefined;

    var ntStatus = pDsa.setKey(pKey);
    h.check3(ntStatus == STATUS_SUCCESS, "Failed to set key at line %lld", line);

    ntStatus = pDsa.verify(pbHash, cbHash, pbSig, cbSig);
    h.check3(ntStatus == STATUS_SUCCESS, "Verification failed at line %lld", line);

    @memcpy(abSig[0..cbSig], pbSig[0..cbSig]);
    const t: usize = rng.scTestRngUint32(&rng.g_rng) % cbSig;
    abSig[t] ^= @as(u8, 1) << @intCast(rng.scTestRngUint32(&rng.g_rng) & 7);

    ntStatus = pDsa.verify(pbHash, cbHash, &abSig, cbSig);
    h.check3(ntStatus != STATUS_SUCCESS, "Bad signature verified at line %lld", line);

    ntStatus = pDsa.setKey(null);
    h.check3(ntStatus == STATUS_SUCCESS, "Failed to clear key at line %lld", line);
}

fn testDsaSingle(
    pDsa: *DsaMultiImp,
    pKey: *const dh.DlkeyTestBlob,
    pbHash: [*]const u8,
    cbHash: usize,
    pbSig: [*]const u8,
    cbSig: usize,
    line: i64,
) void {
    var abSig: [MAX_DSA_SIG_SIZE]u8 = undefined;

    testDsaVerify(pDsa, pKey, pbHash, cbHash, pbSig, cbSig, line);

    var ntStatus = pDsa.setKey(pKey);
    h.check3(ntStatus == STATUS_SUCCESS, "Failed to set key at line %lld", line);

    ntStatus = pDsa.sign(pbHash, cbHash, &abSig, cbSig);
    h.check3(ntStatus == STATUS_SUCCESS, "Error signing message at line %lld", line);

    testDsaVerify(pDsa, pKey, pbHash, cbHash, &abSig, cbSig, line);
    _ = pDsa.setKey(null);
}

fn testDsaRandom(pDsa: *DsaMultiImp) void {
    var key: dh.DlkeyTestBlob = std.mem.zeroes(dh.DlkeyTestBlob);
    var abSig: [2 * DLKEY_MAXKEYSIZE]u8 = undefined;
    var abHash: [128]u8 = undefined;

    var i: u32 = dh.g_nDhNamedGroups;
    while (i < dh.g_nDlgroups) : (i += 1) {
        const pGroup = &dh.g_DlGroup[i];
        if (pGroup.fHasPrimeQ == 0) {
            continue;
        }

        dh.dlgroupRandomKey(pGroup, &key, 0);

        if (key.fPrivateModP != 0) {
            continue;
        }

        if (pDsa.setKey(&key) == STATUS_NOT_SUPPORTED) {
            continue;
        }

        const cbHash: usize = 1 + (rng.scTestRngUint32(&rng.g_rng) % @sizeOf(@TypeOf(abHash)));
        const cbSig: usize = 2 * pGroup.cbPrimeQ;

        SymCryptCallbackRandom(&abHash, cbHash);

        for (pDsa.imps[0..pDsa.n_imps]) |imp| {
            var ntStatus = scTestDsaImpSign(imp, &abHash, cbHash, &abSig, cbSig);
            h.check(ntStatus == STATUS_SUCCESS, "Failure during DSA signing");

            ntStatus = pDsa.verify(&abHash, cbHash, &abSig, cbSig);
            h.check(ntStatus == STATUS_SUCCESS, "Failure during DSA signature verification");

            abSig[rng.scTestRngUint32(&rng.g_rng) % cbSig] ^= @intCast(1 + (rng.scTestRngUint32(&rng.g_rng) % 255));

            ntStatus = pDsa.verify(&abHash, cbHash, &abSig, cbSig);
            h.check(ntStatus != STATUS_SUCCESS, "Success during modified DSA signature verification");
        }
    }

    h.check(pDsa.setKey(null) == STATUS_SUCCESS, "Failed to clear key");
}

fn testDsaKats() void {
    const pResource = h.findDataItem("kat_dsa.dat") orelse h.fatal("kat_dsa.dat not found", .{});
    var katDsa = kat.KatData.init(pResource.name, pResource.pbData, pResource.cbData);
    var katItem: kat.KatItem = .{};
    defer katItem.deinitDataItems();

    var sep: []const u8 = "";
    var doneAnything = false;

    var pDsa = DsaMultiImp.init("Dsa");
    defer {
        if (pDsa) |*dsa| {
            dsa.deinit();
        }
    }

    var dlGroup: dh.DlgroupTestBlob = std.mem.zeroes(dh.DlgroupTestBlob);
    var dlKey: dh.DlkeyTestBlob = std.mem.zeroes(dh.DlkeyTestBlob);

    while (true) {
        katDsa.getKatItem(&katItem);
        const ulLine: i64 = katItem.line;

        if (katItem.itemType == kat.KAT_TYPE_END) {
            break;
        }

        if (katItem.itemType == kat.KAT_TYPE_CATEGORY) {
            if (pDsa != null) {
                h.ziprint("{s}{s}", .{ sep, katItem.categoryName() });
                sep = ", ";
                doneAnything = true;
            }
        }

        if (katItem.itemType == kat.KAT_TYPE_DATASET and pDsa != null) {
            if (kat.katIsFieldPresent(&katItem, "p")) {
                SymCryptWipe(@ptrCast(&dlGroup), @sizeOf(dh.DlgroupTestBlob));
                const bP = kat.katParseData(&katItem, "p");
                defer bP.deinit();
                const bQ = kat.katParseData(&katItem, "q");
                defer bQ.deinit();
                const bG = kat.katParseData(&katItem, "g");
                defer bG.deinit();
                const bX = kat.katParseData(&katItem, "x");
                defer bX.deinit();
                const bH = kat.katParseData(&katItem, "h");
                defer bH.deinit();
                const bHash = kat.katParseData(&katItem, "hash");
                defer bHash.deinit();
                const bSig = kat.katParseData(&katItem, "sig");
                defer bSig.deinit();

                h.check3(bP.cbData <= DLKEY_MAXKEYSIZE, "P array too large at line %lld", ulLine);
                h.check3(bQ.cbData <= DLKEY_MAXKEYSIZE, "Q array too large at line %lld", ulLine);
                h.check3(bG.cbData == bP.cbData, "G and P didn't match at line %lld", ulLine);
                h.check3(bH.cbData == bP.cbData, "H and P didn't match at line %lld", ulLine);

                dlGroup.nBitsP = @intCast(bP.cbData * 8);
                dlGroup.cbPrimeP = @intCast(bP.cbData);
                dlGroup.cbPrimeQ = @intCast(bQ.cbData);
                dlGroup.fipsStandard = SYMCRYPT_DLGROUP_FIPS_NONE;
                dlGroup.pHashAlgorithm = null;
                dlGroup.cbSeed = 0;
                dlGroup.genCounter = 0;
                dlGroup.fHasPrimeQ = 1;
                dlGroup.pcstrHashAlgName = null;
                @memcpy(dlGroup.abPrimeP[0..bP.cbData], bP.pbData[0..bP.cbData]);
                @memcpy(dlGroup.abPrimeQ[0..bQ.cbData], bQ.pbData[0..bQ.cbData]);
                @memcpy(dlGroup.abGenG[0..bG.cbData], bG.pbData[0..bG.cbData]);

                dlKey = std.mem.zeroes(dh.DlkeyTestBlob);
                dlKey.pGroup = &dlGroup;
                dlKey.nBitsPriv = 0;
                dlKey.cbPrivKey = @intCast(bX.cbData);
                dlKey.fPrivateModP = 0;
                @memcpy(dlKey.abPubKey[0..bH.cbData], bH.pbData[0..bH.cbData]);
                @memcpy(dlKey.abPrivKey[0..bX.cbData], bX.pbData[0..bX.cbData]);

                testDsaSingle(&pDsa.?, &dlKey, bHash.pbData, bHash.cbData, bSig.pbData, bSig.cbData, ulLine);
                continue;
            }

            if (kat.katIsFieldPresent(&katItem, "rnd")) {
                dh.generateDlGroups();
                testDsaRandom(&pDsa.?);
                continue;
            }

            h.fatal("Unknown data record at line {d}", .{ulLine});
        }
    }

    if (pDsa) |*dsa| {
        testDsaRandom(dsa);
    }

    if (doneAnything) {
        h.ziprint("\n", .{});
    }
}

pub export fn testDsaAlgorithms() callconv(.c) void {
    if (!h.isAlgorithmPresent("Dsa", 0)) {
        return;
    }
    dh.generateDlGroups();
    testDsaKats();
}
