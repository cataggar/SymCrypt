// Copyright (c) Microsoft Corporation. Licensed under the MIT license.

const std = @import("std");
const h = @import("main_harness.zig");
const rng = @import("rng.zig");
const kat = @import("kat.zig");
const rm = @import("result_merge.zig");

pub const DLKEY_MAXKEYSIZE: usize = 1024;
pub const MAX_N_DLGROUPS: usize = 50;

const STATUS_SUCCESS: u32 = 0;
const STATUS_NOT_SUPPORTED: u32 = 0xC00000BB;

const SYMCRYPT_NO_ERROR: u32 = 0;
const SYMCRYPT_INVALID_ARGUMENT: u32 = 0x800e;
const SYMCRYPT_AUTHENTICATION_FAILURE: u32 = 0x8007;
const SYMCRYPT_FIPS_FAILURE: u32 = 0x8009;

const SYMCRYPT_NUMBER_FORMAT_LSB_FIRST: i32 = 1;
const SYMCRYPT_NUMBER_FORMAT_MSB_FIRST: i32 = 2;

const SYMCRYPT_DLGROUP_FIPS_NONE: i32 = 0;
const SYMCRYPT_DLGROUP_FIPS_186_2: i32 = 1;
const SYMCRYPT_DLGROUP_FIPS_186_3: i32 = 2;
const SYMCRYPT_DLGROUP_FIPS_LATEST: i32 = 2;

const SYMCRYPT_DLGROUP_DH_SAFEPRIMES_NONE: i32 = 0;
const SYMCRYPT_DLGROUP_DH_SAFEPRIMETYPE_IKE_3526: i32 = 1;
const SYMCRYPT_DLGROUP_DH_SAFEPRIMETYPE_TLS_7919: i32 = 2;

const SYMCRYPT_FLAG_DLKEY_GEN_MODP: u32 = 0x01;
const SYMCRYPT_FLAG_KEY_NO_FIPS: u32 = 0x0100;
const SYMCRYPT_FLAG_KEY_MINIMAL_VALIDATION: u32 = 0x0200;
const SYMCRYPT_FLAG_DLKEY_VERIFY: u32 = 0x0800;
const SYMCRYPT_FLAG_DLKEY_DSA: u32 = 0x1000;
const SYMCRYPT_FLAG_DLKEY_DH: u32 = 0x2000;
const SYMCRYPT_FLAG_DLKEY_PRIVATE_MOD_P: u32 = 0x01;

pub const DlgroupTestBlob = extern struct {
    nBitsP: u32,
    cbPrimeP: u32,
    cbPrimeQ: u32,
    fipsStandard: i32,
    pHashAlgorithm: ?*const anyopaque,
    cbSeed: u32,
    genCounter: u32,
    fHasPrimeQ: u8,
    isSafePrimeGroup: u8,
    pcstrHashAlgName: ?[*:0]const u8,
    abPrimeP: [DLKEY_MAXKEYSIZE]u8,
    abPrimeQ: [DLKEY_MAXKEYSIZE]u8,
    abGenG: [DLKEY_MAXKEYSIZE]u8,
    abSeed: [DLKEY_MAXKEYSIZE]u8,
};

pub const DlkeyTestBlob = extern struct {
    pGroup: ?*const DlgroupTestBlob,
    nBitsPriv: u32,
    cbPrivKey: u32,
    abPubKey: [DLKEY_MAXKEYSIZE]u8,
    abPrivKey: [DLKEY_MAXKEYSIZE]u8,
    fPrivateModP: i32,
};

pub export var g_DlGroup: [MAX_N_DLGROUPS]DlgroupTestBlob = std.mem.zeroes([MAX_N_DLGROUPS]DlgroupTestBlob);
pub export var g_nDlgroups: u32 = 0;
pub export var g_nDhNamedGroups: u32 = 0;

extern const SymCryptSha1Algorithm: *const anyopaque;
extern const SymCryptSha256Algorithm: *const anyopaque;
extern const SymCryptSha384Algorithm: *const anyopaque;
extern const SymCryptSha512Algorithm: *const anyopaque;

extern fn SymCryptDlgroupAllocate(nBitsOfP: u32, nBitsOfQ: u32) callconv(.c) ?*anyopaque;
extern fn SymCryptDlgroupFree(pDlgroup: ?*anyopaque) callconv(.c) void;
extern fn SymCryptDlgroupGenerate(
    pHashAlgorithm: ?*const anyopaque,
    fipsStandard: i32,
    pDlgroup: ?*anyopaque,
) callconv(.c) u32;
extern fn SymCryptDlgroupSetValue(
    pbPrimeP: [*]const u8,
    cbPrimeP: usize,
    pbPrimeQ: ?[*]const u8,
    cbPrimeQ: usize,
    pbGenG: ?[*]const u8,
    cbGenG: usize,
    numFormat: i32,
    pHashAlgorithm: ?*const anyopaque,
    pbSeed: ?[*]const u8,
    cbSeed: usize,
    genCounter: u32,
    fipsStandard: i32,
    pDlgroup: ?*anyopaque,
) callconv(.c) u32;
extern fn SymCryptDlgroupSetValueSafePrime(
    dhSafePrimeType: i32,
    pDlgroup: ?*anyopaque,
) callconv(.c) u32;
extern fn SymCryptDlgroupGetValue(
    pcDlgroup: ?*const anyopaque,
    pbPrimeP: ?[*]u8,
    cbPrimeP: usize,
    pbPrimeQ: ?[*]u8,
    cbPrimeQ: usize,
    pbGenG: ?[*]u8,
    cbGenG: usize,
    numFormat: i32,
    ppHashAlgorithm: ?*?*const anyopaque,
    pbSeed: ?[*]u8,
    cbSeed: usize,
    pGenCounter: ?*u32,
) callconv(.c) u32;
extern fn SymCryptDlgroupGetSizes(
    pcDlgroup: ?*const anyopaque,
    pcbPrimeP: ?*usize,
    pcbPrimeQ: ?*usize,
    pcbGenG: ?*usize,
    pcbSeed: ?*usize,
) callconv(.c) void;
extern fn SymCryptDlgroupIsSame(
    pcDlgroup1: ?*const anyopaque,
    pcDlgroup2: ?*const anyopaque,
) callconv(.c) u32;

extern fn SymCryptDlkeyAllocate(pcDlgroup: ?*const anyopaque) callconv(.c) ?*anyopaque;
extern fn SymCryptDlkeyFree(pkDlkey: ?*anyopaque) callconv(.c) void;
extern fn SymCryptDlkeySetPrivateKeyLength(
    pkDlkey: ?*anyopaque,
    nBitsPriv: u32,
    flags: u32,
) callconv(.c) u32;
extern fn SymCryptDlkeyGenerate(flags: u32, pkDlkey: ?*anyopaque) callconv(.c) u32;
extern fn SymCryptDlkeySetValue(
    pbPrivateKey: ?[*]const u8,
    cbPrivateKey: usize,
    pbPublicKey: ?[*]const u8,
    cbPublicKey: usize,
    numFormat: i32,
    flags: u32,
    pkDlkey: ?*anyopaque,
) callconv(.c) u32;
extern fn SymCryptDlkeyGetValue(
    pcDlkey: ?*const anyopaque,
    pbPrivateKey: ?[*]u8,
    cbPrivateKey: usize,
    pbPublicKey: ?[*]u8,
    cbPublicKey: usize,
    numFormat: i32,
    flags: u32,
) callconv(.c) u32;
extern fn SymCryptDlkeySizeofPublicKey(pcDlkey: ?*const anyopaque) callconv(.c) u32;
extern fn SymCryptDlkeySizeofPrivateKey(pcDlkey: ?*const anyopaque) callconv(.c) u32;
extern fn SymCryptDhSecretAgreement(
    pkPrivate: ?*const anyopaque,
    pkPublic: ?*const anyopaque,
    numFormat: i32,
    flags: u32,
    pbAgreedSecret: [*]u8,
    cbAgreedSecret: usize,
) callconv(.c) u32;
extern fn SymCryptIntIsEqual(piSrc1: ?*const anyopaque, piSrc2: ?*const anyopaque) callconv(.c) u32;
extern fn SymCryptModElementIsEqual(
    pmMod: ?*const anyopaque,
    peSrc1: ?*const anyopaque,
    peSrc2: ?*const anyopaque,
) callconv(.c) u32;

extern fn SymCryptWipe(pbData: [*]u8, cbData: usize) callconv(.c) void;
extern fn SymCryptCallbackRandom(pbBuffer: [*]u8, cbBuffer: usize) callconv(.c) void;

extern fn scTestDlgroupIsSafePrime(pGroup: ?*const anyopaque) callconv(.c) u8;
extern fn scTestDlgroupNBitsOfQ(pGroup: ?*const anyopaque) callconv(.c) u32;
extern fn scTestDlgroupNBitsOfP(pGroup: ?*const anyopaque) callconv(.c) u32;
extern fn scTestDlgroupNMinBitsPriv(pGroup: ?*const anyopaque) callconv(.c) u32;
extern fn scTestDlgroupNDefaultBitsPriv(pGroup: ?*const anyopaque) callconv(.c) u32;
extern fn scTestDlgroupPmP(pGroup: ?*const anyopaque) callconv(.c) ?*const anyopaque;
extern fn scTestDlkeyFPrivateModQ(pkKey: ?*const anyopaque) callconv(.c) i32;
extern fn scTestDlkeyNBitsPriv(pkKey: ?*const anyopaque) callconv(.c) u32;
extern fn scTestDlkeyPiPrivateKey(pkKey: ?*const anyopaque) callconv(.c) ?*const anyopaque;
extern fn scTestDlkeyPePublicKey(pkKey: ?*const anyopaque) callconv(.c) ?*const anyopaque;
extern fn scTestDlgroupObjectFromTestBlob(pGroupBlob: *const DlgroupTestBlob) callconv(.c) ?*anyopaque;

extern fn scTestGetAllImplementations(
    algNamePtr: [*]const u8,
    algNameLen: usize,
    outImps: [*]*anyopaque,
    maxImps: usize,
) callconv(.c) usize;
extern fn scTestImpIncResults(impPtr: *anyopaque) callconv(.c) void;
extern fn scTestResultMergeAddAlgImp(
    handle: *anyopaque,
    impPtr: *anyopaque,
    pbData: [*]const u8,
    cbData: usize,
) callconv(.c) void;
extern fn scTestDhImpSetKey(impPtr: *anyopaque, pcKeyBlob: ?*const DlkeyTestBlob) callconv(.c) u32;
extern fn scTestDhImpSharedSecret(
    impPtr: *anyopaque,
    pcPubkey: *const DlkeyTestBlob,
    pbSecret: [*]u8,
    cbSecret: usize,
) callconv(.c) u32;

const DhNamedGroupSize = struct {
    nBitsOfP: u32,
    safePrimeEnum: i32,
};

const g_dhNamedGroupSizes = [_]DhNamedGroupSize{
    .{ .nBitsOfP = 2048, .safePrimeEnum = SYMCRYPT_DLGROUP_DH_SAFEPRIMETYPE_IKE_3526 },
    .{ .nBitsOfP = 3072, .safePrimeEnum = SYMCRYPT_DLGROUP_DH_SAFEPRIMETYPE_IKE_3526 },
    .{ .nBitsOfP = 4096, .safePrimeEnum = SYMCRYPT_DLGROUP_DH_SAFEPRIMETYPE_IKE_3526 },
    .{ .nBitsOfP = 2048, .safePrimeEnum = SYMCRYPT_DLGROUP_DH_SAFEPRIMETYPE_TLS_7919 },
    .{ .nBitsOfP = 3072, .safePrimeEnum = SYMCRYPT_DLGROUP_DH_SAFEPRIMETYPE_TLS_7919 },
    .{ .nBitsOfP = 4096, .safePrimeEnum = SYMCRYPT_DLGROUP_DH_SAFEPRIMETYPE_TLS_7919 },
};

const DlgroupTestSizes = struct {
    nBitsOfP: u32,
    nBitsOfQ: u32,
};

const g_dlgroupTestSizes = [_]DlgroupTestSizes{
    .{ .nBitsOfP = 512, .nBitsOfQ = 0 },
    .{ .nBitsOfP = 768, .nBitsOfQ = 0 },
    .{ .nBitsOfP = 999, .nBitsOfQ = 0 },
    .{ .nBitsOfP = 1024, .nBitsOfQ = 0 },
    .{ .nBitsOfP = 1536, .nBitsOfQ = 0 },
    .{ .nBitsOfP = 2048, .nBitsOfQ = 0 },
    .{ .nBitsOfP = 3072, .nBitsOfQ = 0 },
    .{ .nBitsOfP = 2000, .nBitsOfQ = 200 },
    .{ .nBitsOfP = 2048, .nBitsOfQ = 224 },
    .{ .nBitsOfP = 2048, .nBitsOfQ = 256 },
    .{ .nBitsOfP = 4096, .nBitsOfQ = 250 },
};

const HashEntry = struct {
    pHash: *const anyopaque,
    name: [*:0]const u8,
};

fn getTestHashes() [5]HashEntry {
    return [5]HashEntry{
        .{ .pHash = SymCryptSha1Algorithm, .name = "SHA1" },
        .{ .pHash = SymCryptSha256Algorithm, .name = "SHA256" },
        .{ .pHash = SymCryptSha384Algorithm, .name = "SHA384" },
        .{ .pHash = SymCryptSha512Algorithm, .name = "SHA512" },
        .{ .pHash = SymCryptSha512Algorithm, .name = "SHA512" },
    };
}

fn dlgroupClearTestBlob(pBlob: *DlgroupTestBlob) void {
    SymCryptWipe(@ptrCast(pBlob), @sizeOf(DlgroupTestBlob));
}

pub fn dlgroupTestBlobFromObject(pGroup: ?*const anyopaque, pBlob: *DlgroupTestBlob) void {
    var cbP: usize = 0;
    var cbQ: usize = 0;
    var cbG: usize = 0;
    var cbS: usize = 0;

    dlgroupClearTestBlob(pBlob);

    SymCryptDlgroupGetSizes(pGroup, &cbP, &cbQ, &cbG, &cbS);
    h.check(
        cbP <= DLKEY_MAXKEYSIZE and cbQ <= DLKEY_MAXKEYSIZE and cbG == cbP and cbS <= DLKEY_MAXKEYSIZE,
        "Invalid sizes",
    );

    pBlob.cbPrimeP = @intCast(cbP);
    pBlob.cbPrimeQ = @intCast(cbQ);
    pBlob.cbSeed = @intCast(cbS);
    pBlob.isSafePrimeGroup = scTestDlgroupIsSafePrime(pGroup);

    const scError = SymCryptDlgroupGetValue(
        pGroup,
        &pBlob.abPrimeP,
        cbP,
        &pBlob.abPrimeQ,
        cbQ,
        &pBlob.abGenG,
        cbG,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        &pBlob.pHashAlgorithm,
        &pBlob.abSeed,
        cbS,
        &pBlob.genCounter,
    );
    h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptDlgroupGetValue failed");
}

pub export fn dlgroupForSize(nBits: usize, forDiffieHellman: u8) callconv(.c) *DlgroupTestBlob {
    if (forDiffieHellman != 0) {
        var i: u32 = 0;
        while (i < g_nDhNamedGroups) : (i += 1) {
            if (g_DlGroup[i].nBitsP >= nBits) {
                return &g_DlGroup[i];
            }
        }
    }

    var i: u32 = g_nDhNamedGroups;
    while (i < g_nDlgroups) : (i += 1) {
        if (g_DlGroup[i].nBitsP >= nBits) {
            return &g_DlGroup[i];
        }
    }
    h.check(false, "No suitable DLGroup found");
    return &g_DlGroup[0];
}

pub export fn generateDlGroups() callconv(.c) void {
    if (g_nDlgroups > 0) {
        return;
    }

    h.ziprint("Generating DL groups", .{});
    const hashes = getTestHashes();

    for (g_dhNamedGroupSizes) |entry| {
        const pBlob = &g_DlGroup[g_nDlgroups];
        dlgroupClearTestBlob(pBlob);

        pBlob.nBitsP = entry.nBitsOfP;
        const pGroup = SymCryptDlgroupAllocate(pBlob.nBitsP, pBlob.nBitsP - 1);
        h.check(pGroup != null, "Failed to allocate dlgroup");

        const scError = SymCryptDlgroupSetValueSafePrime(entry.safePrimeEnum, pGroup);
        h.check(scError == SYMCRYPT_NO_ERROR, "Failed to set named safe-prime group");

        dlgroupTestBlobFromObject(pGroup, pBlob);
        pBlob.nBitsP = entry.nBitsOfP;
        pBlob.fipsStandard = SYMCRYPT_DLGROUP_FIPS_NONE;
        pBlob.fHasPrimeQ = 1;

        const pGroup2 = scTestDlgroupObjectFromTestBlob(pBlob);
        h.check(SymCryptDlgroupIsSame(pGroup, pGroup2) != 0, "Mismatch between original and recreated safe-prime group");

        SymCryptDlgroupFree(pGroup);
        SymCryptDlgroupFree(pGroup2);

        g_nDlgroups += 1;
        g_nDhNamedGroups += 1;
        h.ziprint(".", .{});
    }

    for (g_dlgroupTestSizes) |entry| {
        const pBlob = &g_DlGroup[g_nDlgroups];
        dlgroupClearTestBlob(pBlob);

        pBlob.nBitsP = entry.nBitsOfP;
        const nBitsQ: u32 = entry.nBitsOfQ;
        const pGroup = SymCryptDlgroupAllocate(pBlob.nBitsP, nBitsQ);
        h.check(pGroup != null, "Failed to allocate dlgroup");

        if (pBlob.nBitsP <= 1024 and nBitsQ == 0) {
            pBlob.fipsStandard = @intCast(1 + (rng.scTestRngUint32(&rng.g_rng) & 1));
        } else {
            pBlob.fipsStandard = SYMCRYPT_DLGROUP_FIPS_LATEST;
        }

        var hashIdx: usize = rng.scTestRngUint32(&rng.g_rng) % 5;
        if ((pBlob.nBitsP > 1024 or nBitsQ > 160) and hashIdx == 0) {
            hashIdx = 1;
        }
        const pHash = hashes[hashIdx].pHash;
        if (pBlob.fipsStandard == SYMCRYPT_DLGROUP_FIPS_186_2) {
            pBlob.pHashAlgorithm = null;
            pBlob.pcstrHashAlgName = null;
        } else {
            pBlob.pHashAlgorithm = pHash;
            pBlob.pcstrHashAlgName = hashes[hashIdx].name;
        }

        const scError = SymCryptDlgroupGenerate(pBlob.pHashAlgorithm, pBlob.fipsStandard, pGroup);
        h.check(scError == SYMCRYPT_NO_ERROR, "Failed to generate dlgroup");

        const fHasPrimeQ: u8 = if (scTestDlgroupNBitsOfQ(pGroup) > 160 or (rng.scTestRngUint32(&rng.g_rng) & 1) == 0) 1 else 0;
        var fipsStandard = pBlob.fipsStandard;
        var pcstrHashAlgName = pBlob.pcstrHashAlgName;
        if (fHasPrimeQ == 0) {
            fipsStandard = SYMCRYPT_DLGROUP_FIPS_NONE;
            pcstrHashAlgName = null;
        } else if ((rng.scTestRngUint32(&rng.g_rng) % 4) == 0) {
            fipsStandard = SYMCRYPT_DLGROUP_FIPS_NONE;
            pcstrHashAlgName = null;
        }

        dlgroupTestBlobFromObject(pGroup, pBlob);

        pBlob.nBitsP = entry.nBitsOfP;
        pBlob.fipsStandard = fipsStandard;
        pBlob.fHasPrimeQ = fHasPrimeQ;
        pBlob.pcstrHashAlgName = pcstrHashAlgName;
        if (fHasPrimeQ == 0) {
            pBlob.cbPrimeQ = 0;
        }
        if (fipsStandard == SYMCRYPT_DLGROUP_FIPS_NONE) {
            pBlob.cbSeed = 0;
            pBlob.genCounter = 0;
            pBlob.pHashAlgorithm = null;
        }

        const pGroup2 = scTestDlgroupObjectFromTestBlob(pBlob);
        h.check(SymCryptDlgroupIsSame(pGroup, pGroup2) != 0, "Mismatch between generated and recreated group");

        SymCryptDlgroupFree(pGroup);
        SymCryptDlgroupFree(pGroup2);

        g_nDlgroups += 1;
        h.ziprint(".", .{});
    }
    h.ziprint("done\n", .{});
}

fn testDlExtendKeySetValue(
    pGroup: ?*const anyopaque,
    pkKeyOrig: ?*const anyopaque,
    fPublicOnly: u8,
    numFormat: i32,
    flagsOrig: u32,
) void {
    var scError: u32 = SYMCRYPT_NO_ERROR;
    var pbKey: [2 * DLKEY_MAXKEYSIZE]u8 = undefined;

    var cbPrivateKey: usize = 0;
    const cbPublicKey: usize = SymCryptDlkeySizeofPublicKey(pkKeyOrig);
    var flagsKeyType: u32 = flagsOrig & (SYMCRYPT_FLAG_DLKEY_DSA | SYMCRYPT_FLAG_DLKEY_DH);
    var flagsValidation: u32 = 0;

    var pkKeyNew: ?*anyopaque = null;

    if (fPublicOnly == 0) {
        cbPrivateKey = SymCryptDlkeySizeofPrivateKey(pkKeyOrig);
    }

    scError = SymCryptDlkeyGetValue(
        pkKeyOrig,
        if (cbPrivateKey > 0) pbKey[0..].ptr else null,
        cbPrivateKey,
        pbKey[cbPrivateKey..].ptr,
        cbPublicKey,
        numFormat,
        0,
    );
    h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptDlkeyGetValue failed");

    // Pick only one key type if original key has both
    if (flagsKeyType == (SYMCRYPT_FLAG_DLKEY_DSA | SYMCRYPT_FLAG_DLKEY_DH)) {
        if ((rng.scTestRngUint32(&rng.g_rng) & 1) != 0) {
            flagsKeyType = SYMCRYPT_FLAG_DLKEY_DSA;
        } else {
            flagsKeyType = SYMCRYPT_FLAG_DLKEY_DH;
        }
    }

    // Check random flags
    while (true) {
        const flagsRandom: u32 = rng.scTestRngUint32(&rng.g_rng);
        if ((flagsRandom & ~(SYMCRYPT_FLAG_DLKEY_DSA | SYMCRYPT_FLAG_DLKEY_DH | SYMCRYPT_FLAG_DLKEY_PRIVATE_MOD_P |
            SYMCRYPT_FLAG_KEY_NO_FIPS | SYMCRYPT_FLAG_KEY_MINIMAL_VALIDATION)) != 0)
        {
            pkKeyNew = SymCryptDlkeyAllocate(pGroup);
            h.check(pkKeyNew != null, "SymCryptDlkeyAllocate failed");

            scError = SymCryptDlkeySetValue(
                if (cbPrivateKey > 0) pbKey[0..].ptr else null,
                cbPrivateKey,
                pbKey[cbPrivateKey..].ptr,
                cbPublicKey,
                numFormat,
                flagsRandom,
                pkKeyNew,
            );
            h.check(scError == SYMCRYPT_INVALID_ARGUMENT, "Random flags succeed");

            SymCryptDlkeyFree(pkKeyNew);
            break;
        }
    }

    // Validated imported keys according to capabilities
    if (flagsKeyType == SYMCRYPT_FLAG_DLKEY_DSA) {
        if (scTestDlgroupIsSafePrime(pGroup) != 0) {
            flagsValidation = SYMCRYPT_INVALID_ARGUMENT;
        } else if ((flagsOrig & SYMCRYPT_FLAG_KEY_NO_FIPS) != 0) {
            flagsValidation = SYMCRYPT_FIPS_FAILURE;
        } else if (scTestDlgroupNBitsOfP(pGroup) < 2048) {
            if (fPublicOnly != 0) {
                flagsValidation = SYMCRYPT_FLAG_KEY_MINIMAL_VALIDATION;
            } else {
                flagsValidation = SYMCRYPT_FIPS_FAILURE;
            }
        }
    } else if (flagsKeyType == SYMCRYPT_FLAG_DLKEY_DH) {
        if (scTestDlgroupNBitsOfP(pGroup) < 2048) {
            flagsValidation = SYMCRYPT_FIPS_FAILURE;
        } else if ((flagsOrig & SYMCRYPT_FLAG_KEY_NO_FIPS) != 0) {
            if (scTestDlgroupIsSafePrime(pGroup) == 0) {
                flagsValidation = SYMCRYPT_FIPS_FAILURE;
            } else if (scTestDlkeyNBitsPriv(pkKeyOrig) < scTestDlgroupNMinBitsPriv(pGroup)) {
                flagsValidation = SYMCRYPT_INVALID_ARGUMENT;
            } else if (scTestDlkeyNBitsPriv(pkKeyOrig) > scTestDlgroupNBitsOfQ(pGroup)) {
                flagsValidation = SYMCRYPT_INVALID_ARGUMENT;
            }
        }
    }

    var cntr: u32 = 0;
    while (cntr < 3) : (cntr += 1) {
        var flags: u32 = flagsKeyType;

        if (scTestDlkeyFPrivateModQ(pkKeyOrig) == 0) {
            flags |= SYMCRYPT_FLAG_DLKEY_PRIVATE_MOD_P;
        }

        if (cntr == 1) {
            flags |= SYMCRYPT_FLAG_KEY_MINIMAL_VALIDATION;
        } else if (cntr == 2) {
            flags |= SYMCRYPT_FLAG_KEY_NO_FIPS;
            if ((rng.scTestRngUint32(&rng.g_rng) & 1) != 0) {
                flags |= SYMCRYPT_FLAG_KEY_MINIMAL_VALIDATION;
            }
        }

        pkKeyNew = SymCryptDlkeyAllocate(pGroup);
        h.check(pkKeyNew != null, "SymCryptDlkeyAllocate failed");

        if (fPublicOnly == 0 and scTestDlgroupIsSafePrime(pGroup) != 0) {
            scError = SymCryptDlkeySetPrivateKeyLength(pkKeyNew, scTestDlkeyNBitsPriv(pkKeyOrig), 0);
            h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptDlkeySetPrivateKeyLength failed");
        }

        scError = SymCryptDlkeySetValue(
            if (cbPrivateKey > 0) pbKey[0..].ptr else null,
            cbPrivateKey,
            pbKey[cbPrivateKey..].ptr,
            cbPublicKey,
            numFormat,
            flags,
            pkKeyNew,
        );

        if (flagsValidation == SYMCRYPT_INVALID_ARGUMENT) {
            h.check(scError == SYMCRYPT_INVALID_ARGUMENT, "SymCryptDlkeySetValue succeeded for invalid arguments");
        } else if (flagsValidation == SYMCRYPT_FIPS_FAILURE) {
            if (cntr < 2) {
                h.check(scError == SYMCRYPT_FIPS_FAILURE, "SymCryptDlkeySetValue succeeded for non-FIPS length");
            } else {
                h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptDlkeySetValue failed when NO_FIPS passed in");
            }
        } else if (flagsValidation == SYMCRYPT_FLAG_KEY_MINIMAL_VALIDATION) {
            if (cntr == 0) {
                h.check(scError == SYMCRYPT_FIPS_FAILURE, "SymCryptDlkeySetValue succeeded for non-FIPS group");
            } else {
                h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptDlkeySetValue failed when MINIMAL_VALIDATION or NO_FIPS passed in");
            }
        } else {
            h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptDlkeySetValue failed");
        }

        if (scError == SYMCRYPT_NO_ERROR) {
            if (fPublicOnly == 0) {
                h.check(
                    SymCryptIntIsEqual(scTestDlkeyPiPrivateKey(pkKeyOrig), scTestDlkeyPiPrivateKey(pkKeyNew)) != 0,
                    "Recreating matching private keys failed",
                );
            }
            h.check(
                SymCryptModElementIsEqual(scTestDlgroupPmP(pGroup), scTestDlkeyPePublicKey(pkKeyOrig), scTestDlkeyPePublicKey(pkKeyNew)) != 0,
                "Recreating matching public keys failed",
            );

            // Modify the public key and run again except when NO_FIPS and MINIMAL_VALIDATION
            if (flagsKeyType != 0 and
                ((flags & (SYMCRYPT_FLAG_KEY_NO_FIPS | SYMCRYPT_FLAG_KEY_MINIMAL_VALIDATION)) !=
                    (SYMCRYPT_FLAG_KEY_NO_FIPS | SYMCRYPT_FLAG_KEY_MINIMAL_VALIDATION)))
            {
                const bytePos: usize = rng.scTestRngUint32(&rng.g_rng) % cbPublicKey;
                const bitMask: u8 = @as(u8, 1) << @intCast(rng.scTestRngUint32(&rng.g_rng) % 8);
                pbKey[cbPrivateKey + bytePos] ^= bitMask;

                scError = SymCryptDlkeySetValue(
                    if (cbPrivateKey > 0) pbKey[0..].ptr else null,
                    cbPrivateKey,
                    pbKey[cbPrivateKey..].ptr,
                    cbPublicKey,
                    numFormat,
                    flags,
                    pkKeyNew,
                );
                if (fPublicOnly != 0 and scTestDlgroupNBitsOfQ(pGroup) == 0) {
                    h.check(
                        scError == SYMCRYPT_AUTHENTICATION_FAILURE or scError == SYMCRYPT_NO_ERROR,
                        "Failed to reject an invalid public key for group without Q",
                    );
                } else {
                    h.check(scError == SYMCRYPT_AUTHENTICATION_FAILURE, "Failed to reject an invalid public key");
                }

                pbKey[cbPrivateKey + bytePos] ^= bitMask;
            }
        }

        SymCryptDlkeyFree(pkKeyNew);
    }
}

fn testDlExtendKeyGen(pGroup: ?*const anyopaque) void {
    var scError: u32 = SYMCRYPT_NO_ERROR;
    var flagsValidation: u32 = 0;

    // Test random flags first
    var pkKey = SymCryptDlkeyAllocate(pGroup);
    h.check(pkKey != null, "SymCryptDlkeyAllocate failed");

    while (true) {
        const flagsRandom: u32 = rng.scTestRngUint32(&rng.g_rng);
        if ((flagsRandom & ~(SYMCRYPT_FLAG_DLKEY_DSA | SYMCRYPT_FLAG_DLKEY_DH | SYMCRYPT_FLAG_DLKEY_PRIVATE_MOD_P |
            SYMCRYPT_FLAG_KEY_NO_FIPS | SYMCRYPT_FLAG_KEY_MINIMAL_VALIDATION)) != 0)
        {
            scError = SymCryptDlkeyGenerate(flagsRandom, pkKey);
            h.check(scError == SYMCRYPT_INVALID_ARGUMENT, "Random flags succeed");
            break;
        }
    }

    SymCryptDlkeyFree(pkKey);

    var cntr: u32 = 0;
    while (cntr < 10) : (cntr += 1) {
        pkKey = SymCryptDlkeyAllocate(pGroup);
        h.check(pkKey != null, "SymCryptDlkeyAllocate failed");

        var flags: u32 = 0;
        switch (rng.scTestRngUint32(&rng.g_rng) % 4) {
            0 => {},
            1 => flags = SYMCRYPT_FLAG_DLKEY_DSA,
            2 => flags = SYMCRYPT_FLAG_DLKEY_DH,
            3 => flags = SYMCRYPT_FLAG_DLKEY_DSA | SYMCRYPT_FLAG_DLKEY_DH,
            else => {},
        }

        if ((rng.scTestRngUint32(&rng.g_rng) % 4) == 0) {
            flags |= SYMCRYPT_FLAG_DLKEY_PRIVATE_MOD_P;
        }
        if ((rng.scTestRngUint32(&rng.g_rng) % 2) == 0) {
            flags |= SYMCRYPT_FLAG_KEY_NO_FIPS;
        }
        if ((rng.scTestRngUint32(&rng.g_rng) % 2) == 0) {
            flags |= SYMCRYPT_FLAG_KEY_MINIMAL_VALIDATION;
        }

        var nBitsPriv: u32 = 0;
        if (scTestDlgroupIsSafePrime(pGroup) != 0 and ((rng.scTestRngUint32(&rng.g_rng) % 2) == 0)) {
            const range = scTestDlgroupNBitsOfQ(pGroup) - scTestDlgroupNMinBitsPriv(pGroup) + 1;
            nBitsPriv = (rng.scTestRngUint32(&rng.g_rng) % range) + scTestDlgroupNMinBitsPriv(pGroup);
            scError = SymCryptDlkeySetPrivateKeyLength(pkKey, nBitsPriv, 0);
            h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptDlkeySetPrivateKeyLength failed");
            h.check(scTestDlkeyNBitsPriv(pkKey) == nBitsPriv, "Private key size incorrectly set");
        } else {
            nBitsPriv = if (scTestDlgroupIsSafePrime(pGroup) != 0)
                scTestDlgroupNDefaultBitsPriv(pGroup)
            else if (scTestDlgroupNBitsOfQ(pGroup) != 0)
                scTestDlgroupNBitsOfQ(pGroup)
            else
                scTestDlgroupNBitsOfP(pGroup) - 1;
        }

        if ((flags & SYMCRYPT_FLAG_DLKEY_DSA) != 0 and scTestDlgroupIsSafePrime(pGroup) != 0) {
            flagsValidation = SYMCRYPT_INVALID_ARGUMENT;
        } else if ((flags & SYMCRYPT_FLAG_KEY_NO_FIPS) == 0 and scTestDlgroupNBitsOfP(pGroup) < 2048) {
            flagsValidation = SYMCRYPT_FIPS_FAILURE;
        } else {
            flagsValidation = SYMCRYPT_NO_ERROR;
        }

        scError = SymCryptDlkeyGenerate(flags, pkKey);
        h.check(scError == flagsValidation, "Unexpected result from SymCryptDlkeyGenerate");

        if (flagsValidation == SYMCRYPT_NO_ERROR) {
            h.check(scTestDlkeyNBitsPriv(pkKey) == nBitsPriv, "Mismatch of private key bitsize");

            const numFormat: i32 = if ((rng.scTestRngUint32(&rng.g_rng) & 1) != 0)
                SYMCRYPT_NUMBER_FORMAT_MSB_FIRST
            else
                SYMCRYPT_NUMBER_FORMAT_LSB_FIRST;
            const fPublicOnly: u8 = if ((rng.scTestRngUint32(&rng.g_rng) & 1) != 0) 1 else 0;

            testDlExtendKeySetValue(pGroup, pkKey, fPublicOnly, numFormat, flags);
        }

        SymCryptDlkeyFree(pkKey);
    }
}

fn testDlExtend() void {
    var scError: u32 = SYMCRYPT_NO_ERROR;
    const hashes = getTestHashes();

    var pGroup = SymCryptDlgroupAllocate(1024, 0);
    h.check(pGroup != null, "SymCryptDlgroupAllocate failed");

    var bEmpty: [1]u8 = .{0};
    scError = SymCryptDlgroupSetValue(
        &bEmpty,
        0,
        &bEmpty,
        0,
        &bEmpty,
        0,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        null,
        null,
        0,
        0,
        SYMCRYPT_DLGROUP_FIPS_NONE,
        pGroup,
    );
    h.check(scError == SYMCRYPT_INVALID_ARGUMENT, "Succeeded setting an empty group");

    SymCryptDlgroupFree(pGroup);

    for (g_dhNamedGroupSizes) |entry| {
        const nBitsOfP = entry.nBitsOfP;
        pGroup = SymCryptDlgroupAllocate(nBitsOfP, nBitsOfP - 1);
        h.check(pGroup != null, "SymCryptDlgroupAllocate failed");

        scError = SymCryptDlgroupSetValueSafePrime(entry.safePrimeEnum, pGroup);
        h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptDlgroupSetValueSafePrime failed");

        testDlExtendKeyGen(pGroup);

        SymCryptDlgroupFree(pGroup);
    }

    for (g_dlgroupTestSizes) |entry| {
        const nBitsOfP = entry.nBitsOfP;
        const nBitsOfQ = entry.nBitsOfQ;

        pGroup = SymCryptDlgroupAllocate(nBitsOfP, nBitsOfQ);
        h.check(pGroup != null, "SymCryptDlgroupAllocate failed");

        scError = SymCryptDlgroupSetValueSafePrime(SYMCRYPT_DLGROUP_DH_SAFEPRIMES_NONE, pGroup);
        h.check(scError == SYMCRYPT_INVALID_ARGUMENT, "SymCryptDlgroupSetValueSafePrime succeeded with invalid parameter");

        var fipsStandard: i32 = 0;
        var pHashAlgorithm: ?*const anyopaque = null;
        if (nBitsOfP <= 1024 and nBitsOfQ == 0) {
            fipsStandard = @intCast(1 + (rng.scTestRngUint32(&rng.g_rng) & 1));
        } else {
            fipsStandard = SYMCRYPT_DLGROUP_FIPS_LATEST;
        }

        pHashAlgorithm = hashes[rng.scTestRngUint32(&rng.g_rng) % 5].pHash;
        if (fipsStandard == SYMCRYPT_DLGROUP_FIPS_186_2) {
            pHashAlgorithm = null;
        }

        scError = SymCryptDlgroupGenerate(pHashAlgorithm, fipsStandard, pGroup);
        h.check(scError == SYMCRYPT_NO_ERROR, "Failed to generate dlgroup");

        testDlExtendKeyGen(pGroup);

        SymCryptDlgroupFree(pGroup);
    }
}

pub fn dlgroupRandomKey(pGroup: *const DlgroupTestBlob, pKey: *DlkeyTestBlob, fPublic: u8) void {
    var scError: u32 = SYMCRYPT_NO_ERROR;
    const pScGroup = scTestDlgroupObjectFromTestBlob(pGroup);
    const pkKey = SymCryptDlkeyAllocate(pScGroup);
    var flags: u32 = SYMCRYPT_FLAG_KEY_NO_FIPS;

    pKey.pGroup = pGroup;

    switch (rng.scTestRngUint32(&rng.g_rng) % 3) {
        0 => flags |= SYMCRYPT_FLAG_DLKEY_DH | SYMCRYPT_FLAG_DLKEY_DSA,
        1 => flags |= SYMCRYPT_FLAG_DLKEY_DSA,
        2 => flags |= SYMCRYPT_FLAG_DLKEY_DH,
        else => {},
    }

    scError = SymCryptDlkeyGenerate(flags, pkKey);
    h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptDlkeyGenerate in dlgroupRandomKey failed");

    if (pGroup.isSafePrimeGroup != 0) {
        pKey.nBitsPriv = scTestDlkeyNBitsPriv(pkKey);
    } else {
        pKey.nBitsPriv = 0;
    }
    pKey.cbPrivKey = SymCryptDlkeySizeofPrivateKey(pkKey);
    pKey.fPrivateModP = if (scTestDlkeyFPrivateModQ(pkKey) != 0) 0 else 1;

    scError = SymCryptDlkeyGetValue(
        pkKey,
        if (fPublic != 0) null else &pKey.abPrivKey,
        if (fPublic != 0) 0 else pKey.cbPrivKey,
        &pKey.abPubKey,
        pGroup.cbPrimeP,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        0,
    );
    h.check(scError == SYMCRYPT_NO_ERROR, "?");

    SymCryptDlkeyFree(pkKey);
    SymCryptDlgroupFree(pScGroup);
}

const DhMultiImp = struct {
    comps: [16]*anyopaque = undefined,
    n_comps: usize = 0,
    imps: [16]*anyopaque = undefined,
    n_imps: usize = 0,

    fn init(algName: []const u8) ?DhMultiImp {
        if (!h.isAlgorithmPresent(algName.ptr, 0)) {
            return null;
        }
        var self = DhMultiImp{};
        self.n_comps = scTestGetAllImplementations(algName.ptr, algName.len, &self.comps, self.comps.len);
        if (self.n_comps == 0) {
            return null;
        }
        return self;
    }

    fn deinit(self: *DhMultiImp) void {
        for (self.comps[0..self.n_comps]) |imp| {
            scTestImpIncResults(imp);
        }
    }

    fn setKey(self: *DhMultiImp, pcKeyBlob: ?*const DlkeyTestBlob) u32 {
        self.n_imps = 0;
        for (self.comps[0..self.n_comps]) |imp| {
            if (scTestDhImpSetKey(imp, pcKeyBlob) == STATUS_SUCCESS) {
                self.imps[self.n_imps] = imp;
                self.n_imps += 1;
            }
        }
        return if (self.n_imps == 0) STATUS_NOT_SUPPORTED else STATUS_SUCCESS;
    }

    fn sharedSecret(self: *DhMultiImp, pcPubkey: *const DlkeyTestBlob, pbSecret: [*]u8, cbSecret: usize) u32 {
        var bBuf: [DLKEY_MAXKEYSIZE]u8 = undefined;
        const res = rm.scTestResultMergeCreate() orelse h.fatal("OOM", .{});
        defer rm.scTestResultMergeDestroy(res);

        var nSuccess: u32 = 0;
        for (self.imps[0..self.n_imps]) |imp| {
            SymCryptWipe(&bBuf, bBuf.len);
            const status = scTestDhImpSharedSecret(imp, pcPubkey, &bBuf, cbSecret);
            if (status != STATUS_NOT_SUPPORTED) {
                h.check(status == STATUS_SUCCESS, "Error during DH shared secret");
                scTestResultMergeAddAlgImp(res, imp, &bBuf, cbSecret);
                nSuccess += 1;
            }
        }
        if (nSuccess == 0) {
            return STATUS_NOT_SUPPORTED;
        }
        rm.scTestResultMergeGetResult(res, pbSecret, cbSecret, 1);
        return STATUS_SUCCESS;
    }
};

fn testDhPair(pDh: *DhMultiImp, pKey1: *const DlkeyTestBlob, pKey2: *const DlkeyTestBlob) void {
    var abSecret1: [DLKEY_MAXKEYSIZE]u8 = undefined;
    var abSecret2: [DLKEY_MAXKEYSIZE]u8 = undefined;

    const cbP: usize = pKey1.pGroup.?.cbPrimeP;
    h.check(cbP == pKey2.pGroup.?.cbPrimeP and cbP <= DLKEY_MAXKEYSIZE, "?");

    h.check(pDh.setKey(pKey1) == STATUS_SUCCESS, "Failed to set key 1");
    h.check(pDh.sharedSecret(pKey2, &abSecret1, cbP) == STATUS_SUCCESS, "Failed to get secret 1");
    h.check(pDh.setKey(pKey2) == STATUS_SUCCESS, "Failed to set key 2");
    h.check(pDh.sharedSecret(pKey1, &abSecret2, cbP) == STATUS_SUCCESS, "Failed to get secret 2");

    h.check(std.mem.eql(u8, abSecret1[0..cbP], abSecret2[0..cbP]), "Dishonest shared secrets");
}

fn testDhChangePrivKeySize(pGroupBlob: *const DlgroupTestBlob) void {
    if (pGroupBlob.isSafePrimeGroup == 0) {
        return;
    }

    var abSecret1: [DLKEY_MAXKEYSIZE]u8 = undefined;
    var abSecret2: [DLKEY_MAXKEYSIZE]u8 = undefined;
    var scError: u32 = SYMCRYPT_NO_ERROR;

    const pGroup = scTestDlgroupObjectFromTestBlob(pGroupBlob);
    const pkKey1 = SymCryptDlkeyAllocate(pGroup);
    const pkKey2 = SymCryptDlkeyAllocate(pGroup);

    const range = scTestDlgroupNBitsOfQ(pGroup) - scTestDlgroupNMinBitsPriv(pGroup);
    var nBitsPriv1: u32 = (rng.scTestRngUint32(&rng.g_rng) % range) + scTestDlgroupNMinBitsPriv(pGroup);
    const nBitsPriv2: u32 = (rng.scTestRngUint32(&rng.g_rng) % range) + scTestDlgroupNMinBitsPriv(pGroup);

    scError = SymCryptDlkeySetPrivateKeyLength(pkKey1, nBitsPriv1, 0);
    h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptDlkeySetPrivateKeyLength failed");
    scError = SymCryptDlkeyGenerate(SYMCRYPT_FLAG_DLKEY_DH, pkKey1);
    h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptDlkeyGenerate failed");
    h.check(scTestDlkeyNBitsPriv(pkKey1) == nBitsPriv1, "SymCryptDlkeyGenerate set wrong private key length");

    scError = SymCryptDlkeySetPrivateKeyLength(pkKey2, nBitsPriv2, 0);
    h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptDlkeySetPrivateKeyLength failed");
    scError = SymCryptDlkeyGenerate(SYMCRYPT_FLAG_DLKEY_DH, pkKey2);
    h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptDlkeyGenerate failed");
    h.check(scTestDlkeyNBitsPriv(pkKey2) == nBitsPriv2, "SymCryptDlkeyGenerate set wrong private key length");

    scError = SymCryptDhSecretAgreement(pkKey1, pkKey2, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, 0, &abSecret1, pGroupBlob.cbPrimeP);
    h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptDhSecretAgreement failed");
    scError = SymCryptDhSecretAgreement(pkKey2, pkKey1, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, 0, &abSecret2, pGroupBlob.cbPrimeP);
    h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptDhSecretAgreement failed");
    h.check(std.mem.eql(u8, abSecret1[0..pGroupBlob.cbPrimeP], abSecret2[0..pGroupBlob.cbPrimeP]), "Shared secrets do not match");

    const minMinusOne = scTestDlgroupNMinBitsPriv(pGroup) - 1;
    nBitsPriv1 = (rng.scTestRngUint32(&rng.g_rng) % minMinusOne) + 1;

    scError = SymCryptDlkeySetPrivateKeyLength(pkKey1, nBitsPriv1, 0);
    h.check(scError == SYMCRYPT_INVALID_ARGUMENT, "SymCryptDlkeySetPrivateKeyLength succeeded on too-short length without NO_FIPS");
    scError = SymCryptDlkeySetPrivateKeyLength(pkKey1, scTestDlgroupNBitsOfP(pGroup), 0);
    h.check(scError == SYMCRYPT_INVALID_ARGUMENT, "SymCryptDlkeySetPrivateKeyLength succeeded on too-long length without NO_FIPS");

    SymCryptDlkeyFree(pkKey1);
    SymCryptDlkeyFree(pkKey2);
    SymCryptDlgroupFree(pGroup);
}

fn testDhSignVerifyRandom(pDh: *DhMultiImp) void {
    var key1: DlkeyTestBlob = std.mem.zeroes(DlkeyTestBlob);
    var key2: DlkeyTestBlob = std.mem.zeroes(DlkeyTestBlob);

    var i: u32 = 0;
    while (i < g_nDlgroups) : (i += 1) {
        const pGroup = &g_DlGroup[i];
        dlgroupRandomKey(pGroup, &key1, 0);
        dlgroupRandomKey(pGroup, &key2, 0);
        testDhPair(pDh, &key1, &key2);
        testDhChangePrivKeySize(pGroup);
    }

    h.check(pDh.setKey(null) == STATUS_SUCCESS, "Failed to clear key");
}

fn testDhSingle(
    pDh: *DhMultiImp,
    pKeyPriv: *const DlkeyTestBlob,
    pKeyPub: *const DlkeyTestBlob,
    pbSecret: [*]const u8,
    cbSecret: usize,
) void {
    var abSecret: [DLKEY_MAXKEYSIZE]u8 = undefined;

    h.check(pDh.setKey(pKeyPriv) == STATUS_SUCCESS, "Failed to set key");
    h.check(pDh.sharedSecret(pKeyPub, &abSecret, cbSecret) == STATUS_SUCCESS, "Failed to compute shared secret");
    h.check(std.mem.eql(u8, pbSecret[0..cbSecret], abSecret[0..cbSecret]), "Computed shared secret didn't match KAT");
    h.check(pDh.setKey(null) == STATUS_SUCCESS, "Failed to clear key");
}

fn testDhInvalidSharedSecret(
    pGroup: *const DlgroupTestBlob,
    pKeyPriv: *const DlkeyTestBlob,
    pKeyPub: *const DlkeyTestBlob,
) void {
    var scError: u32 = SYMCRYPT_NO_ERROR;
    var abSecret: [DLKEY_MAXKEYSIZE]u8 = undefined;
    var abInvalidPubKey: [DLKEY_MAXKEYSIZE]u8 = undefined;

    const pScGroup = scTestDlgroupObjectFromTestBlob(pGroup);
    const pkKeyPriv = SymCryptDlkeyAllocate(pScGroup);
    const pkKeyPub = SymCryptDlkeyAllocate(pScGroup);

    if (pKeyPriv.nBitsPriv != 0) {
        scError = SymCryptDlkeySetPrivateKeyLength(pkKeyPriv, pKeyPriv.nBitsPriv, 0);
        h.check(scError == SYMCRYPT_NO_ERROR, "Failed to set private key length");
    }

    var flags: u32 = SYMCRYPT_FLAG_KEY_NO_FIPS | SYMCRYPT_FLAG_DLKEY_DH;
    if (pKeyPriv.fPrivateModP != 0) {
        flags |= SYMCRYPT_FLAG_DLKEY_PRIVATE_MOD_P;
    }

    scError = SymCryptDlkeySetValue(
        &pKeyPriv.abPrivKey,
        pKeyPriv.cbPrivKey,
        &pKeyPriv.abPubKey,
        pKeyPriv.pGroup.?.cbPrimeP,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        flags,
        pkKeyPriv,
    );
    h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptDlkeySetValue failed");

    var cntr: u32 = 0;
    while (cntr < 3) : (cntr += 1) {
        flags = SYMCRYPT_FLAG_KEY_NO_FIPS | SYMCRYPT_FLAG_DLKEY_DH;

        if (cntr == 1) {
            flags |= SYMCRYPT_FLAG_KEY_MINIMAL_VALIDATION;
        } else if (cntr == 2) {
            flags = SYMCRYPT_FLAG_KEY_NO_FIPS | SYMCRYPT_FLAG_KEY_MINIMAL_VALIDATION;
        }

        scError = SymCryptDlkeySetValue(
            null,
            0,
            &pKeyPub.abPubKey,
            pKeyPub.pGroup.?.cbPrimeP,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            flags,
            pkKeyPub,
        );

        if (cntr == 0) {
            if (pGroup.fHasPrimeQ != 0) {
                h.check(scError == SYMCRYPT_AUTHENTICATION_FAILURE, "SymCryptDlkeySetValue accepted an invalid public key");
            } else {
                h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptDlkeySetValue failed on an invalid public key for group without Q");
            }
        } else if (cntr == 1) {
            if (pGroup.fHasPrimeQ != 0) {
                if ((std.mem.allEqual(u8, pKeyPub.abPubKey[0 .. pGroup.cbPrimeP - 1], 0) and
                    (pKeyPub.abPubKey[pGroup.cbPrimeP - 1] <= 1)) or
                    std.mem.order(u8, pKeyPub.abPubKey[0..pGroup.cbPrimeP], pGroup.abPrimeP[0..pGroup.cbPrimeP]) != .lt)
                {
                    h.check(scError == SYMCRYPT_AUTHENTICATION_FAILURE, "SymCryptDlkeySetValue accepted an invalid public key");
                } else {
                    h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptDlkeySetValue failed on an invalid public key when MINIMAL_VALIDATION specified");
                    scError = SymCryptDhSecretAgreement(pkKeyPriv, pkKeyPub, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, 0, &abSecret, pGroup.cbPrimeP);
                    h.check(scError == SYMCRYPT_AUTHENTICATION_FAILURE, "SymCryptDhSecretAgreement accepted an invalid shared secret (==1)");
                }
            } else {
                h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptDlkeySetValue failed on an invalid public key for group without Q");
            }
        } else if (cntr == 2) {
            h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptDlkeySetValue failed on an invalid public key when no DLKEY flag and MINIMAL_VALIDATION specified");
        }
    }

    // Create a random key mod P which won't be in the subgroup generated by G
    var i: u32 = 0;
    while (i < 5) : (i += 1) {
        abInvalidPubKey[0] = 0;
        SymCryptCallbackRandom(abInvalidPubKey[1..].ptr, pGroup.cbPrimeP - 1);

        scError = SymCryptDlkeySetValue(
            null,
            0,
            &abInvalidPubKey,
            pGroup.cbPrimeP,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            SYMCRYPT_FLAG_DLKEY_DH | SYMCRYPT_FLAG_KEY_NO_FIPS,
            pkKeyPub,
        );
        if (pGroup.fHasPrimeQ != 0) {
            h.check(scError == SYMCRYPT_AUTHENTICATION_FAILURE, "SymCryptDlkeySetValue succeeded on an invalid public key");
        } else {
            h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptDlkeySetValue failed on an invalid public key for group without Q");
        }

        scError = SymCryptDlkeySetValue(
            null,
            0,
            &abInvalidPubKey,
            pGroup.cbPrimeP,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            SYMCRYPT_FLAG_DLKEY_DH | SYMCRYPT_FLAG_KEY_NO_FIPS | SYMCRYPT_FLAG_KEY_MINIMAL_VALIDATION,
            pkKeyPub,
        );
        h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptDlkeySetValue failed on an invalid public key when MINIMAL_VALIDATION specified");

        scError = SymCryptDhSecretAgreement(pkKeyPriv, pkKeyPub, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, 0, &abSecret, pGroup.cbPrimeP);
        h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptDhSecretAgreement failed on a valid shared secret (!= 1)");
    }

    SymCryptDlkeyFree(pkKeyPriv);
    SymCryptDlkeyFree(pkKeyPub);
    SymCryptDlgroupFree(pScGroup);
}

fn testDhKats() void {
    const pResource = h.findDataItem("kat_dh.dat") orelse h.fatal("kat_dh.dat not found", .{});
    var katDh = kat.KatData.init(pResource.name, pResource.pbData, pResource.cbData);
    var katItem: kat.KatItem = .{};

    var sep: []const u8 = "";

    var doneAnything = false;

    var pDh = DhMultiImp.init("Dh");
    defer {
        if (pDh) |*dh| {
            dh.deinit();
        }
    }

    var dlGroup: DlgroupTestBlob = std.mem.zeroes(DlgroupTestBlob);
    var dlKeyPriv: DlkeyTestBlob = std.mem.zeroes(DlkeyTestBlob);
    var dlKeyPub: DlkeyTestBlob = std.mem.zeroes(DlkeyTestBlob);

    while (true) {
        katDh.getKatItem(&katItem);
        const ulLine: i64 = katItem.line;

        if (katItem.itemType == kat.KAT_TYPE_END) {
            break;
        }

        if (katItem.itemType == kat.KAT_TYPE_CATEGORY) {
            // We never skip data and the algorithm is only just "Dh"
            if (pDh != null) {
                h.ziprint("{s}{s}", .{ sep, katItem.categoryName() });
                sep = ", ";
                doneAnything = true;
            }
        }

        if (katItem.itemType == kat.KAT_TYPE_DATASET and pDh != null) {
            if (kat.katIsFieldPresent(&katItem, "p")) {
                dlgroupClearTestBlob(&dlGroup);
                const bP = kat.katParseData(&katItem, "p");
                defer bP.deinit();
                const bG = kat.katParseData(&katItem, "g");
                defer bG.deinit();

                dlGroup.nBitsP = @intCast(bP.cbData * 8);
                dlGroup.cbPrimeP = @intCast(bP.cbData);
                dlGroup.cbPrimeQ = 0;
                dlGroup.fipsStandard = SYMCRYPT_DLGROUP_FIPS_NONE;
                dlGroup.pHashAlgorithm = null;
                dlGroup.cbSeed = 0;
                dlGroup.genCounter = 0;
                dlGroup.fHasPrimeQ = 0;
                dlGroup.pcstrHashAlgName = null;
                h.check3(bP.cbData <= DLKEY_MAXKEYSIZE, "P array too large at line %lld", ulLine);
                h.check3(bG.cbData == bP.cbData, "G and P didn't match at line %lld", ulLine);
                @memcpy(dlGroup.abPrimeP[0..bP.cbData], bP.pbData[0..bP.cbData]);
                @memcpy(dlGroup.abGenG[0..bG.cbData], bG.pbData[0..bG.cbData]);

                if (kat.katIsFieldPresent(&katItem, "q")) {
                    const bQ = kat.katParseData(&katItem, "q");
                    defer bQ.deinit();
                    h.check3(bQ.cbData <= DLKEY_MAXKEYSIZE, "Q array too large at line %lld", ulLine);
                    dlGroup.cbPrimeQ = @intCast(bQ.cbData);
                    dlGroup.fHasPrimeQ = 1;
                    @memcpy(dlGroup.abPrimeQ[0..bQ.cbData], bQ.pbData[0..bQ.cbData]);
                }

                const bX1 = kat.katParseData(&katItem, "x1");
                defer bX1.deinit();
                const bH1 = kat.katParseData(&katItem, "h1");
                defer bH1.deinit();
                const bX2 = kat.katParseData(&katItem, "x2");
                defer bX2.deinit();
                const bH2 = kat.katParseData(&katItem, "h2");
                defer bH2.deinit();
                const bSecret = kat.katParseData(&katItem, "ss");
                defer bSecret.deinit();

                h.check3(bH1.cbData == dlGroup.cbPrimeP and bH2.cbData == dlGroup.cbPrimeP, "Wrong public key sizes at line %lld", ulLine);

                dlKeyPriv = std.mem.zeroes(DlkeyTestBlob);
                dlKeyPriv.pGroup = &dlGroup;
                dlKeyPriv.nBitsPriv = 0;
                dlKeyPriv.cbPrivKey = @intCast(bX1.cbData);
                dlKeyPriv.fPrivateModP = 0;
                @memcpy(dlKeyPriv.abPubKey[0..bH1.cbData], bH1.pbData[0..bH1.cbData]);
                @memcpy(dlKeyPriv.abPrivKey[0..bX1.cbData], bX1.pbData[0..bX1.cbData]);

                dlKeyPub = std.mem.zeroes(DlkeyTestBlob);
                dlKeyPub.pGroup = &dlGroup;
                dlKeyPub.nBitsPriv = 0;
                dlKeyPub.cbPrivKey = @intCast(bX2.cbData);
                dlKeyPub.fPrivateModP = 0;
                @memcpy(dlKeyPub.abPubKey[0..bH2.cbData], bH2.pbData[0..bH2.cbData]);
                @memcpy(dlKeyPub.abPrivKey[0..bX2.cbData], bX2.pbData[0..bX2.cbData]);

                testDhSingle(&pDh.?, &dlKeyPriv, &dlKeyPub, bSecret.pbData, bSecret.cbData);
                testDhSingle(&pDh.?, &dlKeyPub, &dlKeyPriv, bSecret.pbData, bSecret.cbData);
                continue;
            }

            if (kat.katIsFieldPresent(&katItem, "rnd")) {
                generateDlGroups();
                testDhSignVerifyRandom(&pDh.?);
                continue;
            }

            h.fatal("Unknown data record at line {d}", .{ulLine});
        }
    }

    if (pDh) |*dh| {
        testDhSignVerifyRandom(dh);
    }

    if (doneAnything) {
        h.ziprint("\n", .{});
    }
}

pub export fn testDhAlgorithms() callconv(.c) void {
    if (!h.isAlgorithmPresent("Dh", 0)) {
        return;
    }
    generateDlGroups();
    testDhKats();
}
