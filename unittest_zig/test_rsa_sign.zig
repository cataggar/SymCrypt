// Copyright (c) Microsoft Corporation. Licensed under the MIT license.

const std = @import("std");
const h = @import("main_harness.zig");
const rng = @import("rng.zig");
const kat = @import("kat.zig");
const rm = @import("result_merge.zig");

pub const RSAKEY_MAXKEYSIZE: usize = 1024;
pub const MAX_RSA_TESTKEYS: usize = 50;

const STATUS_SUCCESS: u32 = 0;
const STATUS_NOT_SUPPORTED: u32 = 0xC00000BB;
const STATUS_INVALID_PARAMETER: u32 = 0xC000000D;

const SYMCRYPT_NO_ERROR: u32 = 0;
const SYMCRYPT_INVALID_ARGUMENT: u32 = 0x800e;
const SYMCRYPT_BUFFER_TOO_SMALL: u32 = 0x800d;
const SYMCRYPT_AUTHENTICATION_FAILURE: u32 = 0x8007;
const SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE: u32 = 0x8010;
const SYMCRYPT_FIPS_FAILURE: u32 = 0x8009;

const SYMCRYPT_NUMBER_FORMAT_LSB_FIRST: i32 = 1;
const SYMCRYPT_NUMBER_FORMAT_MSB_FIRST: i32 = 2;

const SYMCRYPT_FLAG_KEY_NO_FIPS: u32 = 0x0100;
const SYMCRYPT_FLAG_KEY_MINIMAL_VALIDATION: u32 = 0x0200;
const SYMCRYPT_FLAG_RSAKEY_SIGN: u32 = 0x1000;
const SYMCRYPT_FLAG_RSAKEY_ENCRYPT: u32 = 0x2000;

const SYMCRYPT_FLAG_RSA_PKCS1_NO_ASN1: u32 = 0x01;
const SYMCRYPT_FLAG_RSA_PKCS1_OPTIONAL_HASH_OID: u32 = 0x02;
const SYMCRYPT_FLAG_RSA_PSS_VERIFY_WITH_MINIMUM_SALT: u32 = 0x04;

pub const RsakeyTestBlob = extern struct {
    nBitsModulus: u32,
    u64PubExp: u64,
    cbModulus: u32,
    cbPrime1: u32,
    cbPrime2: u32,
    abModulus: [RSAKEY_MAXKEYSIZE]u8,
    abPrime1: [RSAKEY_MAXKEYSIZE]u8,
    abPrime2: [RSAKEY_MAXKEYSIZE]u8,
    abPrivateExp: [RSAKEY_MAXKEYSIZE]u8,
    pcstrSource: ?[*:0]const u8,
    u64Line: i64,
};

pub const SymCryptRsakeyParams = extern struct {
    version: u32,
    nBitsOfModulus: u32,
    nPrimes: u32,
    nPubExp: u32,
};

pub export var g_RsaTestKeyBlobs: [MAX_RSA_TESTKEYS]RsakeyTestBlob = std.mem.zeroes([MAX_RSA_TESTKEYS]RsakeyTestBlob);
pub export var g_nRsaTestKeyBlobs: u32 = 0;

const g_RsaTestKeySizes = [_]u32{
    384,
    391,
    512,
    519,
    768,
    999,
    1024,
    1536,
    2048,
    3072,
    4096,
};

extern const SymCryptMd5Algorithm: *const anyopaque;
extern const SymCryptSha1Algorithm: *const anyopaque;
extern const SymCryptSha256Algorithm: *const anyopaque;
extern const SymCryptSha384Algorithm: *const anyopaque;
extern const SymCryptSha512Algorithm: *const anyopaque;
extern const SymCryptSha3_256Algorithm: *const anyopaque;
extern const SymCryptSha3_384Algorithm: *const anyopaque;
extern const SymCryptSha3_512Algorithm: *const anyopaque;

extern const SymCryptMd5OidList: u8;
extern const SymCryptSha1OidList: u8;
extern const SymCryptSha256OidList: u8;
extern const SymCryptSha384OidList: u8;
extern const SymCryptSha512OidList: u8;
extern const SymCryptSha3_256OidList: u8;
extern const SymCryptSha3_384OidList: u8;
extern const SymCryptSha3_512OidList: u8;

pub const RsaHashAlgEntry = struct {
    pszName: [*:0]const u8,
    pHashAlg: *const anyopaque,
    pOidList: *const anyopaque,
    nOidCount: usize,
};

pub fn getRsaHashAlgs() [8]RsaHashAlgEntry {
    return [8]RsaHashAlgEntry{
        .{ .pszName = "MD5", .pHashAlg = SymCryptMd5Algorithm, .pOidList = @ptrCast(&SymCryptMd5OidList), .nOidCount = 2 },
        .{ .pszName = "SHA1", .pHashAlg = SymCryptSha1Algorithm, .pOidList = @ptrCast(&SymCryptSha1OidList), .nOidCount = 2 },
        .{ .pszName = "SHA256", .pHashAlg = SymCryptSha256Algorithm, .pOidList = @ptrCast(&SymCryptSha256OidList), .nOidCount = 2 },
        .{ .pszName = "SHA384", .pHashAlg = SymCryptSha384Algorithm, .pOidList = @ptrCast(&SymCryptSha384OidList), .nOidCount = 2 },
        .{ .pszName = "SHA512", .pHashAlg = SymCryptSha512Algorithm, .pOidList = @ptrCast(&SymCryptSha512OidList), .nOidCount = 2 },
        .{ .pszName = "SHA3-256", .pHashAlg = SymCryptSha3_256Algorithm, .pOidList = @ptrCast(&SymCryptSha3_256OidList), .nOidCount = 2 },
        .{ .pszName = "SHA3-384", .pHashAlg = SymCryptSha3_384Algorithm, .pOidList = @ptrCast(&SymCryptSha3_384OidList), .nOidCount = 2 },
        .{ .pszName = "SHA3-512", .pHashAlg = SymCryptSha3_512Algorithm, .pOidList = @ptrCast(&SymCryptSha3_512OidList), .nOidCount = 2 },
    };
}

extern fn SymCryptRsakeyAllocate(pParams: *const SymCryptRsakeyParams, flags: u32) callconv(.c) ?*anyopaque;
extern fn SymCryptRsakeyFree(pkObj: ?*anyopaque) callconv(.c) void;
extern fn SymCryptRsakeyGenerate(
    pkRsakey: ?*anyopaque,
    pu64PubExp: ?[*]const u64,
    nPubExp: u32,
    flags: u32,
) callconv(.c) u32;
extern fn SymCryptRsakeySizeofModulus(pkRsakey: ?*const anyopaque) callconv(.c) u32;
extern fn SymCryptRsakeySizeofPrime(pkRsakey: ?*const anyopaque, index: u32) callconv(.c) u32;
extern fn SymCryptRsakeyNumberOfPrimes(pkRsakey: ?*const anyopaque) callconv(.c) u32;
extern fn SymCryptRsakeyGetValue(
    pkRsakey: ?*const anyopaque,
    pbModulus: ?[*]u8,
    cbModulus: usize,
    pu64PubExp: ?[*]u64,
    nPubExp: u32,
    ppbPrimes: ?[*]const [*]u8,
    pcbPrimes: ?[*]const usize,
    nPrimes: u32,
    numFormat: i32,
    flags: u32,
) callconv(.c) u32;
extern fn SymCryptRsakeyGetCrtValue(
    pkRsakey: ?*const anyopaque,
    ppCrtExponents: ?[*]const [*]u8,
    pcbCrtExponents: ?[*]const usize,
    nCrtExponents: u32,
    pbCrtCoefficient: ?[*]u8,
    cbCrtCoefficient: usize,
    pbPrivateExponent: ?[*]u8,
    cbPrivateExponent: usize,
    numFormat: i32,
    flags: u32,
) callconv(.c) u32;
extern fn SymCryptRsakeySetValue(
    pbModulus: [*]const u8,
    cbModulus: usize,
    pu64PubExp: ?[*]const u64,
    nPubExp: u32,
    ppbPrimes: ?[*]const [*]const u8,
    pcbPrimes: ?[*]const usize,
    nPrimes: u32,
    numFormat: i32,
    flags: u32,
    pkRsakey: ?*anyopaque,
) callconv(.c) u32;

extern fn SymCryptRsaPkcs1Sign(
    pkRsakey: ?*const anyopaque,
    pbHashValue: [*]const u8,
    cbHashValue: usize,
    pHashOIDs: ?*const anyopaque,
    nOIDCount: usize,
    flags: u32,
    numFormat: i32,
    pbSignature: ?[*]u8,
    cbSignature: usize,
    pcbSignature: *usize,
) callconv(.c) u32;
extern fn SymCryptRsaPkcs1Verify(
    pkRsakey: ?*const anyopaque,
    pbHashValue: [*]const u8,
    cbHashValue: usize,
    pbSignature: [*]const u8,
    cbSignature: usize,
    numFormat: i32,
    pHashOIDs: ?*const anyopaque,
    nOIDCount: usize,
    flags: u32,
) callconv(.c) u32;
extern fn SymCryptRsaPssSign(
    pkRsakey: ?*const anyopaque,
    pbHashValue: [*]const u8,
    cbHashValue: usize,
    pHashAlgorithm: ?*const anyopaque,
    cbSalt: usize,
    flags: u32,
    numFormat: i32,
    pbSignature: ?[*]u8,
    cbSignature: usize,
    pcbSignature: *usize,
) callconv(.c) u32;
extern fn SymCryptRsaPssVerify(
    pkRsakey: ?*const anyopaque,
    pbHashValue: [*]const u8,
    cbHashValue: usize,
    pbSignature: [*]const u8,
    cbSignature: usize,
    numFormat: i32,
    pHashAlgorithm: ?*const anyopaque,
    cbSalt: usize,
    flags: u32,
) callconv(.c) u32;
extern fn SymCryptRsaPkcs1ApplySignaturePadding(
    pbHash: [*]const u8,
    cbHash: usize,
    pbHashOid: ?[*]const u8,
    cbHashOid: usize,
    flags: u32,
    pbPKCS1Format: [*]u8,
    cbPKCS1Format: usize,
) callconv(.c) u32;
extern fn SymCryptRsaPkcs1VerifySignaturePadding(
    pbHash: [*]const u8,
    cbHash: usize,
    pHashOIDs: ?*const anyopaque,
    nOIDCount: usize,
    pbPKCS1Format: [*]const u8,
    cbPKCS1Format: usize,
    flags: u32,
    pbScratch: [*]u8,
    cbScratch: usize,
) callconv(.c) u32;
extern fn SymCryptRsaPssApplySignaturePadding(
    pbHash: [*]const u8,
    cbHash: usize,
    pHashAlgorithm: ?*const anyopaque,
    pbSalt: [*]const u8,
    cbSalt: usize,
    nBitsOfModulus: u32,
    flags: u32,
    pbPSSFormat: [*]u8,
    cbPSSFormat: usize,
    pbScratch: [*]u8,
    cbScratch: usize,
) callconv(.c) u32;
extern fn SymCryptRsaPssVerifySignaturePadding(
    pbHash: [*]const u8,
    cbHash: usize,
    pHashAlgorithm: ?*const anyopaque,
    cbSalt: usize,
    pbPSSFormat: [*]const u8,
    cbPSSFormat: usize,
    nBitsOfModulus: u32,
    flags: u32,
    pbScratch: [*]u8,
    cbScratch: usize,
) callconv(.c) u32;

extern fn SymCryptHashResultSize(pHashAlgorithm: ?*const anyopaque) callconv(.c) usize;
extern fn SymCryptHash(
    pHashAlgorithm: ?*const anyopaque,
    pbData: [*]const u8,
    cbData: usize,
    pbResult: [*]u8,
    cbResult: usize,
) callconv(.c) void;
extern fn SymCryptWipe(pbData: [*]u8, cbData: usize) callconv(.c) void;
extern fn SymCryptCallbackAlloc(nBytes: usize) callconv(.c) ?*anyopaque;
extern fn SymCryptCallbackFree(ptr: ?*anyopaque) callconv(.c) void;
extern fn SymCryptCallbackRandom(pbBuffer: [*]u8, cbBuffer: usize) callconv(.c) void;

extern fn scTestRsakeySetAlgorithmInfo(pKey: ?*anyopaque, flags: u32) callconv(.c) void;
extern fn scTestScratchBytesForRsaPkcs1(cbPKCS1Format: usize) callconv(.c) usize;
extern fn scTestScratchBytesForRsaPss(
    pHashAlgorithm: ?*const anyopaque,
    cbHash: usize,
    cbPSSFormat: usize,
) callconv(.c) usize;

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
extern fn scTestRsaSignImpSetKey(impPtr: *anyopaque, pcKeyBlob: ?*const RsakeyTestBlob) callconv(.c) u32;
extern fn scTestRsaSignImpSign(
    impPtr: *anyopaque,
    pbHash: [*]const u8,
    cbHash: usize,
    pcstrHashAlgName: ?[*:0]const u8,
    u32Other: u32,
    pbSig: [*]u8,
    cbSig: usize,
) callconv(.c) u32;
extern fn scTestRsaSignImpVerify(
    impPtr: *anyopaque,
    pbHash: [*]const u8,
    cbHash: usize,
    pbSig: [*]const u8,
    cbSig: usize,
    pcstrHashAlgName: ?[*:0]const u8,
    u32Other: u32,
) callconv(.c) u32;

pub fn rsaTestBlobFromKey(pKey: ?*const anyopaque, pBlob: *RsakeyTestBlob) void {
    SymCryptWipe(@ptrCast(pBlob), @sizeOf(RsakeyTestBlob));

    pBlob.cbModulus = SymCryptRsakeySizeofModulus(pKey);
    pBlob.cbPrime1 = SymCryptRsakeySizeofPrime(pKey, 0);
    pBlob.cbPrime2 = SymCryptRsakeySizeofPrime(pKey, 1);

    var ppbPrimes = [2][*]u8{ &pBlob.abPrime1, &pBlob.abPrime2 };
    var pcbPrimes = [2]usize{ pBlob.cbPrime1, pBlob.cbPrime2 };

    h.check(
        pBlob.cbModulus <= RSAKEY_MAXKEYSIZE and pBlob.cbPrime1 <= RSAKEY_MAXKEYSIZE and pBlob.cbPrime2 <= RSAKEY_MAXKEYSIZE,
        "Test blob too small",
    );

    var scError = SymCryptRsakeyGetValue(
        pKey,
        &pBlob.abModulus,
        pBlob.cbModulus,
        @ptrCast(&pBlob.u64PubExp),
        1,
        &ppbPrimes,
        &pcbPrimes,
        2,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        0,
    );
    h.check(scError == SYMCRYPT_NO_ERROR, "Error exporting SymCryptRsakey to test blob");

    scError = SymCryptRsakeyGetCrtValue(
        pKey,
        null,
        null,
        0,
        null,
        0,
        &pBlob.abPrivateExp,
        pBlob.cbModulus,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        0,
    );
    h.check(scError == SYMCRYPT_NO_ERROR, "Error exporting SymCryptRsakey CRT value to test blob");
}

pub export fn rsaKeyFromTestBlob(pcBlob: *const RsakeyTestBlob) callconv(.c) ?*anyopaque {
    var params = SymCryptRsakeyParams{
        .version = 1,
        .nBitsOfModulus = pcBlob.nBitsModulus,
        .nPrimes = if (pcBlob.cbPrime1 == 0) 0 else 2,
        .nPubExp = 1,
    };

    const res = SymCryptRsakeyAllocate(&params, 0);
    h.check(res != null, "Out of memory");

    var ppbPrimes = [2][*]const u8{ &pcBlob.abPrime1, &pcBlob.abPrime2 };
    var pcbPrimes = [2]usize{ pcBlob.cbPrime1, pcBlob.cbPrime2 };

    const scError = SymCryptRsakeySetValue(
        &pcBlob.abModulus,
        pcBlob.cbModulus,
        @ptrCast(&pcBlob.u64PubExp),
        1,
        &ppbPrimes,
        &pcbPrimes,
        params.nPrimes,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        SYMCRYPT_FLAG_RSAKEY_SIGN | SYMCRYPT_FLAG_RSAKEY_ENCRYPT | SYMCRYPT_FLAG_KEY_NO_FIPS,
        res,
    );
    h.check(scError == SYMCRYPT_NO_ERROR, "Error importing key from test blob");

    scTestRsakeySetAlgorithmInfo(res, SYMCRYPT_FLAG_RSAKEY_SIGN | SYMCRYPT_FLAG_RSAKEY_ENCRYPT);

    return res;
}

fn rsaKeyPublicFromTestBlob(pcBlob: *const RsakeyTestBlob) ?*anyopaque {
    var params = SymCryptRsakeyParams{
        .version = 1,
        .nBitsOfModulus = pcBlob.nBitsModulus,
        .nPrimes = 0,
        .nPubExp = 1,
    };

    const res = SymCryptRsakeyAllocate(&params, 0);
    h.check(res != null, "Out of memory");

    const scError = SymCryptRsakeySetValue(
        &pcBlob.abModulus,
        pcBlob.cbModulus,
        @ptrCast(&pcBlob.u64PubExp),
        1,
        null,
        null,
        params.nPrimes,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        SYMCRYPT_FLAG_RSAKEY_SIGN | SYMCRYPT_FLAG_RSAKEY_ENCRYPT | SYMCRYPT_FLAG_KEY_NO_FIPS,
        res,
    );
    h.check(scError == SYMCRYPT_NO_ERROR, "Error importing key from test blob");

    scTestRsakeySetAlgorithmInfo(res, SYMCRYPT_FLAG_RSAKEY_SIGN | SYMCRYPT_FLAG_RSAKEY_ENCRYPT);

    return res;
}

pub export fn rsaTestKeysGenerate() callconv(.c) void {
    if (g_nRsaTestKeyBlobs > 0) {
        return;
    }

    h.ziprint("Generating RSA test keys ", .{});
    for (g_RsaTestKeySizes) |keySize| {
        h.check(g_nRsaTestKeyBlobs < MAX_RSA_TESTKEYS, "Too many RSA test keys");
        const pBlob = &g_RsaTestKeyBlobs[g_nRsaTestKeyBlobs];

        const nBits = keySize;
        var params = SymCryptRsakeyParams{
            .version = 1,
            .nBitsOfModulus = nBits,
            .nPrimes = 2,
            .nPubExp = 1,
        };
        const pKey = SymCryptRsakeyAllocate(&params, 0);
        h.check(pKey != null, "Failure to allocate RSA key");

        var flags: u32 = SYMCRYPT_FLAG_RSAKEY_SIGN | SYMCRYPT_FLAG_RSAKEY_ENCRYPT;
        if (nBits < 2048) {
            flags |= SYMCRYPT_FLAG_KEY_NO_FIPS;
        }

        const scError = SymCryptRsakeyGenerate(pKey, null, 0, flags);
        h.check(scError == SYMCRYPT_NO_ERROR, "Failure to generate RSA key");

        rsaTestBlobFromKey(pKey, pBlob);

        pBlob.nBitsModulus = nBits;
        pBlob.pcstrSource = "Generated random test key";
        pBlob.u64Line = 0;

        SymCryptRsakeyFree(pKey);
        g_nRsaTestKeyBlobs += 1;

        h.ziprint(".", .{});
    }
    h.ziprint(" done\n", .{});
}

pub export fn rsaTestKeyRandom() callconv(.c) *RsakeyTestBlob {
    h.check(g_nRsaTestKeyBlobs > 0, "No RSA test keys available");
    return &g_RsaTestKeyBlobs[rng.scTestRngUint32(&rng.g_rng) % g_nRsaTestKeyBlobs];
}

pub export fn rsaTestKeyForSize(nBits: usize) callconv(.c) *RsakeyTestBlob {
    h.check(g_nRsaTestKeyBlobs > 0, "No RSA test keys available");
    var i: u32 = 0;
    while (i < g_nRsaTestKeyBlobs) : (i += 1) {
        if (g_RsaTestKeyBlobs[i].nBitsModulus >= nBits) {
            return &g_RsaTestKeyBlobs[i];
        }
    }
    h.check(false, "No suitable RSA test key found");
    return &g_RsaTestKeyBlobs[0];
}

pub const RsaSignMultiImp = struct {
    comps: [16]*anyopaque = undefined,
    n_comps: usize = 0,
    imps: [16]*anyopaque = undefined,
    n_imps: usize = 0,

    pub fn init(algName: []const u8) ?RsaSignMultiImp {
        if (!h.isAlgorithmPresent(algName.ptr, 0)) {
            return null;
        }
        var self = RsaSignMultiImp{};
        self.n_comps = scTestGetAllImplementations(algName.ptr, algName.len, &self.comps, self.comps.len);
        if (self.n_comps == 0) {
            return null;
        }
        return self;
    }

    pub fn deinit(self: *RsaSignMultiImp) void {
        for (self.comps[0..self.n_comps]) |imp| {
            scTestImpIncResults(imp);
        }
    }

    pub fn setKey(self: *RsaSignMultiImp, pcKeyBlob: ?*const RsakeyTestBlob) u32 {
        self.n_imps = 0;
        for (self.comps[0..self.n_comps]) |imp| {
            if (scTestRsaSignImpSetKey(imp, pcKeyBlob) == STATUS_SUCCESS) {
                self.imps[self.n_imps] = imp;
                self.n_imps += 1;
            }
        }
        return if (self.n_imps == 0) STATUS_NOT_SUPPORTED else STATUS_SUCCESS;
    }

    pub fn sign(
        self: *RsaSignMultiImp,
        pbHash: [*]const u8,
        cbHash: usize,
        pcstrHashAlgName: ?[*:0]const u8,
        cbSalt: u32,
        pbSig: [*]u8,
        cbSig: usize,
    ) u32 {
        var bBuf: [RSAKEY_MAXKEYSIZE]u8 = undefined;
        const res = rm.scTestResultMergeCreate() orelse h.fatal("OOM", .{});
        defer rm.scTestResultMergeDestroy(res);

        var nSuccess: u32 = 0;
        for (self.imps[0..self.n_imps]) |imp| {
            SymCryptWipe(&bBuf, bBuf.len);
            const status = scTestRsaSignImpSign(imp, pbHash, cbHash, pcstrHashAlgName, cbSalt, &bBuf, cbSig);
            if (status != STATUS_NOT_SUPPORTED) {
                scTestResultMergeAddAlgImp(res, imp, &bBuf, cbSig);
                nSuccess += 1;
            }
        }
        if (nSuccess == 0) {
            return STATUS_NOT_SUPPORTED;
        }
        rm.scTestResultMergeGetResult(res, pbSig, cbSig, 1);
        return STATUS_SUCCESS;
    }

    pub fn verify(
        self: *RsaSignMultiImp,
        pbHash: [*]const u8,
        cbHash: usize,
        pbSig: [*]const u8,
        cbSig: usize,
        pcstrHashAlgName: ?[*:0]const u8,
        cbSalt: u32,
    ) u32 {
        var bBuf: [4]u8 = undefined;
        const res = rm.scTestResultMergeCreate() orelse h.fatal("OOM", .{});
        defer rm.scTestResultMergeDestroy(res);

        var nSuccess: u32 = 0;
        for (self.imps[0..self.n_imps]) |imp| {
            const status = scTestRsaSignImpVerify(imp, pbHash, cbHash, pbSig, cbSig, pcstrHashAlgName, cbSalt);
            if (status != STATUS_NOT_SUPPORTED) {
                std.mem.writeInt(u32, &bBuf, status, .little);
                scTestResultMergeAddAlgImp(res, imp, &bBuf, 4);
                nSuccess += 1;
            }
        }
        if (nSuccess == 0) {
            return STATUS_NOT_SUPPORTED;
        }
        rm.scTestResultMergeGetResult(res, &bBuf, 4, 1);
        return std.mem.readInt(u32, &bBuf, .little);
    }
};

fn testRsaSignPkcs1Random(pRsaSign: *RsaSignMultiImp) void {
    var abSig: [RSAKEY_MAXKEYSIZE]u8 = undefined;
    var abHash: [128]u8 = undefined;
    var cbHash: usize = 0;
    const hashAlgs = getRsaHashAlgs();

    for (g_RsaTestKeyBlobs[0..g_nRsaTestKeyBlobs]) |*pBlob| {
        h.check(pRsaSign.setKey(pBlob) == STATUS_SUCCESS, "Failure to set key");

        var c: u32 = 0;
        while (c < 25) : (c += 1) {
            const cbMod: usize = pBlob.cbModulus;
            const hashAlgIdx: usize = rng.scTestRngUint32(&rng.g_rng) % hashAlgs.len;
            const pcstrHashAlgName: ?[*:0]const u8 = hashAlgs[hashAlgIdx].pszName;
            cbHash = SymCryptHashResultSize(hashAlgs[hashAlgIdx].pHashAlg);

            if (cbHash + 30 > cbMod) {
                continue;
            }

            SymCryptCallbackRandom(&abHash, cbHash);

            var status = pRsaSign.sign(&abHash, cbHash, pcstrHashAlgName, 0, &abSig, cbMod);
            if (status == STATUS_NOT_SUPPORTED) {
                continue;
            }

            h.check(status == STATUS_SUCCESS, "Error during RSA PKCS1 signing");

            status = pRsaSign.verify(&abHash, cbHash, &abSig, cbMod, pcstrHashAlgName, 0);
            h.check(status == STATUS_SUCCESS, "Error during RSA PKCS1 verification");

            const modPos: usize = rng.scTestRngUint32(&rng.g_rng) % (cbMod + cbHash);
            const modVal: u8 = @intCast(1 + (rng.scTestRngUint32(&rng.g_rng) % 255));
            if (modPos < cbMod) {
                abSig[modPos] ^= modVal;
            } else {
                abHash[modPos - cbMod] ^= modVal;
            }

            status = pRsaSign.verify(&abHash, cbHash, &abSig, cbMod, pcstrHashAlgName, 0);
            h.check(status != STATUS_SUCCESS, "Corrupted PKCS1 signature verified OK");
        }
    }

    h.check(pRsaSign.setKey(null) == STATUS_SUCCESS, "Failed to clear key");
}

fn testRsaSignPssRandom(pRsaSign: *RsaSignMultiImp) void {
    var abSig: [RSAKEY_MAXKEYSIZE]u8 = undefined;
    var abHash: [128]u8 = undefined;
    const hashAlgs = getRsaHashAlgs();

    for (g_RsaTestKeyBlobs[0..g_nRsaTestKeyBlobs]) |*pBlob| {
        if (pBlob.nBitsModulus < 512) {
            continue;
        }

        h.check(pRsaSign.setKey(pBlob) == STATUS_SUCCESS, "Failure to set key");

        var c: u32 = 0;
        while (c < 25) : (c += 1) {
            const cbMod: usize = pBlob.cbModulus;
            const hashAlgIdx: usize = rng.scTestRngUint32(&rng.g_rng) % hashAlgs.len;
            const pcstrHashAlgName = hashAlgs[hashAlgIdx].pszName;

            const cbHash: usize = SymCryptHashResultSize(hashAlgs[hashAlgIdx].pHashAlg);
            const cbSalt: u32 = @intCast(rng.scTestRngUint32(&rng.g_rng) % (cbHash + 2));

            if (cbHash + cbSalt + 3 > cbMod) {
                continue;
            }

            SymCryptCallbackRandom(&abHash, cbHash);

            for (pRsaSign.imps[0..pRsaSign.n_imps]) |imp| {
                var status = scTestRsaSignImpSign(imp, &abHash, cbHash, pcstrHashAlgName, cbSalt, &abSig, cbMod);
                if (status == STATUS_NOT_SUPPORTED) {
                    continue;
                }

                h.check(status == STATUS_SUCCESS, "Error during RSA PSS signing");

                status = pRsaSign.verify(&abHash, cbHash, &abSig, cbMod, pcstrHashAlgName, cbSalt);
                h.check(status == STATUS_SUCCESS, "Error during RSA PSS verification");

                const modPos: usize = rng.scTestRngUint32(&rng.g_rng) % (cbMod + cbHash);
                const modVal: u8 = @intCast(1 + (rng.scTestRngUint32(&rng.g_rng) % 255));
                if (modPos < cbMod) {
                    abSig[modPos] ^= modVal;
                } else {
                    abHash[modPos - cbMod] ^= modVal;
                }

                status = pRsaSign.verify(&abHash, cbHash, &abSig, cbMod, pcstrHashAlgName, cbSalt);
                h.check(status != STATUS_SUCCESS, "Corrupted PSS signature verified OK");

                if (modPos < cbMod) {
                    abSig[modPos] ^= modVal;
                } else {
                    abHash[modPos - cbMod] ^= modVal;
                }
            }
        }
    }

    h.check(pRsaSign.setKey(null) == STATUS_SUCCESS, "Failed to clear key");
}

fn testRsaSignInterfaces() void {
    var scError: u32 = SYMCRYPT_NO_ERROR;
    var abHash: [64]u8 = undefined;
    var abSig: [RSAKEY_MAXKEYSIZE]u8 = undefined;
    var cbSig: usize = 0;

    const pKey = rsaKeyFromTestBlob(&g_RsaTestKeyBlobs[6]);
    const pPubKey = rsaKeyPublicFromTestBlob(&g_RsaTestKeyBlobs[6]);

    const hashAlgs = getRsaHashAlgs();
    const cbHash = SymCryptHashResultSize(hashAlgs[2].pHashAlg);
    SymCryptCallbackRandom(&abHash, cbHash);

    const cbModulus: usize = SymCryptRsakeySizeofModulus(pKey);

    // Sign with a public-only key (must fail with SYMCRYPT_INVALID_ARGUMENT)
    scError = SymCryptRsaPkcs1Sign(
        pPubKey,
        &abHash,
        cbHash,
        hashAlgs[2].pOidList,
        hashAlgs[2].nOidCount,
        0,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        &abSig,
        cbModulus,
        &cbSig,
    );
    h.check(scError == SYMCRYPT_INVALID_ARGUMENT, "SymCryptRsaPkcs1Sign should fail with public key");

    scError = SymCryptRsaPssSign(
        pPubKey,
        &abHash,
        cbHash,
        hashAlgs[2].pHashAlg,
        cbHash,
        0,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        &abSig,
        cbModulus,
        &cbSig,
    );
    h.check(scError == SYMCRYPT_INVALID_ARGUMENT, "SymCryptRsaPssSign should fail with public key");

    // Sign with null pbSignature to query size
    scError = SymCryptRsaPkcs1Sign(
        pKey,
        &abHash,
        cbHash,
        hashAlgs[2].pOidList,
        hashAlgs[2].nOidCount,
        0,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        null,
        0,
        &cbSig,
    );
    h.check(scError == SYMCRYPT_NO_ERROR and cbSig == cbModulus, "SymCryptRsaPkcs1Sign query size failed");

    scError = SymCryptRsaPssSign(
        pKey,
        &abHash,
        cbHash,
        hashAlgs[2].pHashAlg,
        cbHash,
        0,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        null,
        0,
        &cbSig,
    );
    h.check(scError == SYMCRYPT_NO_ERROR and cbSig == cbModulus, "SymCryptRsaPssSign query size failed");

    // Sign with buffer too small
    scError = SymCryptRsaPkcs1Sign(
        pKey,
        &abHash,
        cbHash,
        hashAlgs[2].pOidList,
        hashAlgs[2].nOidCount,
        0,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        &abSig,
        cbModulus - 1,
        &cbSig,
    );
    h.check(scError == SYMCRYPT_INVALID_ARGUMENT, "SymCryptRsaPkcs1Sign should fail with INVALID_ARGUMENT");

    scError = SymCryptRsaPssSign(
        pKey,
        &abHash,
        cbHash,
        hashAlgs[2].pHashAlg,
        cbHash,
        0,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        &abSig,
        cbModulus - 1,
        &cbSig,
    );
    h.check(scError == SYMCRYPT_INVALID_ARGUMENT, "SymCryptRsaPssSign should fail with INVALID_ARGUMENT");

    // Sign with MSB first and verify with MSB first
    scError = SymCryptRsaPkcs1Sign(
        pKey,
        &abHash,
        cbHash,
        hashAlgs[2].pOidList,
        hashAlgs[2].nOidCount,
        0,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        &abSig,
        cbModulus,
        &cbSig,
    );
    h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptRsaPkcs1Sign MSB failed");

    scError = SymCryptRsaPkcs1Verify(
        pPubKey,
        &abHash,
        cbHash,
        &abSig,
        cbModulus,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        hashAlgs[2].pOidList,
        hashAlgs[2].nOidCount,
        0,
    );
    h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptRsaPkcs1Verify MSB failed");

    // Sign with OPTIONAL_HASH_OID flag (fails on sign, valid on verify)
    scError = SymCryptRsaPkcs1Sign(
        pKey,
        &abHash,
        cbHash,
        hashAlgs[2].pOidList,
        hashAlgs[2].nOidCount,
        SYMCRYPT_FLAG_RSA_PKCS1_OPTIONAL_HASH_OID,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        &abSig,
        cbModulus,
        &cbSig,
    );
    h.check(scError == SYMCRYPT_INVALID_ARGUMENT, "SymCryptRsaPkcs1Sign should reject OPTIONAL_HASH_OID");

    scError = SymCryptRsaPkcs1Sign(
        pKey,
        &abHash,
        cbHash,
        null,
        0,
        SYMCRYPT_FLAG_RSA_PKCS1_NO_ASN1,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        &abSig,
        cbModulus,
        &cbSig,
    );
    h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptRsaPkcs1Sign NO_ASN1 failed");

    scError = SymCryptRsaPkcs1Verify(
        pPubKey,
        &abHash,
        cbHash,
        &abSig,
        cbModulus,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        hashAlgs[2].pOidList,
        hashAlgs[2].nOidCount,
        SYMCRYPT_FLAG_RSA_PKCS1_OPTIONAL_HASH_OID,
    );
    h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptRsaPkcs1Verify OPTIONAL_HASH_OID failed");

    // PSS MSB first and PSS minimum salt flag
    scError = SymCryptRsaPssSign(
        pKey,
        &abHash,
        cbHash,
        hashAlgs[2].pHashAlg,
        cbHash,
        0,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        &abSig,
        cbModulus,
        &cbSig,
    );
    h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptRsaPssSign MSB failed");

    scError = SymCryptRsaPssVerify(
        pPubKey,
        &abHash,
        cbHash,
        &abSig,
        cbModulus,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        hashAlgs[2].pHashAlg,
        cbHash,
        0,
    );
    h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptRsaPssVerify MSB failed");

    scError = SymCryptRsaPssVerify(
        pPubKey,
        &abHash,
        cbHash,
        &abSig,
        cbModulus,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        hashAlgs[2].pHashAlg,
        cbHash - 1,
        SYMCRYPT_FLAG_RSA_PSS_VERIFY_WITH_MINIMUM_SALT,
    );
    h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptRsaPssVerify with minimum salt failed");

    scError = SymCryptRsaPssVerify(
        pPubKey,
        &abHash,
        cbHash,
        &abSig,
        cbModulus,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        hashAlgs[2].pHashAlg,
        cbHash + 1,
        SYMCRYPT_FLAG_RSA_PSS_VERIFY_WITH_MINIMUM_SALT,
    );
    h.check(scError == SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE, "SymCryptRsaPssVerify with larger minimum salt should fail");

    SymCryptRsakeyFree(pPubKey);
    SymCryptRsakeyFree(pKey);
}

fn testRsaPaddingFunctions() void {
    var scError: u32 = SYMCRYPT_NO_ERROR;
    var abHash: [64]u8 = undefined;
    var abSalt: [64]u8 = undefined;
    var abFormat: [256]u8 = undefined;

    const hashAlgs = getRsaHashAlgs();
    const cbHash = SymCryptHashResultSize(hashAlgs[2].pHashAlg);
    SymCryptCallbackRandom(&abHash, cbHash);
    SymCryptCallbackRandom(&abSalt, cbHash);

    const cbFormat: usize = abFormat.len;
    const cbScratchPkcs1 = scTestScratchBytesForRsaPkcs1(cbFormat);
    const cbScratchPss = scTestScratchBytesForRsaPss(hashAlgs[2].pHashAlg, cbHash, cbFormat);
    const cbScratch = @max(cbScratchPkcs1, cbScratchPss);

    const pbScratchRaw = SymCryptCallbackAlloc(cbScratch);
    h.check(pbScratchRaw != null, "Scratch allocation failed");
    const pbScratch: [*]u8 = @ptrCast(pbScratchRaw.?);
    defer {
        SymCryptWipe(pbScratch, cbScratch);
        SymCryptCallbackFree(pbScratch);
    }

    // PKCS1 No-ASN1 padding
    scError = SymCryptRsaPkcs1ApplySignaturePadding(
        &abHash,
        cbHash,
        null,
        0,
        SYMCRYPT_FLAG_RSA_PKCS1_NO_ASN1,
        &abFormat,
        cbFormat,
    );
    h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptRsaPkcs1ApplySignaturePadding failed");

    scError = SymCryptRsaPkcs1VerifySignaturePadding(
        &abHash,
        cbHash,
        null,
        0,
        &abFormat,
        cbFormat,
        0,
        pbScratch,
        cbScratch,
    );
    h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptRsaPkcs1VerifySignaturePadding failed");

    // PSS padding
    scError = SymCryptRsaPssApplySignaturePadding(
        &abHash,
        cbHash,
        hashAlgs[2].pHashAlg,
        &abSalt,
        cbHash,
        @intCast(cbFormat * 8),
        0,
        &abFormat,
        cbFormat,
        pbScratch,
        cbScratch,
    );
    h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptRsaPssApplySignaturePadding failed");

    scError = SymCryptRsaPssVerifySignaturePadding(
        &abHash,
        cbHash,
        hashAlgs[2].pHashAlg,
        cbHash,
        &abFormat,
        cbFormat,
        @intCast(cbFormat * 8),
        0,
        pbScratch,
        cbScratch,
    );
    h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptRsaPssVerifySignaturePadding failed");
}

fn testRsaSignKats() void {
    const pResource = h.findDataItem("kat_rsasign.dat") orelse h.fatal("kat_rsasign.dat not found", .{});
    var katRsaSign = kat.KatData.init(pResource.name, pResource.pbData, pResource.cbData);
    var katItem: kat.KatItem = .{};
    defer katItem.deinitDataItems();

    var sep: []const u8 = "    ";
    var doneAnything = false;

    var pRsaSignPkcs1 = RsaSignMultiImp.init("RsaSignPkcs1");
    defer {
        if (pRsaSignPkcs1) |*imp| {
            imp.deinit();
        }
    }

    var pRsaSignPss = RsaSignMultiImp.init("RsaSignPss");
    defer {
        if (pRsaSignPss) |*imp| {
            imp.deinit();
        }
    }

    var keyBlob: RsakeyTestBlob = std.mem.zeroes(RsakeyTestBlob);
    var abSig: [RSAKEY_MAXKEYSIZE]u8 = undefined;
    var catBuf: [64]u8 = undefined;
    var catLen: usize = 0;

    while (true) {
        katRsaSign.getKatItem(&katItem);
        const ulLine: i64 = katItem.line;

        if (katItem.itemType == kat.KAT_TYPE_END) {
            break;
        }

        if (katItem.itemType == kat.KAT_TYPE_CATEGORY) {
            const cat = katItem.categoryName();
            catLen = @min(cat.len, catBuf.len);
            @memcpy(catBuf[0..catLen], cat[0..catLen]);
            const currentCategory = catBuf[0..catLen];
            if ((std.mem.eql(u8, currentCategory, "RsaSignPkcs1") and pRsaSignPkcs1 != null) or
                (std.mem.eql(u8, currentCategory, "RsaSignPss") and pRsaSignPss != null))
            {
                h.ziprint("{s}{s}", .{ sep, currentCategory });
                sep = ", ";
                doneAnything = true;
            }
        }

        if (katItem.itemType == kat.KAT_TYPE_DATASET) {
            const currentCategory = catBuf[0..catLen];
            const isPkcs1 = std.mem.eql(u8, currentCategory, "RsaSignPkcs1");
            const isPss = std.mem.eql(u8, currentCategory, "RsaSignPss");

            if ((!isPkcs1 and !isPss) or (isPkcs1 and pRsaSignPkcs1 == null) or (isPss and pRsaSignPss == null)) {
                continue;
            }

            if (kat.katIsFieldPresent(&katItem, "n")) {
                const bN = kat.katParseData(&katItem, "n");
                defer bN.deinit();
                const bE = kat.katParseData(&katItem, "e");
                defer bE.deinit();
                const bD = kat.katParseData(&katItem, "d");
                defer bD.deinit();
                const bP1 = kat.katParseData(&katItem, "p1");
                defer bP1.deinit();
                const bP2 = kat.katParseData(&katItem, "p2");
                defer bP2.deinit();
                const bHashAlg = kat.katParseData(&katItem, "hashalg");
                defer bHashAlg.deinit();
                const bHash = kat.katParseData(&katItem, "hash");
                defer bHash.deinit();
                const bSig = kat.katParseData(&katItem, "sig");
                defer bSig.deinit();

                var u32Other: u32 = 0;
                if (kat.findDataItem(&katItem, "cbsalt") != null) {
                    u32Other = @intCast(kat.katParseInteger(&katItem, "cbsalt"));
                }

                SymCryptWipe(@ptrCast(&keyBlob), @sizeOf(RsakeyTestBlob));
                keyBlob.nBitsModulus = @intCast(bN.cbData * 8);
                var pubExp: u64 = 0;
                for (bE.pbData[0..bE.cbData]) |byte| {
                    pubExp = (pubExp << 8) | byte;
                }
                keyBlob.u64PubExp = pubExp;
                keyBlob.cbModulus = @intCast(bN.cbData);
                keyBlob.cbPrime1 = @intCast(bP1.cbData);
                keyBlob.cbPrime2 = @intCast(bP2.cbData);

                h.check(
                    keyBlob.cbModulus <= RSAKEY_MAXKEYSIZE and keyBlob.cbPrime1 <= RSAKEY_MAXKEYSIZE and keyBlob.cbPrime2 <= RSAKEY_MAXKEYSIZE,
                    "Test vector too large",
                );
                @memcpy(keyBlob.abModulus[0..bN.cbData], bN.pbData[0..bN.cbData]);
                @memcpy(keyBlob.abPrime1[0..bP1.cbData], bP1.pbData[0..bP1.cbData]);
                @memcpy(keyBlob.abPrime2[0..bP2.cbData], bP2.pbData[0..bP2.cbData]);
                @memcpy(keyBlob.abPrivateExp[0..bD.cbData], bD.pbData[0..bD.cbData]);

                var acStringName: [100:0]u8 = std.mem.zeroes([100:0]u8);
                h.check(bHashAlg.cbData < acStringName.len, "?");
                @memcpy(acStringName[0..bHashAlg.cbData], bHashAlg.pbData[0..bHashAlg.cbData]);

                if (isPkcs1) {
                    var imp = &pRsaSignPkcs1.?;
                    h.check3(imp.setKey(&keyBlob) == STATUS_SUCCESS, "Failed to set key at line %lld", ulLine);
                    const vStatus = imp.verify(bHash.pbData, bHash.cbData, bSig.pbData, bSig.cbData, &acStringName, u32Other);
                    h.check3(vStatus == STATUS_SUCCESS, "Verify failed at line %lld", ulLine);
                    const sStatus = imp.sign(bHash.pbData, bHash.cbData, &acStringName, u32Other, &abSig, keyBlob.cbModulus);
                    h.check3(sStatus == STATUS_SUCCESS, "Sign failed at line %lld", ulLine);
                    _ = imp.setKey(null);
                } else if (isPss) {
                    var imp = &pRsaSignPss.?;
                    h.check3(imp.setKey(&keyBlob) == STATUS_SUCCESS, "Failed to set key at line %lld", ulLine);
                    const vStatus = imp.verify(bHash.pbData, bHash.cbData, bSig.pbData, bSig.cbData, &acStringName, u32Other);
                    h.check3(vStatus == STATUS_SUCCESS, "PSS Verify failed at line %lld", ulLine);
                    for (imp.imps[0..imp.n_imps]) |subImp| {
                        const sStatus = scTestRsaSignImpSign(subImp, bHash.pbData, bHash.cbData, &acStringName, u32Other, &abSig, keyBlob.cbModulus);
                        if (sStatus != STATUS_NOT_SUPPORTED) {
                            h.check3(sStatus == STATUS_SUCCESS, "PSS Sign failed at line %lld", ulLine);
                            const vStatus2 = imp.verify(bHash.pbData, bHash.cbData, &abSig, keyBlob.cbModulus, &acStringName, u32Other);
                            h.check3(vStatus2 == STATUS_SUCCESS, "PSS cross-verify failed at line %lld", ulLine);
                        }
                    }
                    _ = imp.setKey(null);
                }
            } else if (kat.katIsFieldPresent(&katItem, "rnd")) {
                if (isPkcs1) {
                    if (pRsaSignPkcs1) |*imp| {
                        testRsaSignPkcs1Random(imp);
                    }
                } else if (isPss) {
                    if (pRsaSignPss) |*imp| {
                        testRsaSignPssRandom(imp);
                    }
                }
            }
        }
    }

    if (doneAnything) {
        h.ziprint("\n", .{});
    }
}

pub export fn testRsaSignAlgorithms() callconv(.c) void {
    if (!h.isAlgorithmPresent("Rsa", 1)) {
        return;
    }
    rsaTestKeysGenerate();
    testRsaSignInterfaces();
    testRsaPaddingFunctions();
    testRsaSignKats();
}
