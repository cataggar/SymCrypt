// Copyright (c) Microsoft Corporation. Licensed under the MIT license.

const std = @import("std");
const h = @import("main_harness.zig");
const rng = @import("rng.zig");
const kat = @import("kat.zig");
const rm = @import("result_merge.zig");
const rsa_sign = @import("test_rsa_sign.zig");

const RSAKEY_MAXKEYSIZE = rsa_sign.RSAKEY_MAXKEYSIZE;
const RsakeyTestBlob = rsa_sign.RsakeyTestBlob;

const STATUS_SUCCESS: u32 = 0;
const STATUS_NOT_SUPPORTED: u32 = 0xC00000BB;
const STATUS_UNSUCCESSFUL: u32 = 0xC0000001;

const SYMCRYPT_NO_ERROR: u32 = 0;
const SYMCRYPT_INVALID_ARGUMENT: u32 = 0x800e;
const SYMCRYPT_BUFFER_TOO_SMALL: u32 = 0x800d;

const SYMCRYPT_NUMBER_FORMAT_LSB_FIRST: i32 = 1;
const SYMCRYPT_NUMBER_FORMAT_MSB_FIRST: i32 = 2;

extern fn SymCryptRsakeySizeofModulus(pkRsakey: ?*const anyopaque) callconv(.c) u32;
extern fn SymCryptRsakeyFree(pkObj: ?*anyopaque) callconv(.c) void;

extern fn SymCryptRsaRawEncrypt(
    pkRsakey: ?*const anyopaque,
    pbSrc: [*]const u8,
    cbSrc: usize,
    numFormat: i32,
    flags: u32,
    pbDst: [*]u8,
    cbDst: usize,
) callconv(.c) u32;
extern fn SymCryptRsaRawDecrypt(
    pkRsakey: ?*const anyopaque,
    pbSrc: [*]const u8,
    cbSrc: usize,
    numFormat: i32,
    flags: u32,
    pbDst: [*]u8,
    cbDst: usize,
) callconv(.c) u32;
extern fn SymCryptRsaPkcs1Encrypt(
    pkRsakey: ?*const anyopaque,
    pbSrc: [*]const u8,
    cbSrc: usize,
    flags: u32,
    numFormat: i32,
    pbDst: ?[*]u8,
    cbDst: usize,
    pcbDst: *usize,
) callconv(.c) u32;
extern fn SymCryptRsaPkcs1Decrypt(
    pkRsakey: ?*const anyopaque,
    pbSrc: [*]const u8,
    cbSrc: usize,
    numFormat: i32,
    flags: u32,
    pbDst: ?[*]u8,
    cbDst: usize,
    pcbDst: *usize,
) callconv(.c) u32;
extern fn SymCryptRsaOaepEncrypt(
    pkRsakey: ?*const anyopaque,
    pbSrc: [*]const u8,
    cbSrc: usize,
    pHashAlgorithm: ?*const anyopaque,
    pbLabel: ?[*]const u8,
    cbLabel: usize,
    flags: u32,
    numFormat: i32,
    pbDst: ?[*]u8,
    cbDst: usize,
    pcbDst: *usize,
) callconv(.c) u32;
extern fn SymCryptRsaOaepDecrypt(
    pkRsakey: ?*const anyopaque,
    pbSrc: [*]const u8,
    cbSrc: usize,
    numFormat: i32,
    pHashAlgorithm: ?*const anyopaque,
    pbLabel: ?[*]const u8,
    cbLabel: usize,
    flags: u32,
    pbDst: ?[*]u8,
    cbDst: usize,
    pcbDst: *usize,
) callconv(.c) u32;
extern fn SymCryptRsaPkcs1ApplyEncryptionPadding(
    pbPlaintext: [*]const u8,
    cbPlaintext: usize,
    pbPKCS1Format: [*]u8,
    cbPKCS1Format: usize,
) callconv(.c) u32;
extern fn SymCryptRsaPkcs1RemoveEncryptionPadding(
    pbPKCS1Format: [*]u8,
    cbPKCS1Format: usize,
    cbPKCS1Buffer: usize,
    pbPlaintext: [*]u8,
    cbPlaintext: usize,
    pcbPlaintext: *usize,
) callconv(.c) u32;
extern fn SymCryptRsaOaepApplyEncryptionPadding(
    pbPlaintext: [*]const u8,
    cbPlaintext: usize,
    pHashAlgorithm: ?*const anyopaque,
    pbLabel: ?[*]const u8,
    cbLabel: usize,
    pbSeed: ?[*]const u8,
    cbSeed: usize,
    pbOAEPFormat: [*]u8,
    cbOAEPFormat: usize,
    pbScratch: [*]u8,
    cbScratch: usize,
) callconv(.c) u32;
extern fn SymCryptRsaOaepRemoveEncryptionPadding(
    pbOAEPFormat: [*]const u8,
    cbOAEPFormat: usize,
    pHashAlgorithm: ?*const anyopaque,
    pbLabel: ?[*]const u8,
    cbLabel: usize,
    flags: u32,
    pbPlaintext: [*]u8,
    cbPlaintext: usize,
    pcbPlaintext: *usize,
    pbScratch: [*]u8,
    cbScratch: usize,
) callconv(.c) u32;

extern fn SymCryptHashResultSize(pHashAlgorithm: ?*const anyopaque) callconv(.c) usize;
extern fn SymCryptWipe(pbData: [*]u8, cbData: usize) callconv(.c) void;
extern fn SymCryptCallbackAlloc(nBytes: usize) callconv(.c) ?*anyopaque;
extern fn SymCryptCallbackFree(ptr: ?*anyopaque) callconv(.c) void;
extern fn SymCryptCallbackRandom(pbBuffer: [*]u8, cbBuffer: usize) callconv(.c) void;

extern fn scTestScratchBytesForRsaOaep(
    pHashAlgorithm: ?*const anyopaque,
    cbOAEPFormat: usize,
) callconv(.c) usize;

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
extern fn scTestRsaEncImpSetKey(impPtr: *anyopaque, pcKeyBlob: ?*const RsakeyTestBlob) callconv(.c) u32;
extern fn scTestRsaEncImpEncrypt(
    impPtr: *anyopaque,
    pbMsg: [*]const u8,
    cbMsg: usize,
    pcstrHashAlgName: ?[*:0]const u8,
    pbLabel: ?[*]const u8,
    cbLabel: usize,
    pbCiphertext: [*]u8,
    cbCiphertext: usize,
) callconv(.c) u32;
extern fn scTestRsaEncImpDecrypt(
    impPtr: *anyopaque,
    pbCiphertext: [*]const u8,
    cbCiphertext: usize,
    pcstrHashAlgName: ?[*:0]const u8,
    pbLabel: ?[*]const u8,
    cbLabel: usize,
    pbMsg: [*]u8,
    cbMsg: usize,
    pcbMsg: *usize,
) callconv(.c) u32;

const RsaEncMultiImp = struct {
    comps: [16]*anyopaque = undefined,
    n_comps: usize = 0,
    imps: [16]*anyopaque = undefined,
    n_imps: usize = 0,

    fn init(algName: []const u8) ?RsaEncMultiImp {
        if (!h.isAlgorithmPresent(algName.ptr, 0)) {
            return null;
        }
        var self = RsaEncMultiImp{};
        self.n_comps = scTestGetAllImplementations(algName.ptr, algName.len, &self.comps, self.comps.len);
        if (self.n_comps == 0) {
            return null;
        }
        return self;
    }

    fn deinit(self: *RsaEncMultiImp) void {
        for (self.comps[0..self.n_comps]) |imp| {
            scTestImpIncResults(imp);
        }
    }

    fn setKey(self: *RsaEncMultiImp, pcKeyBlob: ?*const RsakeyTestBlob) u32 {
        self.n_imps = 0;
        for (self.comps[0..self.n_comps]) |imp| {
            if (scTestRsaEncImpSetKey(imp, pcKeyBlob) == STATUS_SUCCESS) {
                self.imps[self.n_imps] = imp;
                self.n_imps += 1;
            }
        }
        return if (self.n_imps == 0) STATUS_NOT_SUPPORTED else STATUS_SUCCESS;
    }

    fn encrypt(
        self: *RsaEncMultiImp,
        pbMsg: [*]const u8,
        cbMsg: usize,
        pcstrHashAlgName: ?[*:0]const u8,
        pbLabel: ?[*]const u8,
        cbLabel: usize,
        pbCiphertext: [*]u8,
        cbCiphertext: usize,
    ) u32 {
        var bBuf: [RSAKEY_MAXKEYSIZE]u8 = undefined;
        const res = rm.scTestResultMergeCreate() orelse h.fatal("OOM", .{});
        defer rm.scTestResultMergeDestroy(res);

        var nSuccess: u32 = 0;
        for (self.imps[0..self.n_imps]) |imp| {
            SymCryptWipe(&bBuf, bBuf.len);
            const status = scTestRsaEncImpEncrypt(imp, pbMsg, cbMsg, pcstrHashAlgName, pbLabel, cbLabel, &bBuf, cbCiphertext);
            if (status != STATUS_NOT_SUPPORTED) {
                scTestResultMergeAddAlgImp(res, imp, &bBuf, cbCiphertext);
                nSuccess += 1;
            }
        }
        if (nSuccess == 0) {
            return STATUS_NOT_SUPPORTED;
        }
        rm.scTestResultMergeGetResult(res, pbCiphertext, cbCiphertext, 1);
        return STATUS_SUCCESS;
    }

    fn decrypt(
        self: *RsaEncMultiImp,
        pbCiphertext: [*]const u8,
        cbCiphertext: usize,
        pcstrHashAlgName: ?[*:0]const u8,
        pbLabel: ?[*]const u8,
        cbLabel: usize,
        pbMsg: [*]u8,
        cbBuf: usize,
        pcbMsg: *usize,
    ) u32 {
        var bBuf: [RSAKEY_MAXKEYSIZE + 8]u8 = undefined;
        const res = rm.scTestResultMergeCreate() orelse h.fatal("OOM", .{});
        defer rm.scTestResultMergeDestroy(res);

        var nSuccess: u32 = 0;
        for (self.imps[0..self.n_imps]) |imp| {
            SymCryptWipe(&bBuf, bBuf.len);
            var cbMsgOut: usize = 0x12345678;
            const status = scTestRsaEncImpDecrypt(imp, pbCiphertext, cbCiphertext, pcstrHashAlgName, pbLabel, cbLabel, bBuf[8..].ptr, cbBuf, &cbMsgOut);
            if (status != STATUS_NOT_SUPPORTED) {
                std.mem.writeInt(u32, bBuf[0..4], status, .little);
                if (status == STATUS_SUCCESS) {
                    std.mem.writeInt(u32, bBuf[4..8], @intCast(cbMsgOut), .little);
                } else {
                    SymCryptWipe(bBuf[8..].ptr, cbBuf);
                }
                scTestResultMergeAddAlgImp(res, imp, &bBuf, 8 + cbBuf);
                nSuccess += 1;
            }
        }
        if (nSuccess == 0) {
            return STATUS_NOT_SUPPORTED;
        }
        rm.scTestResultMergeGetResult(res, &bBuf, 8 + cbBuf, 1);
        const outStatus = std.mem.readInt(u32, bBuf[0..4], .little);
        const outLen: usize = std.mem.readInt(u32, bBuf[4..8], .little);
        h.check(outLen <= cbBuf, "Plaintext size too large");
        pcbMsg.* = outLen;
        @memcpy(pbMsg[0..outLen], bBuf[8 .. 8 + outLen]);
        return outStatus;
    }
};

fn testRsaEncRawRandom(pRsaEnc: *RsaEncMultiImp) void {
    var abMsg1: [RSAKEY_MAXKEYSIZE]u8 = undefined;
    var abMsg2: [RSAKEY_MAXKEYSIZE]u8 = undefined;
    var abCiphertext: [RSAKEY_MAXKEYSIZE]u8 = undefined;
    var cbMsg2: usize = 0;

    for (rsa_sign.g_RsaTestKeyBlobs[0..rsa_sign.g_nRsaTestKeyBlobs]) |*pBlob| {
        h.check(pRsaEnc.setKey(pBlob) == STATUS_SUCCESS, "Failure to set key");

        var c: u32 = 0;
        while (c < 25) : (c += 1) {
            const cbMod: usize = pBlob.cbModulus;
            SymCryptCallbackRandom(&abMsg1, cbMod);
            abMsg1[0] = 0; // Ensure msg < modulus

            var status = pRsaEnc.encrypt(&abMsg1, cbMod, null, null, 0, &abCiphertext, cbMod);
            h.check(status == STATUS_SUCCESS, "Error during RSA Raw encryption");

            status = pRsaEnc.decrypt(&abCiphertext, cbMod, null, null, 0, &abMsg2, cbMod, &cbMsg2);
            h.check(status == STATUS_SUCCESS, "Error during RSA Raw decryption");

            h.check(cbMsg2 == cbMod and std.mem.eql(u8, abMsg1[0..cbMod], abMsg2[0..cbMod]), "Raw decrypt mismatch");
        }
    }

    h.check(pRsaEnc.setKey(null) == STATUS_SUCCESS, "Failed to clear key");
}

fn testRsaEncPkcs1Random(pRsaEnc: *RsaEncMultiImp) void {
    var abMsg1: [RSAKEY_MAXKEYSIZE]u8 = undefined;
    var abMsg2: [RSAKEY_MAXKEYSIZE]u8 = undefined;
    var abCiphertext: [RSAKEY_MAXKEYSIZE]u8 = undefined;
    var cbMsg2: usize = 0;

    for (rsa_sign.g_RsaTestKeyBlobs[0..rsa_sign.g_nRsaTestKeyBlobs]) |*pBlob| {
        h.check(pRsaEnc.setKey(pBlob) == STATUS_SUCCESS, "Failure to set key");

        var c: u32 = 0;
        while (c < 25) : (c += 1) {
            const cbMod: usize = pBlob.cbModulus;
            if (cbMod < 11) continue;

            const cbMsg1: usize = rng.scTestRngUint32(&rng.g_rng) % (cbMod - 10);
            SymCryptCallbackRandom(&abMsg1, cbMsg1);

            for (pRsaEnc.imps[0..pRsaEnc.n_imps]) |imp| {
                var status = scTestRsaEncImpEncrypt(imp, &abMsg1, cbMsg1, null, null, 0, &abCiphertext, cbMod);
                if (status == STATUS_NOT_SUPPORTED) {
                    continue;
                }
                h.check(status == STATUS_SUCCESS, "Error during RSA PKCS1 encryption");

                status = pRsaEnc.decrypt(&abCiphertext, cbMod, null, null, 0, &abMsg2, cbMod, &cbMsg2);
                h.check(status == STATUS_SUCCESS, "Error during RSA PKCS1 decryption");
                h.check(cbMsg1 == cbMsg2 and std.mem.eql(u8, abMsg1[0..cbMsg1], abMsg2[0..cbMsg1]), "PKCS1 decrypt mismatch");

                // Corrupt ciphertext (avoid most-significant byte to stay < modulus)
                const modPos: usize = 1 + (rng.scTestRngUint32(&rng.g_rng) % (cbMod - 1));
                abCiphertext[modPos] ^= @intCast(1 + (rng.scTestRngUint32(&rng.g_rng) % 255));

                status = pRsaEnc.decrypt(&abCiphertext, cbMod, null, null, 0, &abMsg2, cbMod, &cbMsg2);
                h.check(
                    status != STATUS_SUCCESS or cbMsg1 != cbMsg2 or !std.mem.eql(u8, abMsg1[0..cbMsg1], abMsg2[0..cbMsg1]),
                    "Corrupted PKCS1 ciphertext decrypted to original message",
                );
            }
        }
    }

    h.check(pRsaEnc.setKey(null) == STATUS_SUCCESS, "Failed to clear key");
}

fn testRsaEncOaepRandom(pRsaEnc: *RsaEncMultiImp) void {
    var abMsg1: [RSAKEY_MAXKEYSIZE]u8 = undefined;
    var abMsg2: [RSAKEY_MAXKEYSIZE]u8 = undefined;
    var abLabel: [64]u8 = undefined;
    var abCiphertext: [RSAKEY_MAXKEYSIZE]u8 = undefined;
    var cbMsg2: usize = 0;
    const hashAlgs = rsa_sign.getRsaHashAlgs();

    for (rsa_sign.g_RsaTestKeyBlobs[0..rsa_sign.g_nRsaTestKeyBlobs]) |*pBlob| {
        h.check(pRsaEnc.setKey(pBlob) == STATUS_SUCCESS, "Failure to set key");

        var c: u32 = 0;
        while (c < 25) : (c += 1) {
            const cbMod: usize = pBlob.cbModulus;
            const hashAlgIdx: usize = rng.scTestRngUint32(&rng.g_rng) % hashAlgs.len;
            const pcstrHashAlgName = hashAlgs[hashAlgIdx].pszName;
            const cbHash = SymCryptHashResultSize(hashAlgs[hashAlgIdx].pHashAlg);

            if (cbMod < 2 * cbHash + 2) {
                continue;
            }

            const cbMsg1: usize = rng.scTestRngUint32(&rng.g_rng) % (cbMod - 2 * cbHash - 1);
            const cbLabel: usize = rng.scTestRngUint32(&rng.g_rng) % abLabel.len;
            SymCryptCallbackRandom(&abMsg1, cbMsg1);
            SymCryptCallbackRandom(&abLabel, cbLabel);

            for (pRsaEnc.imps[0..pRsaEnc.n_imps]) |imp| {
                var status = scTestRsaEncImpEncrypt(imp, &abMsg1, cbMsg1, pcstrHashAlgName, &abLabel, cbLabel, &abCiphertext, cbMod);
                if (status == STATUS_NOT_SUPPORTED) {
                    continue;
                }
                h.check(status == STATUS_SUCCESS, "Error during RSA OAEP encryption");

                status = pRsaEnc.decrypt(&abCiphertext, cbMod, pcstrHashAlgName, &abLabel, cbLabel, &abMsg2, cbMod, &cbMsg2);
                h.check(status == STATUS_SUCCESS, "Error during RSA OAEP decryption");
                h.check(cbMsg1 == cbMsg2 and std.mem.eql(u8, abMsg1[0..cbMsg1], abMsg2[0..cbMsg1]), "OAEP decrypt mismatch");

                const modPos: usize = 1 + (rng.scTestRngUint32(&rng.g_rng) % (cbMod - 1));
                abCiphertext[modPos] ^= @intCast(1 + (rng.scTestRngUint32(&rng.g_rng) % 255));

                status = pRsaEnc.decrypt(&abCiphertext, cbMod, pcstrHashAlgName, &abLabel, cbLabel, &abMsg2, cbMod, &cbMsg2);
                h.check(status != STATUS_SUCCESS, "Corrupted OAEP ciphertext decrypted OK");
            }
        }
    }

    h.check(pRsaEnc.setKey(null) == STATUS_SUCCESS, "Failed to clear key");
}

fn testRsaEncInterfaces() void {
    var scError: u32 = SYMCRYPT_NO_ERROR;
    var abPlain: [64]u8 = undefined;
    var abCipher: [RSAKEY_MAXKEYSIZE]u8 = undefined;
    var abOut: [RSAKEY_MAXKEYSIZE]u8 = undefined;
    var cbCipher: usize = 0;
    var cbOut: usize = 0;

    const pKey = rsa_sign.rsaKeyFromTestBlob(&rsa_sign.g_RsaTestKeyBlobs[6]); // 1024-bit
    const cbModulus: usize = SymCryptRsakeySizeofModulus(pKey);
    const hashAlgs = rsa_sign.getRsaHashAlgs();

    SymCryptCallbackRandom(&abPlain, 32);

    // Query output size with null buffer
    scError = SymCryptRsaPkcs1Encrypt(pKey, &abPlain, 32, 0, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, null, 0, &cbCipher);
    h.check(scError == SYMCRYPT_NO_ERROR and cbCipher == cbModulus, "SymCryptRsaPkcs1Encrypt query size failed");

    scError = SymCryptRsaOaepEncrypt(pKey, &abPlain, 32, hashAlgs[2].pHashAlg, null, 0, 0, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, null, 0, &cbCipher);
    h.check(scError == SYMCRYPT_NO_ERROR and cbCipher == cbModulus, "SymCryptRsaOaepEncrypt query size failed");

    // Encrypt and Decrypt with MSB_FIRST
    scError = SymCryptRsaPkcs1Encrypt(pKey, &abPlain, 32, 0, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, &abCipher, cbModulus, &cbCipher);
    h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptRsaPkcs1Encrypt MSB failed");

    scError = SymCryptRsaPkcs1Decrypt(pKey, &abCipher, cbModulus, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, 0, &abOut, cbModulus, &cbOut);
    h.check(scError == SYMCRYPT_NO_ERROR and cbOut == 32 and std.mem.eql(u8, abPlain[0..32], abOut[0..32]), "SymCryptRsaPkcs1Decrypt MSB failed");

    scError = SymCryptRsaOaepEncrypt(pKey, &abPlain, 32, hashAlgs[2].pHashAlg, null, 0, 0, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, &abCipher, cbModulus, &cbCipher);
    h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptRsaOaepEncrypt MSB failed");

    scError = SymCryptRsaOaepDecrypt(pKey, &abCipher, cbModulus, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, hashAlgs[2].pHashAlg, null, 0, 0, &abOut, cbModulus, &cbOut);
    h.check(scError == SYMCRYPT_NO_ERROR and cbOut == 32 and std.mem.eql(u8, abPlain[0..32], abOut[0..32]), "SymCryptRsaOaepDecrypt MSB failed");

    // Raw encrypt & decrypt with LSB_FIRST
    SymCryptWipe(&abCipher, cbModulus);
    @memcpy(abCipher[0..32], abPlain[0..32]);
    scError = SymCryptRsaRawEncrypt(pKey, &abCipher, cbModulus, SYMCRYPT_NUMBER_FORMAT_LSB_FIRST, 0, &abOut, cbModulus);
    h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptRsaRawEncrypt LSB failed");

    scError = SymCryptRsaRawDecrypt(pKey, &abOut, cbModulus, SYMCRYPT_NUMBER_FORMAT_LSB_FIRST, 0, &abOut, cbModulus);
    h.check(scError == SYMCRYPT_NO_ERROR and std.mem.eql(u8, abCipher[0..cbModulus], abOut[0..cbModulus]), "SymCryptRsaRawDecrypt LSB failed");

    // Encryption padding functions
    var abFormat: [128]u8 = undefined;
    scError = SymCryptRsaPkcs1ApplyEncryptionPadding(&abPlain, 32, &abFormat, abFormat.len);
    h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptRsaPkcs1ApplyEncryptionPadding failed");

    scError = SymCryptRsaPkcs1RemoveEncryptionPadding(&abFormat, abFormat.len, abFormat.len, &abOut, abOut.len, &cbOut);
    h.check(scError == SYMCRYPT_NO_ERROR and cbOut == 32 and std.mem.eql(u8, abPlain[0..32], abOut[0..32]), "SymCryptRsaPkcs1RemoveEncryptionPadding failed");

    const cbScratch = scTestScratchBytesForRsaOaep(hashAlgs[2].pHashAlg, abFormat.len);
    const pbScratchRaw = SymCryptCallbackAlloc(cbScratch);
    h.check(pbScratchRaw != null, "OOM");
    const pbScratch: [*]u8 = @ptrCast(pbScratchRaw.?);

    var abSeed: [32]u8 = undefined;
    SymCryptCallbackRandom(&abSeed, 32);

    scError = SymCryptRsaOaepApplyEncryptionPadding(&abPlain, 32, hashAlgs[2].pHashAlg, null, 0, &abSeed, 32, &abFormat, abFormat.len, pbScratch, cbScratch);
    h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptRsaOaepApplyEncryptionPadding failed");

    scError = SymCryptRsaOaepRemoveEncryptionPadding(&abFormat, abFormat.len, hashAlgs[2].pHashAlg, null, 0, 0, &abOut, abOut.len, &cbOut, pbScratch, cbScratch);
    h.check(scError == SYMCRYPT_NO_ERROR and cbOut == 32 and std.mem.eql(u8, abPlain[0..32], abOut[0..32]), "SymCryptRsaOaepRemoveEncryptionPadding failed");

    SymCryptWipe(pbScratch, cbScratch);
    SymCryptCallbackFree(pbScratch);
    SymCryptRsakeyFree(pKey);
}

pub export fn testRsaEncAlgorithms() callconv(.c) void {
    if (!h.isAlgorithmPresent("Rsa", 1)) {
        return;
    }

    rsa_sign.rsaTestKeysGenerate();
    testRsaEncInterfaces();

    var sep: []const u8 = "";
    var doneAnything = false;

    var pRsaEncRaw = RsaEncMultiImp.init("RsaEncRaw");
    defer {
        if (pRsaEncRaw) |*imp| {
            imp.deinit();
        }
    }
    if (pRsaEncRaw) |*imp| {
        h.ziprint("{s}RsaEncRaw", .{sep});
        sep = ", ";
        doneAnything = true;
        testRsaEncRawRandom(imp);
    }

    var pRsaEncPkcs1 = RsaEncMultiImp.init("RsaEncPkcs1");
    defer {
        if (pRsaEncPkcs1) |*imp| {
            imp.deinit();
        }
    }
    if (pRsaEncPkcs1) |*imp| {
        h.ziprint("{s}RsaEncPkcs1", .{sep});
        sep = ", ";
        doneAnything = true;
        testRsaEncPkcs1Random(imp);
    }

    var pRsaEncOaep = RsaEncMultiImp.init("RsaEncOaep");
    defer {
        if (pRsaEncOaep) |*imp| {
            imp.deinit();
        }
    }
    if (pRsaEncOaep) |*imp| {
        h.ziprint("{s}RsaEncOaep", .{sep});
        sep = ", ";
        doneAnything = true;
        testRsaEncOaepRandom(imp);
    }

    if (doneAnything) {
        h.ziprint("\n", .{});
    }
}
