// Copyright (c) Microsoft Corporation. Licensed under the MIT license.

const std = @import("std");
const h = @import("main_harness.zig");
const kat = @import("kat.zig");
const rng = @import("rng.zig");
const rm = @import("result_merge.zig");

const KdfArgumentGeneric: c_int = 1;
const KdfArgumentPbkdf2: c_int = 2;
const KdfArgumentSp800_108: c_int = 3;
const KdfArgumentTlsPrf: c_int = 4;
const KdfArgumentHkdf: c_int = 5;
const KdfArgumentSshKdf: c_int = 6;
const KdfArgumentSrtpKdf: c_int = 7;
const KdfArgumentSskdf: c_int = 8;

const SYMCRYPT_SSHKDF_IV_CLIENT_TO_SERVER: u8 = 'A';
const SYMCRYPT_SSHKDF_IV_SERVER_TO_CLIENT: u8 = 'B';
const SYMCRYPT_SSHKDF_ENCRYPTION_KEY_CLIENT_TO_SERVER: u8 = 'C';
const SYMCRYPT_SSHKDF_ENCRYPTION_KEY_SERVER_TO_CLIENT: u8 = 'D';
const SYMCRYPT_SSHKDF_INTEGRITY_KEY_CLIENT_TO_SERVER: u8 = 'E';
const SYMCRYPT_SSHKDF_INTEGRITY_KEY_SERVER_TO_CLIENT: u8 = 'F';

const SYMCRYPT_SRTP_ENCRYPTION_KEY: u8 = 0x00;
const SYMCRYPT_SRTP_AUTHENTICATION_KEY: u8 = 0x01;
const SYMCRYPT_SRTP_SALTING_KEY: u8 = 0x02;
const SYMCRYPT_SRTCP_ENCRYPTION_KEY: u8 = 0x03;
const SYMCRYPT_SRTCP_AUTHENTICATION_KEY: u8 = 0x04;
const SYMCRYPT_SRTCP_SALTING_KEY: u8 = 0x05;

const SYMCRYPT_SHA256_RESULT_SIZE: usize = 32;
const SYMCRYPT_NO_ERROR: u32 = 0;

const g_katMasterSecretLabel = "master secret";
const g_katKeyExpansionLabel = "key expansion";

pub const KDF_ARGUMENTS = extern struct {
    argType: c_int,
    u: extern union {
        uGeneric: extern struct {
            pbSelector: ?[*]const u8,
            cbSelector: usize,
        },
        uPbkdf2: extern struct {
            pbSalt: ?[*]const u8,
            cbSalt: usize,
            iterationCnt: u64,
        },
        uSp800_108: extern struct {
            pbLabel: ?[*]const u8,
            cbLabel: usize,
            pbContext: ?[*]const u8,
            cbContext: usize,
        },
        uTlsPrf: extern struct {
            pbLabel: ?[*]const u8,
            cbLabel: usize,
            pbSeed: ?[*]const u8,
            cbSeed: usize,
        },
        uHkdf: extern struct {
            pbSalt: ?[*]const u8,
            cbSalt: usize,
            pbInfo: ?[*]const u8,
            cbInfo: usize,
        },
        uSshKdf: extern struct {
            hashName: ?[*:0]const u8,
            pbHashValue: ?[*]const u8,
            cbHashValue: usize,
            pbSessionId: ?[*]const u8,
            cbSessionId: usize,
            label: u8,
        },
        uSrtpKdf: extern struct {
            pbSalt: ?[*]const u8,
            cbSalt: usize,
            uKeyDerivationRate: u32,
            uIndex: u64,
            uIndexWidth: u32,
            label: u8,
        },
        uSskdf: extern struct {
            pbSalt: ?[*]const u8,
            cbSalt: usize,
            pbInfo: ?[*]const u8,
            cbInfo: usize,
        },
    },
};

extern fn SymCryptWipe(pbData: [*]u8, cbData: usize) callconv(.c) void;
extern fn SymCryptSha256(pbData: ?[*]const u8, cbData: usize, pbResult: [*]u8) callconv(.c) void;
extern fn SymCryptLoadMsbFirstUint32(pbSrc: [*]const u8, cbSrc: usize, puDst: *u32) callconv(.c) u32;
extern fn SymCryptLoadMsbFirstUint64(pbSrc: [*]const u8, cbSrc: usize, puDst: *u64) callconv(.c) u32;

extern fn scTestGetKdfImps(algNamePtr: [*]const u8, algNameLen: usize, outImps: [*]*anyopaque, maxImps: usize) callconv(.c) usize;
extern fn scTestAlgImpAddErrorKatFailure(pImp: *anyopaque, delta: u64) callconv(.c) void;
extern fn scTestResultMergeAddAlgImp(resMergeHandle: ?*anyopaque, pImp: *anyopaque, pbData: [*]const u8, cbData: usize) callconv(.c) void;
extern fn scTestKdfImpDerive(pImp: *anyopaque, pbKey: ?[*]const u8, cbKey: usize, pArgs: *KDF_ARGUMENTS, pbDst: [*]u8, cbDst: usize) callconv(.c) void;

const KdfMultiImp = struct {
    m_algorithmName: []u8,
    m_imps: std.ArrayListUnmanaged(*anyopaque) = .empty,
    m_nErrorKatFailure: u64 = 0,

    fn initNew(algName: []const u8) ?*KdfMultiImp {
        var imp_buf: [64]*anyopaque = undefined;
        const count = scTestGetKdfImps(algName.ptr, algName.len, &imp_buf, imp_buf.len);
        if (count == 0) return null;

        const self = std.heap.c_allocator.create(KdfMultiImp) catch h.fatal("Out of memory", .{});
        self.* = .{
            .m_algorithmName = std.heap.c_allocator.dupe(u8, algName) catch h.fatal("Out of memory", .{}),
        };
        const n = @min(count, imp_buf.len);
        self.m_imps.appendSlice(std.heap.c_allocator, imp_buf[0..n]) catch h.fatal("Out of memory", .{});
        return self;
    }

    fn deinit(self: *KdfMultiImp) void {
        for (self.m_imps.items) |imp| {
            scTestAlgImpAddErrorKatFailure(imp, self.m_nErrorKatFailure);
        }
        self.m_imps.deinit(std.heap.c_allocator);
        std.heap.c_allocator.free(self.m_algorithmName);
        std.heap.c_allocator.destroy(self);
    }

    fn derive(
        self: *KdfMultiImp,
        pbKey: ?[*]const u8,
        cbKey: usize,
        pArgs: *KDF_ARGUMENTS,
        pbDst: [*]u8,
        cbDst: usize,
    ) void {
        var buf: [1024]u8 = undefined;
        const res = rm.scTestResultMergeCreate();
        defer rm.scTestResultMergeDestroy(res);

        h.check(cbDst <= buf.len, "Buffer too small");

        for (self.m_imps.items) |imp| {
            SymCryptWipe(&buf, cbDst);
            scTestKdfImpDerive(imp, pbKey, cbKey, pArgs, &buf, cbDst);
            scTestResultMergeAddAlgImp(res, imp, &buf, cbDst);
        }

        rm.scTestResultMergeGetResult(res, pbDst, cbDst, 1);
    }
};

fn katKdfSingle(
    pImp: *KdfMultiImp,
    pbKey: [*]const u8,
    cbKey: usize,
    pArgs: *KDF_ARGUMENTS,
    pbResult: [*]const u8,
    cbResult: usize,
    line: i64,
) void {
    var buf: [512]u8 = undefined;
    h.check(cbResult <= buf.len, "Buffer too small");

    pImp.derive(pbKey, cbKey, pArgs, &buf, cbResult);
    h.check3(std.mem.eql(u8, buf[0..cbResult], pbResult[0..cbResult]), "Result mismatch in line {d}", line);
}

fn testKdfRandom(
    pImp: *KdfMultiImp,
    argType: c_int,
    rrep: usize,
    keyLen: usize,
    pbResult: [*]const u8,
    cbResult: usize,
    line: i64,
) void {
    var buf: [1024]u8 = undefined;
    var tmp1: [256]u8 = undefined;
    var local_rng: rng.Rng = undefined;
    rng.scTestRngInit(&local_rng);
    defer rng.scTestRngDeinit(&local_rng);

    const algNameSize = pImp.m_algorithmName.len;
    h.check(algNameSize < buf.len - @sizeOf(u64), "Algorithm name too long");
    @memcpy(buf[0..algNameSize], pImp.m_algorithmName);
    std.mem.writeInt(u64, buf[algNameSize..][0..8], @as(u64, @intCast(keyLen)), .little);
    rng.scTestRngReset(&local_rng, &buf, algNameSize + @sizeOf(u64));

    @memset(&buf, 0);

    const bufSize = buf.len;

    for (0..rrep) |_| {
        var kLen: usize = 0;
        if ((keyLen & 0xff000000) != 0) {
            kLen = rng.scTestRngSizet(&local_rng, (keyLen & 0xffff) + 1);
        } else {
            kLen = keyLen & 0xffff;
        }

        h.check3(kLen <= bufSize, "Key length too large in line {d}", line);

        const keyIdx = rng.scTestRngSizet(&local_rng, bufSize - kLen);

        var args: KDF_ARGUMENTS = undefined;
        args.argType = argType;

        var len: usize = 0;
        var pos: usize = 0;

        switch (argType) {
            KdfArgumentGeneric => {
                len = rng.scTestRngSizet(&local_rng, bufSize);
                pos = rng.scTestRngSizet(&local_rng, bufSize - len);
                args.u.uGeneric.pbSelector = buf[pos..].ptr;
                args.u.uGeneric.cbSelector = len;
            },
            KdfArgumentPbkdf2 => {
                len = rng.scTestRngSizet(&local_rng, bufSize);
                pos = rng.scTestRngSizet(&local_rng, bufSize - len);
                args.u.uPbkdf2.pbSalt = buf[pos..].ptr;
                args.u.uPbkdf2.cbSalt = len;
                args.u.uPbkdf2.iterationCnt = 1 + rng.scTestRngSizetNonUniform(&local_rng, 1024, 4, 1);
            },
            KdfArgumentSp800_108 => {
                len = rng.scTestRngSizet(&local_rng, tmp1.len);
                pos = rng.scTestRngSizet(&local_rng, bufSize - len);
                @memcpy(tmp1[0..len], buf[pos .. pos + len]);
                if (len < tmp1.len) tmp1[len] = 0;
                args.u.uSp800_108.pbLabel = &tmp1;
                args.u.uSp800_108.cbLabel = len;

                len = rng.scTestRngSizet(&local_rng, tmp1.len);
                pos = rng.scTestRngSizet(&local_rng, bufSize - len);
                args.u.uSp800_108.pbContext = buf[pos..].ptr;
                args.u.uSp800_108.cbContext = len;
            },
            else => {
                h.check(false, "?");
            },
        }

        len = 1 + rng.scTestRngSizetNonUniform(&local_rng, bufSize - 1, 32, 1);
        h.check(len <= bufSize, "?");
        pos = rng.scTestRngSizet(&local_rng, bufSize - len);
        pImp.derive(buf[keyIdx..].ptr, kLen, &args, buf[pos..].ptr, len);
    }

    SymCryptSha256(&buf, bufSize, &buf);

    h.check3(cbResult <= SYMCRYPT_SHA256_RESULT_SIZE, "Result size too long in line {d}", line);
    if (!std.mem.eql(u8, buf[0..cbResult], pbResult[0..cbResult])) {
        h.zprint("*\nWrong KDF result in line {d}. \nExpected ", .{line});
        h.printHex(pbResult[0..cbResult]);
        h.zprint("\nGot      ", .{});
        h.printHex(buf[0..cbResult]);
        h.ziprint("\n", .{});
        pImp.m_nErrorKatFailure += 1;
    }
}

fn testKdfKats() void {
    var katKdf = kat.ZigKatReader.init("kat_kdf.dat");
    var katItem: kat.ZigKatItem = .{};
    defer katItem.deinit();

    var sep: []const u8 = "    ";
    var doneAnything = false;

    var pKdfMultiImp: ?*KdfMultiImp = null;
    defer if (pKdfMultiImp) |p| p.deinit();
    var skipData = true;

    while (true) {
        katKdf.getKatItem(&katItem);
        const line = katItem.line;
        if (katItem.type == kat.KAT_TYPE_END) break;

        if (katItem.type == kat.KAT_TYPE_CATEGORY) {
            if (pKdfMultiImp) |p| {
                p.deinit();
                pKdfMultiImp = null;
            }
            pKdfMultiImp = KdfMultiImp.initNew(katItem.categoryName);
            skipData = (pKdfMultiImp == null);
            if (!skipData) {
                h.ziprint("{s}{s}", .{ sep, katItem.categoryName });
                sep = ", ";
                doneAnything = true;
            }
        }

        if (katItem.type == kat.KAT_TYPE_DATASET and !skipData) {
            const pKdf = pKdfMultiImp.?;
            var args: KDF_ARGUMENTS = undefined;

            if (katItem.isFieldPresent("iterationcnt")) {
                args.argType = KdfArgumentPbkdf2;
                h.check3(katItem.dataItems.items.len == 4, "Too many items in PBKDF2 record at line {d}", line);

                const katKey = katItem.parseData("key");
                defer std.heap.c_allocator.free(katKey);
                const katSalt = katItem.parseData("salt");
                defer std.heap.c_allocator.free(katSalt);
                const iterationCnt: u64 = @bitCast(katItem.parseInteger("iterationcnt"));
                const katRes = katItem.parseData("res");
                defer std.heap.c_allocator.free(katRes);

                args.u.uPbkdf2.pbSalt = katSalt.ptr;
                args.u.uPbkdf2.cbSalt = katSalt.len;
                args.u.uPbkdf2.iterationCnt = iterationCnt;

                katKdfSingle(pKdf, katKey.ptr, katKey.len, &args, katRes.ptr, katRes.len, line);
                continue;
            }

            if (katItem.isFieldPresent("selector")) {
                args.argType = KdfArgumentGeneric;
                h.check3(katItem.dataItems.items.len == 3, "Too many items in KDF generic record in line {d}", line);

                const katKey = katItem.parseData("key");
                defer std.heap.c_allocator.free(katKey);
                const katSelector = katItem.parseData("selector");
                defer std.heap.c_allocator.free(katSelector);
                const katRes = katItem.parseData("res");
                defer std.heap.c_allocator.free(katRes);

                args.u.uGeneric.pbSelector = katSelector.ptr;
                args.u.uGeneric.cbSelector = katSelector.len;

                katKdfSingle(pKdf, katKey.ptr, katKey.len, &args, katRes.ptr, katRes.len, line);
                continue;
            }

            if (katItem.isFieldPresent("label")) {
                args.argType = KdfArgumentSp800_108;
                h.check3(katItem.dataItems.items.len == 4, "Too many items in SP800-108 record in line {d}", line);

                const katKey = katItem.parseData("key");
                defer std.heap.c_allocator.free(katKey);
                const katLabel = katItem.parseData("label");
                defer std.heap.c_allocator.free(katLabel);
                const katContext = katItem.parseData("context");
                defer std.heap.c_allocator.free(katContext);
                const katRes = katItem.parseData("res");
                defer std.heap.c_allocator.free(katRes);

                args.u.uSp800_108.pbLabel = katLabel.ptr;
                args.u.uSp800_108.cbLabel = katLabel.len;
                args.u.uSp800_108.pbContext = katContext.ptr;
                args.u.uSp800_108.cbContext = katContext.len;

                katKdfSingle(pKdf, katKey.ptr, katKey.len, &args, katRes.ptr, katRes.len, line);
                continue;
            }

            if (katItem.isFieldPresent("rnd")) {
                h.check3(katItem.dataItems.items.len == 4, "Too many items in KDF rnd record in line {d}", line);

                const rrep: usize = @intCast(katItem.parseInteger("rrep"));
                const argType: c_int = @intCast(katItem.parseInteger("argtype"));
                const keyLen: usize = @intCast(katItem.parseInteger("keylen"));
                const katRnd = katItem.parseData("rnd");
                defer std.heap.c_allocator.free(katRnd);

                h.check3(argType >= KdfArgumentGeneric and argType <= KdfArgumentSp800_108, "Invalid argType value in line {d}", line);

                testKdfRandom(pKdf, argType, rrep, keyLen, katRnd.ptr, katRnd.len, line);
                continue;
            }

            if (katItem.isFieldPresent("pre_master_secret")) {
                args.argType = KdfArgumentTlsPrf;
                h.check3(katItem.dataItems.items.len == 8, "Too many items in TLS PRF record in line {d}", line);

                const katPreMasterSecret = katItem.parseData("pre_master_secret");
                defer std.heap.c_allocator.free(katPreMasterSecret);
                const katClientHello = katItem.parseData("clienthello_random");
                defer std.heap.c_allocator.free(katClientHello);
                const katServerHello = katItem.parseData("serverhello_random");
                defer std.heap.c_allocator.free(katServerHello);
                const katClientHelloAndServerHello = std.mem.concat(std.heap.c_allocator, u8, &.{ katClientHello, katServerHello }) catch h.fatal("Out of memory", .{});
                defer std.heap.c_allocator.free(katClientHelloAndServerHello);

                const katServerRandom = katItem.parseData("server_random");
                defer std.heap.c_allocator.free(katServerRandom);
                const katClientRandom = katItem.parseData("client_random");
                defer std.heap.c_allocator.free(katClientRandom);
                const katServerRandomAndClientRandom = std.mem.concat(std.heap.c_allocator, u8, &.{ katServerRandom, katClientRandom }) catch h.fatal("Out of memory", .{});
                defer std.heap.c_allocator.free(katServerRandomAndClientRandom);

                const katMasterSecret = katItem.parseData("master_secret");
                defer std.heap.c_allocator.free(katMasterSecret);
                const katKeyBlock = katItem.parseData("key_block");
                defer std.heap.c_allocator.free(katKeyBlock);

                args.u.uTlsPrf.pbLabel = g_katMasterSecretLabel.ptr;
                args.u.uTlsPrf.cbLabel = g_katMasterSecretLabel.len;
                args.u.uTlsPrf.pbSeed = katClientHelloAndServerHello.ptr;
                args.u.uTlsPrf.cbSeed = katClientHelloAndServerHello.len;

                katKdfSingle(pKdf, katPreMasterSecret.ptr, katPreMasterSecret.len, &args, katMasterSecret.ptr, katMasterSecret.len, line);

                args.u.uTlsPrf.pbLabel = g_katKeyExpansionLabel.ptr;
                args.u.uTlsPrf.cbLabel = g_katKeyExpansionLabel.len;
                args.u.uTlsPrf.pbSeed = katServerRandomAndClientRandom.ptr;
                args.u.uTlsPrf.cbSeed = katServerRandomAndClientRandom.len;

                katKdfSingle(pKdf, katMasterSecret.ptr, katMasterSecret.len, &args, katKeyBlock.ptr, katKeyBlock.len, line);
                continue;
            }

            if (katItem.isFieldPresent("ikm")) {
                args.argType = KdfArgumentHkdf;
                h.check3(katItem.dataItems.items.len == 6, "Too many items in HKDF record in line {d}", line);

                const katKey = katItem.parseData("ikm");
                defer std.heap.c_allocator.free(katKey);
                const katSalt = katItem.parseData("salt");
                defer std.heap.c_allocator.free(katSalt);
                const katInfo = katItem.parseData("info");
                defer std.heap.c_allocator.free(katInfo);
                const katRes = katItem.parseData("okm");
                defer std.heap.c_allocator.free(katRes);

                args.u.uHkdf.pbSalt = katSalt.ptr;
                args.u.uHkdf.cbSalt = katSalt.len;
                args.u.uHkdf.pbInfo = katInfo.ptr;
                args.u.uHkdf.cbInfo = katInfo.len;

                katKdfSingle(pKdf, katKey.ptr, katKey.len, &args, katRes.ptr, katRes.len, line);
                continue;
            }

            if (katItem.isFieldPresent("session_id")) {
                args.argType = KdfArgumentSshKdf;
                h.check3(katItem.dataItems.items.len == 14, "Incorrect number of fields in SSH-KDF record in line {d}", line);

                const hashName = katItem.parseDataZ("hash");
                defer std.heap.c_allocator.free(hashName);
                const SharedKey = katItem.parseData("k");
                defer std.heap.c_allocator.free(SharedKey);
                const HashValue = katItem.parseData("h");
                defer std.heap.c_allocator.free(HashValue);
                const SessionId = katItem.parseData("session_id");
                defer std.heap.c_allocator.free(SessionId);

                args.u.uSshKdf.pbHashValue = HashValue.ptr;
                args.u.uSshKdf.cbHashValue = HashValue.len;
                args.u.uSshKdf.pbSessionId = SessionId.ptr;
                args.u.uSshKdf.cbSessionId = SessionId.len;
                args.u.uSshKdf.hashName = hashName.ptr;

                const katInitialIV_ClientToServer = katItem.parseData("initial iv (client to server)");
                defer std.heap.c_allocator.free(katInitialIV_ClientToServer);
                const katInitialIV_ServerToClient = katItem.parseData("initial iv (server to client)");
                defer std.heap.c_allocator.free(katInitialIV_ServerToClient);
                const katEncryptionKey_ClientToServer = katItem.parseData("encryption key (client to server)");
                defer std.heap.c_allocator.free(katEncryptionKey_ClientToServer);
                const katEncryptionKey_ServerToClient = katItem.parseData("encryption key (server to client)");
                defer std.heap.c_allocator.free(katEncryptionKey_ServerToClient);
                const katIntegrityKey_ClientToServer = katItem.parseData("integrity key (client to server)");
                defer std.heap.c_allocator.free(katIntegrityKey_ClientToServer);
                const katIntegrityKey_ServerToClient = katItem.parseData("integrity key (server to client)");
                defer std.heap.c_allocator.free(katIntegrityKey_ServerToClient);

                args.u.uSshKdf.label = SYMCRYPT_SSHKDF_IV_CLIENT_TO_SERVER;
                katKdfSingle(pKdf, SharedKey.ptr, SharedKey.len, &args, katInitialIV_ClientToServer.ptr, katInitialIV_ClientToServer.len, line);

                args.u.uSshKdf.label = SYMCRYPT_SSHKDF_IV_SERVER_TO_CLIENT;
                katKdfSingle(pKdf, SharedKey.ptr, SharedKey.len, &args, katInitialIV_ServerToClient.ptr, katInitialIV_ServerToClient.len, line);

                args.u.uSshKdf.label = SYMCRYPT_SSHKDF_ENCRYPTION_KEY_CLIENT_TO_SERVER;
                katKdfSingle(pKdf, SharedKey.ptr, SharedKey.len, &args, katEncryptionKey_ClientToServer.ptr, katEncryptionKey_ClientToServer.len, line);

                args.u.uSshKdf.label = SYMCRYPT_SSHKDF_ENCRYPTION_KEY_SERVER_TO_CLIENT;
                katKdfSingle(pKdf, SharedKey.ptr, SharedKey.len, &args, katEncryptionKey_ServerToClient.ptr, katEncryptionKey_ServerToClient.len, line);

                args.u.uSshKdf.label = SYMCRYPT_SSHKDF_INTEGRITY_KEY_CLIENT_TO_SERVER;
                katKdfSingle(pKdf, SharedKey.ptr, SharedKey.len, &args, katIntegrityKey_ClientToServer.ptr, katIntegrityKey_ClientToServer.len, line);

                args.u.uSshKdf.label = SYMCRYPT_SSHKDF_INTEGRITY_KEY_SERVER_TO_CLIENT;
                katKdfSingle(pKdf, SharedKey.ptr, SharedKey.len, &args, katIntegrityKey_ServerToClient.ptr, katIntegrityKey_ServerToClient.len, line);
                continue;
            }

            if (katItem.isFieldPresent("srtp k_e")) {
                args.argType = KdfArgumentSrtpKdf;
                h.check3(katItem.dataItems.items.len == 12, "Incorrect number of fields in SRTP-KDF record in line {d}", line);

                const k_master = katItem.parseData("k_master");
                defer std.heap.c_allocator.free(k_master);
                const master_salt = katItem.parseData("master_salt");
                defer std.heap.c_allocator.free(master_salt);
                const kdr = katItem.parseData("kdr");
                defer std.heap.c_allocator.free(kdr);
                const index = katItem.parseData("index");
                defer std.heap.c_allocator.free(index);
                const indexSRTCP = katItem.parseData("index (srtcp)");
                defer std.heap.c_allocator.free(indexSRTCP);

                args.u.uSrtpKdf.pbSalt = master_salt.ptr;
                args.u.uSrtpKdf.cbSalt = master_salt.len;

                var scError = SymCryptLoadMsbFirstUint32(kdr.ptr, kdr.len, &args.u.uSrtpKdf.uKeyDerivationRate);
                h.check(scError == SYMCRYPT_NO_ERROR, "Error reading srtp key derivation rate");

                const katSRTPk_e = katItem.parseData("srtp k_e");
                defer std.heap.c_allocator.free(katSRTPk_e);
                const katSRTPk_a = katItem.parseData("srtp k_a");
                defer std.heap.c_allocator.free(katSRTPk_a);
                const katSRTPk_s = katItem.parseData("srtp k_s");
                defer std.heap.c_allocator.free(katSRTPk_s);
                const katSRTCPk_e = katItem.parseData("srtcp k_e");
                defer std.heap.c_allocator.free(katSRTCPk_e);
                const katSRTCPk_a = katItem.parseData("srtcp k_a");
                defer std.heap.c_allocator.free(katSRTCPk_a);
                const katSRTCPk_s = katItem.parseData("srtcp k_s");
                defer std.heap.c_allocator.free(katSRTCPk_s);

                {
                    args.u.uSrtpKdf.uIndexWidth = 48;
                    scError = SymCryptLoadMsbFirstUint64(index.ptr, index.len, &args.u.uSrtpKdf.uIndex);
                    h.check(scError == SYMCRYPT_NO_ERROR, "Error reading srtp index");

                    args.u.uSrtpKdf.label = SYMCRYPT_SRTP_ENCRYPTION_KEY;
                    katKdfSingle(pKdf, k_master.ptr, k_master.len, &args, katSRTPk_e.ptr, katSRTPk_e.len, line);

                    args.u.uSrtpKdf.label = SYMCRYPT_SRTP_AUTHENTICATION_KEY;
                    katKdfSingle(pKdf, k_master.ptr, k_master.len, &args, katSRTPk_a.ptr, katSRTPk_a.len, line);

                    args.u.uSrtpKdf.label = SYMCRYPT_SRTP_SALTING_KEY;
                    katKdfSingle(pKdf, k_master.ptr, k_master.len, &args, katSRTPk_s.ptr, katSRTPk_s.len, line);
                }

                {
                    args.u.uSrtpKdf.uIndexWidth = 32;
                    scError = SymCryptLoadMsbFirstUint64(indexSRTCP.ptr, indexSRTCP.len, &args.u.uSrtpKdf.uIndex);
                    h.check(scError == SYMCRYPT_NO_ERROR, "Error reading srtcp index");

                    args.u.uSrtpKdf.label = SYMCRYPT_SRTCP_ENCRYPTION_KEY;
                    katKdfSingle(pKdf, k_master.ptr, k_master.len, &args, katSRTCPk_e.ptr, katSRTCPk_e.len, line);

                    args.u.uSrtpKdf.label = SYMCRYPT_SRTCP_AUTHENTICATION_KEY;
                    katKdfSingle(pKdf, k_master.ptr, k_master.len, &args, katSRTCPk_a.ptr, katSRTCPk_a.len, line);

                    args.u.uSrtpKdf.label = SYMCRYPT_SRTCP_SALTING_KEY;
                    katKdfSingle(pKdf, k_master.ptr, k_master.len, &args, katSRTCPk_s.ptr, katSRTCPk_s.len, line);
                }
                continue;
            }

            if (katItem.isFieldPresent("fixed_info")) {
                args.argType = KdfArgumentSskdf;
                h.check3(katItem.dataItems.items.len == 4, "Incorrect number of fields in SSKDF record in line {d}", line);

                const katSecret = katItem.parseData("z");
                defer std.heap.c_allocator.free(katSecret);
                const katFixedInfo = katItem.parseData("fixed_info");
                defer std.heap.c_allocator.free(katFixedInfo);
                const katSalt = katItem.parseData("salt");
                defer std.heap.c_allocator.free(katSalt);
                const katRes = katItem.parseData("res");
                defer std.heap.c_allocator.free(katRes);

                args.u.uSskdf.cbInfo = katFixedInfo.len;
                args.u.uSskdf.pbInfo = if (katFixedInfo.len > 0) katFixedInfo.ptr else null;
                args.u.uSskdf.cbSalt = katSalt.len;
                args.u.uSskdf.pbSalt = if (katSalt.len > 0) katSalt.ptr else null;

                katKdfSingle(pKdf, katSecret.ptr, katSecret.len, &args, katRes.ptr, katRes.len, line);
                continue;
            }

            h.fatal("Unknown data record at line {d}", .{line});
        }
    }

    if (doneAnything) {
        h.ziprint("\n", .{});
    }
}

pub export fn testKdf() callconv(.c) void {
    testKdfKats();
}

pub export fn testKdfAlgorithms() callconv(.c) void {
    testKdf();
}
