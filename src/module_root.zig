//
// module_root.zig
// Shared library module root for SymCrypt (libsymcrypt.so / libsymcrypt.dylib / symcrypt.dll)
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");

pub const core = @import("root.zig");

const types = @import("types.zig");
const macros = @import("macros.zig");
const libmain = @import("libmain.zig");
const env = @import("env.zig");
const sha256 = @import("sha256.zig");
const aes_ctr_drbg = @import("aes_ctr_drbg.zig");
const aes_selftest = @import("aes_selftest.zig");
const aescmac = @import("aescmac.zig");
const ccm = @import("ccm.zig");
const gcm = @import("gcm.zig");
const xtsaes = @import("xtsaes.zig");
const des3 = @import("des3.zig");
const hmac = @import("hmac.zig");
const sha256_par = @import("sha256_par.zig");
const sha512_par = @import("sha512_par.zig");
const tlsprf = @import("tlsprf.zig");
const hkdf = @import("hkdf.zig");
const sp800_108 = @import("sp800_108.zig");
const pbkdf2 = @import("pbkdf2.zig");
const srtp_kdf = @import("srtp_kdf.zig");
const ssh_kdf = @import("ssh_kdf.zig");
const sskdf = @import("sskdf.zig");
const fips_selftest = @import("fips_selftest.zig");

comptime {
    _ = core;
}

// ==============================================================================================
// Informative Product String & Environment Bindings
// ==============================================================================================

const product_string_literal: [:0]const u8 = if (builtin.os.tag == .windows)
    "SymCrypt_WindowsUserMode_Zig"
else
    "SymCrypt_PosixUserMode_Zig";

pub export const g_SymCryptInformativeProductString: [*:0]const types.CHAR = product_string_literal.ptr;

pub export fn SymCryptFatalIntercept(fatalCode: types.UINT32) callconv(types.SYMCRYPT_CALL) void {
    _ = fatalCode;
}

pub export fn SymCryptInit() callconv(types.SYMCRYPT_CALL) void {
    if (builtin.os.tag == .windows) {
        env.SymCryptInitEnvWindowsUsermodeWin8_1nLater(types.SYMCRYPT_API_VERSION);
    } else {
        env.SymCryptInitEnvPosixUsermode(types.SYMCRYPT_API_VERSION);
    }
}

pub export fn SymCryptFatal(fatalCode: types.UINT32) callconv(types.SYMCRYPT_CALL) noreturn {
    if (builtin.os.tag == .windows) {
        env.SymCryptFatalEnvWindowsUsermodeWin8_1nLater(fatalCode);
    } else {
        env.SymCryptFatalEnvPosixUsermode(fatalCode);
    }
}

pub export fn SymCryptCpuFeaturesNeverPresent() callconv(types.SYMCRYPT_CALL) types.SYMCRYPT_CPU_FEATURES {
    if (builtin.os.tag == .windows) {
        return env.SymCryptCpuFeaturesNeverPresentEnvWindowsUsermodeWin8_1nLater();
    } else {
        return env.SymCryptCpuFeaturesNeverPresentEnvPosixUsermode();
    }
}

pub export fn SymCryptInjectError(
    pbData: ?[*]types.BYTE,
    cbData: types.SIZE_T,
) callconv(types.SYMCRYPT_CALL) void {
    if (builtin.os.tag == .windows) {
        env.SymCryptTestInjectErrorEnvWindowsUsermodeWin8_1nLater(pbData, cbData);
    } else {
        env.SymCryptTestInjectErrorEnvPosixUsermode(pbData, cbData);
    }
}

pub fn SymCryptSaveXmm(pSaveData: ?*anyopaque) callconv(types.SYMCRYPT_CALL) types.SYMCRYPT_ERROR {
    if (builtin.os.tag == .windows) {
        return env.SymCryptSaveXmmEnvWindowsUsermodeWin8_1nLater(pSaveData);
    } else {
        return env.SymCryptSaveXmmEnvPosixUsermode(pSaveData);
    }
}

pub fn SymCryptRestoreXmm(pSaveData: ?*anyopaque) callconv(types.SYMCRYPT_CALL) void {
    if (builtin.os.tag == .windows) {
        env.SymCryptRestoreXmmEnvWindowsUsermodeWin8_1nLater(pSaveData);
    } else {
        env.SymCryptRestoreXmmEnvPosixUsermode(pSaveData);
    }
}

pub fn SymCryptSaveYmm(pSaveData: ?*anyopaque) callconv(types.SYMCRYPT_CALL) types.SYMCRYPT_ERROR {
    if (builtin.os.tag == .windows) {
        return env.SymCryptSaveYmmEnvWindowsUsermodeWin8_1nLater(pSaveData);
    } else {
        return env.SymCryptSaveYmmEnvPosixUsermode(pSaveData);
    }
}

pub fn SymCryptRestoreYmm(pSaveData: ?*anyopaque) callconv(types.SYMCRYPT_CALL) void {
    if (builtin.os.tag == .windows) {
        env.SymCryptRestoreYmmEnvWindowsUsermodeWin8_1nLater(pSaveData);
    } else {
        env.SymCryptRestoreYmmEnvPosixUsermode(pSaveData);
    }
}

pub fn SymCryptSaveZmm(pSaveData: ?*anyopaque) callconv(types.SYMCRYPT_CALL) types.SYMCRYPT_ERROR {
    if (builtin.os.tag == .windows) {
        return env.SymCryptSaveZmmEnvWindowsUsermodeWin8_1nLater(pSaveData);
    } else {
        return env.SymCryptSaveZmmEnvPosixUsermode(pSaveData);
    }
}

pub fn SymCryptRestoreZmm(pSaveData: ?*anyopaque) callconv(types.SYMCRYPT_CALL) void {
    if (builtin.os.tag == .windows) {
        env.SymCryptRestoreZmmEnvWindowsUsermodeWin8_1nLater(pSaveData);
    } else {
        env.SymCryptRestoreZmmEnvPosixUsermode(pSaveData);
    }
}

pub fn SymCryptCpuidExFunc(
    cpuInfo: *[4]c_int,
    function_id: c_int,
    subfunction_id: c_int,
) callconv(types.SYMCRYPT_CALL) void {
    if (builtin.os.tag == .windows) {
        env.SymCryptCpuidExFuncEnvWindowsUsermodeWin8_1nLater(cpuInfo, function_id, subfunction_id);
    } else {
        env.SymCryptCpuidExFuncEnvPosixUsermode(cpuInfo, function_id, subfunction_id);
    }
}

comptime {
    if (types.CPU_AMD64 or types.CPU_X86) {
        @export(&SymCryptSaveXmm, .{ .name = "SymCryptSaveXmm" });
        @export(&SymCryptRestoreXmm, .{ .name = "SymCryptRestoreXmm" });
        @export(&SymCryptSaveYmm, .{ .name = "SymCryptSaveYmm" });
        @export(&SymCryptRestoreYmm, .{ .name = "SymCryptRestoreYmm" });
        @export(&SymCryptSaveZmm, .{ .name = "SymCryptSaveZmm" });
        @export(&SymCryptRestoreZmm, .{ .name = "SymCryptRestoreZmm" });
        @export(&SymCryptCpuidExFunc, .{ .name = "SymCryptCpuidExFunc" });
    }
}

pub export fn SctestDisableCpuFeatures(features: types.SYMCRYPT_CPU_FEATURES) callconv(types.SYMCRYPT_CALL) types.SYMCRYPT_CPU_FEATURES {
    libmain.g_SymCryptCpuFeaturesNotPresent |= features;
    return libmain.g_SymCryptCpuFeaturesNotPresent;
}

// ==============================================================================================
// Memory & Mutex Callbacks
// ==============================================================================================

const ALIGN_VALUE: usize = types.SYMCRYPT_ASYM_ALIGN_VALUE;

pub export fn SymCryptCallbackAlloc(nBytes: types.SIZE_T) callconv(types.SYMCRYPT_CALL) types.PVOID {
    const alignedSize = (nBytes + (ALIGN_VALUE - 1)) & ~(ALIGN_VALUE - 1);
    const totalSize = alignedSize + ALIGN_VALUE;
    const raw = std.c.malloc(totalSize) orelse return null;
    const rawAddr = @intFromPtr(raw);
    const alignedAddr = (rawAddr + ALIGN_VALUE) & ~(ALIGN_VALUE - 1);
    const headerPtr: *usize = @ptrFromInt(alignedAddr - @sizeOf(usize));
    headerPtr.* = rawAddr;
    return @ptrFromInt(alignedAddr);
}

pub export fn SymCryptCallbackFree(pMem: types.PVOID) callconv(types.SYMCRYPT_CALL) void {
    const ptr = pMem orelse return;
    const alignedAddr = @intFromPtr(ptr);
    const headerPtr: *const usize = @ptrFromInt(alignedAddr - @sizeOf(usize));
    const rawPtr: *anyopaque = @ptrFromInt(headerPtr.*);
    std.c.free(rawPtr);
}

const FastMutex = struct {
    state: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),

    fn lock(self: *FastMutex) void {
        while (self.state.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) {
            std.atomic.spinLoopHint();
        }
    }

    fn unlock(self: *FastMutex) void {
        self.state.store(0, .release);
    }
};

pub export fn SymCryptCallbackAllocateMutexFastInproc() callconv(types.SYMCRYPT_CALL) types.PVOID {
    const raw = std.c.malloc(@sizeOf(FastMutex)) orelse return null;
    const m: *FastMutex = @ptrCast(@alignCast(raw));
    m.* = .{};
    return m;
}

pub export fn SymCryptCallbackFreeMutexFastInproc(pMutex: types.PVOID) callconv(types.SYMCRYPT_CALL) void {
    if (pMutex) |ptr| {
        std.c.free(ptr);
    }
}

pub export fn SymCryptCallbackAcquireMutexFastInproc(pMutex: types.PVOID) callconv(types.SYMCRYPT_CALL) void {
    const m: *FastMutex = @ptrCast(@alignCast(pMutex orelse return));
    m.lock();
}

pub export fn SymCryptCallbackReleaseMutexFastInproc(pMutex: types.PVOID) callconv(types.SYMCRYPT_CALL) void {
    const m: *FastMutex = @ptrCast(@alignCast(pMutex orelse return));
    m.unlock();
}

// ==============================================================================================
// JitterEntropy FIPS Entropy Source (cataggar/jitterentropy)
// ==============================================================================================

const JENT_FORCE_FIPS: c_uint = 1 << 4;
const RandData = opaque {};

extern fn jent_entropy_init() callconv(.c) c_int;
extern fn jent_entropy_collector_alloc(osr: c_uint, flags: c_uint) callconv(.c) ?*RandData;
extern fn jent_entropy_collector_free(entropy_collector: ?*RandData) callconv(.c) void;
extern fn jent_read_entropy(entropy_collector: ?*RandData, data: [*]u8, len: usize) callconv(.c) isize;

var g_jitter_entropy_collector: ?*RandData = null;

pub export fn SymCryptEntropyFipsInit() callconv(types.SYMCRYPT_CALL) void {
    if (jent_entropy_init() != 0) {
        macros.SymCryptFatal(macros.multiCharConstant("jiti"));
    }

    g_jitter_entropy_collector = jent_entropy_collector_alloc(1, JENT_FORCE_FIPS);
    if (g_jitter_entropy_collector == null) {
        macros.SymCryptFatal(macros.multiCharConstant("jita"));
    }
}

pub export fn SymCryptEntropyFipsUninit() callconv(types.SYMCRYPT_CALL) void {
    if (g_jitter_entropy_collector) |ec| {
        jent_entropy_collector_free(ec);
        g_jitter_entropy_collector = null;
    }
}

pub export fn SymCryptEntropyFipsGet(
    pbResult: types.PBYTE,
    cbResult: types.SIZE_T,
) callconv(types.SYMCRYPT_CALL) void {
    const result = jent_read_entropy(g_jitter_entropy_collector, pbResult, cbResult);
    if (result < 0 or @as(usize, @intCast(result)) != cbResult) {
        macros.SymCryptFatal(macros.multiCharConstant("jite"));
    }
}

// ==============================================================================================
// OS Secure Entropy Source & Fork Detection
// ==============================================================================================

const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x00000002;
extern "bcrypt" fn BCryptGenRandom(
    hAlgorithm: ?*anyopaque,
    pbBuffer: [*]u8,
    cbBuffer: u32,
    dwFlags: u32,
) callconv(.winapi) i32;

extern "c" fn getentropy(buffer: [*]u8, length: usize) callconv(.c) c_int;
extern "c" fn getpid() callconv(.c) c_int;

pub export fn SymCryptEntropySecureInit() callconv(types.SYMCRYPT_CALL) void {}

pub export fn SymCryptEntropySecureUninit() callconv(types.SYMCRYPT_CALL) void {}

pub export fn SymCryptEntropySecureGet(
    pbResult: types.PBYTE,
    cbResult: types.SIZE_T,
) callconv(types.SYMCRYPT_CALL) void {
    if (builtin.os.tag == .windows) {
        const status = BCryptGenRandom(null, pbResult, @intCast(cbResult), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (status < 0) {
            macros.SymCryptFatal(macros.multiCharConstant("entr"));
        }
    } else {
        var offset: usize = 0;
        while (offset < cbResult) {
            const chunk = @min(cbResult - offset, 256);
            if (getentropy(pbResult + offset, chunk) != 0) {
                macros.SymCryptFatal(macros.multiCharConstant("entr"));
            }
            offset += chunk;
        }
    }
}

var g_savedPid: c_int = 0;

pub export fn SymCryptRngForkDetectionInit() callconv(types.SYMCRYPT_CALL) void {
    if (builtin.os.tag != .windows) {
        g_savedPid = getpid();
    }
}

pub export fn SymCryptRngForkDetect() callconv(types.SYMCRYPT_CALL) types.BOOL {
    if (builtin.os.tag != .windows) {
        const currentPid = getpid();
        if (currentPid != g_savedPid) {
            g_savedPid = currentPid;
            return 1;
        }
    }
    return 0;
}

// ==============================================================================================
// Module DRBG & SymCryptRandom (modules/posix/common/rng.c)
// ==============================================================================================

const RANDOM_NUM_CACHE_SIZE: usize = 128;
const MAX_GENERATE_BEFORE_RESEED: u32 = 8192;
const SYMCRYPT_SELFTEST_ALGORITHM_STARTUP: u32 = 0x0001;

var g_rngLock: types.PVOID = null;
var g_RngStateInstantiated: bool = false;
var g_AesRngState: types.SYMCRYPT_RNG_AES_STATE = undefined;
var g_randomBytesCache: [RANDOM_NUM_CACHE_SIZE]u8 = @splat(0);
var g_cbRandomBytesCache: usize = 0;
var g_rngCounter: u32 = 0;

pub export fn SymCryptRngReseed() callconv(types.SYMCRYPT_CALL) void {
    var seed: [64]u8 = undefined;

    SymCryptEntropySecureGet(seed[32..].ptr, 32);

    if (build_options.fips_build) {
        SymCryptEntropyFipsGet(seed[0..32].ptr, 32);
    } else {
        macros.SymCryptWipeKnownSize(seed[0..32].ptr, 32);
    }

    _ = aes_ctr_drbg.SymCryptRngAesReseed(&g_AesRngState, &seed, seed.len);

    g_cbRandomBytesCache = 0;

    macros.SymCryptWipeKnownSize(&seed, seed.len);
}

pub export fn SymCryptRngInit() callconv(types.SYMCRYPT_CALL) void {
    g_rngLock = SymCryptCallbackAllocateMutexFastInproc();
    if (g_rngLock == null) {
        macros.SymCryptFatal(macros.multiCharConstant("rngi"));
    }
}

pub export fn SymCryptRngInstantiate() callconv(types.SYMCRYPT_CALL) void {
    var seed: [64]u8 = undefined;

    if (build_options.fips_build) {
        SymCryptEntropyFipsInit();
    }
    SymCryptEntropySecureInit();

    if (build_options.fips_build) {
        SymCryptEntropyFipsGet(seed[0..32].ptr, 32);
    } else {
        macros.SymCryptWipeKnownSize(seed[0..32].ptr, 32);
    }

    SymCryptEntropySecureGet(seed[32..].ptr, 32);

    const scError = aes_ctr_drbg.SymCryptRngAesInstantiate(&g_AesRngState, &seed, seed.len);
    if (scError != .SYMCRYPT_NO_ERROR) {
        macros.SymCryptFatal(macros.multiCharConstant("rngi"));
    }

    macros.SymCryptWipeKnownSize(&seed, seed.len);

    SymCryptRngForkDetectionInit();

    g_RngStateInstantiated = true;
}

pub export fn SymCryptRngUninit() callconv(types.SYMCRYPT_CALL) void {
    if (build_options.fips_build) {
        SymCryptEntropyFipsUninit();
    }
    SymCryptEntropySecureUninit();
    if (g_RngStateInstantiated) {
        aes_ctr_drbg.SymCryptRngAesUninstantiate(&g_AesRngState);
        g_RngStateInstantiated = false;
    }
    SymCryptCallbackFreeMutexFastInproc(g_rngLock);
    g_rngLock = null;
}

pub export fn SymCryptRandom(
    pbRandom_in: types.PBYTE,
    cbRandom: types.SIZE_T,
) callconv(types.SYMCRYPT_CALL) void {
    if (cbRandom == 0) {
        return;
    }

    var pbRandom = pbRandom_in;
    var cbRandomTmp = cbRandom;

    SymCryptCallbackAcquireMutexFastInproc(g_rngLock);
    defer SymCryptCallbackReleaseMutexFastInproc(g_rngLock);

    if (!g_RngStateInstantiated) {
        SymCryptRngInstantiate();
    } else {
        g_rngCounter += 1;
        if (SymCryptRngForkDetect() != 0 or g_rngCounter > MAX_GENERATE_BEFORE_RESEED) {
            SymCryptRngReseed();
            g_rngCounter = 0;
        }
    }

    if (cbRandom < RANDOM_NUM_CACHE_SIZE) {
        if (g_cbRandomBytesCache > 0) {
            const cbFill = @min(cbRandomTmp, g_cbRandomBytesCache);
            const startIdx = g_cbRandomBytesCache - cbFill;
            @memcpy(pbRandom[0..cbFill], g_randomBytesCache[startIdx .. startIdx + cbFill]);
            macros.SymCryptWipe(g_randomBytesCache[startIdx..].ptr, cbFill);
            g_cbRandomBytesCache -= cbFill;

            pbRandom += cbFill;
            cbRandomTmp -= cbFill;
        }

        if (cbRandomTmp > 0) {
            aes_ctr_drbg.SymCryptRngAesGenerate(&g_AesRngState, &g_randomBytesCache, RANDOM_NUM_CACHE_SIZE);
            g_cbRandomBytesCache = RANDOM_NUM_CACHE_SIZE;

            const startIdx = g_cbRandomBytesCache - cbRandomTmp;
            @memcpy(pbRandom[0..cbRandomTmp], g_randomBytesCache[startIdx .. startIdx + cbRandomTmp]);
            macros.SymCryptWipe(g_randomBytesCache[startIdx..].ptr, cbRandomTmp);
            g_cbRandomBytesCache -= cbRandomTmp;

            var mask: usize = cbRandom;
            mask = mask ^ (mask - 1);
            mask = (mask >> 1) & 15;
            g_cbRandomBytesCache &= ~mask;
        }
    } else {
        aes_ctr_drbg.SymCryptRngAesGenerate(&g_AesRngState, pbRandom, cbRandom);
    }
}

pub export fn SymCryptCallbackRandom(
    pbBuffer: types.PBYTE,
    cbBuffer: types.SIZE_T,
) callconv(types.SYMCRYPT_CALL) types.SYMCRYPT_ERROR {
    SymCryptRandom(pbBuffer, cbBuffer);
    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptProvideEntropy(
    pbEntropy: types.PCBYTE,
    cbEntropy: types.SIZE_T,
) callconv(types.SYMCRYPT_CALL) void {
    var additionalInput: [32]u8 = undefined;
    var hashState: sha256.SYMCRYPT_SHA256_STATE = undefined;

    sha256.SymCryptSha256Init(&hashState);
    sha256.SymCryptSha256Append(&hashState, pbEntropy, cbEntropy);

    SymCryptEntropySecureGet(&additionalInput, 32);
    sha256.SymCryptSha256Append(&hashState, &additionalInput, 32);
    sha256.SymCryptSha256Result(&hashState, &additionalInput);

    SymCryptCallbackAcquireMutexFastInproc(g_rngLock);
    if (!g_RngStateInstantiated) {
        SymCryptRngInstantiate();
    }
    const scError = aes_ctr_drbg.SymCryptRngAesGenerateSmall(
        &g_AesRngState,
        &additionalInput,
        0,
        &additionalInput,
        additionalInput.len,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        macros.SymCryptFatal(macros.multiCharConstant("acdx"));
    }
    SymCryptCallbackReleaseMutexFastInproc(g_rngLock);

    macros.SymCryptWipeKnownSize(&additionalInput, additionalInput.len);
}

// ==============================================================================================
// Module Init, Integrity Verification, Status Indicator & Lifecycle
// ==============================================================================================

pub export fn SymCryptModuleVerifyIntegrity() callconv(types.SYMCRYPT_CALL) void {
    // Module integrity verification hook
}

pub export fn SymCryptModuleInitEx(
    api: types.UINT32,
    minor: types.UINT32,
) callconv(types.SYMCRYPT_CALL) types.SYMCRYPT_ERROR {
    if (api != types.CODE_VERSION_API or
        (api == types.CODE_VERSION_API and minor > types.CODE_VERSION_MINOR))
    {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }
    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptModuleInit(
    api: types.UINT32,
    minor: types.UINT32,
) callconv(types.SYMCRYPT_CALL) void {
    if (SymCryptModuleInitEx(api, minor) != .SYMCRYPT_NO_ERROR) {
        macros.SymCryptFatal(macros.multiCharConstant("vers"));
    }
}

const status_indicator_text: [:0]const u8 = std.fmt.comptimePrint(
    "SymCrypt v{d}.{d}.{d}\n\n" ++
        "Algorithm Providers and Properties\n\n" ++
        "Encryption and Decryption\n" ++
        "\t- For symmetric encryption, SymCryptAes* functions are allowed. For functions that take a parameter of type PCSYMCRYPT_BLOCKCIPHER, a reference to SymCryptAesBlockCipher must be provided.\n" ++
        "\t- For asymmetric encryption, SymCryptRsaOaepEncrypt and SymCryptRsaOaepDecrypt are allowed.\n\n" ++
        "Entropy Source\n\n" ++
        "Hashing and Message Authentication\n" ++
        "\t- SymCryptHmacMd5 and SymCryptHmacSha1 functions are not allowed.\n" ++
        "\t- For SymCryptHash*, and SymCryptHmac* functions other than the two mentioned above, PCSYMCRYPT_HASH parameter cannot be specified as a reference to one of SymCryptMd2Algorithm, SymCryptMd4Algorithm, SymCryptMd5Algorithm, SymCryptSha1Algorithm.\n\n" ++
        "Key and Key-Pair Generation\n" ++
        "\t- For RSA key-pair generation, pParams parameter must point to a SYMCRYPT_RSA_PARAMS structure whose nBitsOfModulus must be greater than or equal to 2048 when calling SymCryptRsakeyAllocate, SymCryptRsakeyCreate, SymCryptRsakeyGenerate.\n" ++
        "\t- For Diffie-Hellman and DSA key-pair generation, nBitsOfP parameter must be set to one of 2048 or 3072, and nBitsOfQ parameter must be set to one of 0 or 256 when calling SymCryptDlgroupCreate.\n" ++
        "\t- For ECDH and ECDSA, pCurve parameter must refer to one of SymCryptEcurveParamsNistP256, SymCryptEcurveParamsNistP384, SymCryptEcurveParamsNistP521 when calling SymCryptEckeyAllocate, SymCryptEckeyCreate, SymCryptEckeySetRandom.\n\n" ++
        "Key Derivation\n" ++
        "\t- PCSYMCRYPT_MAC parameter must not refer to one of SymCryptMd5HmacAlgorithm, SymCryptHmacSha1Algorithm when calling SymCryptSp800_108, SymCryptTksPrf1_2, SymCryptPbkdf2, SymCryptSskdfMac.\n" ++
        "\t- PCSYMCRYPT_HASH parameter must not refer to one of SymCryptMd2Algorithm, SymCryptMd4Algorithm, SymCryptMd5Algorithm, SymCryptSha1Algorithm when calling SymCryptSshKdf, SymCryptSskdfHash.\n\n" ++
        "Key Entry and Output\n" ++
        "\t- For RSA keys, flags parameter must not set SYMCRYPT_FLAG_KEY_NO_FIPS flag, cbModulus parameter must be at least 256 if ppPrimes parameter is not NULL, and at least 128 if ppPrimes parameter is NULL when calling SymCryptRsakeySetValue or SymCryptRsakeySetValueFromPrivateExponent.\n" ++
        "\t- For ECDH and ECDSA keys, pEckey->pCurve parameter must refer to one of SymCryptEcurveParamsNistP256, SymCryptEcurveParamsNistP384, SymCryptEcurveParamsNistP521, and flags parameter must not set SYMCRYPT_FLAG_KEY_NO_FIPS flag when calling SymCryptEckeySetValue.\n" ++
        "\t- For Diffie-Hellman key-pairs, the call to SymCryptDlgroupSetValueSafePrime must return SYMCRYPT_NO_ERROR before calling SymCryptDlkeySetValue.\n" ++
        "\t- For DSA, SymCryptDlgroupSetValue must be called with fipsStandard parameter not equal to SYMCRYPT_DLGROUP_FIPS_NONE and pDlgroup parameter must be created with nBitsofP parameter equal to 2048 or 3072 and nBitsofQ parameter equal to 256 or 0 in a preceding call to SymCryptDlgroupAllocate or SymCryptDlgroupCreate.\n\n" ++
        "Random Number Generation\n\n" ++
        "Self-Tests\n\n" ++
        "Show Status\n\n" ++
        "Show Version\n\n" ++
        "Signing and Verification\n" ++
        "\t- pkRsakey parameter must be created in a preceding call to SymCryptRsakeyAllocate, SymCryptRsakeyCreate, SymCryptRsakeyGenerate with pParams parameter pointing to a SYMCRYPT_RSA_PARAMS structure whose nBitsOfModulus member is greater than or equal to 2048 when calling SymCryptRsaPkcs1Sign and SymCryptRsaPssSign\n" ++
        "\t- pkRsakey parameter must be created in a preceding call to SymCryptRsakeySetValue or SymCryptRsakeySetValueFromPrivateExponent with cbModulus parameter greater than or equal to 128 when calling SymCryptRsaPkcs1Verify and SymCryptRsaPssVerify.\n" ++
        "\t- hashAlgorithm parameter may refer to SymCryptSha1Algorithm only when calling SymCryptRsaPssVerify.\n" ++
        "\t- pHashOID parameter may refer to the OID of SHA-1 only when calling SymCryptRsaPkcs1Verify.\n" ++
        "\t- For DSA, pKey parameter of SymCryptDsaSign and SymCryptDsaVerify must be created with nBitsOfP parameter set to one of 2048 or 3072, and nBitsOfQ parameter set to one of 0 or 256 in a preceding call to SymCryptDlgroupCreate.\n" ++
        "\t- For ECDSA, pKey parameter of SymCryptEcDsaSign and SymCryptEcDsaVerify must be created in a preceding call to one of SymCryptEckeyAllocate, SymCryptEckeyCreate, SymCryptEckeySetRandom such that pCurve parameter is referring to one of SymCryptEcurveParamsNistP256, SymCryptEcurveParamsNistP384, SymCryptEcurveParamsNistP521.\n\n" ++
        "Secret Agreement\n" ++
        "\t- For Diffie-Hellman secret agreement using SymCryptDhSecretAgreement, pkPrivate and pbPublic must be created with nBitsOfP parameter set to one of 2048 or 3072, and nBitsOfQ parameter set to one of 0 or 256 in a preceding call to SymCryptDlgroupCreate.\n" ++
        "\t- For ECDH, pCurve member of pkPrivate and pkPublic must refer to one of SymCryptEcurveParamsNistP256, SymCryptEcurveParamsNistP384, SymCryptEcurveParamsNistP521 when calling SymCryptEcDhSecretAgreement.\n\n" ++
        "Zeroizing Cryptographic Material\n\n",
    .{
        types.CODE_VERSION_API,
        types.CODE_VERSION_MINOR,
        types.CODE_VERSION_PATCH,
    },
);

pub export fn SymCryptDeprecatedStatusIndicator(
    pbOutput: ?types.PBYTE,
    cbOutput: types.UINT32,
) callconv(types.SYMCRYPT_CALL) types.UINT32 {
    const requiredSize: types.UINT32 = @intCast(status_indicator_text.len + 1);
    if (pbOutput == null) {
        return requiredSize;
    } else if (cbOutput >= requiredSize) {
        @memcpy(pbOutput.?[0..requiredSize], status_indicator_text[0..requiredSize]);
        return requiredSize;
    }
    return 0;
}

pub export fn SymCryptModuleMain() callconv(.c) void {
    SymCryptInit();

    if (build_options.fips_build) {
        hmac.SymCryptHmacSha256Selftest();

        SymCryptModuleVerifyIntegrity();

        aes_ctr_drbg.SymCryptRngAesInstantiateSelftest();
        aes_ctr_drbg.SymCryptRngAesReseedSelftest();
        aes_ctr_drbg.SymCryptRngAesGenerateSelftest();
    }

    SymCryptRngInit();

    if (build_options.fips_build) {
        des3.SymCrypt3DesSelftest();

        aes_selftest.SymCryptAesSelftest(types.SYMCRYPT_AES_SELFTEST_ALL);
        aescmac.SymCryptAesCmacSelftest();
        ccm.SymCryptCcmSelftest();
        gcm.SymCryptGcmSelftest();
        xtsaes.SymCryptXtsAesSelftest();

        hmac.SymCryptHmacSha1Selftest();
        hmac.SymCryptHmacSha384Selftest();
        hmac.SymCryptHmacSha512Selftest();

        sha256_par.SymCryptParallelSha256Selftest();
        sha512_par.SymCryptParallelSha512Selftest();

        tlsprf.SymCryptTlsPrf1_1SelfTest();
        tlsprf.SymCryptTlsPrf1_2SelfTest();

        hkdf.SymCryptHkdfSelfTest();

        sp800_108.SymCryptSp800_108_HmacSha1SelfTest();
        sp800_108.SymCryptSp800_108_HmacSha256SelfTest();
        sp800_108.SymCryptSp800_108_HmacSha384SelfTest();
        sp800_108.SymCryptSp800_108_HmacSha512SelfTest();

        pbkdf2.SymCryptPbkdf2_HmacSha1SelfTest();

        srtp_kdf.SymCryptSrtpKdfSelfTest();

        ssh_kdf.SymCryptSshKdfSha256SelfTest();
        ssh_kdf.SymCryptSshKdfSha512SelfTest();

        sskdf.SymCryptSskdfSelfTest();

        hmac.SymCryptHmacSha3_256Selftest();

        fips_selftest.g_SymCryptFipsSelftestsPerformed |= SYMCRYPT_SELFTEST_ALGORITHM_STARTUP;
    }
}

pub export fn SymCryptModuleDestructor() callconv(.c) void {
    SymCryptRngUninit();
}

comptime {
    if (builtin.os.tag == .linux) {
        const init_array = struct {
            export const symcrypt_init_array_ptr: [1]*const fn () callconv(.c) void linksection(".init_array") = .{&SymCryptModuleMain};
        };
        const fini_array = struct {
            export const symcrypt_fini_array_ptr: [1]*const fn () callconv(.c) void linksection(".fini_array") = .{&SymCryptModuleDestructor};
        };
        _ = init_array.symcrypt_init_array_ptr;
        _ = fini_array.symcrypt_fini_array_ptr;
    } else if (builtin.os.tag.isDarwin()) {
        const mod_init = struct {
            export const symcrypt_mod_init_ptr: [1]*const fn () callconv(.c) void linksection("__DATA,__mod_init_func") = .{&SymCryptModuleMain};
        };
        _ = mod_init.symcrypt_mod_init_ptr;
    } else if (builtin.os.tag == .windows) {
        const win_dll = struct {
            pub export fn DllMain(
                instance: ?*anyopaque,
                reason: u32,
                reserved: ?*anyopaque,
            ) callconv(.winapi) c_int {
                _ = instance;
                _ = reserved;
                if (reason == 1) {
                    SymCryptModuleMain();
                } else if (reason == 0) {
                    SymCryptModuleDestructor();
                }
                return 1;
            }
        };
        _ = win_dll.DllMain;
    }
}
