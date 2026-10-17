// Copyright (c) Microsoft Corporation. Licensed under the MIT license.

const std = @import("std");
const h = @import("main_harness.zig");
const sc = @import("sc_implementations.zig");
const tu = @import("testutil.zig");

const g_szStatusIndicator: [:0]const u8 =
    "SymCrypt v103.11.0\n\n" ++
    "Algorithm Providers and Properties\n\n" ++
    "Encryption and Decryption\n" ++
    "\t- For symmetric encryption, SymCryptAes* functions are allowed. For functions that take a parameter of type PCSYMCRYPT_BLOCKCIPHER, a reference to SymCryptAesBlockCipher must be provided.\n" ++
    "\t- For asymmetric encryption, SymCryptRsaOaepEncrypt and SymCryptRsaOaepDecrypt are allowed.\n\n" ++
    "Hashing and Message Authentication\n" ++
    "\t- SymCryptHmacMd5 and SymCryptHmacSha1 functions are not allowed.\n" ++
    "\t- For SymCryptHash*, and SymCryptHmac* functions other than the two mentioned above, PCSYMCRYPT_HASH parameter cannot be specified as a reference to one of SymCryptMd2Algorithm, SymCryptMd4Algorithm, SymCryptMd5Algorithm, SymCryptSha1Algorithm.\n\n" ++
    "Key and Keypair Generation\n" ++
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
    "Zeroizing Cryptographic Material\n\n";

pub export fn SymCryptDeprecatedStatusIndicator(pbOutput: ?[*]u8, cbOutput: u32) callconv(.c) u32 {
    const uRequiredSize: u32 = @intCast(g_szStatusIndicator.len + 1);
    var result: u32 = 0;

    if (pbOutput == null) {
        result = uRequiredSize;
    } else if (cbOutput >= uRequiredSize) {
        @memcpy(pbOutput.?[0..g_szStatusIndicator.len], g_szStatusIndicator);
        pbOutput.?[g_szStatusIndicator.len] = 0;
        result = uRequiredSize;
    }

    return result;
}

const StatusIndicatorFn = *const fn (?[*]u8, u32) callconv(.c) u32;

pub export fn testStatusIndicator(bPrintString: c_int) callconv(.c) void {
    if (!tu.hasDispatchSym("SymCryptDeprecatedStatusIndicator")) {
        h.zprint("testStatusIndicator skipped\n", .{});
        return;
    }

    h.zprint("status-indicator\n", .{});

    const bufferLength = sc.callSymCrypt(
        "SymCryptDeprecatedStatusIndicator",
        StatusIndicatorFn,
        SymCryptDeprecatedStatusIndicator,
        .{ null, 0 },
    );
    h.check(bufferLength > 0, "SymCryptDeprecatedStatusIndicator returned buffer length=0");

    const pbStatusIndicator = std.heap.c_allocator.alloc(u8, bufferLength) catch {
        h.check3(false, "SymCryptDeprecatedStatusIndicator cannot allocate memory of size {d}", bufferLength);
        return;
    };
    defer std.heap.c_allocator.free(pbStatusIndicator);

    const bytesCopied = sc.callSymCrypt(
        "SymCryptDeprecatedStatusIndicator",
        StatusIndicatorFn,
        SymCryptDeprecatedStatusIndicator,
        .{ pbStatusIndicator.ptr, bufferLength },
    );

    const str = std.mem.sliceTo(pbStatusIndicator, 0);
    if (bPrintString != 0) {
        h.zprint("---BEGIN STATUS INDICATOR STRING\n", .{});
        h.zprint("{s}", .{str});
        h.zprint("---END STATUS INDICATOR STRING\n", .{});
    }

    h.check4(bytesCopied == bufferLength, "bytesCopied {d} is not equal to bufferLength {d}", bytesCopied, bufferLength);
    h.check(
        std.mem.indexOf(u8, str, "Algorithm Providers and Properties") != null,
        "Service string does not exist in SymCryptDeprecatedStatusIndicator: Algorithm Providers and Properties",
    );
    h.check(
        std.mem.indexOf(u8, str, "Zeroizing Cryptographic Material") != null,
        "Service string does not exist in SymCryptDeprecatedStatusIndicator: Zeroizing Cryptographic Material",
    );

    h.zprint("\n", .{});
}
