//
// fdef_mod.zig
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
// Modular arithmetic functions for default number format (generic and Montgomery).
// Ported from lib/fdef_mod.c.
//

const std = @import("std");
const types = @import("types.zig");
const macros = @import("macros.zig");
const aes_ctr_drbg = @import("aes_ctr_drbg.zig");
const fdef_general = @import("fdef_general.zig");
const fdef_int = @import("fdef_int.zig");
const a_dispatch = @import("a_dispatch.zig");

const SYMCRYPT_CALL = types.SYMCRYPT_CALL;
const SYMCRYPT_ERROR = types.SYMCRYPT_ERROR;
const SYMCRYPT_NUMBER_FORMAT = types.SYMCRYPT_NUMBER_FORMAT;
const BYTE = types.BYTE;
const PBYTE = types.PBYTE;
const PCBYTE = types.PCBYTE;
const UINT32 = types.UINT32;
const PUINT32 = types.PUINT32;
const PCUINT32 = types.PCUINT32;
const UINT64 = types.UINT64;
const SIZE_T = types.SIZE_T;
const PVOID = types.PVOID;
const PSYMCRYPT_INT = types.PSYMCRYPT_INT;
const PCSYMCRYPT_INT = types.PCSYMCRYPT_INT;
const PSYMCRYPT_DIVISOR = types.PSYMCRYPT_DIVISOR;
const PCSYMCRYPT_DIVISOR = types.PCSYMCRYPT_DIVISOR;
const SYMCRYPT_MODULUS = types.SYMCRYPT_MODULUS;
const PSYMCRYPT_MODULUS = types.PSYMCRYPT_MODULUS;
const PCSYMCRYPT_MODULUS = types.PCSYMCRYPT_MODULUS;
const PSYMCRYPT_MODELEMENT = types.PSYMCRYPT_MODELEMENT;
const PCSYMCRYPT_MODELEMENT = types.PCSYMCRYPT_MODELEMENT;

const SYMCRYPT_FDEF_DIGIT_SIZE = types.SYMCRYPT_FDEF_DIGIT_SIZE;
const SYMCRYPT_FDEF_DIGIT_NUINT32 = types.SYMCRYPT_FDEF_DIGIT_NUINT32;

const SYMCRYPT_FLAG_MODRANDOM_ALLOW_ZERO: UINT32 = 0x01;
const SYMCRYPT_FLAG_MODRANDOM_ALLOW_ONE: UINT32 = 0x02;
const SYMCRYPT_FLAG_MODRANDOM_ALLOW_MINUSONE: UINT32 = 0x04;

const SYMCRYPT_CPU_FEATURES_FOR_MULX: types.SYMCRYPT_CPU_FEATURES =
    types.SYMCRYPT_CPU_FEATURE_BMI2 | types.SYMCRYPT_CPU_FEATURE_ADX;

extern var g_SymCryptCpuFeaturesNotPresent: types.SYMCRYPT_CPU_FEATURES;
extern fn SymCryptCpuFeaturesNeverPresent() callconv(SYMCRYPT_CALL) types.SYMCRYPT_CPU_FEATURES;
extern fn SymCryptCallbackAlloc(cbData: SIZE_T) callconv(SYMCRYPT_CALL) PVOID;
extern fn SymCryptCallbackFree(pData: PVOID) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptCallbackRandom(pbBuffer: PBYTE, cbBuffer: SIZE_T) callconv(SYMCRYPT_CALL) void;

inline fn SYMCRYPT_CPU_FEATURES_PRESENT(x: types.SYMCRYPT_CPU_FEATURES) bool {
    return ((x & SymCryptCpuFeaturesNeverPresent()) == 0) and ((x & g_SymCryptCpuFeaturesNotPresent) == 0);
}

// In the worst case there is a 1 in 8 chance of successfully generating a value
// This is when the modulus is 4 (nBits of modulus is 3), and 0, 1, and -1 are disallowed.
// In this case, having 1000 retries, there is a ~ 2^-193 chance of failure unless SymCryptCallbackRandom
// is completely broken. This passes the bar of being reasonable to Fatal.
const FDEF_MOD_SET_RANDOM_GENERIC_LIMIT: UINT32 = 1000;

pub inline fn SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(nModDigits: UINT32) UINT32 {
    return (2 * nModDigits * SYMCRYPT_FDEF_DIGIT_SIZE) + types.SYMCRYPT_SCRATCH_BYTES_FOR_INT_DIVMOD(2 * nModDigits, nModDigits);
}

pub inline fn SYMCRYPT_SCRATCH_BYTES_FOR_MODINV(nModDigits: UINT32) UINT32 {
    return 4 * types.SYMCRYPT_FDEF_SIZEOF_MODELEMENT_FROM_DIGITS(nModDigits) +
        3 * types.SYMCRYPT_FDEF_SIZEOF_INT_FROM_DIGITS(nModDigits) +
        SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(nModDigits);
}

inline fn SymCryptCountTrailingZeros32(value: UINT32) UINT32 {
    if (value == 0) {
        return 32;
    }
    return @as(UINT32, @ctz(value));
}

// External curve params pointer for NIST P-384 modulus detection (from lib/ec_internal_curve_params.c)
// sizeof(SYMCRYPT_ECURVE_PARAMS) is 7 * sizeof(UINT32) = 28 bytes.
extern const SymCryptEcurveParamsNistP384: PCBYTE;
const SIZEOF_SYMCRYPT_ECURVE_PARAMS: usize = 7 * @sizeOf(UINT32);

// External assembly routines
extern fn SymCryptFdefModDivSmallPow2Mulx(
    pmMod: PCSYMCRYPT_MODULUS,
    peSrc: PCSYMCRYPT_MODELEMENT,
    exp: UINT32,
    peDst: PSYMCRYPT_MODELEMENT,
) callconv(SYMCRYPT_CALL) void;

extern fn SymCryptFdefModDivSmallPow2Asm(
    pmMod: PCSYMCRYPT_MODULUS,
    peSrc: PCSYMCRYPT_MODELEMENT,
    exp: UINT32,
    peDst: PSYMCRYPT_MODELEMENT,
) callconv(SYMCRYPT_CALL) void;

extern fn SymCryptFdefMontgomeryReduceAsm(
    pmMod: PCSYMCRYPT_MODULUS,
    pSrc: PUINT32,
    pDst: PUINT32,
) callconv(SYMCRYPT_CALL) void;

extern fn SymCryptFdefMontgomeryReduceMulx(
    pmMod: PCSYMCRYPT_MODULUS,
    pSrc: PUINT32,
    pDst: PUINT32,
) callconv(SYMCRYPT_CALL) void;

extern fn SymCryptFdefMontgomeryReduceMulx1024(
    pmMod: PCSYMCRYPT_MODULUS,
    pSrc: PUINT32,
    pDst: PUINT32,
) callconv(SYMCRYPT_CALL) void;

extern fn SymCryptFdefMontgomeryReduce256Asm(
    pmMod: PCSYMCRYPT_MODULUS,
    pSrc: PUINT32,
    pDst: PUINT32,
) callconv(SYMCRYPT_CALL) void;

extern fn SymCryptFdefRawMulMulx(
    pSrc1: PCUINT32,
    nDigits1: UINT32,
    pSrc2: PCUINT32,
    nDigits2: UINT32,
    pDst: PUINT32,
) callconv(SYMCRYPT_CALL) void;

extern fn SymCryptFdefRawMulMulx1024(
    pSrc1: PCUINT32,
    pSrc2: PCUINT32,
    nDigits: UINT32,
    pDst: PUINT32,
) callconv(SYMCRYPT_CALL) void;

extern fn SymCryptFdefRawSquareMulx(
    pSrc: PCUINT32,
    nDigits: UINT32,
    pDst: PUINT32,
) callconv(SYMCRYPT_CALL) void;

extern fn SymCryptFdefRawSquareMulx1024(
    pSrc: PCUINT32,
    nDigits: UINT32,
    pDst: PUINT32,
) callconv(SYMCRYPT_CALL) void;

extern fn SymCryptFdefModMulMontgomeryMulx256Asm(
    pmMod: PCSYMCRYPT_MODULUS,
    peSrc1: PCSYMCRYPT_MODELEMENT,
    peSrc2: PCSYMCRYPT_MODELEMENT,
    peDst: PSYMCRYPT_MODELEMENT,
) callconv(SYMCRYPT_CALL) void;

extern fn SymCryptFdefModMulMontgomeryMulxP384Asm(
    pmMod: PCSYMCRYPT_MODULUS,
    peSrc1: PCSYMCRYPT_MODELEMENT,
    peSrc2: PCSYMCRYPT_MODELEMENT,
    peDst: PSYMCRYPT_MODELEMENT,
) callconv(SYMCRYPT_CALL) void;

// ==============================================================================================
// Modulus & ModElement Allocation, Creation, Copy, Wipe
// ==============================================================================================

pub export fn SymCryptFdefModulusAllocate(nDigits: UINT32) callconv(SYMCRYPT_CALL) ?PSYMCRYPT_MODULUS {
    var p: ?*anyopaque = null;
    var res: ?PSYMCRYPT_MODULUS = null;

    // The nDigits requirements are enforced by SymCryptFdefSizeofModulusFromDigits. Thus
    // the result does not overflow and is upper bounded by 2^19.
    const cb = SymCryptFdefSizeofModulusFromDigits(nDigits);

    if (cb != 0) {
        p = SymCryptCallbackAlloc(cb);
    }

    if (p == null) {
        return null;
    }

    res = SymCryptFdefModulusCreate(@ptrCast(p.?), cb, nDigits);
    return res;
}

pub export fn SymCryptFdefModulusFree(pmObj: PSYMCRYPT_MODULUS) callconv(SYMCRYPT_CALL) void {
    a_dispatch.SymCryptModulusWipe(pmObj);
    SymCryptCallbackFree(@ptrCast(pmObj));
}

pub export fn SymCryptFdefSizeofModulusFromDigits(nDigits: UINT32) callconv(SYMCRYPT_CALL) UINT32 {
    macros.SYMCRYPT_ASSERT(nDigits != 0);
    macros.SYMCRYPT_ASSERT(nDigits <= types.SYMCRYPT_FDEF_UPB_DIGITS);

    // Ensure we do not overflow the following calculation when provided with invalid inputs
    if (nDigits == 0 or nDigits > types.SYMCRYPT_FDEF_UPB_DIGITS) {
        return 0;
    }

    // Room for the Modulus structure, the Divisor, the negated divisor, and the R^2 Montgomery factor
    return @as(UINT32, @intCast(@offsetOf(SYMCRYPT_MODULUS, "Divisor"))) +
        fdef_general.SymCryptFdefSizeofDivisorFromDigits(nDigits) +
        (2 * nDigits * SYMCRYPT_FDEF_DIGIT_SIZE);
}

pub export fn SymCryptFdefModulusCreate(
    pbBuffer: PBYTE,
    cbBuffer: SIZE_T,
    nDigits: UINT32,
) callconv(SYMCRYPT_CALL) ?PSYMCRYPT_MODULUS {
    const cb = SymCryptFdefSizeofModulusFromDigits(nDigits);
    const offset = @offsetOf(SYMCRYPT_MODULUS, "Divisor");

    macros.SYMCRYPT_ASSERT(cb >= @sizeOf(SYMCRYPT_MODULUS));
    macros.SYMCRYPT_ASSERT(cbBuffer >= cb);
    if (cb == 0 or cbBuffer < cb) {
        return null;
    }

    macros.SYMCRYPT_ASSERT(@intFromPtr(pbBuffer) % types.SYMCRYPT_ASYM_ALIGN_VALUE == 0);
    const pmMod: PSYMCRYPT_MODULUS = @ptrCast(@alignCast(pbBuffer));

    pmMod.type = macros.multiCharConstant("gM") << 16;
    pmMod.nDigits = nDigits;

    // The nDigits requirements are enforced by SymCryptFdefSizeofModulusFromDigits. Thus
    // the result does not overflow and is upper bounded by 2^19.
    pmMod.cbSize = cb;
    pmMod.flags = 0;

    // The following is bounded by 2^17
    pmMod.cbModElement = nDigits * SYMCRYPT_FDEF_DIGIT_SIZE;

    _ = fdef_general.SymCryptFdefDivisorCreate(pbBuffer + offset, cbBuffer - offset, nDigits);

    // We don't have a modulus value yet, so we don't create/initialize any implementation-specific things.

    macros.SYMCRYPT_SET_MAGIC(pmMod);

    return pmMod;
}

pub export fn SymCryptFdefModulusInitGeneric(
    pmMod: PSYMCRYPT_MODULUS,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    _ = pmMod;
    _ = pbScratch;
    _ = cbScratch;
}

pub export fn SymCryptFdefModulusCopy(
    pmSrc: PCSYMCRYPT_MODULUS,
    pmDst: PSYMCRYPT_MODULUS,
) callconv(SYMCRYPT_CALL) void {
    macros.SYMCRYPT_ASSERT(pmSrc.nDigits == pmDst.nDigits);

    if (pmSrc != pmDst) {
        const pbSrc: PCBYTE = @ptrCast(pmSrc);
        const pbDst: PBYTE = @ptrCast(pmDst);
        @memcpy(pbDst[0..pmDst.cbSize], pbSrc[0..pmDst.cbSize]);

        fdef_general.SymCryptFdefDivisorCopyFixup(&pmSrc.Divisor, &pmDst.Divisor);

        // Copy the type-specific fields
        a_dispatch.SYMCRYPT_MOD_FUNCTIONS(pmSrc).modulusCopyFixup.?(pmSrc, pmDst);

        macros.SYMCRYPT_SET_MAGIC(pmDst);
    }
}

pub export fn SymCryptFdefModulusCopyFixupGeneric(
    pmSrc: PCSYMCRYPT_MODULUS,
    pmDst: PSYMCRYPT_MODULUS,
) callconv(SYMCRYPT_CALL) void {
    // Only have to handle the type-specific fields, which we don't have any of.
    _ = pmSrc;
    _ = pmDst;
}

pub export fn SymCryptFdefModElementAllocate(pmMod: PCSYMCRYPT_MODULUS) callconv(SYMCRYPT_CALL) ?PSYMCRYPT_MODELEMENT {
    // The nDigits requirements are enforced by the modulus object. Thus
    // the result does not overflow and is upper bounded by 2^17.
    const cb = SymCryptFdefSizeofModElementFromModulus(pmMod);

    const p = SymCryptCallbackAlloc(cb);
    if (p == null) {
        return null;
    }

    return SymCryptFdefModElementCreate(@ptrCast(p.?), cb, pmMod);
}

pub export fn SymCryptFdefModElementFree(
    pmMod: PCSYMCRYPT_MODULUS,
    peObj: PSYMCRYPT_MODELEMENT,
) callconv(SYMCRYPT_CALL) void {
    SymCryptFdefModElementWipe(pmMod, peObj);
    SymCryptCallbackFree(@ptrCast(peObj));
}

pub export fn SymCryptFdefSizeofModElementFromModulus(pmMod: PCSYMCRYPT_MODULUS) callconv(SYMCRYPT_CALL) UINT32 {
    // Upper bounded by 2^17 since the modulus is up to SYMCRYPT_INT_MAXBITS = 2^20 bits.
    return pmMod.cbModElement;
}

pub export fn SymCryptFdefModElementCreate(
    pbBuffer: PBYTE,
    cbBuffer: SIZE_T,
    pmMod: PCSYMCRYPT_MODULUS,
) callconv(SYMCRYPT_CALL) ?PSYMCRYPT_MODELEMENT {
    const pDst: PSYMCRYPT_MODELEMENT = @ptrCast(@alignCast(pbBuffer));

    macros.SYMCRYPT_ASSERT(@intFromPtr(pbBuffer) % types.SYMCRYPT_ASYM_ALIGN_VALUE == 0);
    macros.SYMCRYPT_ASSERT(cbBuffer >= SymCryptFdefSizeofModElementFromModulus(pmMod));
    macros.SYMCRYPT_ASSERT(cbBuffer >= pmMod.nDigits * SYMCRYPT_FDEF_DIGIT_SIZE);

    // We have various optimizations where we use only part of the last digit
    // Simple and fast solution: always wipe the last digit
    if (comptime (types.CPU_AMD64 or types.CPU_ARM64)) {
        const nDigits = pmMod.nDigits;
        macros.SymCryptWipeKnownSize(pbBuffer + (nDigits - 1) * SYMCRYPT_FDEF_DIGIT_SIZE, SYMCRYPT_FDEF_DIGIT_SIZE);
    }

    return pDst;
}

pub export fn SymCryptFdefModElementWipe(
    pmMod: PCSYMCRYPT_MODULUS,
    peDst: PSYMCRYPT_MODELEMENT,
) callconv(SYMCRYPT_CALL) void {
    macros.SymCryptWipe(@ptrCast(peDst), pmMod.cbModElement);
}

pub export fn SymCryptFdefModElementCopy(
    pmMod: PCSYMCRYPT_MODULUS,
    peSrc: PCSYMCRYPT_MODELEMENT,
    peDst: PSYMCRYPT_MODELEMENT,
) callconv(SYMCRYPT_CALL) void {
    if (peSrc != peDst) {
        const pbSrc: PCBYTE = @ptrCast(peSrc);
        const pbDst: PBYTE = @ptrCast(peDst);
        @memcpy(pbDst[0..pmMod.cbModElement], pbSrc[0..pmMod.cbModElement]);
    }
}

pub export fn SymCryptFdefModElementMaskedCopy(
    pmMod: PCSYMCRYPT_MODULUS,
    peSrc: PCSYMCRYPT_MODELEMENT,
    peDst: PSYMCRYPT_MODELEMENT,
    mask: UINT32,
) callconv(SYMCRYPT_CALL) void {
    fdef_general.SymCryptFdefMaskedCopy(@ptrCast(peSrc), @ptrCast(peDst), pmMod.nDigits, mask);
}

pub export fn SymCryptFdefDivisorFromModulus(pmSrc: PSYMCRYPT_MODULUS) callconv(SYMCRYPT_CALL) PSYMCRYPT_DIVISOR {
    return &pmSrc.Divisor;
}

pub export fn SymCryptFdefModElementConditionalSwap(
    pmMod: PCSYMCRYPT_MODULUS,
    peData1: PSYMCRYPT_MODELEMENT,
    peData2: PSYMCRYPT_MODELEMENT,
    cond: UINT32,
) callconv(SYMCRYPT_CALL) void {
    fdef_general.SymCryptFdefConditionalSwap(
        @ptrCast(types.SYMCRYPT_FDEF_MODELEMENT_PUINT32(peData1)),
        @ptrCast(types.SYMCRYPT_FDEF_MODELEMENT_PUINT32(peData2)),
        pmMod.nDigits,
        cond,
    );
}

pub export fn SymCryptFdefIntFromModulus(pmSrc: PSYMCRYPT_MODULUS) callconv(SYMCRYPT_CALL) PSYMCRYPT_INT {
    return fdef_int.SymCryptFdefIntFromDivisor(&pmSrc.Divisor);
}

// ==============================================================================================
// Modulus Type Decision & Conversion
// ==============================================================================================

pub export fn SymCryptFdefDecideModulusType(
    piSrc: PCSYMCRYPT_INT,
    nDigits: UINT32,
    averageOperations: UINT32,
    flags: UINT32,
) callconv(SYMCRYPT_CALL) UINT32 {
    var res: UINT32 = 0;
    const disableMontgomery: bool = false;
    var tempBuf: [64]BYTE = undefined;

    const nBitsizeOfValue = a_dispatch.SymCryptIntBitsizeOfValue(piSrc);
    var modulusFeatures: UINT32 = 0;

    if (!disableMontgomery and
        (flags & (types.SYMCRYPT_FLAG_DATA_PUBLIC | types.SYMCRYPT_FLAG_MODULUS_PARITY_PUBLIC)) != 0 and
        (a_dispatch.SymCryptIntGetValueLsbits32(piSrc) & 1) == 1 and
        averageOperations >= 10)
    {
        modulusFeatures |= types.SYMCRYPT_MODULUS_FEATURE_MONTGOMERY;

        // Specific modulus value detection
        if ((flags & types.SYMCRYPT_FLAG_DATA_PUBLIC) != 0) {
            // Detect if modulus value is the P384 field modulus (convert piSrc to big endian and do comparison with known value of P384 modulus)
            if (nBitsizeOfValue == 384 and
                fdef_general.SymCryptFdefRawGetValue(
                    types.SYMCRYPT_FDEF_INT_PCUINT32(piSrc),
                    types.SYMCRYPT_FDEF_DIGITS_FROM_BITS(384),
                    &tempBuf,
                    64,
                    .SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                ) == .SYMCRYPT_NO_ERROR)
            {
                // First 16 bytes are guaranteed to be zero because nBitsizeOfValue is 384
                const p384Modulus = (SymCryptEcurveParamsNistP384 + SIZEOF_SYMCRYPT_ECURVE_PARAMS)[0..48];
                if (std.mem.eql(u8, tempBuf[16..64], p384Modulus)) {
                    modulusFeatures |= types.SYMCRYPT_MODULUS_FEATURE_NISTP384;
                }
            }
        }
    }

    var idx: usize = 0;
    while (true) : (idx += 1) {
        const entry = a_dispatch.SymCryptModulusTypeSelections[idx];
        if (SYMCRYPT_CPU_FEATURES_PRESENT(entry.cpuFeatures) and
            (entry.maxBits == 0 or (nDigits <= a_dispatch.SymCryptDigitsFromBits(entry.maxBits) and nBitsizeOfValue <= entry.maxBits)) and
            (entry.modulusFeatures & ~modulusFeatures) == 0)
        {
            res = entry.type;
            break;
        }
    }

    return res;
}

pub export fn SymCryptFdefModSetPostGeneric(
    pmMod: PCSYMCRYPT_MODULUS,
    peObj: PSYMCRYPT_MODELEMENT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    _ = pmMod;
    _ = peObj;
    _ = pbScratch;
    _ = cbScratch;
}

pub export fn SymCryptFdefModPreGetGeneric(
    pmMod: PCSYMCRYPT_MODULUS,
    peObj: PCSYMCRYPT_MODELEMENT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) PCUINT32 {
    _ = pmMod;
    _ = pbScratch;
    _ = cbScratch;

    return types.SYMCRYPT_FDEF_MODELEMENT_PCUINT32(peObj);
}

pub export fn SymCryptFdefIntToModulus(
    piSrc: PCSYMCRYPT_INT,
    pmDst: PSYMCRYPT_MODULUS,
    averageOperations: UINT32,
    flags: UINT32,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    pmDst.flags = flags;
    a_dispatch.SymCryptIntToDivisor(piSrc, &pmDst.Divisor, averageOperations, flags & types.SYMCRYPT_FLAG_DATA_PUBLIC, pbScratch, cbScratch);

    pmDst.type = SymCryptFdefDecideModulusType(piSrc, pmDst.nDigits, averageOperations, flags);

    // Set inv64 - note the value is only valid if the modulus is odd, but the computation
    // is constant time regardless of the parity, so we can safely compute it in all cases
    pmDst.inv64 = 0 -% fdef_general.SymCryptInverseMod2e64(a_dispatch.SymCryptIntGetValueLsbits64(piSrc));

    a_dispatch.SYMCRYPT_MOD_FUNCTIONS(pmDst).modulusInit.?(pmDst, pbScratch, cbScratch);
}

pub export fn SymCryptFdefIntToModElement(
    piSrc: PCSYMCRYPT_INT,
    pmMod: PCSYMCRYPT_MODULUS,
    peDst: PSYMCRYPT_MODELEMENT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    fdef_int.SymCryptFdefRawDivMod(
        types.SYMCRYPT_FDEF_INT_PCUINT32(piSrc),
        piSrc.nDigits,
        &pmMod.Divisor,
        null, // throw away the quotient
        types.SYMCRYPT_FDEF_MODELEMENT_PUINT32(peDst),
        pbScratch,
        cbScratch,
    );

    a_dispatch.SYMCRYPT_MOD_FUNCTIONS(pmMod).modSetPost.?(pmMod, peDst, pbScratch, cbScratch);
}

pub export fn SymCryptFdefModElementToIntGeneric(
    pmMod: PCSYMCRYPT_MODULUS,
    pSrc: PCUINT32,
    piDst: PSYMCRYPT_INT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    const cbMod = pmMod.nDigits * SYMCRYPT_FDEF_DIGIT_SIZE;
    const pbDst: PBYTE = @ptrCast(types.SYMCRYPT_FDEF_INT_PUINT32(piDst));
    const pbSrc: PCBYTE = @ptrCast(pSrc);
    @memcpy(pbDst[0..cbMod], pbSrc[0..cbMod]);

    macros.SymCryptWipe(
        @ptrCast(&types.SYMCRYPT_FDEF_INT_PUINT32(piDst)[pmMod.nDigits * SYMCRYPT_FDEF_DIGIT_NUINT32]),
        (piDst.nDigits - pmMod.nDigits) * SYMCRYPT_FDEF_DIGIT_SIZE,
    );

    fdef_general.SymCryptFdefClaimScratch(pbScratch, cbScratch, SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(pmMod.nDigits));
}

pub export fn SymCryptFdefModElementSetValueGeneric(
    pbSrc: PCBYTE,
    cbSrc: SIZE_T,
    format: SYMCRYPT_NUMBER_FORMAT,
    pmMod: PCSYMCRYPT_MODULUS,
    peDst: PSYMCRYPT_MODELEMENT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    const nDigits = pmMod.nDigits;

    fdef_general.SymCryptFdefClaimScratch(pbScratch, cbScratch, SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(nDigits));

    macros.SYMCRYPT_ASSERT(cbSrc <= nDigits * SYMCRYPT_FDEF_DIGIT_SIZE);

    const pDst = types.SYMCRYPT_FDEF_MODELEMENT_PUINT32(peDst);
    const scError = fdef_general.SymCryptFdefRawSetValue(pbSrc, cbSrc, format, pDst, nDigits);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    fdef_int.SymCryptFdefRawDivMod(
        pDst,
        nDigits,
        &pmMod.Divisor,
        null,
        pDst,
        pbScratch,
        cbScratch,
    );

    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptFdefModElementGetValue(
    pmMod: PCSYMCRYPT_MODULUS,
    peSrc: PCSYMCRYPT_MODELEMENT,
    pbDst: PBYTE,
    cbDst: SIZE_T,
    format: SYMCRYPT_NUMBER_FORMAT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    const nDigits = pmMod.nDigits;

    fdef_general.SymCryptFdefClaimScratch(pbScratch, cbScratch, SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(nDigits));

    macros.SYMCRYPT_ASSERT(cbDst <= nDigits * SYMCRYPT_FDEF_DIGIT_SIZE);

    const pUint32 = a_dispatch.SYMCRYPT_MOD_FUNCTIONS(pmMod).modPreGet.?(pmMod, peSrc, pbScratch, cbScratch);

    return fdef_general.SymCryptFdefRawGetValue(pUint32, nDigits, pbDst, cbDst, format);
}

pub export fn SymCryptFdefModElementIsEqual(
    pmMod: PCSYMCRYPT_MODULUS,
    peSrc1: PCSYMCRYPT_MODELEMENT,
    peSrc2: PCSYMCRYPT_MODELEMENT,
) callconv(SYMCRYPT_CALL) UINT32 {
    var d: UINT32 = 0;
    const pSrc1 = types.SYMCRYPT_FDEF_MODELEMENT_PUINT32(peSrc1);
    const pSrc2 = types.SYMCRYPT_FDEF_MODELEMENT_PUINT32(peSrc2);
    const nWords = pmMod.nDigits * SYMCRYPT_FDEF_DIGIT_NUINT32;

    for (0..nWords) |i| {
        d |= pSrc1[i] ^ pSrc2[i];
    }

    return macros.MASK32_ZERO(d);
}

pub export fn SymCryptFdefModElementIsZero(
    pmMod: PCSYMCRYPT_MODULUS,
    peSrc: PCSYMCRYPT_MODELEMENT,
) callconv(SYMCRYPT_CALL) UINT32 {
    var d: UINT32 = 0;
    const pSrc = types.SYMCRYPT_FDEF_MODELEMENT_PUINT32(peSrc);
    const nWords = pmMod.nDigits * SYMCRYPT_FDEF_DIGIT_NUINT32;

    for (0..nWords) |i| {
        d |= pSrc[i]; // Check that all bits are zero
    }

    return macros.MASK32_ZERO(d);
}

// ==============================================================================================
// Generic Modular Arithmetic Operations
// ==============================================================================================

pub export fn SymCryptFdefModAddGeneric(
    pmMod: PCSYMCRYPT_MODULUS,
    peSrc1: PCSYMCRYPT_MODELEMENT,
    peSrc2: PCSYMCRYPT_MODELEMENT,
    peDst: PSYMCRYPT_MODELEMENT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    const nDigits = pmMod.nDigits;

    fdef_general.SymCryptFdefClaimScratch(pbScratch, cbScratch, SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(nDigits));
    macros.SYMCRYPT_ASSERT(cbScratch >= nDigits * SYMCRYPT_FDEF_DIGIT_SIZE);

    const pSrc1 = types.SYMCRYPT_FDEF_MODELEMENT_PUINT32(peSrc1);
    const pSrc2 = types.SYMCRYPT_FDEF_MODELEMENT_PUINT32(peSrc2);
    const pDst = types.SYMCRYPT_FDEF_MODELEMENT_PUINT32(peDst);
    const pScratchWords: PUINT32 = @ptrCast(@alignCast(pbScratch));

    const c = fdef_int.SymCryptFdefRawAdd(pSrc1, pSrc2, pDst, nDigits);
    const d = fdef_int.SymCryptFdefRawSub(pDst, types.SYMCRYPT_FDEF_INT_PCUINT32(&pmMod.Divisor.Int), pScratchWords, nDigits);
    fdef_general.SymCryptFdefMaskedCopy(pbScratch, @ptrCast(pDst), nDigits, (c ^ d) -% 1);

    // We can't have a carry in the first addition, and no carry in the subtraction.
    macros.SYMCRYPT_ASSERT(!(c == 1 and d == 0));
}

pub export fn SymCryptFdefModSubGeneric(
    pmMod: PCSYMCRYPT_MODULUS,
    peSrc1: PCSYMCRYPT_MODELEMENT,
    peSrc2: PCSYMCRYPT_MODELEMENT,
    peDst: PSYMCRYPT_MODELEMENT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    const nDigits = pmMod.nDigits;

    fdef_general.SymCryptFdefClaimScratch(pbScratch, cbScratch, SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(nDigits));
    macros.SYMCRYPT_ASSERT(cbScratch >= nDigits * SYMCRYPT_FDEF_DIGIT_SIZE);

    const pSrc1 = types.SYMCRYPT_FDEF_MODELEMENT_PUINT32(peSrc1);
    const pSrc2 = types.SYMCRYPT_FDEF_MODELEMENT_PUINT32(peSrc2);
    const pDst = types.SYMCRYPT_FDEF_MODELEMENT_PUINT32(peDst);
    const pScratchWords: PUINT32 = @ptrCast(@alignCast(pbScratch));

    const c = fdef_int.SymCryptFdefRawSub(pSrc1, pSrc2, pDst, nDigits);
    const d = fdef_int.SymCryptFdefRawAdd(pDst, types.SYMCRYPT_FDEF_INT_PCUINT32(&pmMod.Divisor.Int), pScratchWords, nDigits);
    fdef_general.SymCryptFdefMaskedCopy(pbScratch, @ptrCast(pDst), nDigits, 0 -% c);

    macros.SYMCRYPT_ASSERT(!(c == 1 and d == 0));
}

pub export fn SymCryptFdefModNegGeneric(
    pmMod: PCSYMCRYPT_MODULUS,
    peSrc: PCSYMCRYPT_MODELEMENT,
    peDst: PSYMCRYPT_MODELEMENT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    const nDigits = pmMod.nDigits;

    fdef_general.SymCryptFdefClaimScratch(pbScratch, cbScratch, SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(nDigits));

    // We have to be careful to handle the value 0 properly as it does NOT map to Modulus - Value.
    const pSrc = types.SYMCRYPT_FDEF_MODELEMENT_PUINT32(peSrc);
    const pDst = types.SYMCRYPT_FDEF_MODELEMENT_PUINT32(peDst);
    const isZero = fdef_general.SymCryptFdefRawIsEqualUint32(pSrc, nDigits, 0);
    _ = fdef_int.SymCryptFdefRawSub(types.SYMCRYPT_FDEF_INT_PCUINT32(&pmMod.Divisor.Int), pSrc, pDst, nDigits);

    // Now we set the result to zero if the input was zero
    const nWords = nDigits * SYMCRYPT_FDEF_DIGIT_NUINT32;
    for (0..nWords) |i| {
        pDst[i] &= ~isZero;
    }
}

pub export fn SymCryptFdefModElementSetValueUint32Generic(
    value: UINT32,
    pmMod: PCSYMCRYPT_MODULUS,
    peDst: PSYMCRYPT_MODELEMENT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    const nDigits = pmMod.nDigits;
    var v = value;

    fdef_general.SymCryptFdefClaimScratch(pbScratch, cbScratch, SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(nDigits));

    if (pmMod.Divisor.nBits <= 32 and v >= types.SYMCRYPT_FDEF_INT_PCUINT32(&pmMod.Divisor.Int)[0]) {
        // The value is >= the modulus; this is not supported
        // For now do a possibly non-sidechannel safe, but mathematically correct modulo operation
        v %= types.SYMCRYPT_FDEF_INT_PCUINT32(&pmMod.Divisor.Int)[0];
    }

    const pDst = types.SYMCRYPT_FDEF_MODELEMENT_PUINT32(peDst);
    pDst[0] = v;

    macros.SymCryptWipe(@ptrCast(pDst + 1), nDigits * SYMCRYPT_FDEF_DIGIT_SIZE - @sizeOf(UINT32));
}

pub export fn SymCryptFdefModElementSetValueNegUint32(
    value: UINT32,
    pmMod: PCSYMCRYPT_MODULUS,
    peDst: PSYMCRYPT_MODELEMENT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    const nDigits = pmMod.nDigits;
    var v = value;

    fdef_general.SymCryptFdefClaimScratch(pbScratch, cbScratch, SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(nDigits));

    if (pmMod.Divisor.nBits <= 32 and v >= types.SYMCRYPT_FDEF_INT_PCUINT32(&pmMod.Divisor.Int)[0]) {
        // The value is >= the modulus; this is not supported.
        // For now do a possibly non-sidechannel safe, but mathematically correct modulo operation
        v %= types.SYMCRYPT_FDEF_INT_PCUINT32(&pmMod.Divisor.Int)[0];
    }

    const pDst = types.SYMCRYPT_FDEF_MODELEMENT_PUINT32(peDst);
    if (v == 0) {
        macros.SymCryptWipe(@ptrCast(pDst), nDigits * SYMCRYPT_FDEF_DIGIT_SIZE);
    } else {
        _ = fdef_int.SymCryptFdefRawSubUint32(types.SYMCRYPT_FDEF_INT_PCUINT32(&pmMod.Divisor.Int), v, pDst, nDigits);
    }

    // Possible future optimization: we can optimize the value==0 and value==1 cases on a per-type basis
    a_dispatch.SYMCRYPT_MOD_FUNCTIONS(pmMod).modSetPost.?(pmMod, peDst, pbScratch, cbScratch);
}

pub export fn SymCryptFdefModSetRandomGeneric(
    pmMod: PCSYMCRYPT_MODULUS,
    peDst: PSYMCRYPT_MODELEMENT,
    flags: UINT32,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    SymCryptFdefModSetRandomGenericEx(
        pmMod,
        peDst,
        flags,
        null,
        pbScratch,
        cbScratch,
    );
}

pub export fn SymCryptFdefModSetRandomGenericEx(
    pmMod: PCSYMCRYPT_MODULUS,
    peDst: PSYMCRYPT_MODELEMENT,
    flags: UINT32,
    pRngState: ?*anyopaque,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    const nDigits = pmMod.nDigits;
    const pTmp: PUINT32 = @ptrCast(@alignCast(pbScratch));
    const pDst = types.SYMCRYPT_FDEF_MODELEMENT_PUINT32(peDst);
    const pMod = types.SYMCRYPT_FDEF_INT_PCUINT32(&pmMod.Divisor.Int);

    fdef_general.SymCryptFdefClaimScratch(pbScratch, cbScratch, SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(nDigits));

    var offset: UINT32 = undefined;
    if ((flags & SYMCRYPT_FLAG_MODRANDOM_ALLOW_ZERO) != 0) {
        // SYMCRYPT_FLAG_MODRANDOM_ALLOW_ZERO => SYMCRYPT_FLAG_MODRANDOM_ALLOW_ONE
        offset = 0;
    } else if ((flags & SYMCRYPT_FLAG_MODRANDOM_ALLOW_ONE) != 0) {
        offset = 1;
    } else {
        offset = 2;
    }

    var ulimit: UINT32 = if ((flags & SYMCRYPT_FLAG_MODRANDOM_ALLOW_MINUSONE) != 0) 0 else 1;

    // Special case for small divisors:
    //  When the divisor is 1, 2, or 3 we always allow returning -1
    //  We may also allow returning 1 or 0 depending on the flags specified
    if (pmMod.Divisor.nBits < 3) {
        // At a minimum, allow -1
        offset = @min(offset, pMod[0] - 1);
        ulimit = 0;
    }

    // Set pTmp to pMod-(offset+ulimit)
    macros.SYMCRYPT_ASSERT(nDigits * SYMCRYPT_FDEF_DIGIT_SIZE <= cbScratch);
    var c = fdef_int.SymCryptFdefRawSubUint32(pMod, offset + ulimit, pTmp, nDigits);
    macros.SYMCRYPT_ASSERT(c == 0);

    const nUsedBytes = (pmMod.Divisor.nBits + 7) / 8;
    const mask: UINT32 = (@as(UINT32, 0x100) >> @intCast((8 -% pmMod.Divisor.nBits) & 7)) - 1;

    // Wipe any bytes we won't fill with random
    const pbDstBytes: PBYTE = @ptrCast(pDst);
    macros.SymCryptWipe(pbDstBytes + nUsedBytes, (nDigits * SYMCRYPT_FDEF_DIGIT_SIZE) - nUsedBytes);

    var cntr: UINT32 = 0;
    while (cntr < FDEF_MOD_SET_RANDOM_GENERIC_LIMIT) : (cntr += 1) {
        // Try random values until we get one we like
        if (pRngState != null) {
            aes_ctr_drbg.SymCryptRngAesGenerate(@ptrCast(@alignCast(pRngState.?)), pbDstBytes, nUsedBytes);
        } else {
            SymCryptCallbackRandom(pbDstBytes, nUsedBytes);
        }
        pbDstBytes[nUsedBytes - 1] &= @truncate(mask);

        // Compare value to pMod-(offset+ulimit)
        if (fdef_int.SymCryptFdefRawIsLessThan(pDst, pTmp, nDigits) != 0) {
            // The value is within required range [0, Divisor-offset-ulimit)
            break;
        }
    }

    // Wipe all the digits in pTmp
    macros.SymCryptWipe(@ptrCast(pTmp), nDigits * SYMCRYPT_FDEF_DIGIT_SIZE);

    if (cntr >= FDEF_MOD_SET_RANDOM_GENERIC_LIMIT) {
        macros.SymCryptFatal(macros.multiCharConstant("rndc"));
    }

    // Add the offset which allows us to avoid 0 and/or 1 if required.
    // Now result is in range [offset, Divisor-ulimit)
    c = fdef_int.SymCryptFdefRawAddUint32(pDst, offset, pDst, nDigits);
    macros.SYMCRYPT_ASSERT(c == 0);
}

pub export fn SymCryptFdefModDivSmallPow2Generic(
    pmMod: PCSYMCRYPT_MODULUS,
    peSrc: PCSYMCRYPT_MODELEMENT,
    exp: UINT32,
    peDst: PSYMCRYPT_MODELEMENT,
) callconv(SYMCRYPT_CALL) void {
    const nDigits = pmMod.nDigits;
    const pMod = types.SYMCRYPT_FDEF_INT_PCUINT32(&pmMod.Divisor.Int);

    // mod must be odd
    macros.SYMCRYPT_ASSERT((pMod[0] & 1) != 0);
    macros.SYMCRYPT_ASSERT(exp >= 1 and exp <= types.NATIVE_BITS);

    var e = exp;
    var src = peSrc;
    while (true) {
        const pSrc = types.SYMCRYPT_FDEF_MODELEMENT_PUINT32(src);
        const pDst = types.SYMCRYPT_FDEF_MODELEMENT_PUINT32(peDst);

        const mask: UINT32 = 0 -% (pSrc[0] & 1);

        var t: UINT64 = @as(UINT64, pSrc[0]) + (pMod[0] & mask);
        var u: UINT64 = @as(UINT32, @truncate(t));
        t >>= 32;

        const nWords = nDigits * SYMCRYPT_FDEF_DIGIT_NUINT32;
        var i: UINT32 = 1;
        while (i < nWords) : (i += 1) {
            t += pMod[i] & mask;
            t += pSrc[i];

            u |= t << 32;

            pDst[i - 1] = @truncate(u >> 1);
            t >>= 32;
            u >>= 32;
        }
        u |= t << 32;
        pDst[i - 1] = @truncate(u >> 1);

        e -= 1;

        // First iteration reads from peSrc and writes to peDst
        // subsequent iterations must read from and write to peDst
        src = peDst;
        if (e == 0) break;
    }
}

pub export fn SymCryptFdefModDivSmallPow2(
    pmMod: PCSYMCRYPT_MODULUS,
    peSrc: PCSYMCRYPT_MODELEMENT,
    exp: UINT32,
    peDst: PSYMCRYPT_MODELEMENT,
) callconv(SYMCRYPT_CALL) void {
    if (comptime types.CPU_AMD64) {
        if (SYMCRYPT_CPU_FEATURES_PRESENT(SYMCRYPT_CPU_FEATURES_FOR_MULX)) {
            SymCryptFdefModDivSmallPow2Mulx(pmMod, peSrc, exp, peDst);
        } else {
            // Currently SymCryptAsm does not support AMD64 functions with shl/shr/shrd
            // by a variable count, as this needs special handling of the rcx (cl) register
            // For now we just fallback to the generic implementation on machines without MULX
            SymCryptFdefModDivSmallPow2Generic(pmMod, peSrc, exp, peDst);
        }
    } else if (comptime types.CPU_ARM64) {
        SymCryptFdefModDivSmallPow2Asm(pmMod, peSrc, exp, peDst);
    } else {
        SymCryptFdefModDivSmallPow2Generic(pmMod, peSrc, exp, peDst);
    }
}

pub export fn SymCryptFdefModDivPow2(
    pmMod: PCSYMCRYPT_MODULUS,
    peSrc: PCSYMCRYPT_MODELEMENT,
    exp: UINT32,
    peDst: PSYMCRYPT_MODELEMENT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    _ = pbScratch;
    _ = cbScratch;

    // mod must be odd
    macros.SYMCRYPT_ASSERT((types.SYMCRYPT_FDEF_INT_PCUINT32(&pmMod.Divisor.Int)[0] & 1) != 0);

    if (exp == 0) {
        // If exp is 0 we just need to copy peSrc to peDst
        SymCryptFdefModElementCopy(pmMod, peSrc, peDst);
        return;
    }

    var e = exp;
    var src = peSrc;
    while (true) {
        const shiftAmount = @min(@as(UINT32, types.NATIVE_BITS), e);
        SymCryptFdefModDivSmallPow2(pmMod, src, shiftAmount, peDst);
        e -= shiftAmount;

        // First iteration reads from peSrc and writes to peDst
        // subsequent iterations must read from and write to peDst
        src = peDst;
        if (e == 0) break;
    }
}

pub export fn SymCryptFdefModMulGeneric(
    pmMod: PCSYMCRYPT_MODULUS,
    peSrc1: PCSYMCRYPT_MODELEMENT,
    peSrc2: PCSYMCRYPT_MODELEMENT,
    peDst: PSYMCRYPT_MODELEMENT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    const nDigits = pmMod.nDigits;
    const pTmp: PUINT32 = @ptrCast(@alignCast(pbScratch));
    const scratchOffset = 2 * nDigits * SYMCRYPT_FDEF_DIGIT_SIZE;

    fdef_general.SymCryptFdefClaimScratch(pbScratch, cbScratch, SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(nDigits));
    macros.SYMCRYPT_ASSERT(cbScratch >= SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(nDigits));
    macros.SYMCRYPT_ASSERT(SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(nDigits) >= scratchOffset + types.SYMCRYPT_SCRATCH_BYTES_FOR_INT_DIVMOD(2 * nDigits, nDigits));
    macros.SYMCRYPT_ASSERT(@intFromPtr(pbScratch) % types.SYMCRYPT_ASYM_ALIGN_VALUE == 0);

    // Tmp space is enough for the product plus the DivMod scratch
    fdef_int.SymCryptFdefRawMul(
        types.SYMCRYPT_FDEF_MODELEMENT_PUINT32(peSrc1),
        nDigits,
        types.SYMCRYPT_FDEF_MODELEMENT_PUINT32(peSrc2),
        nDigits,
        pTmp,
    );

    fdef_int.SymCryptFdefRawDivMod(
        pTmp,
        2 * nDigits,
        &pmMod.Divisor,
        null,
        types.SYMCRYPT_FDEF_MODELEMENT_PUINT32(peDst),
        pbScratch + scratchOffset,
        cbScratch - scratchOffset,
    );
}

pub export fn SymCryptFdefModSquareGeneric(
    pmMod: PCSYMCRYPT_MODULUS,
    peSrc: PCSYMCRYPT_MODELEMENT,
    peDst: PSYMCRYPT_MODELEMENT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    const nDigits = pmMod.nDigits;
    const pTmp: PUINT32 = @ptrCast(@alignCast(pbScratch));
    const scratchOffset = 2 * nDigits * SYMCRYPT_FDEF_DIGIT_SIZE;

    fdef_general.SymCryptFdefClaimScratch(pbScratch, cbScratch, SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(nDigits));
    macros.SYMCRYPT_ASSERT(cbScratch >= SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(nDigits));
    macros.SYMCRYPT_ASSERT(SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(nDigits) >= scratchOffset + types.SYMCRYPT_SCRATCH_BYTES_FOR_INT_DIVMOD(2 * nDigits, nDigits));
    macros.SYMCRYPT_ASSERT(@intFromPtr(pbScratch) % types.SYMCRYPT_ASYM_ALIGN_VALUE == 0);

    // Tmp space is enough for the product plus the DivMod scratch
    fdef_int.SymCryptFdefRawSquare(
        types.SYMCRYPT_FDEF_MODELEMENT_PUINT32(peSrc),
        nDigits,
        pTmp,
    );

    fdef_int.SymCryptFdefRawDivMod(
        pTmp,
        2 * nDigits,
        &pmMod.Divisor,
        null,
        types.SYMCRYPT_FDEF_MODELEMENT_PUINT32(peDst),
        pbScratch + scratchOffset,
        cbScratch - scratchOffset,
    );
}

pub export fn SymCryptFdefModInvGeneric(
    pmMod: PCSYMCRYPT_MODULUS,
    peSrc: PCSYMCRYPT_MODELEMENT,
    peDst: PSYMCRYPT_MODELEMENT,
    flags: UINT32,
    pbScratchIn: PBYTE,
    cbScratchIn: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    const nDigits = pmMod.nDigits;
    var pbScratch = pbScratchIn;
    var cbScratch = cbScratchIn;

    macros.SYMCRYPT_ASSERT(cbScratch >= SYMCRYPT_SCRATCH_BYTES_FOR_MODINV(nDigits));

    if ((pmMod.flags & (types.SYMCRYPT_FLAG_DATA_PUBLIC | types.SYMCRYPT_FLAG_MODULUS_PRIME)) != (types.SYMCRYPT_FLAG_DATA_PUBLIC | types.SYMCRYPT_FLAG_MODULUS_PRIME)) {
        // Inversion over non-public or non-prime moduli currently not supported.
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    var nBytes = a_dispatch.SymCryptSizeofModElementFromModulus(pmMod);

    macros.SYMCRYPT_ASSERT(cbScratch >= 4 * nBytes);
    const peR = a_dispatch.SymCryptModElementCreate(pbScratch, nBytes, pmMod).?;
    pbScratch += nBytes;
    const peX = a_dispatch.SymCryptModElementCreate(pbScratch, nBytes, pmMod).?;
    pbScratch += nBytes;
    var peVa = a_dispatch.SymCryptModElementCreate(pbScratch, nBytes, pmMod).?;
    pbScratch += nBytes;
    var peVb = a_dispatch.SymCryptModElementCreate(pbScratch, nBytes, pmMod).?;
    pbScratch += nBytes;
    cbScratch -= 4 * nBytes;

    nBytes = a_dispatch.SymCryptSizeofIntFromDigits(nDigits);
    macros.SYMCRYPT_ASSERT(cbScratch >= 3 * nBytes);
    var piA = a_dispatch.SymCryptIntCreate(pbScratch, nBytes, nDigits).?;
    pbScratch += nBytes;
    var piB = a_dispatch.SymCryptIntCreate(pbScratch, nBytes, nDigits).?;
    pbScratch += nBytes;
    const piT = a_dispatch.SymCryptIntCreate(pbScratch, nBytes, nDigits).?;
    pbScratch += nBytes;
    cbScratch -= 3 * nBytes;

    macros.SYMCRYPT_ASSERT(cbScratch >= SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(nDigits));

    // If the data is not public, multiply by a random blinding factor; otherwise copy the value
    if ((flags & types.SYMCRYPT_FLAG_DATA_PUBLIC) == 0) {
        a_dispatch.SymCryptModSetRandom(pmMod, peR, SYMCRYPT_FLAG_MODRANDOM_ALLOW_ONE | SYMCRYPT_FLAG_MODRANDOM_ALLOW_MINUSONE, pbScratch, cbScratch); // R = random
        a_dispatch.SymCryptModMul(pmMod, peR, peSrc, peX, pbScratch, cbScratch); // X = R * Src
    } else {
        a_dispatch.SymCryptModElementCopy(pmMod, peSrc, peX);
    }

    // Set up piA and piB
    SymCryptFdefModElementToIntGeneric(pmMod, types.SYMCRYPT_FDEF_MODELEMENT_PUINT32(peX), piA, pbScratch, cbScratch); // A = X
    a_dispatch.SymCryptIntCopy(a_dispatch.SymCryptIntFromModulus(@constCast(pmMod)), piB); // B = Mod

    // Reject if A = 0, B = 0, or A and B both even
    if ((a_dispatch.SymCryptIntIsEqualUint32(piA, 0) |
        a_dispatch.SymCryptIntIsEqualUint32(piB, 0) |
        (((a_dispatch.SymCryptIntGetValueLsbits32(piA) | a_dispatch.SymCryptIntGetValueLsbits32(piB)) & 1) ^ 1)) != 0)
    {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    if (a_dispatch.SymCryptIntIsEqualUint32(piB, 2) != 0) {
        // Mod = 2 is a valid input. Luckily, modular inversion is easy.
        // The rest of the code assumes that Mod is odd. Other even values are not prime.
        a_dispatch.SymCryptModElementCopy(pmMod, peSrc, peDst);
        return .SYMCRYPT_NO_ERROR;
    }

    SymCryptFdefModElementSetValueUint32Generic(1, pmMod, peVa, pbScratch, cbScratch); // Va = 1
    SymCryptFdefModElementSetValueUint32Generic(0, pmMod, peVb, pbScratch, cbScratch); // Vb = 0

    while (true) {
        // invariant: A = Va*X (mod Mod), B = Vb*X (mod Mod), A != 0, B > 1.
        // Remove factors of 2 from A. This loop terminates because A != 0
        var leastSignificantUint32 = a_dispatch.SymCryptIntGetValueLsbits32(piA);
        while ((leastSignificantUint32 & 1) == 0) {
            const trailingZeros = SymCryptCountTrailingZeros32(leastSignificantUint32);
            a_dispatch.SymCryptIntDivPow2(piA, trailingZeros, piA);
            SymCryptFdefModDivSmallPow2(pmMod, peVa, trailingZeros, peVa);
            leastSignificantUint32 = a_dispatch.SymCryptIntGetValueLsbits32(piA);
        }

        if (a_dispatch.SymCryptIntIsEqualUint32(piA, 1) != 0) {
            // A = 1 = Va * X (mod Mod), so Va is the inverse of X
            break;
        }

        const c = a_dispatch.SymCryptIntSubSameSize(piB, piA, piT);

        // If A != 1 and A=B, then A is the GCD of the original inputs, and there is no inverse
        if (a_dispatch.SymCryptIntIsEqualUint32(piT, 0) != 0) {
            return .SYMCRYPT_INVALID_ARGUMENT;
        }

        if (c == 0) {
            // B > A, we set B to B-A and swap (B,A)
            // that way we continue our halving on B-A
            a_dispatch.SymCryptIntCopy(piT, piB);
            a_dispatch.SymCryptModSub(pmMod, peVb, peVa, peVb, pbScratch, cbScratch);

            const piTmpPtr = piB;
            piB = piA;
            piA = piTmpPtr;
            const peVtmpPtr = peVb;
            peVb = peVa;
            peVa = peVtmpPtr;
        } else {
            // B < A, Set A to A-B and continue halving A
            a_dispatch.SymCryptIntNeg(piT, piA);
            a_dispatch.SymCryptModSub(pmMod, peVa, peVb, peVa, pbScratch, cbScratch);
        }
    }

    // 1 = A = Va * X (mod Mod), so Va is the inverse of X
    // Check computation that we can test in the debugger
    a_dispatch.SymCryptModMul(pmMod, peVa, peX, peVb, pbScratch, cbScratch);

    // Actual answer
    // If the data is not public, multiply by the random blinding factor; otherwise copy the value
    if ((flags & types.SYMCRYPT_FLAG_DATA_PUBLIC) == 0) {
        a_dispatch.SymCryptModMul(pmMod, peVa, peR, peDst, pbScratch, cbScratch);
    } else {
        a_dispatch.SymCryptModElementCopy(pmMod, peVa, peDst);
    }

    return .SYMCRYPT_NO_ERROR;
}

// ==============================================================================================
// Montgomery Representation
// ==============================================================================================

pub export fn SymCryptFdefModulusInitMontgomeryInternal(
    pmMod: PSYMCRYPT_MODULUS,
    nUint32Used: UINT32, // R = 2^{32 * this parameter}
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    // Scratch space is big enough for an nDigit+1 byte value + sufficient divmod scratch
    const nDigits = pmMod.nDigits;
    const pbDivisor: PBYTE = @ptrCast(&pmMod.Divisor);
    const modR2: PUINT32 = @ptrCast(@alignCast(pbDivisor + fdef_general.SymCryptFdefSizeofDivisorFromDigits(nDigits)));

    macros.SYMCRYPT_ASSERT(@intFromPtr(pbScratch) % types.SYMCRYPT_ASYM_ALIGN_VALUE == 0);

    pmMod.tm.montgomery.Rsqr = modR2;
    const negDivisor: PUINT32 = @ptrCast(@alignCast(@as(PBYTE, @ptrCast(modR2)) + (nDigits * SYMCRYPT_FDEF_DIGIT_SIZE)));

    // We pre-compute R^2 mod M
    const pR2: PUINT32 = @ptrCast(@alignCast(pbScratch));
    const cbR2 = (2 * nDigits + 1) * SYMCRYPT_FDEF_DIGIT_SIZE;
    macros.SYMCRYPT_ASSERT(cbScratch >= cbR2);
    macros.SYMCRYPT_ASSERT(cbScratch >= 2 * nUint32Used * @sizeOf(UINT32));

    // Set it to R^2
    macros.SymCryptWipe(@ptrCast(pR2), cbR2);
    pR2[2 * nUint32Used] = 1;
    fdef_int.SymCryptFdefRawDivMod(pR2, 2 * nDigits + 1, &pmMod.Divisor, null, modR2, pbScratch + cbR2, cbScratch - cbR2);

    _ = fdef_int.SymCryptFdefRawNeg(types.SYMCRYPT_FDEF_INT_PCUINT32(&pmMod.Divisor.Int), 0, negDivisor, nDigits);
}

pub export fn SymCryptFdefModulusInitMontgomery(
    pmMod: PSYMCRYPT_MODULUS,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    SymCryptFdefModulusInitMontgomeryInternal(pmMod, pmMod.nDigits * SYMCRYPT_FDEF_DIGIT_NUINT32, pbScratch, cbScratch);
}

pub export fn SymCryptFdefMontgomeryReduceC(
    pmMod: PCSYMCRYPT_MODULUS,
    pSrc: PUINT32,
    pDst: PUINT32,
) callconv(SYMCRYPT_CALL) void {
    const nDigits = pmMod.nDigits;
    const nWords = nDigits * SYMCRYPT_FDEF_DIGIT_NUINT32;
    const pMod = types.SYMCRYPT_FDEF_INT_PCUINT32(&pmMod.Divisor.Int);

    var pWork = pSrc;
    var hc: UINT32 = 0;
    for (0..nWords) |_| {
        const m: UINT32 = @as(UINT32, @truncate(pmMod.inv64)) *% pWork[0];
        var c: UINT64 = 0;
        for (0..nWords) |j| {
            // Invariant: c < 2^32
            c += @as(UINT64, pMod[j]) * @as(UINT64, m);
            c += pWork[j];
            // There is no overflow on C because the max value is
            // (2^32 - 1) * (2^32 - 1) + 2^32 - 1 + 2^32 - 1 = 2^64 - 1.
            pWork[j] = @truncate(c);
            c >>= 32;
        }
        c = c + pWork[nWords] + hc;
        pWork[nWords] = @truncate(c);
        hc = @truncate(c >> 32);
        pWork += 1;
    }
    macros.SYMCRYPT_ASSERT(hc < 2);

    const d = fdef_int.SymCryptFdefRawSub(pWork, pMod, pDst, nDigits);

    macros.SYMCRYPT_ASSERT(hc <= d); // if hc = 1, then d = 1 is mandatory

    fdef_general.SymCryptFdefMaskedCopy(@ptrCast(pWork), @ptrCast(pDst), nDigits, hc -% (hc | d)); // copy only if hc=0, d=1
}

pub export fn SymCryptFdefMontgomeryReduce(
    pmMod: PCSYMCRYPT_MODULUS,
    pSrc: PUINT32,
    pDst: PUINT32,
) callconv(SYMCRYPT_CALL) void {
    if (comptime types.CPU_AMD64) {
        if (SYMCRYPT_CPU_FEATURES_PRESENT(SYMCRYPT_CPU_FEATURES_FOR_MULX)) {
            SymCryptFdefMontgomeryReduceMulx(pmMod, pSrc, pDst);
        } else {
            SymCryptFdefMontgomeryReduceAsm(pmMod, pSrc, pDst);
        }
    } else if (comptime (types.CPU_X86 or types.CPU_ARM64 or types.CPU_ARM)) {
        SymCryptFdefMontgomeryReduceAsm(pmMod, pSrc, pDst);
    } else {
        SymCryptFdefMontgomeryReduceC(pmMod, pSrc, pDst);
    }
}

pub export fn SymCryptFdefModSetPostMontgomery(
    pmMod: PCSYMCRYPT_MODULUS,
    peObj: PSYMCRYPT_MODELEMENT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    const nDigits = pmMod.nDigits;

    macros.SYMCRYPT_ASSERT(cbScratch >= nDigits * 2 * SYMCRYPT_FDEF_DIGIT_SIZE);

    const pObj = types.SYMCRYPT_FDEF_MODELEMENT_PUINT32(peObj);
    const pScratchWords: PUINT32 = @ptrCast(@alignCast(pbScratch));
    fdef_int.SymCryptFdefRawMul(pObj, nDigits, pmMod.tm.montgomery.Rsqr, nDigits, pScratchWords);
    SymCryptFdefMontgomeryReduce(pmMod, pScratchWords, pObj);
}

pub export fn SymCryptFdefModPreGetMontgomery(
    pmMod: PCSYMCRYPT_MODULUS,
    peObj: PCSYMCRYPT_MODELEMENT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) PCUINT32 {
    const pTmp: PUINT32 = @ptrCast(@alignCast(pbScratch));
    const nDigits = pmMod.nDigits;

    macros.SYMCRYPT_ASSERT(cbScratch >= nDigits * 2 * SYMCRYPT_FDEF_DIGIT_SIZE);

    const cbElem = nDigits * SYMCRYPT_FDEF_DIGIT_SIZE;
    const pbObj: PCBYTE = @ptrCast(types.SYMCRYPT_FDEF_MODELEMENT_PUINT32(peObj));
    @memcpy(pbScratch[0..cbElem], pbObj[0..cbElem]);
    macros.SymCryptWipe(pbScratch + cbElem, cbElem);
    SymCryptFdefMontgomeryReduce(pmMod, pTmp, pTmp);

    return pTmp;
}

pub export fn SymCryptFdefModulusCopyFixupMontgomery(
    pmSrc: PCSYMCRYPT_MODULUS,
    pmDst: PSYMCRYPT_MODULUS,
) callconv(SYMCRYPT_CALL) void {
    _ = pmSrc;
    const pbDivisor: PBYTE = @ptrCast(&pmDst.Divisor);
    pmDst.tm.montgomery.Rsqr = @ptrCast(@alignCast(pbDivisor + fdef_general.SymCryptFdefSizeofDivisorFromDigits(pmDst.nDigits)));
}

pub export fn SymCryptFdefModMulMontgomery(
    pmMod: PCSYMCRYPT_MODULUS,
    peSrc1: PCSYMCRYPT_MODELEMENT,
    peSrc2: PCSYMCRYPT_MODELEMENT,
    peDst: PSYMCRYPT_MODELEMENT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    const nDigits = pmMod.nDigits;
    const pTmp: PUINT32 = @ptrCast(@alignCast(pbScratch));

    macros.SYMCRYPT_ASSERT(cbScratch >= 2 * nDigits * SYMCRYPT_FDEF_DIGIT_SIZE);

    fdef_int.SymCryptFdefRawMul(
        types.SYMCRYPT_FDEF_MODELEMENT_PUINT32(peSrc1),
        nDigits,
        types.SYMCRYPT_FDEF_MODELEMENT_PUINT32(peSrc2),
        nDigits,
        pTmp,
    );
    SymCryptFdefMontgomeryReduce(pmMod, pTmp, types.SYMCRYPT_FDEF_MODELEMENT_PUINT32(peDst));
}

pub fn SymCryptFdefModMulMontgomeryMulx(
    pmMod: PCSYMCRYPT_MODULUS,
    peSrc1: PCSYMCRYPT_MODELEMENT,
    peSrc2: PCSYMCRYPT_MODELEMENT,
    peDst: PSYMCRYPT_MODELEMENT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    const nDigits = pmMod.nDigits;
    const pTmp: PUINT32 = @ptrCast(@alignCast(pbScratch));

    macros.SYMCRYPT_ASSERT(cbScratch >= 2 * nDigits * SYMCRYPT_FDEF_DIGIT_SIZE);

    SymCryptFdefRawMulMulx(
        types.SYMCRYPT_FDEF_MODELEMENT_PUINT32(peSrc1),
        nDigits,
        types.SYMCRYPT_FDEF_MODELEMENT_PUINT32(peSrc2),
        nDigits,
        pTmp,
    );
    SymCryptFdefMontgomeryReduceMulx(pmMod, pTmp, types.SYMCRYPT_FDEF_MODELEMENT_PUINT32(peDst));
}

pub fn SymCryptFdefModMulMontgomeryMulx1024(
    pmMod: PCSYMCRYPT_MODULUS,
    peSrc1: PCSYMCRYPT_MODELEMENT,
    peSrc2: PCSYMCRYPT_MODELEMENT,
    peDst: PSYMCRYPT_MODELEMENT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    const nDigits = pmMod.nDigits;
    const pTmp: PUINT32 = @ptrCast(@alignCast(pbScratch));

    macros.SYMCRYPT_ASSERT(cbScratch >= 2 * nDigits * SYMCRYPT_FDEF_DIGIT_SIZE);

    SymCryptFdefRawMulMulx1024(
        types.SYMCRYPT_FDEF_MODELEMENT_PUINT32(peSrc1),
        types.SYMCRYPT_FDEF_MODELEMENT_PUINT32(peSrc2),
        nDigits,
        pTmp,
    );
    SymCryptFdefMontgomeryReduceMulx1024(pmMod, pTmp, types.SYMCRYPT_FDEF_MODELEMENT_PUINT32(peDst));
}

pub export fn SymCryptFdefModSquareMontgomery(
    pmMod: PCSYMCRYPT_MODULUS,
    peSrc: PCSYMCRYPT_MODELEMENT,
    peDst: PSYMCRYPT_MODELEMENT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    const nDigits = pmMod.nDigits;
    const pTmp: PUINT32 = @ptrCast(@alignCast(pbScratch));

    macros.SYMCRYPT_ASSERT(cbScratch >= 2 * nDigits * SYMCRYPT_FDEF_DIGIT_SIZE);

    fdef_int.SymCryptFdefRawSquare(types.SYMCRYPT_FDEF_MODELEMENT_PUINT32(peSrc), nDigits, pTmp);
    SymCryptFdefMontgomeryReduce(pmMod, pTmp, types.SYMCRYPT_FDEF_MODELEMENT_PUINT32(peDst));
}

pub fn SymCryptFdefModSquareMontgomeryMulx(
    pmMod: PCSYMCRYPT_MODULUS,
    peSrc: PCSYMCRYPT_MODELEMENT,
    peDst: PSYMCRYPT_MODELEMENT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    const nDigits = pmMod.nDigits;
    const pTmp: PUINT32 = @ptrCast(@alignCast(pbScratch));

    macros.SYMCRYPT_ASSERT(cbScratch >= 2 * nDigits * SYMCRYPT_FDEF_DIGIT_SIZE);

    SymCryptFdefRawSquareMulx(types.SYMCRYPT_FDEF_MODELEMENT_PUINT32(peSrc), nDigits, pTmp);
    SymCryptFdefMontgomeryReduceMulx(pmMod, pTmp, types.SYMCRYPT_FDEF_MODELEMENT_PUINT32(peDst));
}

pub fn SymCryptFdefModSquareMontgomeryMulx1024(
    pmMod: PCSYMCRYPT_MODULUS,
    peSrc: PCSYMCRYPT_MODELEMENT,
    peDst: PSYMCRYPT_MODELEMENT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    const nDigits = pmMod.nDigits;
    const pTmp: PUINT32 = @ptrCast(@alignCast(pbScratch));

    macros.SYMCRYPT_ASSERT(cbScratch >= 2 * nDigits * SYMCRYPT_FDEF_DIGIT_SIZE);

    SymCryptFdefRawSquareMulx1024(types.SYMCRYPT_FDEF_MODELEMENT_PUINT32(peSrc), nDigits, pTmp);
    SymCryptFdefMontgomeryReduceMulx1024(pmMod, pTmp, types.SYMCRYPT_FDEF_MODELEMENT_PUINT32(peDst));
}

pub export fn SymCryptFdefModInvMontgomery(
    pmMod: PCSYMCRYPT_MODULUS,
    peSrc: PCSYMCRYPT_MODELEMENT,
    peDst: PSYMCRYPT_MODELEMENT,
    flags: UINT32,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    const nDigits = pmMod.nDigits;
    const nBytes = nDigits * SYMCRYPT_FDEF_DIGIT_SIZE;
    const pTmp: PUINT32 = @ptrCast(@alignCast(pbScratch));

    macros.SYMCRYPT_ASSERT(@intFromPtr(pTmp) % types.SYMCRYPT_ASYM_ALIGN_VALUE == 0);

    // We have R*X; we first apply the montgomery reduction twice to get X/R, and then invert that
    // using the generic inversion to get R/X.
    macros.SYMCRYPT_ASSERT(cbScratch >= 2 * nBytes);
    const pbSrc: PCBYTE = @ptrCast(types.SYMCRYPT_FDEF_MODELEMENT_PUINT32(peSrc));
    @memcpy(pbScratch[0..nBytes], pbSrc[0..nBytes]);

    macros.SymCryptWipe(pbScratch + nBytes, nBytes);
    SymCryptFdefMontgomeryReduce(pmMod, pTmp, pTmp);

    macros.SymCryptWipe(pbScratch + nBytes, nBytes);
    SymCryptFdefMontgomeryReduce(pmMod, pTmp, types.SYMCRYPT_FDEF_MODELEMENT_PUINT32(peDst));

    return SymCryptFdefModInvGeneric(pmMod, peDst, peDst, flags, pbScratch, cbScratch);
}

// ==============================================================================================
// AMD64 256-bit and 384-bit Montgomery Modulus Code
// ==============================================================================================

pub fn SymCryptFdefModInvMontgomery256(
    pmMod: PCSYMCRYPT_MODULUS,
    peSrc: PCSYMCRYPT_MODELEMENT,
    peDst: PSYMCRYPT_MODELEMENT,
    flags: UINT32,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    const nBytes: usize = 32;
    const pTmp: PUINT32 = @ptrCast(@alignCast(pbScratch));

    macros.SYMCRYPT_ASSERT(@intFromPtr(pTmp) % types.SYMCRYPT_ASYM_ALIGN_VALUE == 0);

    // We have R*X; we first apply the montgomery reduction twice to get X/R, and then invert that
    // using the generic inversion to get R/X.
    macros.SYMCRYPT_ASSERT(cbScratch >= 2 * nBytes);
    const pbSrc: PCBYTE = @ptrCast(types.SYMCRYPT_FDEF_MODELEMENT_PUINT32(peSrc));
    @memcpy(pbScratch[0..nBytes], pbSrc[0..nBytes]);

    macros.SymCryptWipe(pbScratch + nBytes, nBytes);
    SymCryptFdefMontgomeryReduce256Asm(pmMod, pTmp, pTmp);

    macros.SymCryptWipe(pbScratch + nBytes, nBytes);
    SymCryptFdefMontgomeryReduce256Asm(pmMod, pTmp, types.SYMCRYPT_FDEF_MODELEMENT_PUINT32(peDst));

    return SymCryptFdefModInvGeneric(pmMod, peDst, peDst, flags, pbScratch, cbScratch);
}

pub fn SymCryptFdefModSetPostMontgomeryMulx256(
    pmMod: PCSYMCRYPT_MODULUS,
    peObj: PSYMCRYPT_MODELEMENT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    const nDigits = pmMod.nDigits;

    macros.SYMCRYPT_ASSERT(cbScratch >= nDigits * 2 * SYMCRYPT_FDEF_DIGIT_SIZE);
    _ = pbScratch;

    SymCryptFdefModMulMontgomeryMulx256Asm(pmMod, @ptrCast(@alignCast(pmMod.tm.montgomery.Rsqr)), peObj, peObj);
}

pub fn SymCryptFdefModPreGetMontgomery256(
    pmMod: PCSYMCRYPT_MODULUS,
    peObj: PCSYMCRYPT_MODELEMENT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) PCUINT32 {
    const pTmp: PUINT32 = @ptrCast(@alignCast(pbScratch));
    const nDigits: UINT32 = 1;

    macros.SYMCRYPT_ASSERT(cbScratch >= nDigits * SYMCRYPT_FDEF_DIGIT_SIZE);

    const cbElem = nDigits * SYMCRYPT_FDEF_DIGIT_SIZE;
    const pbObj: PCBYTE = @ptrCast(types.SYMCRYPT_FDEF_MODELEMENT_PUINT32(peObj));
    @memcpy(pbScratch[0..cbElem], pbObj[0..cbElem]);
    SymCryptFdefMontgomeryReduce256Asm(pmMod, pTmp, pTmp);

    // This gives the right result, but relies on peObj having zeroed upper half
    // on AMD64 when digits are 512 bits. This should be true - check in a CHKed build.
    for (8..16) |i| {
        macros.SYMCRYPT_ASSERT(pTmp[i] == 0);
    }

    return pTmp;
}

pub fn SymCryptFdefModulusInitMontgomery256(
    pmMod: PSYMCRYPT_MODULUS,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    SymCryptFdefModulusInitMontgomeryInternal(pmMod, 8, pbScratch, cbScratch);
}

pub fn SymCryptFdefModSetPostMontgomeryMulxP384(
    pmMod: PCSYMCRYPT_MODULUS,
    peObj: PSYMCRYPT_MODELEMENT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    const nDigits = pmMod.nDigits;

    macros.SYMCRYPT_ASSERT(cbScratch >= nDigits * 2 * SYMCRYPT_FDEF_DIGIT_SIZE);
    _ = pbScratch;

    SymCryptFdefModMulMontgomeryMulxP384Asm(pmMod, @ptrCast(@alignCast(pmMod.tm.montgomery.Rsqr)), peObj, peObj);
}

comptime {
    if (types.CPU_AMD64) {
        @export(&SymCryptFdefModMulMontgomeryMulx, .{ .name = "SymCryptFdefModMulMontgomeryMulx" });
        @export(&SymCryptFdefModMulMontgomeryMulx1024, .{ .name = "SymCryptFdefModMulMontgomeryMulx1024" });
        @export(&SymCryptFdefModSquareMontgomeryMulx, .{ .name = "SymCryptFdefModSquareMontgomeryMulx" });
        @export(&SymCryptFdefModSquareMontgomeryMulx1024, .{ .name = "SymCryptFdefModSquareMontgomeryMulx1024" });
        @export(&SymCryptFdefModInvMontgomery256, .{ .name = "SymCryptFdefModInvMontgomery256" });
        @export(&SymCryptFdefModSetPostMontgomeryMulx256, .{ .name = "SymCryptFdefModSetPostMontgomeryMulx256" });
        @export(&SymCryptFdefModPreGetMontgomery256, .{ .name = "SymCryptFdefModPreGetMontgomery256" });
        @export(&SymCryptFdefModulusInitMontgomery256, .{ .name = "SymCryptFdefModulusInitMontgomery256" });
        @export(&SymCryptFdefModSetPostMontgomeryMulxP384, .{ .name = "SymCryptFdefModSetPostMontgomeryMulxP384" });
    }
}
