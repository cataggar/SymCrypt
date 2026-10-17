//
// fdef369_mod.zig
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
// Modular arithmetic routines specifically for 3, 6, and 9 word size implementations (AMD64 and ARM64).
// Ported from lib/fdef369_mod.c.
//

const types = @import("types.zig");
const macros = @import("macros.zig");
const fdef_general = @import("fdef_general.zig");
const fdef_mod = @import("fdef_mod.zig");

const SYMCRYPT_CALL = types.SYMCRYPT_CALL;
const SYMCRYPT_ERROR = types.SYMCRYPT_ERROR;
const UINT32 = types.UINT32;
const PUINT32 = types.PUINT32;
const PCUINT32 = types.PCUINT32;
const PBYTE = types.PBYTE;
const PCBYTE = types.PCBYTE;
const SIZE_T = types.SIZE_T;
const PSYMCRYPT_MODULUS = types.PSYMCRYPT_MODULUS;
const PCSYMCRYPT_MODULUS = types.PCSYMCRYPT_MODULUS;
const PSYMCRYPT_MODELEMENT = types.PSYMCRYPT_MODELEMENT;
const PCSYMCRYPT_MODELEMENT = types.PCSYMCRYPT_MODELEMENT;

pub inline fn SYMCRYPT_FDEF369_DIGITS_TO_NUINT32(nD: UINT32) UINT32 {
    if (comptime types.CPU_AMD64) {
        return (nD + 1) * 6;
    } else if (comptime types.CPU_ARM64) {
        return nD * 6;
    } else {
        unreachable;
    }
}

extern fn SymCryptFdef369RawAddAsm(
    pSrc1: PCUINT32,
    pSrc2: PCUINT32,
    pDst: PUINT32,
    nDigits: UINT32,
) callconv(SYMCRYPT_CALL) UINT32;

extern fn SymCryptFdef369RawSubAsm(
    pSrc1: PCUINT32,
    pSrc2: PCUINT32,
    pDst: PUINT32,
    nDigits: UINT32,
) callconv(SYMCRYPT_CALL) UINT32;

extern fn SymCryptFdef369MaskedCopyAsm(
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    nDigits: UINT32,
    mask: UINT32,
) callconv(SYMCRYPT_CALL) void;

extern fn SymCryptFdef369RawMulAsm(
    pSrc1: PCUINT32,
    nDigits1: UINT32,
    pSrc2: PCUINT32,
    nDigits2: UINT32,
    pDst: PUINT32,
) callconv(SYMCRYPT_CALL) void;

extern fn SymCryptFdef369MontgomeryReduceAsm(
    pmMod: PCSYMCRYPT_MODULUS,
    pSrc: PUINT32,
    pDst: PUINT32,
) callconv(SYMCRYPT_CALL) void;

pub fn SymCryptFdef369ModAddGeneric(
    pmMod: PCSYMCRYPT_MODULUS,
    peSrc1: PCSYMCRYPT_MODELEMENT,
    peSrc2: PCSYMCRYPT_MODELEMENT,
    peDst: PSYMCRYPT_MODELEMENT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    const nDigits = pmMod.nDigits;

    fdef_general.SymCryptFdefClaimScratch(pbScratch, cbScratch, fdef_mod.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(nDigits));
    macros.SYMCRYPT_ASSERT(cbScratch >= nDigits * types.SYMCRYPT_FDEF_DIGIT_SIZE);

    const pSrc1 = types.SYMCRYPT_FDEF_MODELEMENT_PUINT32(peSrc1);
    const pSrc2 = types.SYMCRYPT_FDEF_MODELEMENT_PUINT32(peSrc2);
    const pDst = types.SYMCRYPT_FDEF_MODELEMENT_PUINT32(peDst);
    const pScratchWords: PUINT32 = @ptrCast(@alignCast(pbScratch));

    const c = SymCryptFdef369RawAddAsm(pSrc1, pSrc2, pDst, nDigits);
    const d = SymCryptFdef369RawSubAsm(pDst, types.SYMCRYPT_FDEF_INT_PCUINT32(&pmMod.Divisor.Int), pScratchWords, nDigits);
    SymCryptFdef369MaskedCopyAsm(pbScratch, @ptrCast(pDst), nDigits, (c ^ d) -% 1);

    // We can't have a carry in the first addition, and no carry in the subtraction.
    macros.SYMCRYPT_ASSERT(!(c == 1 and d == 0));
}

pub fn SymCryptFdef369ModSubGeneric(
    pmMod: PCSYMCRYPT_MODULUS,
    peSrc1: PCSYMCRYPT_MODELEMENT,
    peSrc2: PCSYMCRYPT_MODELEMENT,
    peDst: PSYMCRYPT_MODELEMENT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    const nDigits = pmMod.nDigits;

    fdef_general.SymCryptFdefClaimScratch(pbScratch, cbScratch, fdef_mod.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(nDigits));
    macros.SYMCRYPT_ASSERT(cbScratch >= nDigits * types.SYMCRYPT_FDEF_DIGIT_SIZE);

    const pSrc1 = types.SYMCRYPT_FDEF_MODELEMENT_PUINT32(peSrc1);
    const pSrc2 = types.SYMCRYPT_FDEF_MODELEMENT_PUINT32(peSrc2);
    const pDst = types.SYMCRYPT_FDEF_MODELEMENT_PUINT32(peDst);
    const pScratchWords: PUINT32 = @ptrCast(@alignCast(pbScratch));

    const c = SymCryptFdef369RawSubAsm(pSrc1, pSrc2, pDst, nDigits);
    const d = SymCryptFdef369RawAddAsm(pDst, types.SYMCRYPT_FDEF_INT_PCUINT32(&pmMod.Divisor.Int), pScratchWords, nDigits);
    SymCryptFdef369MaskedCopyAsm(pbScratch, @ptrCast(pDst), nDigits, 0 -% c);

    macros.SYMCRYPT_ASSERT(!(c == 1 and d == 0));
}

pub fn SymCryptFdef369ModulusInitMontgomery(
    pmMod: PSYMCRYPT_MODULUS,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    fdef_mod.SymCryptFdefModulusInitMontgomeryInternal(
        pmMod,
        SYMCRYPT_FDEF369_DIGITS_TO_NUINT32(pmMod.nDigits),
        pbScratch,
        cbScratch,
    );
}

pub fn SymCryptFdef369ModMulMontgomery(
    pmMod: PCSYMCRYPT_MODULUS,
    peSrc1: PCSYMCRYPT_MODELEMENT,
    peSrc2: PCSYMCRYPT_MODELEMENT,
    peDst: PSYMCRYPT_MODELEMENT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    const nDigits = pmMod.nDigits;
    const pTmp: PUINT32 = @ptrCast(@alignCast(pbScratch));

    macros.SYMCRYPT_ASSERT(cbScratch >= 2 * nDigits * types.SYMCRYPT_FDEF_DIGIT_SIZE);

    SymCryptFdef369RawMul(
        types.SYMCRYPT_FDEF_MODELEMENT_PUINT32(peSrc1),
        nDigits,
        types.SYMCRYPT_FDEF_MODELEMENT_PUINT32(peSrc2),
        nDigits,
        pTmp,
    );

    SymCryptFdef369MontgomeryReduce(pmMod, pTmp, types.SYMCRYPT_FDEF_MODELEMENT_PUINT32(peDst));
}

pub fn SymCryptFdef369ModSquareMontgomery(
    pmMod: PCSYMCRYPT_MODULUS,
    peSrc: PCSYMCRYPT_MODELEMENT,
    peDst: PSYMCRYPT_MODELEMENT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    SymCryptFdef369ModMulMontgomery(pmMod, peSrc, peSrc, peDst, pbScratch, cbScratch);
}

pub fn SymCryptFdef369ModSetPostMontgomery(
    pmMod: PCSYMCRYPT_MODULUS,
    peObj: PSYMCRYPT_MODELEMENT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    const nDigits = pmMod.nDigits;
    const pScratchWords: PUINT32 = @ptrCast(@alignCast(pbScratch));

    macros.SYMCRYPT_ASSERT(cbScratch >= nDigits * 2 * types.SYMCRYPT_FDEF_DIGIT_SIZE);

    const pObj = types.SYMCRYPT_FDEF_MODELEMENT_PUINT32(peObj);
    SymCryptFdef369RawMul(pObj, nDigits, pmMod.tm.montgomery.Rsqr, nDigits, pScratchWords);
    SymCryptFdef369MontgomeryReduce(pmMod, pScratchWords, pObj);
}

pub fn SymCryptFdef369ModPreGetMontgomery(
    pmMod: PCSYMCRYPT_MODULUS,
    peObj: PCSYMCRYPT_MODELEMENT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) PCUINT32 {
    const pTmp: PUINT32 = @ptrCast(@alignCast(pbScratch));
    const nDigits = pmMod.nDigits;
    const nUint32 = SYMCRYPT_FDEF369_DIGITS_TO_NUINT32(nDigits);
    const cb369 = nUint32 * @sizeOf(UINT32);

    macros.SYMCRYPT_ASSERT(cbScratch >= nDigits * 2 * types.SYMCRYPT_FDEF_DIGIT_SIZE);

    const pbObj: PCBYTE = @ptrCast(types.SYMCRYPT_FDEF_MODELEMENT_PUINT32(peObj));
    @memcpy(pbScratch[0..cb369], pbObj[0..cb369]);
    macros.SymCryptWipe(@ptrCast(pTmp + nUint32), cb369);
    SymCryptFdef369MontgomeryReduce(pmMod, pTmp, pTmp);

    // This gives the right result, but it isn't the size that is expected.
    // Wipe the extra bytes
    macros.SymCryptWipe(@ptrCast(pTmp + nUint32), nDigits * types.SYMCRYPT_FDEF_DIGIT_SIZE - cb369);

    return pTmp;
}

pub fn SymCryptFdef369MontgomeryReduce(
    pmMod: PCSYMCRYPT_MODULUS,
    pSrc: PUINT32,
    pDst: PUINT32,
) callconv(SYMCRYPT_CALL) void {
    SymCryptFdef369MontgomeryReduceAsm(pmMod, pSrc, pDst);
}

pub fn SymCryptFdef369RawMul(
    pSrc1: PCUINT32,
    nDigits1: UINT32,
    pSrc2: PCUINT32,
    nDigits2: UINT32,
    pDst: PUINT32,
) callconv(SYMCRYPT_CALL) void {
    SymCryptFdef369RawMulAsm(pSrc1, nDigits1, pSrc2, nDigits2, pDst);
}

pub fn SymCryptFdef369ModInvMontgomery(
    pmMod: PCSYMCRYPT_MODULUS,
    peSrc: PCSYMCRYPT_MODELEMENT,
    peDst: PSYMCRYPT_MODELEMENT,
    flags: UINT32,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    const nDigits = pmMod.nDigits;
    const nBytes = SYMCRYPT_FDEF369_DIGITS_TO_NUINT32(nDigits) * @sizeOf(UINT32);
    const pTmp: PUINT32 = @ptrCast(@alignCast(pbScratch));

    macros.SYMCRYPT_ASSERT(@intFromPtr(pTmp) % types.SYMCRYPT_ASYM_ALIGN_VALUE == 0);
    macros.SYMCRYPT_ASSERT(cbScratch >= 2 * nBytes);

    // We have R*X; we first apply the montgomery reduction twice to get X/R, and then invert that
    // using the generic inversion to get R/X.
    const pbSrc: PCBYTE = @ptrCast(types.SYMCRYPT_FDEF_MODELEMENT_PUINT32(peSrc));
    @memcpy(pbScratch[0..nBytes], pbSrc[0..nBytes]);

    macros.SymCryptWipe(pbScratch + nBytes, nBytes);
    SymCryptFdef369MontgomeryReduce(pmMod, pTmp, pTmp);

    macros.SymCryptWipe(pbScratch + nBytes, nBytes);
    SymCryptFdef369MontgomeryReduce(pmMod, pTmp, types.SYMCRYPT_FDEF_MODELEMENT_PUINT32(peDst));

    return fdef_mod.SymCryptFdefModInvGeneric(pmMod, peDst, peDst, flags, pbScratch, cbScratch);
}

comptime {
    if (types.CPU_AMD64 or types.CPU_ARM64) {
        @export(&SymCryptFdef369ModAddGeneric, .{ .name = "SymCryptFdef369ModAddGeneric" });
        @export(&SymCryptFdef369ModSubGeneric, .{ .name = "SymCryptFdef369ModSubGeneric" });
        @export(&SymCryptFdef369ModulusInitMontgomery, .{ .name = "SymCryptFdef369ModulusInitMontgomery" });
        @export(&SymCryptFdef369ModMulMontgomery, .{ .name = "SymCryptFdef369ModMulMontgomery" });
        @export(&SymCryptFdef369ModSquareMontgomery, .{ .name = "SymCryptFdef369ModSquareMontgomery" });
        @export(&SymCryptFdef369ModSetPostMontgomery, .{ .name = "SymCryptFdef369ModSetPostMontgomery" });
        @export(&SymCryptFdef369ModPreGetMontgomery, .{ .name = "SymCryptFdef369ModPreGetMontgomery" });
        @export(&SymCryptFdef369MontgomeryReduce, .{ .name = "SymCryptFdef369MontgomeryReduce" });
        @export(&SymCryptFdef369RawMul, .{ .name = "SymCryptFdef369RawMul" });
        @export(&SymCryptFdef369ModInvMontgomery, .{ .name = "SymCryptFdef369ModInvMontgomery" });
    }
}
