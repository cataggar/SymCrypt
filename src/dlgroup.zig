//
// dlgroup.zig   Dlgroup functions
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

const std = @import("std");
const types = @import("types.zig");
const macros = @import("macros.zig");
const a_dispatch = @import("a_dispatch.zig");
const primes = @import("primes.zig");
const hash = @import("hash.zig");
const sha1 = @import("sha1.zig");
const dl_internal_groups = @import("dl_internal_groups.zig");

const SYMCRYPT_CALL = types.SYMCRYPT_CALL;
const SYMCRYPT_ERROR = types.SYMCRYPT_ERROR;
const SYMCRYPT_NUMBER_FORMAT = types.SYMCRYPT_NUMBER_FORMAT;
const SYMCRYPT_DLGROUP_FIPS = types.SYMCRYPT_DLGROUP_FIPS;
const SYMCRYPT_DLGROUP_DH_SAFEPRIMETYPE = types.SYMCRYPT_DLGROUP_DH_SAFEPRIMETYPE;
const PCSYMCRYPT_DLGROUP_DH_SAFEPRIME_PARAMS = types.PCSYMCRYPT_DLGROUP_DH_SAFEPRIME_PARAMS;
const BYTE = types.BYTE;
const PBYTE = types.PBYTE;
const PCBYTE = types.PCBYTE;
const UINT16 = types.UINT16;
const UINT32 = types.UINT32;
const PUINT32 = types.PUINT32;
const UINT64 = types.UINT64;
const SIZE_T = types.SIZE_T;
const PSIZE_T = types.PSIZE_T;
const PVOID = types.PVOID;
const BOOLEAN = types.BOOLEAN;
const PSYMCRYPT_INT = types.PSYMCRYPT_INT;
const PCSYMCRYPT_INT = types.PCSYMCRYPT_INT;
const PSYMCRYPT_DIVISOR = types.PSYMCRYPT_DIVISOR;
const PCSYMCRYPT_DIVISOR = types.PCSYMCRYPT_DIVISOR;
const PSYMCRYPT_MODULUS = types.PSYMCRYPT_MODULUS;
const PCSYMCRYPT_MODULUS = types.PCSYMCRYPT_MODULUS;
const PSYMCRYPT_MODELEMENT = types.PSYMCRYPT_MODELEMENT;
const PCSYMCRYPT_HASH = types.PCSYMCRYPT_HASH;
const PPCSYMCRYPT_HASH = types.PPCSYMCRYPT_HASH;
const PCSYMCRYPT_TRIALDIVISION_CONTEXT = types.PCSYMCRYPT_TRIALDIVISION_CONTEXT;
const SYMCRYPT_DLGROUP = types.SYMCRYPT_DLGROUP;
const PSYMCRYPT_DLGROUP = types.PSYMCRYPT_DLGROUP;
const PCSYMCRYPT_DLGROUP = types.PCSYMCRYPT_DLGROUP;

extern fn SymCryptCallbackAlloc(nBytes: SIZE_T) callconv(SYMCRYPT_CALL) ?PBYTE;
extern fn SymCryptCallbackFree(pMem: PVOID) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptCallbackRandom(pbBuffer: PBYTE, cbBuffer: SIZE_T) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;
extern fn SymCryptWipe(pbData: PVOID, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptXorBytes(pbSrc1: PCBYTE, pbSrc2: PCBYTE, pbDst: PBYTE, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void;

// Miller-Rabin iterations for prime generation
const DLGROUP_MR_ITERATIONS: UINT32 = 64;

// Default size for Q according to FIPS 186-3
const DsaNBitsOfQCutoffs = struct {
    nBitsOfP: UINT32,
    nBitsOfQ: UINT32,
};

const g_nBitsOfQ_Cutoffs = [_]DsaNBitsOfQCutoffs{
    .{ .nBitsOfP = 1024, .nBitsOfQ = 160 },
    .{ .nBitsOfP = 2048, .nBitsOfQ = 256 },
    .{ .nBitsOfP = std.math.maxInt(UINT32), .nBitsOfQ = 256 },
};

// Const label for the generation of generator G according to FIPS 186-3
const ggen = [_]BYTE{ 'g', 'g', 'e', 'n' };

pub export fn SymCryptDlgroupCalculateBitsizeOfQ(
    nBitsOfP: UINT32,
) callconv(SYMCRYPT_CALL) UINT32 {
    var i: usize = 0;
    while ((i < g_nBitsOfQ_Cutoffs.len - 1) and
        (g_nBitsOfQ_Cutoffs[i].nBitsOfP < nBitsOfP))
    {
        i += 1;
    }

    return g_nBitsOfQ_Cutoffs[i].nBitsOfQ;
}

pub export fn SymCryptDlgroupAllocate(
    nBitsOfP: UINT32,
    nBitsOfQ: UINT32,
) callconv(SYMCRYPT_CALL) ?PSYMCRYPT_DLGROUP {
    // Invalid parameters
    if ((nBitsOfP < types.SYMCRYPT_DLGROUP_MIN_BITSIZE_P) or
        ((nBitsOfQ > 0) and (nBitsOfQ < types.SYMCRYPT_DLGROUP_MIN_BITSIZE_Q)) or
        (nBitsOfP < nBitsOfQ))
    {
        return null;
    }

    const cb: SIZE_T = SymCryptSizeofDlgroupFromBitsizes(nBitsOfP, nBitsOfQ);

    const p = SymCryptCallbackAlloc(cb);
    if (p == null) {
        return null;
    }

    return SymCryptDlgroupCreate(p.?, cb, nBitsOfP, nBitsOfQ);
}

pub export fn SymCryptDlgroupFree(
    pgObj: PSYMCRYPT_DLGROUP,
) callconv(SYMCRYPT_CALL) void {
    macros.SYMCRYPT_CHECK_MAGIC(pgObj);
    SymCryptDlgroupWipe(pgObj);
    SymCryptCallbackFree(@ptrCast(pgObj));
}

pub export fn SymCryptSizeofDlgroupFromBitsizes(
    nBitsOfP: UINT32,
    nBitsOfQ_in: UINT32,
) callconv(SYMCRYPT_CALL) UINT32 {
    var nBitsOfQ = nBitsOfQ_in;

    if (nBitsOfQ == 0) {
        nBitsOfQ = nBitsOfP -| 1; // Default to the maximum possible size for Q
    }

    // Invalid parameters
    if ((nBitsOfP < types.SYMCRYPT_DLGROUP_MIN_BITSIZE_P) or
        (nBitsOfQ < types.SYMCRYPT_DLGROUP_MIN_BITSIZE_Q) or
        (nBitsOfP < nBitsOfQ))
    {
        return 0;
    }

    if (nBitsOfP == nBitsOfQ) {
        nBitsOfQ -= 1;
    }

    // Calculate the (tight) bytesize of the seed
    const cbSeed: UINT32 = (nBitsOfQ + 7) / 8;
    const alignVal: UINT32 = @intCast(types.SYMCRYPT_ASYM_ALIGN_VALUE);

    return @as(UINT32, @sizeOf(SYMCRYPT_DLGROUP)) +
        types.SYMCRYPT_INTERNAL_SIZEOF_MODULUS_FROM_BITS(nBitsOfP) +
        types.SYMCRYPT_INTERNAL_SIZEOF_MODULUS_FROM_BITS(nBitsOfQ) +
        types.SYMCRYPT_INTERNAL_SIZEOF_MODELEMENT_FROM_BITS(nBitsOfP) +
        ((cbSeed + alignVal - 1) / alignVal) * alignVal;
}

pub export fn SymCryptDlgroupCreate(
    pbBuffer_in: PBYTE,
    cbBuffer: SIZE_T,
    nBitsOfP: UINT32,
    nBitsOfQ_in: UINT32,
) callconv(SYMCRYPT_CALL) ?PSYMCRYPT_DLGROUP {
    var pbBuffer = pbBuffer_in;
    var nBitsOfQ = nBitsOfQ_in;

    macros.SYMCRYPT_ASSERT(cbBuffer >= SymCryptSizeofDlgroupFromBitsizes(nBitsOfP, nBitsOfQ));
    macros.SYMCRYPT_ASSERT_ASYM_ALIGNED(pbBuffer);

    // Invalid parameters
    if ((nBitsOfP < types.SYMCRYPT_DLGROUP_MIN_BITSIZE_P) or
        ((nBitsOfQ > 0) and (nBitsOfQ < types.SYMCRYPT_DLGROUP_MIN_BITSIZE_Q)) or
        (nBitsOfP < nBitsOfQ))
    {
        return null;
    }

    if (nBitsOfP == nBitsOfQ) {
        nBitsOfQ -= 1;
    }

    const pDlgroup: PSYMCRYPT_DLGROUP = @ptrCast(@alignCast(pbBuffer));

    macros.SYMCRYPT_ASSERT(cbBuffer > @sizeOf(SYMCRYPT_DLGROUP));

    // DLGROUP parameters
    pDlgroup.cbTotalSize = SymCryptSizeofDlgroupFromBitsizes(nBitsOfP, nBitsOfQ);

    pDlgroup.fHasPrimeQ = 0;

    pDlgroup.nBitsOfP = nBitsOfP;
    pDlgroup.cbPrimeP = (nBitsOfP + 7) / 8;
    pDlgroup.nDigitsOfP = a_dispatch.SymCryptDigitsFromBits(nBitsOfP);
    pDlgroup.nMaxBitsOfP = nBitsOfP;

    pDlgroup.nBitsOfQ = nBitsOfQ; // 0 value possible
    pDlgroup.cbPrimeQ = (nBitsOfQ + 7) / 8; // 0 value possible
    pDlgroup.nDigitsOfQ = if (nBitsOfQ > 0) a_dispatch.SymCryptDigitsFromBits(nBitsOfQ) else 0; // 0 value possible
    pDlgroup.nMaxBitsOfQ = if (nBitsOfQ == 0) (nBitsOfP - 1) else nBitsOfQ;

    pDlgroup.isSafePrimeGroup = 0;
    pDlgroup.nMinBitsPriv = 0;
    pDlgroup.nDefaultBitsPriv = nBitsOfQ; // 0 value possible

    pDlgroup.nBitsOfSeed = nBitsOfQ; // 0 value possible
    pDlgroup.cbSeed = (pDlgroup.nBitsOfSeed + 7) / 8; // 0 value possible

    pDlgroup.eFipsStandard = .SYMCRYPT_DLGROUP_FIPS_NONE; // This will be set either on generate or import
    pDlgroup.pHashAlgorithm = null; // Like-wise
    pDlgroup.dwGenCounter = 0; // Like-wise
    pDlgroup.bIndexGenG = 1; // Default: 1

    // Create SymCrypt objects
    pbBuffer += @sizeOf(SYMCRYPT_DLGROUP);

    const cbModP: UINT32 = a_dispatch.SymCryptSizeofModulusFromDigits(pDlgroup.nDigitsOfP);
    macros.SYMCRYPT_ASSERT(cbBuffer > @sizeOf(SYMCRYPT_DLGROUP) + cbModP);
    pDlgroup.pmP = a_dispatch.SymCryptModulusCreate(pbBuffer, cbModP, pDlgroup.nDigitsOfP).?;
    pbBuffer += cbModP;

    //
    // **** Always defer the creation of the Q modulus until the group generation or
    // import of the modulus. This way it is always the fastest possible even when the caller
    // specified nBitsOfQ = 0.
    //
    const cbModQ: UINT32 = if (nBitsOfQ > 0)
        a_dispatch.SymCryptSizeofModulusFromDigits(pDlgroup.nDigitsOfQ)
    else
        cbModP;

    macros.SYMCRYPT_ASSERT(cbBuffer > @sizeOf(SYMCRYPT_DLGROUP) + cbModP + cbModQ);
    pDlgroup.pbQ = pbBuffer; // Set the aligned buffer
    pDlgroup.pmQ = null;
    pbBuffer += cbModQ;

    const cbModElement: UINT32 = a_dispatch.SymCryptSizeofModElementFromModulus(pDlgroup.pmP);
    macros.SYMCRYPT_ASSERT(cbBuffer > @sizeOf(SYMCRYPT_DLGROUP) + cbModP + cbModQ + cbModElement);
    pDlgroup.peG = a_dispatch.SymCryptModElementCreate(pbBuffer, cbModElement, pDlgroup.pmP).?;
    pbBuffer += cbModElement;

    pDlgroup.pbSeed = pbBuffer;

    // Setting the magic
    pDlgroup.magic = macros.SYMCRYPT_MAGIC_VALUE(pDlgroup);

    return pDlgroup;
}

pub export fn SymCryptDlgroupWipe(
    pgDst: PSYMCRYPT_DLGROUP,
) callconv(SYMCRYPT_CALL) void {
    SymCryptWipe(@ptrCast(pgDst), pgDst.cbTotalSize);
}

pub export fn SymCryptDlgroupCopy(
    pgSrc: PCSYMCRYPT_DLGROUP,
    pgDst: PSYMCRYPT_DLGROUP,
) callconv(SYMCRYPT_CALL) void {
    //
    // in-place copy is somewhat common...
    //
    if (pgSrc != pgDst) {
        pgDst.cbTotalSize = pgSrc.cbTotalSize;
        pgDst.fHasPrimeQ = pgSrc.fHasPrimeQ;

        pgDst.nBitsOfP = pgSrc.nBitsOfP;
        pgDst.cbPrimeP = pgSrc.cbPrimeP;
        pgDst.nDigitsOfP = pgSrc.nDigitsOfP;
        pgDst.nMaxBitsOfP = pgSrc.nMaxBitsOfP;

        pgDst.nBitsOfQ = pgSrc.nBitsOfQ;
        pgDst.cbPrimeQ = pgSrc.cbPrimeQ;
        pgDst.nDigitsOfQ = pgSrc.nDigitsOfQ;
        pgDst.nMaxBitsOfQ = pgSrc.nMaxBitsOfQ;

        pgDst.isSafePrimeGroup = pgSrc.isSafePrimeGroup;
        pgDst.nMinBitsPriv = pgSrc.nMinBitsPriv;
        pgDst.nDefaultBitsPriv = pgSrc.nDefaultBitsPriv;

        pgDst.nBitsOfSeed = pgSrc.nBitsOfSeed;
        pgDst.cbSeed = pgSrc.cbSeed;

        pgDst.eFipsStandard = pgSrc.eFipsStandard;
        pgDst.pHashAlgorithm = pgSrc.pHashAlgorithm;
        pgDst.dwGenCounter = pgSrc.dwGenCounter;
        pgDst.bIndexGenG = pgSrc.bIndexGenG;
        pgDst.pbQ = pgSrc.pbQ;

        const pbDstAfter: PBYTE = @as(PBYTE, @ptrCast(pgDst)) + @sizeOf(SYMCRYPT_DLGROUP);
        const pbSrcAfter: PCBYTE = @as(PCBYTE, @ptrCast(pgSrc)) + @sizeOf(SYMCRYPT_DLGROUP);
        const cbCopy: usize = pgSrc.cbTotalSize - @sizeOf(SYMCRYPT_DLGROUP);
        @memcpy(pbDstAfter[0..cbCopy], pbSrcAfter[0..cbCopy]);
    }
}

// DLGROUP-specific functions

pub export fn SymCryptDlgroupGeneratePrimeQ_FIPS(
    pDlgroup: PSYMCRYPT_DLGROUP,
    pTrialDivisionContext: PCSYMCRYPT_TRIALDIVISION_CONTEXT,
    pfPrimeQFound: *UINT32,
    piQ: PSYMCRYPT_INT,
    pdDivTwoQ: PSYMCRYPT_DIVISOR,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;

    const hashAlgorithm: PCSYMCRYPT_HASH = pDlgroup.pHashAlgorithm.?;
    const nBitsOfQ: UINT32 = pDlgroup.nBitsOfQ;
    const cbPrimeQ: UINT32 = pDlgroup.cbPrimeQ;
    const pbSeed: PBYTE = pDlgroup.pbSeed.?;
    const cbSeed: UINT32 = pDlgroup.cbSeed;

    const piDivTwoQ: PSYMCRYPT_INT = a_dispatch.SymCryptIntFromDivisor(pdDivTwoQ);

    const cbHash: SIZE_T = hash.SymCryptHashResultSize(hashAlgorithm);
    var pbTrHash: PBYTE = undefined; // Pointer to the truncated hash value
    var pbHashExtra: PBYTE = undefined; // Needed as temp buffer for 186-2

    const dwShiftBits: u3 = @intCast((8 - (nBitsOfQ % 8)) % 8); // When nBitsOfQ is a multiple of 8 -> dwShiftBits = 0;

    var carry: UINT32 = 0;

    macros.SYMCRYPT_ASSERT(
        cbScratch >= @max(
            types.SYMCRYPT_SCRATCH_BYTES_FOR_INT_TO_DIVISOR(a_dispatch.SymCryptDigitsFromBits(nBitsOfQ + 1)),
            @max(
                types.SYMCRYPT_SCRATCH_BYTES_FOR_INT_IS_PRIME(pDlgroup.nDigitsOfQ),
                2 * cbHash,
            ),
        ),
    );
    macros.SYMCRYPT_ASSERT(cbHash >= cbPrimeQ);

    // Hash the seed according to the standard specified
    if (pDlgroup.eFipsStandard == .SYMCRYPT_DLGROUP_FIPS_186_2) {
        macros.SYMCRYPT_ASSERT(hashAlgorithm == sha1.SymCryptSha1Algorithm);
        macros.SYMCRYPT_ASSERT(cbScratch >= @max(2 * cbHash, @as(SIZE_T, cbSeed)));

        // Hash buffers
        pbTrHash = pbScratch;
        pbHashExtra = pbTrHash + cbHash;

        // Prepare an int for SEED + 1
        scError = a_dispatch.SymCryptIntSetValue(pbSeed, cbSeed, .SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, piDivTwoQ);
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }

        // Add 1
        carry = a_dispatch.SymCryptIntAddUint32(piDivTwoQ, 1, piDivTwoQ);
        if (carry > 0) {
            // This should never happen as the size of piDivTwoQ is at least one bit bigger than Q
            return .SYMCRYPT_FIPS_FAILURE;
        }

        // (SEED+1) Mod 2^nBitsOfSeed
        a_dispatch.SymCryptIntModPow2(piDivTwoQ, nBitsOfQ, piDivTwoQ);

        // Get the value into pbTrHash (Notice the cbSeed size)
        scError = a_dispatch.SymCryptIntGetValue(piDivTwoQ, pbTrHash, cbSeed, .SYMCRYPT_NUMBER_FORMAT_MSB_FIRST);
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }

        // Hash it into pbHashExtra
        hash.SymCryptHash(hashAlgorithm, pbTrHash, cbPrimeQ, pbHashExtra, cbHash);

        // Hash the seed
        hash.SymCryptHash(hashAlgorithm, pbSeed, cbSeed, pbTrHash, cbHash);

        // Xor the two
        SymCryptXorBytes(pbTrHash, pbHashExtra, pbTrHash, cbHash);
    } else if (pDlgroup.eFipsStandard == .SYMCRYPT_DLGROUP_FIPS_186_3) {
        macros.SYMCRYPT_ASSERT(cbScratch >= cbHash);
        pbTrHash = pbScratch;
        hash.SymCryptHash(hashAlgorithm, pbSeed, cbSeed, pbTrHash, cbHash);
    } else {
        return .SYMCRYPT_FIPS_FAILURE;
    }

    // Convert it to (2^{N-1} + (Hash mod 2^{N-1})) | 1
    pbTrHash += (cbHash - cbPrimeQ); // Skip any leading zero bytes
    pbTrHash[0] &= (@as(BYTE, 0xff) >> dwShiftBits); // Cut off top bits in the most significant byte
    pbTrHash[0] |= (@as(BYTE, 0x01) << (7 - dwShiftBits)); // Set the (N-1)-th bit
    pbTrHash[cbPrimeQ - 1] |= @as(BYTE, 0x01); // Make the entire number odd

    // Set the value
    scError = a_dispatch.SymCryptIntSetValue(pbTrHash, cbPrimeQ, .SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, piQ);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    // Assume not a prime
    pfPrimeQFound.* = 0;

    // Fast compositeness check
    if (a_dispatch.SymCryptIntFindSmallDivisor(pTrialDivisionContext, piQ, null, 0) != 0) {
        return scError;
    }

    // IntMillerRabinPrimalityTest requirement:
    //      piQ > 3 since nBitsOfQ is bounded by SYMCRYPT_DLGROUP_MIN_BITSIZE_Q
    pfPrimeQFound.* = primes.SymCryptIntMillerRabinPrimalityTest(
        piQ,
        nBitsOfQ,
        DLGROUP_MR_ITERATIONS,
        types.SYMCRYPT_FLAG_DATA_PUBLIC, // q and p will be public
        pbScratch,
        cbScratch,
    );

    // Set pdDivTwoQ
    if (pfPrimeQFound.* != 0) {
        scError = a_dispatch.SymCryptIntCopyMixedSize(piQ, piDivTwoQ);
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }

        a_dispatch.SymCryptIntMulPow2(piDivTwoQ, 1, piDivTwoQ);

        // IntToDivisor requirement:
        //      Q is non-zero as prime --> 2*Q != 0
        a_dispatch.SymCryptIntToDivisor(
            piDivTwoQ,
            pdDivTwoQ,
            4 * pDlgroup.nBitsOfP, // 4*L
            types.SYMCRYPT_FLAG_DATA_PUBLIC,
            pbScratch,
            cbScratch,
        );
    }

    return scError;
}

pub export fn SymCryptDlgroupGeneratePrimeP_FIPS(
    pDlgroup: PSYMCRYPT_DLGROUP,
    pdDivTwoQ: PSYMCRYPT_DIVISOR,
    dwMaxCounter: UINT32, // Maximum value of counter (used in validation)
    pTrialDivisionContext: PCSYMCRYPT_TRIALDIVISION_CONTEXT,
    pfPrimePFound: *UINT32,
    piP: PSYMCRYPT_INT,
    pdwCounter: *UINT32,
    pbScratch_in: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var pbScratch = pbScratch_in;
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;

    const hashAlgorithm: PCSYMCRYPT_HASH = pDlgroup.pHashAlgorithm.?;
    const nBitsOfP: UINT32 = pDlgroup.nBitsOfP;
    const pbSeed: PBYTE = pDlgroup.pbSeed.?;
    const cbSeed: UINT32 = pDlgroup.cbSeed;
    const nBitsOfSeed: UINT32 = pDlgroup.nBitsOfSeed;

    const cbHash: SIZE_T = hash.SymCryptHashResultSize(hashAlgorithm);

    var counter: UINT32 = 0;

    const ndDivTwoQ: UINT32 = a_dispatch.SymCryptDivisorDigitsizeOfObject(pdDivTwoQ);
    const cbIntTwoQ: UINT32 = a_dispatch.SymCryptSizeofIntFromDigits(ndDivTwoQ);

    const cbW: UINT32 = pDlgroup.cbPrimeP;
    var carry: UINT32 = 0;

    // We will use internal scratch space at the start of pbScratch
    // because cbHash, cbSeed and cbW are not necessarily aligned according
    // to SYMCRYPT_ASYM_ALIGN_VALUE
    const cbScratchInternal: SIZE_T = @max(
        types.SYMCRYPT_SCRATCH_BYTES_FOR_INT_DIVMOD(pDlgroup.nDigitsOfP, ndDivTwoQ),
        types.SYMCRYPT_SCRATCH_BYTES_FOR_INT_IS_PRIME(pDlgroup.nDigitsOfP),
    );
    macros.SYMCRYPT_ASSERT(
        cbScratch >= 2 * @as(SIZE_T, cbIntTwoQ) + cbHash + cbSeed + cbW + cbScratchInternal,
    );

    const pbScratchInternal: PBYTE = pbScratch;
    pbScratch += cbScratchInternal;

    const piPersistent = a_dispatch.SymCryptIntCreate(pbScratch, cbIntTwoQ, ndDivTwoQ).?;
    pbScratch += cbIntTwoQ;

    const piRemainder = a_dispatch.SymCryptIntCreate(pbScratch, cbIntTwoQ, ndDivTwoQ).?;
    pbScratch += cbIntTwoQ;

    const pbHashOutput: PBYTE = pbScratch;
    pbScratch += cbHash;

    const pbTempSeed: PBYTE = pbScratch;
    pbScratch += cbSeed;

    const pbW: PBYTE = pbScratch;

    // Set the value for the expression "domain_parameter_seed + offset + j"
    scError = a_dispatch.SymCryptIntSetValue(pbSeed, cbSeed, .SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, piPersistent);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    // If the standard is 186-2 add 1 since the starting offset is 2
    if (pDlgroup.eFipsStandard == .SYMCRYPT_DLGROUP_FIPS_186_2) {
        carry = a_dispatch.SymCryptIntAddUint32(piPersistent, 1, piPersistent);
        if (carry != 0) {
            // This should never happen as piPersistent has at least one more bit than
            // seedLen == nBitsOfQ
            return .SYMCRYPT_FIPS_FAILURE;
        }

        // Mod 2^seedlen
        a_dispatch.SymCryptIntModPow2(piPersistent, nBitsOfSeed, piPersistent);
    }

    pfPrimePFound.* = 0;

    counter = 0;
    while (counter < dwMaxCounter + 1) : (counter += 1) {
        var cbWBytesLeft: SIZE_T = cbW; // Bytes left to write
        var pbWCurr: PBYTE = pbW + cbW - @min(@as(SIZE_T, cbW), cbHash); // Position of the first hash chunk to write (if cbW < cbHash then we write only 1 chunk)

        while (cbWBytesLeft > 0) {
            // Add 1 to piPersistent
            // This can never generate a carry as piPersistent has at least one more bit than
            // seedLen == nBitsOfQ and in the next step we always do mod 2^seedlen.
            carry = a_dispatch.SymCryptIntAddUint32(piPersistent, 1, piPersistent);
            if (carry != 0) {
                return .SYMCRYPT_FIPS_FAILURE;
            }

            // Mod 2^seedlen
            a_dispatch.SymCryptIntModPow2(piPersistent, nBitsOfSeed, piPersistent);

            // Extract piPersistent into a byte array (this will always be equal to domain_parameter_seed + offset + j)
            scError = a_dispatch.SymCryptIntGetValue(piPersistent, pbTempSeed, cbSeed, .SYMCRYPT_NUMBER_FORMAT_MSB_FIRST);
            if (scError != .SYMCRYPT_NO_ERROR) {
                return scError;
            }

            // Hash it
            hash.SymCryptHash(hashAlgorithm, pbTempSeed, cbSeed, pbHashOutput, cbHash);

            if (cbWBytesLeft >= cbHash) {
                // Move the entire hash output to the correct location in the pbW buffer
                @memcpy(pbWCurr[0..cbHash], pbHashOutput[0..cbHash]);
            } else {
                // Move only the last bytes of the hash output
                @memcpy(pbWCurr[0..cbWBytesLeft], (pbHashOutput + cbHash - cbWBytesLeft)[0..cbWBytesLeft]);
            }

            // Update the positions on the W buffer
            cbWBytesLeft -= @min(cbHash, cbWBytesLeft);
            pbWCurr -= @min(cbHash, cbWBytesLeft);
        }

        // Import the W buffer into P
        scError = a_dispatch.SymCryptIntSetValue(pbW, cbW, .SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, piP);
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }

        // Zero-out the top bits of the integer
        a_dispatch.SymCryptIntModPow2(piP, nBitsOfP, piP);

        // Set the most significant bit
        a_dispatch.SymCryptIntSetBits(piP, 1, nBitsOfP - 1, 1);

        // At this point piP = X = W + 2^{L-1}

        // Calculate c = X mod 2Q
        a_dispatch.SymCryptIntDivMod(piP, pdDivTwoQ, null, piRemainder, pbScratchInternal, cbScratchInternal);

        if (a_dispatch.SymCryptIntIsEqualUint32(piRemainder, 0) != 0) {
            // Just add one to X
            // We can never get a carry here because the remainder X mod 2Q
            // is 0. Therefore X is even.
            carry = a_dispatch.SymCryptIntAddUint32(piP, 1, piP);
            macros.SYMCRYPT_ASSERT(carry == 0);
        } else {
            // Subtract 1 from c
            // We can never get a borrow here because the remainder is not 0.
            carry = a_dispatch.SymCryptIntSubUint32(piRemainder, 1, piRemainder);
            macros.SYMCRYPT_ASSERT(carry == 0);

            // X-(c-1)
            // We can never get a borrow here because c is smaller
            // or equal to X.
            carry = a_dispatch.SymCryptIntSubMixedSize(piP, piRemainder, piP);
            macros.SYMCRYPT_ASSERT(carry == 0);
        }

        // Check if smaller than 2^{L-1} by checking the L-1 bit
        if (a_dispatch.SymCryptIntGetBit(piP, nBitsOfP - 1) == 0) {
            continue;
        }

        // Fast compositeness check
        if (a_dispatch.SymCryptIntFindSmallDivisor(pTrialDivisionContext, piP, null, 0) != 0) {
            continue;
        }

        // IntMillerRabinPrimalityTest requirement:
        //      piP > 3 since nBitsOfP is bounded by SYMCRYPT_DLGROUP_MIN_BITSIZE_P
        pfPrimePFound.* = primes.SymCryptIntMillerRabinPrimalityTest(
            piP,
            nBitsOfP,
            DLGROUP_MR_ITERATIONS,
            types.SYMCRYPT_FLAG_DATA_PUBLIC, // q and p will be public
            pbScratchInternal,
            cbScratchInternal,
        );

        if (pfPrimePFound.* != 0) {
            pdwCounter.* = counter;
            break;
        }
    }

    return scError;
}

pub export fn SymCryptDlgroupGenerateGenG_FIPS(
    pDlgroup: PSYMCRYPT_DLGROUP,
    peG: PSYMCRYPT_MODELEMENT,
    pbScratch_in: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var pbScratch = pbScratch_in;
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;

    const hashAlgorithm: PCSYMCRYPT_HASH = pDlgroup.pHashAlgorithm.?;
    const pmP: PCSYMCRYPT_MODULUS = pDlgroup.pmP;
    const nDigitsOfP: UINT32 = pDlgroup.nDigitsOfP;
    const nBitsOfP: UINT32 = pDlgroup.nBitsOfP;
    const pmQ: PCSYMCRYPT_MODULUS = pDlgroup.pmQ.?;
    const nDigitsOfQ: UINT32 = pDlgroup.nDigitsOfQ;
    const pbSeed: PBYTE = pDlgroup.pbSeed.?;
    const cbSeed: UINT32 = pDlgroup.cbSeed;
    var bIndexGenG: BYTE = pDlgroup.bIndexGenG;

    const cbHash: SIZE_T = hash.SymCryptHashResultSize(hashAlgorithm);
    macros.SYMCRYPT_ASSERT(cbHash == hashAlgorithm.resultSize);
    const cbState: SIZE_T = hash.SymCryptHashStateSize(hashAlgorithm);
    macros.SYMCRYPT_ASSERT(cbState == hashAlgorithm.stateSize);

    var count: UINT16 = 0;
    var bTmp: BYTE = 0;

    const cbExp: UINT32 = a_dispatch.SymCryptSizeofIntFromDigits(nDigitsOfP);
    const cbRem: UINT32 = a_dispatch.SymCryptSizeofIntFromDigits(nDigitsOfQ);
    const cbModElement: UINT32 = a_dispatch.SymCryptSizeofModElementFromModulus(pmP);

    // We will use internal scratch space at the start of pbScratch
    // because cbHash is not necessarily aligned according
    // to SYMCRYPT_ASYM_ALIGN_VALUE
    const pbScratchInternal: PBYTE = pbScratch;
    const cbScratchInternal: SIZE_T = @max(
        types.SYMCRYPT_SCRATCH_BYTES_FOR_MODEXP(nDigitsOfP),
        @max(
            types.SYMCRYPT_SCRATCH_BYTES_FOR_INT_DIVMOD(nDigitsOfP, nDigitsOfQ),
            types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(nDigitsOfP),
        ),
    );
    macros.SYMCRYPT_ASSERT(cbScratch >= cbScratchInternal + cbExp + cbRem);
    macros.SYMCRYPT_ASSERT(cbScratch >= cbScratchInternal + cbExp + cbModElement + cbHash + cbState);
    pbScratch += cbScratchInternal;

    const piExp = a_dispatch.SymCryptIntCreate(pbScratch, cbExp, nDigitsOfP).?;
    pbScratch += cbExp;

    const piRem = a_dispatch.SymCryptIntCreate(pbScratch, cbRem, nDigitsOfQ).?;

    // Calculate the exponent e = (p-1)/q
    const borrow: UINT32 = a_dispatch.SymCryptIntSubUint32(
        a_dispatch.SymCryptIntFromModulus(@constCast(pmP)),
        1,
        piExp,
    );
    if (borrow != 0) {
        // The only way to get a borrow here is if the imported prime P
        // is zero and we generate a G from P and Q.
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    a_dispatch.SymCryptIntDivMod(
        piExp,
        a_dispatch.SymCryptDivisorFromModulus(@constCast(pmQ)),
        piExp,
        piRem,
        pbScratchInternal,
        cbScratchInternal,
    );

    if (a_dispatch.SymCryptIntIsEqualUint32(piRem, 0) == 0) {
        // The only way to get a non-zero remainder is if Q does not divide P-1
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    // To reach here we have guaranteed that P and Q are odd, with bitlength >= 32b, and Q divides P-1.
    // It follows that piExp >= 2, as it must be even and non-zero.

    const peOne = a_dispatch.SymCryptModElementCreate(pbScratch, cbModElement, pmP).?;
    pbScratch += cbModElement;

    const pbState: PBYTE = pbScratch;
    pbScratch += cbState;

    const pbW: PBYTE = pbScratch;

    // Initialize the hash state
    hash.SymCryptHashInit(hashAlgorithm, pbState);

    // Set the modelement equal to one
    a_dispatch.SymCryptModElementSetValueUint32(1, pmP, peOne, pbScratchInternal, cbScratchInternal);

    while (true) {
        count +%= 1;

        if (count == 0) {
            return .SYMCRYPT_FIPS_FAILURE;
        }

        // Hash the seed
        hash.SymCryptHashAppend(hashAlgorithm, pbState, pbSeed, cbSeed);

        // Hash the "ggen" string
        hash.SymCryptHashAppend(hashAlgorithm, pbState, ggen[0..].ptr, ggen.len);

        // Hash the index
        hash.SymCryptHashAppend(hashAlgorithm, pbState, @ptrCast(&bIndexGenG), @sizeOf(BYTE));

        // Hash the count (in MSB)
        bTmp = @truncate(count >> 8);
        hash.SymCryptHashAppend(hashAlgorithm, pbState, @ptrCast(&bTmp), @sizeOf(BYTE));
        bTmp = @truncate(count);
        hash.SymCryptHashAppend(hashAlgorithm, pbState, @ptrCast(&bTmp), @sizeOf(BYTE));

        // Result into W
        hash.SymCryptHashResult(hashAlgorithm, pbState, pbW, cbHash);

        // Set this into G
        scError = a_dispatch.SymCryptModElementSetValue(
            pbW,
            cbHash,
            .SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            pmP,
            peG,
            pbScratchInternal,
            cbScratchInternal,
        );
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }

        // ModExp G in place
        a_dispatch.SymCryptModExp(
            pmP,
            peG,
            piExp,
            nBitsOfP,
            types.SYMCRYPT_FLAG_DATA_PUBLIC,
            peG,
            pbScratchInternal,
            cbScratchInternal,
        );

        if ((a_dispatch.SymCryptModElementIsZero(pmP, peG) == 0) and
            (a_dispatch.SymCryptModElementIsEqual(pmP, peG, peOne) == 0))
        {
            break;
        }
    }

    return scError;
}

// Scratch space requirements for the entire FIPS standards generation of P,Q,G
pub export fn SymCryptDlgroupScratchSpace_FIPS(
    nBitsOfP: UINT32,
    nBitsOfQ: UINT32,
    pHashAlgorithm: PCSYMCRYPT_HASH,
) callconv(SYMCRYPT_CALL) UINT32 {
    const nDigitsOfP: UINT32 = a_dispatch.SymCryptDigitsFromBits(nBitsOfP);
    const nDigitsOfQ: UINT32 = a_dispatch.SymCryptDigitsFromBits(nBitsOfQ);
    const ndDivTwoQ: UINT32 = a_dispatch.SymCryptDigitsFromBits(nBitsOfQ + 1);

    const cbPrimeP: UINT32 = (nBitsOfP + 7) / 8; // Note: The upper bound for nBitsOfP is enforced by SymCryptDigitsFromBits
    const cbDivTwoQ: UINT32 = a_dispatch.SymCryptSizeofDivisorFromDigits(ndDivTwoQ);
    const cbIntTwoQ: UINT32 = a_dispatch.SymCryptSizeofIntFromDigits(ndDivTwoQ);
    const cbSeed: UINT32 = (nBitsOfQ + 7) / 8; // Note: The upper bound for nBitsOfP is enforced by SymCryptDigitsFromBits

    const cbExp: UINT32 = a_dispatch.SymCryptSizeofIntFromDigits(nDigitsOfP);
    const cbRem: UINT32 = a_dispatch.SymCryptSizeofIntFromDigits(nDigitsOfQ);
    const cbModElement: UINT32 = types.SYMCRYPT_INTERNAL_SIZEOF_MODELEMENT_FROM_BITS(nBitsOfP);

    const cbHash: UINT32 = @intCast(hash.SymCryptHashResultSize(pHashAlgorithm));
    const cbState: UINT32 = @intCast(hash.SymCryptHashStateSize(pHashAlgorithm));

    //
    // From symcrypt_internal.h we have:
    //      - sizeof results are upper bounded by 2^19
    //      - SYMCRYPT_SCRATCH_BYTES results are upper bounded by 2^27 (including RSA and ECURVE)
    // Thus the following calculation does not overflow the result and is bounded by 2^28.
    //
    return @max(
        cbDivTwoQ + @max(
            // Generate Q
            @max(
                types.SYMCRYPT_SCRATCH_BYTES_FOR_INT_TO_DIVISOR(ndDivTwoQ),
                @max(
                    types.SYMCRYPT_SCRATCH_BYTES_FOR_INT_IS_PRIME(nDigitsOfQ),
                    2 * cbHash,
                ),
            ),
            // Generate P
            2 * cbIntTwoQ + cbHash + cbSeed + cbPrimeP +
                @max(
                    types.SYMCRYPT_SCRATCH_BYTES_FOR_INT_DIVMOD(nDigitsOfP, ndDivTwoQ),
                    types.SYMCRYPT_SCRATCH_BYTES_FOR_INT_IS_PRIME(nDigitsOfP),
                ),
        ),
        @max(
            // Convert P and Q to moduli
            types.SYMCRYPT_SCRATCH_BYTES_FOR_INT_TO_MODULUS(nDigitsOfP),
            // Generate GenG
            cbExp + @max(cbRem, cbModElement + cbState + cbHash) +
                @max(
                    types.SYMCRYPT_SCRATCH_BYTES_FOR_MODEXP(nDigitsOfP),
                    @max(
                        types.SYMCRYPT_SCRATCH_BYTES_FOR_INT_DIVMOD(nDigitsOfP, nDigitsOfQ),
                        types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(nDigitsOfP),
                    ),
                ),
        ),
    );
}

pub export fn SymCryptDlgroupGenerate(
    hashAlgorithm_in: ?PCSYMCRYPT_HASH,
    fipsStandard_in: SYMCRYPT_DLGROUP_FIPS,
    pDlgroup: PSYMCRYPT_DLGROUP,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var hashAlgorithm = hashAlgorithm_in;
    var fipsStandard = fipsStandard_in;
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;

    var pbScratch: ?PBYTE = null;
    var cbScratch: SIZE_T = 0;

    var fPrimeQFound: UINT32 = 0;
    var fPrimePFound: UINT32 = 0;

    var pTrialDivisionContext: ?PCSYMCRYPT_TRIALDIVISION_CONTEXT = null;

    defer {
        if (pTrialDivisionContext) |ctx| {
            a_dispatch.SymCryptFreeTrialDivisionContext(ctx);
        }
        if (pbScratch) |ptr| {
            SymCryptWipe(@ptrCast(ptr), cbScratch);
            SymCryptCallbackFree(@ptrCast(ptr));
        }
    }

    if (fipsStandard == .SYMCRYPT_DLGROUP_FIPS_NONE) {
        fipsStandard = .SYMCRYPT_DLGROUP_FIPS_186_3;
    }

    // Numbered comments refer to the steps in the FIPS standard
    // 1. Check that L,N is in the list of acceptable pairs
    //      => Skipped as SymCrypt supports more sizes

    // 2. Check that seedlen >= N
    //      => Skipped as we always have seedlen == N (see below)

    // Make sure that a hash algorithm is passed (if needed)
    // and set the FIPS standard
    if (fipsStandard == .SYMCRYPT_DLGROUP_FIPS_186_2) {
        if (hashAlgorithm != null) {
            return .SYMCRYPT_INVALID_ARGUMENT;
        }

        pDlgroup.eFipsStandard = fipsStandard;
        hashAlgorithm = sha1.SymCryptSha1Algorithm;
    } else {
        if (hashAlgorithm == null) {
            return .SYMCRYPT_INVALID_ARGUMENT;
        }

        pDlgroup.eFipsStandard = fipsStandard;
    }

    // If during allocation the caller didn't know the size of Q
    // and set it to 0, pick the default bitsize here
    // and fix all the zero parameters.
    if (pDlgroup.nBitsOfQ == 0) {
        pDlgroup.nBitsOfQ = SymCryptDlgroupCalculateBitsizeOfQ(pDlgroup.nBitsOfP);

        if (pDlgroup.nBitsOfQ > pDlgroup.nMaxBitsOfQ) {
            return .SYMCRYPT_FIPS_FAILURE; // This hits when nMaxBitsOfQ = (nBitsOfP-1) <= 160
        }

        pDlgroup.cbPrimeQ = (pDlgroup.nBitsOfQ + 7) / 8;
        pDlgroup.nDigitsOfQ = a_dispatch.SymCryptDigitsFromBits(pDlgroup.nBitsOfQ);
        pDlgroup.nDefaultBitsPriv = pDlgroup.nBitsOfQ;
        pDlgroup.nBitsOfSeed = pDlgroup.nBitsOfQ;
        pDlgroup.cbSeed = (pDlgroup.nBitsOfSeed + 7) / 8;
    }

    // Helper variables
    const nBitsOfP: UINT32 = pDlgroup.nBitsOfP;
    const nBitsOfQ: UINT32 = pDlgroup.nBitsOfQ;
    const nDigitsOfQ: UINT32 = pDlgroup.nDigitsOfQ;

    // Create the modulus Q
    pDlgroup.pmQ = a_dispatch.SymCryptModulusCreate(
        pDlgroup.pbQ,
        a_dispatch.SymCryptSizeofModulusFromDigits(nDigitsOfQ),
        nDigitsOfQ,
    );

    // Conditions on the hash function output size
    // The second condition is needed for generation of G in SymCrypt
    // since it allows even very small sizes of P.
    const cbHashResultBits: UINT32 = 8 * @as(UINT32, @intCast(hash.SymCryptHashResultSize(hashAlgorithm.?)));
    if ((cbHashResultBits < nBitsOfQ) or (cbHashResultBits > nBitsOfP)) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    // Set the group's hash algorithm
    pDlgroup.pHashAlgorithm = hashAlgorithm;

    // Calculate sizes for the 2*Q divisor
    const ndDivTwoQ: UINT32 = a_dispatch.SymCryptDigitsFromBits(nBitsOfQ + 1);
    const cbDivTwoQ: UINT32 = a_dispatch.SymCryptSizeofDivisorFromDigits(ndDivTwoQ);

    // Scratch space
    cbScratch = SymCryptDlgroupScratchSpace_FIPS(nBitsOfP, nBitsOfQ, hashAlgorithm.?);
    pbScratch = SymCryptCallbackAlloc(cbScratch);
    if (pbScratch == null) {
        return .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
    }

    // Create a divisor 2*Q (needed for the generation of P)
    const pdDivTwoQ = a_dispatch.SymCryptDivisorCreate(pbScratch.?, cbDivTwoQ, ndDivTwoQ).?;
    const pbScratchInternal: PBYTE = pbScratch.? + cbDivTwoQ;
    const cbScratchInternal: SIZE_T = cbScratch - cbDivTwoQ;

    // Create a trial division context for both P and Q
    pTrialDivisionContext = a_dispatch.SymCryptCreateTrialDivisionContext(pDlgroup.nDigitsOfP);
    if (pTrialDivisionContext == null) {
        return .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
    }

    while (true) {
        while (true) {
            // Fill the seed buffer in the DLGroup with seedlen bits
            scError = SymCryptCallbackRandom(pDlgroup.pbSeed.?, pDlgroup.cbSeed);
            if (scError != .SYMCRYPT_NO_ERROR) {
                return scError;
            }

            // Zero-out the top bits if needed
            if ((pDlgroup.nBitsOfSeed % 8) != 0) {
                const shift: u3 = @intCast(8 - (pDlgroup.nBitsOfSeed % 8));
                pDlgroup.pbSeed.?[0] &= (@as(BYTE, 0xff) >> shift);
            }

            scError = SymCryptDlgroupGeneratePrimeQ_FIPS(
                pDlgroup,
                pTrialDivisionContext.?,
                &fPrimeQFound,
                a_dispatch.SymCryptIntFromModulus(pDlgroup.pmQ.?),
                pdDivTwoQ,
                pbScratchInternal,
                cbScratchInternal,
            );
            if (scError != .SYMCRYPT_NO_ERROR) {
                return scError;
            }

            if (fPrimeQFound != 0) {
                break;
            }
        }

        scError = SymCryptDlgroupGeneratePrimeP_FIPS(
            pDlgroup,
            pdDivTwoQ,
            4 * nBitsOfP - 1,
            pTrialDivisionContext.?,
            &fPrimePFound,
            a_dispatch.SymCryptIntFromModulus(pDlgroup.pmP),
            &pDlgroup.dwGenCounter,
            pbScratchInternal,
            cbScratchInternal,
        );
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }

        if (fPrimePFound != 0) {
            break;
        }
    }

    // Specify that we have a Q
    pDlgroup.fHasPrimeQ = 1;

    // Convert both of P and Q to moduli
    // IntToModulus requirement:
    //      Both P,Q > 0 since they are primes
    a_dispatch.SymCryptIntToModulus(
        a_dispatch.SymCryptIntFromModulus(pDlgroup.pmP),
        pDlgroup.pmP,
        1000 * nBitsOfP, // Average operations
        types.SYMCRYPT_FLAG_DATA_PUBLIC | types.SYMCRYPT_FLAG_MODULUS_PRIME,
        pbScratch.?,
        cbScratch,
    );

    a_dispatch.SymCryptIntToModulus(
        a_dispatch.SymCryptIntFromModulus(pDlgroup.pmQ.?),
        pDlgroup.pmQ.?,
        1000 * nBitsOfP, // Average operations
        types.SYMCRYPT_FLAG_DATA_PUBLIC | types.SYMCRYPT_FLAG_MODULUS_PRIME,
        pbScratch.?,
        cbScratch,
    );

    // Generate G
    scError = SymCryptDlgroupGenerateGenG_FIPS(pDlgroup, pDlgroup.peG, pbScratch.?, cbScratch);
    return scError;
}

pub export fn SymCryptDlgroupSetValueSafePrime(
    dhSafePrimeType: SYMCRYPT_DLGROUP_DH_SAFEPRIMETYPE,
    pDlgroup: PSYMCRYPT_DLGROUP,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;

    var pbScratch: ?PBYTE = null;
    var cbScratch: SIZE_T = 0;

    var safePrimeParams: ?PCSYMCRYPT_DLGROUP_DH_SAFEPRIME_PARAMS = null;

    // Given we know nBitsOfP = nBitsOfQ+1 for all safe-prime groups, this specifies a tight bound when selecting a group
    const nMaxBitsOfP: UINT32 = @min(pDlgroup.nMaxBitsOfP, pDlgroup.nMaxBitsOfQ + 1);

    defer {
        if (pbScratch) |ptr| {
            SymCryptWipe(@ptrCast(ptr), cbScratch);
            SymCryptCallbackFree(@ptrCast(ptr));
        }
    }

    if (dhSafePrimeType == .SYMCRYPT_DLGROUP_DH_SAFEPRIMETYPE_NONE) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    // Iterate through all named safe-prime groups until we find one which fits the requested parameters
    // Relies on the fact the SymCryptNamedSafePrimeGroups is ordered from largest to smallest
    for (0..types.SYMCRYPT_DH_SAFEPRIME_GROUP_COUNT) |i| {
        if (dl_internal_groups.SymCryptNamedSafePrimeGroups[i].eDhSafePrimeType == dhSafePrimeType and
            dl_internal_groups.SymCryptNamedSafePrimeGroups[i].nBitsOfP <= nMaxBitsOfP)
        {
            safePrimeParams = dl_internal_groups.SymCryptNamedSafePrimeGroups[i];
            break;
        }
    }

    if (safePrimeParams == null) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    const params = safePrimeParams.?;
    const nMaxDigitsOfP: UINT32 = a_dispatch.SymCryptDigitsFromBits(params.nBitsOfP);

    cbScratch = @max(
        types.SYMCRYPT_SCRATCH_BYTES_FOR_INT_TO_MODULUS(nMaxDigitsOfP),
        types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(nMaxDigitsOfP),
    );
    pbScratch = SymCryptCallbackAlloc(cbScratch);
    if (pbScratch == null) {
        return .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
    }

    // Set fields marking the Dlgroup as being a named safe-prime group
    pDlgroup.isSafePrimeGroup = 1;
    pDlgroup.eFipsStandard = .SYMCRYPT_DLGROUP_FIPS_NONE;
    pDlgroup.nMinBitsPriv = params.nMinBitsPriv;
    pDlgroup.nDefaultBitsPriv = params.nDefaultBitsPriv;

    // Ensure that fields which don't apply to named safe-prime groups are cleared
    pDlgroup.pHashAlgorithm = null;
    pDlgroup.dwGenCounter = 0;

    pDlgroup.nBitsOfSeed = 0;
    pDlgroup.pbSeed = null;
    pDlgroup.cbSeed = 0;

    // Set the bitsize and bytesize of P
    pDlgroup.nBitsOfP = params.nBitsOfP;
    pDlgroup.cbPrimeP = (params.nBitsOfP + 7) / 8;
    pDlgroup.nDigitsOfP = a_dispatch.SymCryptDigitsFromBits(params.nBitsOfP);

    // Set the bitsize and bytesize of Q
    const nBitsOfQ: UINT32 = pDlgroup.nBitsOfP - 1;
    pDlgroup.nBitsOfQ = nBitsOfQ;
    pDlgroup.cbPrimeQ = (nBitsOfQ + 7) / 8;
    pDlgroup.nDigitsOfQ = a_dispatch.SymCryptDigitsFromBits(nBitsOfQ);
    pDlgroup.fHasPrimeQ = 1;

    //
    // Prime P
    //

    // Recreate the modulus P
    pDlgroup.pmP = a_dispatch.SymCryptModulusCreate(
        @ptrCast(pDlgroup.pmP),
        a_dispatch.SymCryptSizeofModulusFromDigits(pDlgroup.nDigitsOfP),
        pDlgroup.nDigitsOfP,
    ).?;

    scError = a_dispatch.SymCryptIntSetValue(
        params.pcbPrimeP,
        pDlgroup.cbPrimeP,
        .SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        a_dispatch.SymCryptIntFromModulus(pDlgroup.pmP),
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    a_dispatch.SymCryptIntToModulus(
        a_dispatch.SymCryptIntFromModulus(pDlgroup.pmP),
        pDlgroup.pmP,
        1000 * pDlgroup.nBitsOfP, // Average operations
        types.SYMCRYPT_FLAG_DATA_PUBLIC | types.SYMCRYPT_FLAG_MODULUS_PRIME,
        pbScratch.?,
        cbScratch,
    );

    //
    // Prime Q
    //

    // Create the modulus Q
    pDlgroup.pmQ = a_dispatch.SymCryptModulusCreate(
        pDlgroup.pbQ,
        a_dispatch.SymCryptSizeofModulusFromDigits(pDlgroup.nDigitsOfQ),
        pDlgroup.nDigitsOfQ,
    );

    // Q = floor( P / 2 )
    a_dispatch.SymCryptIntShr1(
        0,
        a_dispatch.SymCryptIntFromModulus(pDlgroup.pmP),
        a_dispatch.SymCryptIntFromModulus(pDlgroup.pmQ.?),
    );

    a_dispatch.SymCryptIntToModulus(
        a_dispatch.SymCryptIntFromModulus(pDlgroup.pmQ.?),
        pDlgroup.pmQ.?,
        1000 * nBitsOfQ, // Average operations
        types.SYMCRYPT_FLAG_DATA_PUBLIC | types.SYMCRYPT_FLAG_MODULUS_PRIME,
        pbScratch.?,
        cbScratch,
    );

    //
    // Generator G
    //

    // G to 2
    a_dispatch.SymCryptModElementSetValueUint32(2, pDlgroup.pmP, pDlgroup.peG, pbScratch.?, cbScratch);

    return scError;
}

pub export fn SymCryptDlgroupIsSame(
    pDlgroup1: PCSYMCRYPT_DLGROUP,
    pDlgroup2: PCSYMCRYPT_DLGROUP,
) callconv(SYMCRYPT_CALL) BOOLEAN {
    if (pDlgroup1 == pDlgroup2) {
        return 1;
    }

    if ((pDlgroup1.nBitsOfP != pDlgroup2.nBitsOfP) or
        (pDlgroup1.nDigitsOfP != pDlgroup2.nDigitsOfP) or
        (a_dispatch.SymCryptIntIsEqual(
            a_dispatch.SymCryptIntFromModulus(pDlgroup1.pmP),
            a_dispatch.SymCryptIntFromModulus(pDlgroup2.pmP),
        ) == 0) or
        (a_dispatch.SymCryptModElementIsEqual(
            pDlgroup1.pmP,
            pDlgroup1.peG,
            pDlgroup2.peG,
        ) == 0))
    {
        return 0;
    }

    return 1;
}

pub export fn SymCryptDlgroupGetSizes(
    pDlgroup: PCSYMCRYPT_DLGROUP,
    pcbPrimeP: ?PSIZE_T,
    pcbPrimeQ: ?PSIZE_T,
    pcbGenG: ?PSIZE_T,
    pcbSeed: ?PSIZE_T,
) callconv(SYMCRYPT_CALL) void {
    if (pcbPrimeP) |p| {
        p.* = pDlgroup.cbPrimeP;
    }

    if (pcbPrimeQ) |p| {
        p.* = pDlgroup.cbPrimeQ; // This returns 0 if the group does not have a prime Q
    }

    if (pcbGenG) |p| {
        p.* = pDlgroup.cbPrimeP;
    }

    if (pcbSeed) |p| {
        p.* = pDlgroup.cbSeed; // This returns 0 if the group does not have a prime Q
    }
}

pub export fn SymCryptDlgroupAutoCompleteNamedSafePrimeGroup(
    pDlgroup: PSYMCRYPT_DLGROUP,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;
    var safePrimeParams: ?PCSYMCRYPT_DLGROUP_DH_SAFEPRIME_PARAMS = null;

    // Check whether bottom 64b of P all 1 - as first cheap check
    if (a_dispatch.SymCryptIntGetValueLsbits64(a_dispatch.SymCryptIntFromModulus(pDlgroup.pmP)) != std.math.maxInt(UINT64)) {
        return scError; // Not a named safe-prime group
    }

    const cbTemp: UINT32 = a_dispatch.SymCryptSizeofIntFromDigits(pDlgroup.nDigitsOfP);
    macros.SYMCRYPT_ASSERT(cbScratch >= cbTemp);

    // Create an integer piTemp
    const piTemp = a_dispatch.SymCryptIntCreate(pbScratch, cbTemp, pDlgroup.nDigitsOfP).?;
    const pbScratchInternal: PBYTE = pbScratch + cbTemp;
    const cbScratchInternal: SIZE_T = cbScratch - cbTemp;

    // Set piTemp to the generator G
    a_dispatch.SymCryptModElementToInt(pDlgroup.pmP, pDlgroup.peG, piTemp, pbScratchInternal, cbScratchInternal);

    // Generator must be 2 mod P
    if (a_dispatch.SymCryptIntIsEqualUint32(piTemp, 2) == 0) {
        return scError; // Not a named safe-prime group
    }

    // Iterate through all named safe-prime groups and check whether any of them have matching Prime P
    for (0..types.SYMCRYPT_DH_SAFEPRIME_GROUP_COUNT) |i| {
        if (dl_internal_groups.SymCryptNamedSafePrimeGroups[i].nBitsOfP == pDlgroup.nBitsOfP) {
            _ = a_dispatch.SymCryptIntSetValue(
                dl_internal_groups.SymCryptNamedSafePrimeGroups[i].pcbPrimeP,
                pDlgroup.cbPrimeP,
                .SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                piTemp,
            );

            if (a_dispatch.SymCryptIntIsEqual(piTemp, a_dispatch.SymCryptIntFromModulus(pDlgroup.pmP)) != 0) {
                safePrimeParams = dl_internal_groups.SymCryptNamedSafePrimeGroups[i];
                break;
            }
        }
    }

    // If we found a match in the previous loop, auto-populate appropriate fields in pDlGroup
    if (safePrimeParams) |params| {
        if (pDlgroup.eFipsStandard == .SYMCRYPT_DLGROUP_FIPS_186_2 or
            pDlgroup.eFipsStandard == .SYMCRYPT_DLGROUP_FIPS_186_3)
        {
            // Inappropriate use of named safe-prime groups
            return .SYMCRYPT_INVALID_ARGUMENT;
        }

        // Set fields marking the Dlgroup as being a named safe-prime group
        pDlgroup.isSafePrimeGroup = 1;
        pDlgroup.eFipsStandard = .SYMCRYPT_DLGROUP_FIPS_NONE;
        pDlgroup.nMinBitsPriv = params.nMinBitsPriv;
        pDlgroup.nDefaultBitsPriv = params.nDefaultBitsPriv;

        // Ensure that fields which don't apply to named safe-prime groups are cleared
        pDlgroup.pHashAlgorithm = null;
        pDlgroup.dwGenCounter = 0;

        pDlgroup.nBitsOfSeed = 0;
        pDlgroup.pbSeed = null;
        pDlgroup.cbSeed = 0;

        // Set the bitsize and bytesize of Q
        const nBitsOfQ: UINT32 = pDlgroup.nBitsOfP - 1;
        pDlgroup.nBitsOfQ = nBitsOfQ;
        pDlgroup.cbPrimeQ = (nBitsOfQ + 7) / 8;
        pDlgroup.nDigitsOfQ = a_dispatch.SymCryptDigitsFromBits(nBitsOfQ);

        // Create the modulus Q
        pDlgroup.pmQ = a_dispatch.SymCryptModulusCreate(
            pDlgroup.pbQ,
            a_dispatch.SymCryptSizeofModulusFromDigits(pDlgroup.nDigitsOfQ),
            pDlgroup.nDigitsOfQ,
        );

        // piTemp still has the value of P, and Q = floor( P / 2 )
        a_dispatch.SymCryptIntShr1(0, piTemp, piTemp);

        // Set the prime Q
        scError = a_dispatch.SymCryptIntCopyMixedSize(piTemp, a_dispatch.SymCryptIntFromModulus(pDlgroup.pmQ.?));
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }

        a_dispatch.SymCryptIntToModulus(
            a_dispatch.SymCryptIntFromModulus(pDlgroup.pmQ.?),
            pDlgroup.pmQ.?,
            1000 * nBitsOfQ, // Average operations
            types.SYMCRYPT_FLAG_DATA_PUBLIC | types.SYMCRYPT_FLAG_MODULUS_PRIME,
            pbScratch,
            cbScratch,
        );

        pDlgroup.fHasPrimeQ = 1;
    }

    return scError;
}

pub export fn SymCryptDlgroupSetValue(
    pbPrimeP: ?PCBYTE,
    cbPrimeP: SIZE_T,
    pbPrimeQ: ?PCBYTE,
    cbPrimeQ: SIZE_T,
    pbGenG: ?PCBYTE,
    cbGenG: SIZE_T,
    numFormat: SYMCRYPT_NUMBER_FORMAT,
    pHashAlgorithm: ?PCSYMCRYPT_HASH,
    pbSeed: ?PCBYTE,
    cbSeed: SIZE_T,
    genCounter: UINT32,
    fipsStandard: SYMCRYPT_DLGROUP_FIPS,
    pDlgroup: PSYMCRYPT_DLGROUP,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;

    var pbScratch: ?PBYTE = null;
    var cbScratch: SIZE_T = 0;
    var cbScratchVerify: SIZE_T = 0;

    var nBitsOfP: UINT32 = 0;
    var nBitsOfQ: UINT32 = 0;

    const nMaxDigitsOfP: UINT32 = a_dispatch.SymCryptDigitsFromBits(pDlgroup.nMaxBitsOfP);
    const nMaxDigitsOfQ: UINT32 = a_dispatch.SymCryptDigitsFromBits(pDlgroup.nMaxBitsOfQ);

    var pTrialDivisionContext: ?PCSYMCRYPT_TRIALDIVISION_CONTEXT = null;

    defer {
        if (pTrialDivisionContext) |ctx| {
            a_dispatch.SymCryptFreeTrialDivisionContext(ctx);
        }
        if (pbScratch) |ptr| {
            SymCryptWipe(@ptrCast(ptr), cbScratch);
            SymCryptCallbackFree(@ptrCast(ptr));
        }
    }

    // Make sure that the inputs make sense
    if ((pbPrimeP == null) or (cbPrimeP == 0) or // Prime P is needed
        ((pbGenG == null) and (cbGenG > 0)) or
        ((pbPrimeQ == null) and (cbPrimeQ > 0)) or
        ((pbGenG == null) and (pbPrimeQ == null)) or // We can't have both Q and G missing
        ((pbSeed == null) and (cbSeed > 0)))
    {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    // FIPS 186-4 verification is needed
    if (fipsStandard != .SYMCRYPT_DLGROUP_FIPS_NONE) {
        // Make sure we have what we need
        if ((pbPrimeQ == null) or
            (cbPrimeQ == 0) or
            (pbSeed == null) or
            (cbSeed == 0) or
            ((fipsStandard == .SYMCRYPT_DLGROUP_FIPS_186_2) and (pHashAlgorithm != null)) or
            ((fipsStandard != .SYMCRYPT_DLGROUP_FIPS_186_2) and (pHashAlgorithm == null)))
        {
            return .SYMCRYPT_AUTHENTICATION_FAILURE;
        }
    }

    // Set the hashAlgorithm
    if ((fipsStandard == .SYMCRYPT_DLGROUP_FIPS_186_2) or
        ((pHashAlgorithm == null) and (pbGenG == null)))
    {
        pDlgroup.pHashAlgorithm = sha1.SymCryptSha1Algorithm;
    } else {
        pDlgroup.pHashAlgorithm = pHashAlgorithm;
    }

    if ((fipsStandard != .SYMCRYPT_DLGROUP_FIPS_NONE) or (pbGenG == null)) {
        cbScratchVerify = SymCryptDlgroupScratchSpace_FIPS(
            pDlgroup.nMaxBitsOfP,
            pDlgroup.nMaxBitsOfQ,
            pDlgroup.pHashAlgorithm.?,
        ) + @max(
            a_dispatch.SymCryptSizeofIntFromDigits(nMaxDigitsOfP),
            @max(
                a_dispatch.SymCryptSizeofIntFromDigits(nMaxDigitsOfQ),
                2 * types.SYMCRYPT_INTERNAL_SIZEOF_MODELEMENT_FROM_BITS(nMaxDigitsOfP),
            ),
        );
    }

    cbScratch = @max(
        @as(SIZE_T, types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(nMaxDigitsOfP)) +
            @max(
                a_dispatch.SymCryptSizeofIntFromDigits(nMaxDigitsOfQ),
                types.SYMCRYPT_SCRATCH_BYTES_FOR_INT_TO_MODULUS(nMaxDigitsOfP),
            ),
        cbScratchVerify,
    );
    pbScratch = SymCryptCallbackAlloc(cbScratch);
    if (pbScratch == null) {
        return .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
    }

    //
    // Prime P
    //

    // Set the prime P
    scError = a_dispatch.SymCryptIntSetValue(
        pbPrimeP.?,
        cbPrimeP,
        numFormat,
        a_dispatch.SymCryptIntFromModulus(pDlgroup.pmP),
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    // Check the bitsize of value
    nBitsOfP = a_dispatch.SymCryptIntBitsizeOfValue(a_dispatch.SymCryptIntFromModulus(pDlgroup.pmP));
    if (nBitsOfP > pDlgroup.nMaxBitsOfP) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    if (nBitsOfP < types.SYMCRYPT_DLGROUP_MIN_BITSIZE_P) {
        return .SYMCRYPT_WRONG_KEY_SIZE;
    }

    // FIPS 186-4 verification is needed
    // Check genCounter is not too big
    if (fipsStandard != .SYMCRYPT_DLGROUP_FIPS_NONE and
        genCounter > 4 * nBitsOfP - 1)
    {
        return .SYMCRYPT_AUTHENTICATION_FAILURE;
    }

    if ((a_dispatch.SymCryptIntGetValueLsbits32(a_dispatch.SymCryptIntFromModulus(pDlgroup.pmP)) & 1) == 0) {
        // P is even, when it should be a prime of at least 32 bits
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    // Set the bitsize and bytesize of the value
    pDlgroup.nBitsOfP = nBitsOfP;
    pDlgroup.cbPrimeP = (nBitsOfP + 7) / 8;

    a_dispatch.SymCryptIntToModulus(
        a_dispatch.SymCryptIntFromModulus(pDlgroup.pmP),
        pDlgroup.pmP,
        1000 * nBitsOfP, // Average operations
        types.SYMCRYPT_FLAG_DATA_PUBLIC | types.SYMCRYPT_FLAG_MODULUS_PRIME,
        pbScratch.?,
        cbScratch,
    );

    //
    // Prime Q
    //

    // Wiping of previous (optional) parameters related to Q
    if (pDlgroup.pmQ) |pmQ| {
        a_dispatch.SymCryptModulusWipe(pmQ);
    }
    if (pDlgroup.cbSeed != 0 and pDlgroup.pbSeed != null) {
        SymCryptWipe(@ptrCast(pDlgroup.pbSeed.?), pDlgroup.cbSeed);
    }

    if (pbPrimeQ) |qPtr| {
        // Create an integer piTemp
        const piTemp = a_dispatch.SymCryptIntCreate(pbScratch.?, cbScratch, nMaxDigitsOfQ).?;

        // Set the prime Q
        scError = a_dispatch.SymCryptIntSetValue(qPtr, cbPrimeQ, numFormat, piTemp);
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }

        // Check the bitsize of value
        nBitsOfQ = a_dispatch.SymCryptIntBitsizeOfValue(piTemp);
        if (nBitsOfQ > pDlgroup.nMaxBitsOfQ) {
            return .SYMCRYPT_INVALID_ARGUMENT;
        }

        if (nBitsOfQ < types.SYMCRYPT_DLGROUP_MIN_BITSIZE_Q) {
            return .SYMCRYPT_WRONG_KEY_SIZE;
        }

        if ((a_dispatch.SymCryptIntGetValueLsbits32(piTemp) & 1) == 0) {
            return .SYMCRYPT_INVALID_ARGUMENT;
        }

        // Set the bitsize and bytesize of the value
        pDlgroup.nBitsOfQ = nBitsOfQ;
        pDlgroup.cbPrimeQ = (nBitsOfQ + 7) / 8;
        pDlgroup.nDigitsOfQ = a_dispatch.SymCryptDigitsFromBits(nBitsOfQ);
        pDlgroup.nDefaultBitsPriv = nBitsOfQ;
        pDlgroup.nBitsOfSeed = nBitsOfQ;
        pDlgroup.cbSeed = (nBitsOfQ + 7) / 8;

        // Create the modulus Q
        pDlgroup.pmQ = a_dispatch.SymCryptModulusCreate(
            pDlgroup.pbQ,
            a_dispatch.SymCryptSizeofModulusFromDigits(pDlgroup.nDigitsOfQ),
            pDlgroup.nDigitsOfQ,
        );

        // Set the prime Q
        scError = a_dispatch.SymCryptIntCopyMixedSize(piTemp, a_dispatch.SymCryptIntFromModulus(pDlgroup.pmQ.?));
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }

        a_dispatch.SymCryptIntToModulus(
            a_dispatch.SymCryptIntFromModulus(pDlgroup.pmQ.?),
            pDlgroup.pmQ.?,
            1000 * nBitsOfP, // Average operations
            types.SYMCRYPT_FLAG_DATA_PUBLIC | types.SYMCRYPT_FLAG_MODULUS_PRIME,
            pbScratch.?,
            cbScratch,
        );

        pDlgroup.fHasPrimeQ = 1;
    } else {
        // Clear all info about Q
        pDlgroup.cbPrimeQ = 0;
        pDlgroup.nBitsOfQ = 0;
        pDlgroup.nDigitsOfQ = 0;

        pDlgroup.nDefaultBitsPriv = 0;
        pDlgroup.nBitsOfSeed = 0;
        pDlgroup.cbSeed = 0;

        pDlgroup.pmQ = null;
        pDlgroup.fHasPrimeQ = 0;
    }

    pDlgroup.isSafePrimeGroup = 0;
    pDlgroup.nMinBitsPriv = 0;

    //
    // Provided Generator G
    //
    if (pbGenG) |gPtr| {
        scError = a_dispatch.SymCryptModElementSetValue(
            gPtr,
            cbGenG,
            numFormat,
            pDlgroup.pmP,
            pDlgroup.peG,
            pbScratch.?,
            cbScratch,
        );
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }

        scError = SymCryptDlgroupAutoCompleteNamedSafePrimeGroup(pDlgroup, pbScratch.?, cbScratch);
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }

        // Successfully detected, validated and autocompleted named safe-prime group
        if (pDlgroup.isSafePrimeGroup != 0) {
            return scError;
        }
    }

    //
    //  Verification data (this has to be done before possibly generating G)
    //

    // Set the FIPS standard
    pDlgroup.eFipsStandard = fipsStandard;

    // Set the seed
    if (pbSeed) |sPtr| {
        if (cbSeed != pDlgroup.cbSeed) {
            return .SYMCRYPT_INVALID_ARGUMENT;
        }
        @memcpy(pDlgroup.pbSeed.?[0..cbSeed], sPtr[0..cbSeed]);
    }

    // Set the genCounter
    pDlgroup.dwGenCounter = genCounter;

    //
    // Generator G
    //
    if (pbGenG == null) {
        if (pbSeed == null) {
            _ = SymCryptCallbackRandom(pDlgroup.pbSeed.?, pDlgroup.cbSeed);
        }

        scError = SymCryptDlgroupGenerateGenG_FIPS(
            pDlgroup,
            pDlgroup.peG,
            pbScratch.?,
            cbScratch,
        );
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }
    }

    // Verification
    if (fipsStandard != .SYMCRYPT_DLGROUP_FIPS_NONE) {
        var pbScratchInternal: PBYTE = pbScratch.?;
        var cbScratchInternal: SIZE_T = cbScratch;

        const ndDivTwoQ: UINT32 = a_dispatch.SymCryptDigitsFromBits(pDlgroup.nBitsOfQ + 1);
        const cbDivTwoQ: UINT32 = a_dispatch.SymCryptSizeofDivisorFromDigits(ndDivTwoQ);
        const pdDivTwoQ = a_dispatch.SymCryptDivisorCreate(pbScratchInternal, cbDivTwoQ, ndDivTwoQ).?;
        pbScratchInternal += cbDivTwoQ;
        cbScratchInternal -= cbDivTwoQ;

        // Create the temporary integer of size Q
        var cbComputed: UINT32 = a_dispatch.SymCryptSizeofIntFromDigits(pDlgroup.nDigitsOfQ);
        var piComputed = a_dispatch.SymCryptIntCreate(pbScratchInternal, cbComputed, pDlgroup.nDigitsOfQ).?;
        pbScratchInternal += cbComputed;
        cbScratchInternal -= cbComputed;

        // Create a trial division context for both P and Q
        pTrialDivisionContext = a_dispatch.SymCryptCreateTrialDivisionContext(pDlgroup.nDigitsOfP);
        if (pTrialDivisionContext == null) {
            return .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
        }

        var fPrimeComputed: UINT32 = 0;
        var dwComputedCounter: UINT32 = 0;

        // Steps 8,9: Check if computed_q is prime and equal to q
        scError = SymCryptDlgroupGeneratePrimeQ_FIPS(
            pDlgroup,
            pTrialDivisionContext.?,
            &fPrimeComputed,
            piComputed,
            pdDivTwoQ,
            pbScratchInternal,
            cbScratchInternal,
        );
        if (scError != .SYMCRYPT_NO_ERROR) {
            return .SYMCRYPT_AUTHENTICATION_FAILURE;
        }

        if ((fPrimeComputed == 0) or
            (a_dispatch.SymCryptIntIsEqual(piComputed, a_dispatch.SymCryptIntFromModulus(pDlgroup.pmQ.?)) == 0))
        {
            return .SYMCRYPT_AUTHENTICATION_FAILURE;
        }

        // Create the temporary integer of size P
        pbScratchInternal -= cbComputed;
        cbScratchInternal += cbComputed;
        cbComputed = a_dispatch.SymCryptSizeofIntFromDigits(pDlgroup.nDigitsOfP);
        piComputed = a_dispatch.SymCryptIntCreate(pbScratchInternal, cbComputed, pDlgroup.nDigitsOfP).?;
        pbScratchInternal += cbComputed;
        cbScratchInternal -= cbComputed;

        // Steps 10-14: Check if computed_p is prime and equal to p
        scError = SymCryptDlgroupGeneratePrimeP_FIPS(
            pDlgroup,
            pdDivTwoQ,
            pDlgroup.dwGenCounter, // Go up to this
            pTrialDivisionContext.?,
            &fPrimeComputed,
            piComputed,
            &dwComputedCounter,
            pbScratchInternal,
            cbScratchInternal,
        );
        if (scError != .SYMCRYPT_NO_ERROR) {
            return .SYMCRYPT_AUTHENTICATION_FAILURE;
        }

        if ((fPrimeComputed == 0) or
            (dwComputedCounter != pDlgroup.dwGenCounter) or
            (a_dispatch.SymCryptIntIsEqual(piComputed, a_dispatch.SymCryptIntFromModulus(pDlgroup.pmP)) == 0))
        {
            return .SYMCRYPT_AUTHENTICATION_FAILURE;
        }

        // Validation of G

        // Create the temporary modelement mod P
        pbScratchInternal -= cbComputed;
        cbScratchInternal += cbComputed;
        cbComputed = a_dispatch.SymCryptSizeofModElementFromModulus(pDlgroup.pmP);
        const peOne = a_dispatch.SymCryptModElementCreate(pbScratchInternal, cbComputed, pDlgroup.pmP).?;
        pbScratchInternal += cbComputed;
        cbScratchInternal -= cbComputed;
        const peComputed = a_dispatch.SymCryptModElementCreate(pbScratchInternal, cbComputed, pDlgroup.pmP).?;
        pbScratchInternal += cbComputed;
        cbScratchInternal -= cbComputed;

        // Step 2: Verify that 2<= G <= p-1
        a_dispatch.SymCryptModElementSetValueUint32(1, pDlgroup.pmP, peOne, pbScratchInternal, cbScratchInternal);

        if ((a_dispatch.SymCryptModElementIsZero(pDlgroup.pmP, pDlgroup.peG) != 0) or
            (a_dispatch.SymCryptModElementIsEqual(pDlgroup.pmP, pDlgroup.peG, peOne) != 0))
        {
            return .SYMCRYPT_AUTHENTICATION_FAILURE;
        }

        // Step 3: Verify that G^Q == 1
        a_dispatch.SymCryptModExp(
            pDlgroup.pmP,
            pDlgroup.peG,
            a_dispatch.SymCryptIntFromModulus(pDlgroup.pmQ.?),
            nBitsOfQ,
            types.SYMCRYPT_FLAG_DATA_PUBLIC,
            peComputed,
            pbScratchInternal,
            cbScratchInternal,
        );

        if (a_dispatch.SymCryptModElementIsEqual(pDlgroup.pmP, peComputed, peOne) == 0) {
            return .SYMCRYPT_AUTHENTICATION_FAILURE;
        }
    }

    return scError;
}

pub export fn SymCryptDlgroupGetValue(
    pDlgroup: PCSYMCRYPT_DLGROUP,
    pbPrimeP: ?PBYTE,
    cbPrimeP: SIZE_T,
    pbPrimeQ: ?PBYTE,
    cbPrimeQ: SIZE_T,
    pbGenG: ?PBYTE,
    cbGenG: SIZE_T,
    numFormat: SYMCRYPT_NUMBER_FORMAT,
    ppHashAlgorithm: ?PPCSYMCRYPT_HASH,
    pbSeed: ?PBYTE,
    cbSeed: SIZE_T,
    pGenCounter: ?*UINT32,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;

    var pbScratch: ?PBYTE = null;
    var cbScratch: SIZE_T = 0;

    defer {
        if (pbScratch) |ptr| {
            SymCryptWipe(@ptrCast(ptr), cbScratch);
            SymCryptCallbackFree(@ptrCast(ptr));
        }
    }

    if (((pbPrimeP == null) and (cbPrimeP > 0)) or
        ((pbPrimeQ == null) and (cbPrimeQ > 0)) or
        ((pbGenG == null) and (cbGenG > 0)) or
        ((pbSeed == null) and (cbSeed > 0)) or
        ((pbSeed != null) and (cbSeed != pDlgroup.cbSeed)))
    {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    if ((pbPrimeQ != null) and (pDlgroup.fHasPrimeQ == 0)) {
        return .SYMCRYPT_INVALID_BLOB;
    }

    if (pbPrimeP) |pPtr| {
        scError = a_dispatch.SymCryptIntGetValue(
            a_dispatch.SymCryptIntFromModulus(pDlgroup.pmP),
            pPtr,
            cbPrimeP,
            numFormat,
        );
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }
    }

    if (pbPrimeQ) |qPtr| {
        scError = a_dispatch.SymCryptIntGetValue(
            a_dispatch.SymCryptIntFromModulus(pDlgroup.pmQ.?),
            qPtr,
            cbPrimeQ,
            numFormat,
        );
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }
    }

    if (pbGenG) |gPtr| {
        cbScratch = types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS(pDlgroup.nDigitsOfP);
        pbScratch = SymCryptCallbackAlloc(cbScratch);
        if (pbScratch == null) {
            return .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
        }

        scError = a_dispatch.SymCryptModElementGetValue(
            pDlgroup.pmP,
            pDlgroup.peG,
            gPtr,
            cbGenG,
            numFormat,
            pbScratch.?,
            cbScratch,
        );
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }
    }

    if (ppHashAlgorithm) |ppHash| {
        if (pDlgroup.eFipsStandard == .SYMCRYPT_DLGROUP_FIPS_186_2) {
            ppHash.* = null;
        } else {
            ppHash.* = pDlgroup.pHashAlgorithm;
        }
    }

    if (pbSeed != null and pDlgroup.pbSeed != null) {
        @memcpy(pbSeed.?[0..pDlgroup.cbSeed], pDlgroup.pbSeed.?[0..pDlgroup.cbSeed]);
    }

    if (pGenCounter) |pCnt| {
        pCnt.* = pDlgroup.dwGenCounter;
    }

    return scError;
}
