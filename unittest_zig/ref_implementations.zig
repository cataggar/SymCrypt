const std = @import("std");
const main_harness = @import("main_harness.zig");

const check = main_harness.check;

pub const SYMCRYPT_POLY1305_KEY_SIZE: usize = 32;
pub const SYMCRYPT_POLY1305_RESULT_SIZE: usize = 16;

const SYMCRYPT_NUMBER_FORMAT_LSB_FIRST: u32 = 1;
const SYMCRYPT_FLAG_DATA_PUBLIC: u32 = 0x01;
const SYMCRYPT_FLAG_MODULUS_PRIME: u32 = 0x08;

const STATUS_SUCCESS: i32 = 0;

pub const REF_POLY1305_STATE = extern struct {
    pmMod: ?*anyopaque,
    peAcc: ?*anyopaque,
    peR: ?*anyopaque,
    peData: ?*anyopaque,
    piS: ?*anyopaque,
    piAcc: ?*anyopaque,
    block: [17]u8,
    bytesInBuffer: usize,
};

extern fn SymCryptWipe(pbData: [*]u8, cbData: usize) callconv(.c) void;
extern fn SymCryptDigitsFromBits(nBits: u32) callconv(.c) u32;
extern fn SymCryptModulusAllocate(nDigits: u32) callconv(.c) ?*anyopaque;
extern fn SymCryptModulusFree(pmObj: ?*anyopaque) callconv(.c) void;
extern fn SymCryptModElementAllocate(pmMod: ?*const anyopaque) callconv(.c) ?*anyopaque;
extern fn SymCryptModElementFree(pmMod: ?*const anyopaque, peObj: ?*anyopaque) callconv(.c) void;
extern fn SymCryptModElementCopy(pmMod: ?*const anyopaque, peSrc: ?*const anyopaque, peDst: ?*anyopaque) callconv(.c) void;
extern fn SymCryptIntAllocate(nDigits: u32) callconv(.c) ?*anyopaque;
extern fn SymCryptIntFree(piObj: ?*anyopaque) callconv(.c) void;
extern fn SymCryptIntDigitsizeOfObject(piSrc: ?*const anyopaque) callconv(.c) u32;
extern fn SymCryptIntBitsizeOfValue(piSrc: ?*const anyopaque) callconv(.c) u32;
extern fn SymCryptIntFromModulus(pmSrc: ?*anyopaque) callconv(.c) ?*anyopaque;
extern fn SymCryptIntSetValueUint32(u32Src: u32, piDst: ?*anyopaque) callconv(.c) void;
extern fn SymCryptIntSetValue(pbSrc: [*]const u8, cbSrc: usize, format: u32, piDst: ?*anyopaque) callconv(.c) u32;
extern fn SymCryptIntGetValue(piSrc: ?*const anyopaque, pbDst: [*]u8, cbDst: usize, format: u32) callconv(.c) u32;
extern fn SymCryptIntGetValueLsbits32(piSrc: ?*const anyopaque) callconv(.c) u32;
extern fn SymCryptIntGetBit(piSrc: ?*const anyopaque, iBit: u32) callconv(.c) u32;
extern fn SymCryptIntSetBits(piDst: ?*anyopaque, value: u32, iBit: u32, nBits: u32) callconv(.c) void;
extern fn SymCryptIntSubUint32(piSrc1: ?*const anyopaque, u32Src2: u32, piDst: ?*anyopaque) callconv(.c) u32;
extern fn SymCryptIntAddSameSize(piSrc1: ?*const anyopaque, piSrc2: ?*const anyopaque, piDst: ?*anyopaque) callconv(.c) u32;
extern fn SymCryptIntToModulus(piSrc: ?*const anyopaque, pmDst: ?*anyopaque, averageOperations: u32, flags: u32, pbScratch: [*]u8, cbScratch: usize) callconv(.c) void;
extern fn SymCryptModElementSetValueUint32(value: u32, pmMod: ?*const anyopaque, peDst: ?*anyopaque, pbScratch: [*]u8, cbScratch: usize) callconv(.c) void;
extern fn SymCryptModElementSetValueNegUint32(value: u32, pmMod: ?*const anyopaque, peDst: ?*anyopaque, pbScratch: [*]u8, cbScratch: usize) callconv(.c) void;
extern fn SymCryptModElementSetValue(pbSrc: [*]const u8, cbSrc: usize, format: u32, pmMod: ?*const anyopaque, peDst: ?*anyopaque, pbScratch: [*]u8, cbScratch: usize) callconv(.c) u32;
extern fn SymCryptModElementToInt(pmMod: ?*const anyopaque, peSrc: ?*const anyopaque, piDst: ?*anyopaque, pbScratch: [*]u8, cbScratch: usize) callconv(.c) void;
extern fn SymCryptModElementIsEqual(pmMod: ?*const anyopaque, peSrc1: ?*const anyopaque, peSrc2: ?*const anyopaque) callconv(.c) u32;
extern fn SymCryptModSetRandom(pmMod: ?*const anyopaque, peDst: ?*anyopaque, flags: u32, pbScratch: [*]u8, cbScratch: usize) callconv(.c) void;
extern fn SymCryptModAdd(pmMod: ?*const anyopaque, peSrc1: ?*const anyopaque, peSrc2: ?*const anyopaque, peDst: ?*anyopaque, pbScratch: [*]u8, cbScratch: usize) callconv(.c) void;
extern fn SymCryptModMul(pmMod: ?*const anyopaque, peSrc1: ?*const anyopaque, peSrc2: ?*const anyopaque, peDst: ?*anyopaque, pbScratch: [*]u8, cbScratch: usize) callconv(.c) void;
extern fn SymCryptModSquare(pmMod: ?*const anyopaque, peSrc: ?*const anyopaque, peDst: ?*anyopaque, pbScratch: [*]u8, cbScratch: usize) callconv(.c) void;

pub export fn RefPoly1305Init(
    pState: *REF_POLY1305_STATE,
    pbKey: [*]const u8,
) callconv(.c) void {
    var key: [32]u8 = undefined;
    var scratch: [2048]u8 align(64) = undefined;

    @memcpy(key[0..32], pbKey[0..32]);

    // Clamping, directly from the RFC
    key[3] &= 15;
    key[7] &= 15;
    key[11] &= 15;
    key[15] &= 15;
    key[4] &= 252;
    key[8] &= 252;
    key[12] &= 252;

    const nDigits = SymCryptDigitsFromBits(130 + 1); // +1 to deal with the Acc + S addition

    pState.pmMod = SymCryptModulusAllocate(nDigits);
    pState.peAcc = SymCryptModElementAllocate(pState.pmMod);
    pState.peR = SymCryptModElementAllocate(pState.pmMod);
    pState.peData = SymCryptModElementAllocate(pState.pmMod);
    pState.piS = SymCryptIntAllocate(nDigits);
    pState.piAcc = SymCryptIntAllocate(nDigits);

    pState.bytesInBuffer = 0;

    // Get the INT object inside the modulus to create the value before we create the modulus
    const piP = SymCryptIntFromModulus(pState.pmMod);
    SymCryptIntSetValueUint32(0, piP); // P = 0
    SymCryptIntSetBits(piP, 1, 130, 1); // P = 2^130
    _ = SymCryptIntSubUint32(piP, 5, piP); // P = 2^130 - 5

    // Convert integer to modulus.
    SymCryptIntToModulus(
        piP,
        pState.pmMod,
        10,
        SYMCRYPT_FLAG_DATA_PUBLIC | SYMCRYPT_FLAG_MODULUS_PRIME,
        &scratch,
        scratch.len,
    );

    // Acc = 0
    SymCryptModElementSetValueUint32(0, pState.pmMod, pState.peAcc, &scratch, scratch.len);

    // Set R, S
    _ = SymCryptModElementSetValue(&key, 16, SYMCRYPT_NUMBER_FORMAT_LSB_FIRST, pState.pmMod, pState.peR, &scratch, scratch.len);
    _ = SymCryptIntSetValue(key[16..32].ptr, 16, SYMCRYPT_NUMBER_FORMAT_LSB_FIRST, pState.piS);

    SymCryptWipe(&key, key.len);
    SymCryptWipe(&scratch, scratch.len);
}

pub export fn RefPoly1305ProcessBlock(
    pState: *REF_POLY1305_STATE,
    pbData: [*]const u8,
    cbData: usize,
) callconv(.c) void {
    var scratch: [2048]u8 align(64) = undefined;

    check(cbData <= 17, "Block too large");

    _ = SymCryptModElementSetValue(
        pbData,
        cbData,
        SYMCRYPT_NUMBER_FORMAT_LSB_FIRST,
        pState.pmMod,
        pState.peData,
        &scratch,
        scratch.len,
    );
    SymCryptModAdd(pState.pmMod, pState.peAcc, pState.peData, pState.peAcc, &scratch, scratch.len);
    SymCryptModMul(pState.pmMod, pState.peAcc, pState.peR, pState.peAcc, &scratch, scratch.len);
    pState.bytesInBuffer = 0;

    SymCryptWipe(&scratch, scratch.len);
}

pub export fn RefPoly1305Append(
    pState: *REF_POLY1305_STATE,
    pbData: [*]const u8,
    cbData: usize,
) callconv(.c) void {
    var idx: usize = 0;
    while (idx < cbData) : (idx += 1) {
        pState.block[pState.bytesInBuffer] = pbData[idx];
        pState.bytesInBuffer += 1;

        if (pState.bytesInBuffer == 16) {
            pState.block[pState.bytesInBuffer] = 1;
            RefPoly1305ProcessBlock(pState, &pState.block, pState.bytesInBuffer + 1);
            pState.bytesInBuffer = 0;
        }
    }
}

pub export fn RefPoly1305Result(
    pState: *REF_POLY1305_STATE,
    pbResult: [*]u8,
) callconv(.c) void {
    var scratch: [2048]u8 align(64) = undefined;

    if (pState.bytesInBuffer != 0) {
        pState.block[pState.bytesInBuffer] = 1;
        RefPoly1305ProcessBlock(pState, &pState.block, pState.bytesInBuffer + 1);
        pState.bytesInBuffer = 0;
    }

    SymCryptModElementToInt(pState.pmMod, pState.peAcc, pState.piAcc, &scratch, scratch.len);
    _ = SymCryptIntAddSameSize(pState.piAcc, pState.piS, pState.piAcc);

    _ = SymCryptIntGetValue(pState.piAcc, &pState.block, 17, SYMCRYPT_NUMBER_FORMAT_LSB_FIRST);
    @memcpy(pbResult[0..16], pState.block[0..16]);

    SymCryptWipe(&scratch, scratch.len);

    SymCryptIntFree(pState.piAcc);
    SymCryptIntFree(pState.piS);
    SymCryptModElementFree(pState.pmMod, pState.peData);
    SymCryptModElementFree(pState.pmMod, pState.peR);
    SymCryptModElementFree(pState.pmMod, pState.peAcc);
    SymCryptModulusFree(pState.pmMod);

    const state_bytes = std.mem.asBytes(pState);
    SymCryptWipe(state_bytes.ptr, state_bytes.len);
}

pub export fn RefPoly1305(
    pbKey: [*]const u8,
    pbData: [*]const u8,
    cbData: usize,
    pbResult: [*]u8,
) callconv(.c) void {
    var state: REF_POLY1305_STATE = undefined;

    RefPoly1305Init(&state, pbKey);
    RefPoly1305Append(&state, pbData, cbData);
    RefPoly1305Result(&state, pbResult);
}

pub export fn RefIsPossiblePrime(
    piSrc: ?*const anyopaque,
    pbScratch: [*]u8,
    cbScratch: usize,
) callconv(.c) u32 {
    var pmMod: ?*anyopaque = null;
    var peBase: ?*anyopaque = null;
    var peTmp: ?*anyopaque = null;
    var res: u32 = 0;

    defer {
        if (peTmp != null) {
            SymCryptModElementFree(pmMod, peTmp);
        }
        if (peBase != null) {
            SymCryptModElementFree(pmMod, peBase);
        }
        if (pmMod != null) {
            SymCryptModulusFree(pmMod);
        }
    }

    const lwb = SymCryptIntGetValueLsbits32(piSrc);

    // Handle small values that confuse the later code
    if (SymCryptIntBitsizeOfValue(piSrc) < 10) {
        if (lwb < 2) {
            // 0 and 1
            return 0;
        }
        if (lwb <= 3) {
            // 2 and 3
            return 1;
        }
    }

    // Other even numbers are not prime
    if ((lwb & 1) == 0) {
        return 0;
    }

    // Here we know piSrc is odd and > 3
    const nD = SymCryptIntDigitsizeOfObject(piSrc);
    pmMod = SymCryptModulusAllocate(nD);
    check(pmMod != null, "Out of memory");
    SymCryptIntToModulus(piSrc, pmMod, 0, 0, pbScratch, cbScratch);

    peBase = SymCryptModElementAllocate(pmMod);
    peTmp = SymCryptModElementAllocate(pmMod);
    check(peBase != null and peTmp != null, "Out of memory");

    // Pick a random base. Do not allow 0, 1, or -1 as they never show a number to be composite.
    SymCryptModSetRandom(pmMod, peBase, 0, pbScratch, cbScratch);

    // Find the stop bit for the base exponentiation. This is the first nonzero bit closest to the parity bit
    var stopBit: u32 = 1;
    while (SymCryptIntGetBit(piSrc, stopBit) == 0) {
        stopBit += 1;
    }

    var currentBit: u32 = SymCryptIntBitsizeOfValue(piSrc) - 1;
    check(SymCryptIntGetBit(piSrc, currentBit) == 1, "?");
    SymCryptModElementCopy(pmMod, peBase, peTmp);

    // Do the basic exponentiation
    while (currentBit > stopBit) {
        currentBit -= 1;
        SymCryptModSquare(pmMod, peTmp, peTmp, pbScratch, cbScratch);
        if (SymCryptIntGetBit(piSrc, currentBit) != 0) {
            SymCryptModMul(pmMod, peTmp, peBase, peTmp, pbScratch, cbScratch);
        }
    }

    // We don't need peBase anymore, so we use it as scratch
    SymCryptModElementSetValueUint32(1, pmMod, peBase, pbScratch, cbScratch);
    if (SymCryptModElementIsEqual(pmMod, peBase, peTmp) != 0) {
        res = 1;
        return res;
    }

    // Now we need to see a -1 before we reach 1 as we keep squaring
    SymCryptModElementSetValueNegUint32(1, pmMod, peBase, pbScratch, cbScratch);
    while (true) {
        if (SymCryptModElementIsEqual(pmMod, peBase, peTmp) != 0) {
            res = 1;
            return res;
        }

        if (currentBit == 0) {
            res = 0;
            return res;
        }

        SymCryptModSquare(pmMod, peTmp, peTmp, pbScratch, cbScratch);
        currentBit -= 1;
    }
}

pub export fn RefIsPrime(
    piSrc: ?*const anyopaque,
    pbScratch: [*]u8,
    cbScratch: usize,
) callconv(.c) u32 {
    var i: usize = 0;
    while (i < 64) : (i += 1) {
        if (RefIsPossiblePrime(piSrc, pbScratch, cbScratch) == 0) {
            return 0;
        }
    }
    return 1;
}

/// Zig adapter for the Ref Poly1305 MAC implementation, usable by Zig test drivers in Chunks 8.3–8.6.
pub const RefPoly1305Adapter = struct {
    pub const imp_name = "Ref";
    pub const alg_name = "Poly1305";
    pub const input_block_len: usize = SYMCRYPT_POLY1305_RESULT_SIZE;
    pub const result_len: usize = SYMCRYPT_POLY1305_RESULT_SIZE;

    state: REF_POLY1305_STATE = undefined,

    pub fn mac(key: []const u8, data: []const u8, result_buf: []u8) i32 {
        check(key.len == SYMCRYPT_POLY1305_KEY_SIZE, "?");
        check(result_buf.len == SYMCRYPT_POLY1305_RESULT_SIZE, "?");
        const data_ptr: [*]const u8 = if (data.len > 0) data.ptr else key.ptr;
        RefPoly1305(key.ptr, data_ptr, data.len, result_buf.ptr);
        return STATUS_SUCCESS;
    }

    pub fn init(self: *RefPoly1305Adapter, key: []const u8) i32 {
        check(key.len == SYMCRYPT_POLY1305_KEY_SIZE, "?");
        RefPoly1305Init(&self.state, key.ptr);
        return STATUS_SUCCESS;
    }

    pub fn append(self: *RefPoly1305Adapter, data: []const u8) void {
        if (data.len == 0) return;
        RefPoly1305Append(&self.state, data.ptr, data.len);
    }

    pub fn result(self: *RefPoly1305Adapter, result_buf: []u8) void {
        check(result_buf.len == SYMCRYPT_POLY1305_RESULT_SIZE, "Result len error Ref/Poly1305");
        RefPoly1305Result(&self.state, result_buf.ptr);
    }

    pub fn dataPerf(buf1: [*]u8, buf2: [*]u8, buf3: [*]u8, dataSize: usize) callconv(.c) void {
        RefPoly1305(buf1, buf2, dataSize, buf3);
    }
};

pub fn isPossiblePrime(piSrc: ?*const anyopaque, scratch: []u8) bool {
    return RefIsPossiblePrime(piSrc, scratch.ptr, scratch.len) != 0;
}

pub fn isPrime(piSrc: ?*const anyopaque, scratch: []u8) bool {
    return RefIsPrime(piSrc, scratch.ptr, scratch.len) != 0;
}
