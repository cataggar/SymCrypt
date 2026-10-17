//
// scs_table.zig
// Side-channel safe table.
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
// These functions implement a table of large elements.
// Reading an element from the table is done in a way that does not reveal the
// element accessed through memory side channels.
// Basically, the whole table is read by the CPU, and the required data is selected
// using boolean operations.
//

const std = @import("std");
const types = @import("types.zig");
const macros = @import("macros.zig");

const PBYTE = types.PBYTE;
const PCBYTE = types.PCBYTE;
const PVOID = types.PVOID;
const SIZE_T = types.SIZE_T;
const UINT32 = types.UINT32;
const UINT64 = types.UINT64;
const INT64 = types.INT64;
const PSYMCRYPT_SCSTABLE = types.PSYMCRYPT_SCSTABLE;

const USE64: bool = types.CPU_AMD64 or types.CPU_ARM64;
const INTERLEAVE_SIZE: UINT32 = if (USE64) 32 else 16;
const GROUP_SIZE: UINT32 = 4;
const SCSTABLE_TYPE = if (USE64) UINT64 else UINT32;

comptime {
    std.debug.assert(INTERLEAVE_SIZE == 16 or INTERLEAVE_SIZE == 32);
    std.debug.assert(INTERLEAVE_SIZE == 4 * @sizeOf(SCSTABLE_TYPE));
}

extern fn SymCryptWipe(pbData: PVOID, cbData: SIZE_T) callconv(types.SYMCRYPT_CALL) void;

inline fn scsMaskEqual32(a: UINT32, b: UINT32) SCSTABLE_TYPE {
    if (USE64) {
        const diff: UINT64 = @as(UINT64, 0) -% @as(UINT64, a ^ b);
        const sdiff: INT64 = @bitCast(diff);
        return ~@as(UINT64, @bitCast(sdiff >> 32));
    } else {
        return macros.SYMCRYPT_MASK32_EQ(a, b);
    }
}

pub export fn SymCryptScsTableInit(
    pScsTable: PSYMCRYPT_SCSTABLE,
    nElements: UINT32,
    elementSize: UINT32,
) callconv(types.SYMCRYPT_CALL) UINT32 {
    var groupSize: UINT32 = undefined;
    var interleaveSize: UINT32 = undefined;

    macros.SYMCRYPT_ASSERT(nElements > 0);

    if (types.CPU_AMD64 and elementSize == 128) {
        // Highly optimized assembler/XMM mode for 1024-bit entries for RSA-2048...
        interleaveSize = 128;
        groupSize = 1;
    } else {
        // Standard C implementation
        interleaveSize = INTERLEAVE_SIZE;
        groupSize = GROUP_SIZE;
    }

    macros.SYMCRYPT_ASSERT(
        elementSize % interleaveSize == 0 and
            nElements % groupSize == 0 and
            (elementSize | nElements) < (1 << 16) and
            elementSize > 0,
    );

    const cbBuffer: UINT32 = elementSize * nElements;

    pScsTable.groupSize = groupSize;
    pScsTable.interleaveSize = interleaveSize;
    pScsTable.nElements = nElements;
    pScsTable.elementSize = elementSize;
    pScsTable.cbTableData = cbBuffer;
    pScsTable.pbTableData = null;

    return cbBuffer;
}

pub export fn SymCryptScsTableSetBuffer(
    pScsTable: PSYMCRYPT_SCSTABLE,
    pbBuffer: PBYTE,
    cbBuffer: UINT32,
) callconv(types.SYMCRYPT_CALL) void {
    macros.SYMCRYPT_ASSERT(cbBuffer >= pScsTable.cbTableData);
    pScsTable.pbTableData = pbBuffer;
}

pub export fn SymCryptScsTableStoreC(
    pScsTable: PSYMCRYPT_SCSTABLE,
    iIndex: UINT32,
    pbData: PCBYTE,
    cbData: UINT32,
) callconv(types.SYMCRYPT_CALL) void {
    const groupSize: UINT32 = GROUP_SIZE;
    const interleaveSize: UINT32 = INTERLEAVE_SIZE;
    const elementSize: UINT32 = pScsTable.elementSize;

    macros.SYMCRYPT_ASSERT(groupSize == pScsTable.groupSize);
    macros.SYMCRYPT_ASSERT(interleaveSize == pScsTable.interleaveSize);
    macros.SYMCRYPT_ASSERT(cbData == elementSize);
    macros.SYMCRYPT_ASSERT(iIndex < pScsTable.nElements);

    const groupOffset: UINT32 = iIndex % groupSize;
    const basePtr = pScsTable.pbTableData.? +
        @as(usize, (iIndex - groupOffset) * elementSize + groupOffset * interleaveSize);

    var pDst: [*]align(1) SCSTABLE_TYPE = @ptrCast(basePtr);
    var pSrc: [*]align(1) const SCSTABLE_TYPE = @ptrCast(pbData);

    var nInterleaves: UINT32 = elementSize / interleaveSize;

    while (true) {
        pDst[0] = pSrc[0];
        pDst[1] = pSrc[1];
        pDst[2] = pSrc[2];
        pDst[3] = pSrc[3];

        pDst += (interleaveSize * groupSize) / @sizeOf(SCSTABLE_TYPE);
        pSrc += interleaveSize / @sizeOf(SCSTABLE_TYPE);
        nInterleaves -= 1;
        if (nInterleaves == 0) break;
    }
}

pub fn symCryptScsTableStore128XmmImpl(
    pScsTable: PSYMCRYPT_SCSTABLE,
    iIndex: UINT32,
    pbData: PCBYTE,
    cbData: UINT32,
) callconv(types.SYMCRYPT_CALL) void {
    macros.SYMCRYPT_ASSERT(
        cbData == 128 and
            pScsTable.elementSize == 128 and
            iIndex < pScsTable.nElements and
            pScsTable.groupSize == 1,
    );

    const V128 = @Vector(4, u32);
    const dstBase = pScsTable.pbTableData.? + @as(usize, iIndex) * 128;
    const pDst: [*]align(16) V128 = @ptrCast(@alignCast(dstBase));
    const pSrc: [*]align(16) const V128 = @ptrCast(@alignCast(pbData));

    pDst[0] = pSrc[0];
    pDst[1] = pSrc[1];
    pDst[2] = pSrc[2];
    pDst[3] = pSrc[3];
    pDst[4] = pSrc[4];
    pDst[5] = pSrc[5];
    pDst[6] = pSrc[6];
    pDst[7] = pSrc[7];
}

pub export fn SymCryptScsTableLoadC(
    pScsTable: PSYMCRYPT_SCSTABLE,
    iIndex: UINT32,
    pbData: PBYTE,
    cbData: UINT32,
) callconv(types.SYMCRYPT_CALL) void {
    const groupSize: UINT32 = GROUP_SIZE;
    const interleaveSize: UINT32 = INTERLEAVE_SIZE;
    const elementSize: UINT32 = pScsTable.elementSize;
    const nElements: UINT32 = pScsTable.nElements;

    var pSrc: [*]align(1) const SCSTABLE_TYPE = @ptrCast(pScsTable.pbTableData.?);
    const pDst: [*]align(1) SCSTABLE_TYPE = @ptrCast(pbData);

    const nInterleaves: UINT32 = elementSize / interleaveSize;

    macros.SYMCRYPT_ASSERT(groupSize == pScsTable.groupSize);
    macros.SYMCRYPT_ASSERT(interleaveSize == pScsTable.interleaveSize);
    macros.SYMCRYPT_ASSERT(cbData >= @sizeOf(SCSTABLE_TYPE) * GROUP_SIZE);
    macros.SYMCRYPT_ASSERT(cbData == pScsTable.elementSize);

    var i: UINT32 = 0;

    var mask0: SCSTABLE_TYPE = scsMaskEqual32(i + 0, iIndex);
    var mask1: SCSTABLE_TYPE = scsMaskEqual32(i + 1, iIndex);
    var mask2: SCSTABLE_TYPE = scsMaskEqual32(i + 2, iIndex);
    var mask3: SCSTABLE_TYPE = scsMaskEqual32(i + 3, iIndex);

    var j: UINT32 = nInterleaves;
    var pD: [*]align(1) SCSTABLE_TYPE = pDst;

    while (true) {
        pD[0] = (mask0 & pSrc[0]) | (mask1 & pSrc[4]) | (mask2 & pSrc[8]) | (mask3 & pSrc[12]);
        pD[1] = (mask0 & pSrc[1]) | (mask1 & pSrc[5]) | (mask2 & pSrc[9]) | (mask3 & pSrc[13]);
        pD[2] = (mask0 & pSrc[2]) | (mask1 & pSrc[6]) | (mask2 & pSrc[10]) | (mask3 & pSrc[14]);
        pD[3] = (mask0 & pSrc[3]) | (mask1 & pSrc[7]) | (mask2 & pSrc[11]) | (mask3 & pSrc[15]);
        pD += interleaveSize / @sizeOf(SCSTABLE_TYPE);
        pSrc += (interleaveSize * groupSize) / @sizeOf(SCSTABLE_TYPE);
        j -= 1;
        if (j == 0) break;
    }

    i += groupSize;

    while (i + groupSize <= nElements) {
        mask0 = scsMaskEqual32(i + 0, iIndex);
        mask1 = scsMaskEqual32(i + 1, iIndex);
        mask2 = scsMaskEqual32(i + 2, iIndex);
        mask3 = scsMaskEqual32(i + 3, iIndex);

        j = nInterleaves;
        pD = pDst;

        while (true) {
            pD[0] |= (mask0 & pSrc[0]) | (mask1 & pSrc[4]) | (mask2 & pSrc[8]) | (mask3 & pSrc[12]);
            pD[1] |= (mask0 & pSrc[1]) | (mask1 & pSrc[5]) | (mask2 & pSrc[9]) | (mask3 & pSrc[13]);
            pD[2] |= (mask0 & pSrc[2]) | (mask1 & pSrc[6]) | (mask2 & pSrc[10]) | (mask3 & pSrc[14]);
            pD[3] |= (mask0 & pSrc[3]) | (mask1 & pSrc[7]) | (mask2 & pSrc[11]) | (mask3 & pSrc[15]);
            pD += interleaveSize / @sizeOf(SCSTABLE_TYPE);
            pSrc += (interleaveSize * groupSize) / @sizeOf(SCSTABLE_TYPE);
            j -= 1;
            if (j == 0) break;
        }

        i += groupSize;
    }
}

pub fn symCryptScsTableLoad128XmmImpl(
    pScsTable: PSYMCRYPT_SCSTABLE,
    iIndex: UINT32,
    pbData: PBYTE,
    cbData: UINT32,
) callconv(types.SYMCRYPT_CALL) void {
    var nElements: UINT32 = pScsTable.nElements;

    macros.SYMCRYPT_ASSERT(
        cbData == 128 and
            pScsTable.elementSize == 128 and
            iIndex < pScsTable.nElements and
            pScsTable.groupSize == 1,
    );

    const V128 = @Vector(4, u32);
    var count: V128 = @splat(0);
    const ones: V128 = @splat(1);
    const entry: V128 = @splat(iIndex);

    var pSrc: [*]align(16) const V128 = @ptrCast(@alignCast(pScsTable.pbTableData.?));
    const pDst: [*]align(16) V128 = @ptrCast(@alignCast(pbData));

    var mask: V128 = @bitCast(@as(@Vector(4, i32), @intFromBool(count == entry)));
    count +%= ones;

    var r0: V128 = mask & pSrc[0];
    var r1: V128 = mask & pSrc[1];
    var r2: V128 = mask & pSrc[2];
    var r3: V128 = mask & pSrc[3];
    var r4: V128 = mask & pSrc[4];
    var r5: V128 = mask & pSrc[5];
    var r6: V128 = mask & pSrc[6];
    var r7: V128 = mask & pSrc[7];

    pSrc += 8;

    while (true) {
        nElements -= 1;
        if (nElements == 0) break;

        mask = @bitCast(@as(@Vector(4, i32), @intFromBool(count == entry)));
        count +%= ones;

        r0 |= mask & pSrc[0];
        r1 |= mask & pSrc[1];
        r2 |= mask & pSrc[2];
        r3 |= mask & pSrc[3];
        r4 |= mask & pSrc[4];
        r5 |= mask & pSrc[5];
        r6 |= mask & pSrc[6];
        r7 |= mask & pSrc[7];
        pSrc += 8;
    }

    pDst[0] = r0;
    pDst[1] = r1;
    pDst[2] = r2;
    pDst[3] = r3;
    pDst[4] = r4;
    pDst[5] = r5;
    pDst[6] = r6;
    pDst[7] = r7;
}

comptime {
    if (types.CPU_AMD64) {
        @export(&symCryptScsTableStore128XmmImpl, .{ .name = "SymCryptScsTableStore128Xmm" });
        @export(&symCryptScsTableLoad128XmmImpl, .{ .name = "SymCryptScsTableLoad128Xmm" });
    }
}

pub export fn SymCryptScsTableStore(
    pScsTable: PSYMCRYPT_SCSTABLE,
    iIndex: UINT32,
    pbData: PCBYTE,
    cbData: UINT32,
) callconv(types.SYMCRYPT_CALL) void {
    if (types.CPU_AMD64) {
        if (pScsTable.elementSize == 128) {
            symCryptScsTableStore128XmmImpl(pScsTable, iIndex, pbData, cbData);
        } else {
            SymCryptScsTableStoreC(pScsTable, iIndex, pbData, cbData);
        }
    } else {
        SymCryptScsTableStoreC(pScsTable, iIndex, pbData, cbData);
    }
}

pub export fn SymCryptScsTableLoad(
    pScsTable: PSYMCRYPT_SCSTABLE,
    iIndex: UINT32,
    pbData: PBYTE,
    cbData: UINT32,
) callconv(types.SYMCRYPT_CALL) void {
    if (types.CPU_AMD64) {
        if (pScsTable.elementSize == 128) {
            symCryptScsTableLoad128XmmImpl(pScsTable, iIndex, pbData, cbData);
        } else {
            SymCryptScsTableLoadC(pScsTable, iIndex, pbData, cbData);
        }
    } else {
        SymCryptScsTableLoadC(pScsTable, iIndex, pbData, cbData);
    }
}

pub export fn SymCryptScsTableWipe(
    pScsTable: PSYMCRYPT_SCSTABLE,
) callconv(types.SYMCRYPT_CALL) void {
    SymCryptWipe(@ptrCast(pScsTable.pbTableData), pScsTable.cbTableData);
}
