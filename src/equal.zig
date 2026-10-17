//
// equal.zig
// Memory comparison routine that is safe against side channels.
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

const types = @import("types.zig");
const macros = @import("macros.zig");

const BYTE = types.BYTE;
const PCBYTE = types.PCBYTE;
const SIZE_T = types.SIZE_T;
const UINT32 = types.UINT32;
const BOOLEAN = types.BOOLEAN;

pub export fn SymCryptEqual(
    pbSrc1: PCBYTE,
    pbSrc2: PCBYTE,
    cbBytes: SIZE_T,
) callconv(types.SYMCRYPT_CALL) BOOLEAN {
    var neq: UINT32 = 0;
    var p1: [*]const volatile BYTE = pbSrc1;
    var p2: [*]const volatile BYTE = pbSrc2;
    var remaining: SIZE_T = cbBytes;

    //
    // We use forced-access memory reads to ensure that the compiler doesn't get
    // smart and implement an early-out solution.
    //

    while (remaining >= 4) {
        neq |= macros.SYMCRYPT_FORCE_READ32(p1) ^ macros.SYMCRYPT_FORCE_READ32(p2);
        p1 += 4;
        p2 += 4;
        remaining -= 4;
    }

    // We have to deal with the remaining bytes using a separate accumulator to work around an issue in the ARM64 compiler.
    if (remaining > 0) {
        var b: BYTE = 0;
        while (remaining > 0) {
            b |= macros.SYMCRYPT_FORCE_READ8(p1) ^ macros.SYMCRYPT_FORCE_READ8(p2);
            p1 += 1;
            p2 += 1;
            remaining -= 1;
        }
        neq |= b;
    }

    return if (neq == 0) types.TRUE else types.FALSE;
}
