//
// root.zig
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
// Root entry point for the Zig portion of SymCrypt.
// Force-references exported symbol modules so their symbols are emitted into libsymcrypt.a.
//

const std = @import("std");

pub const build_options = @import("build_options");
pub const types = @import("types.zig");
pub const macros = @import("macros.zig");
pub const equal = @import("equal.zig");
pub const data_accessors = @import("data_accessors.zig");
pub const fatal_intercept = @import("fatal_intercept.zig");
pub const selftest = @import("selftest.zig");
pub const scs_table = @import("scs_table.zig");
pub const scs_tools = @import("scs_tools.zig");
pub const recoding = @import("recoding.zig");

comptime {
    _ = build_options;
    _ = types;
    _ = macros;
    _ = equal;
    _ = data_accessors;
    _ = fatal_intercept;
    _ = selftest;
    _ = scs_table;
    _ = scs_tools;
    _ = recoding;

    // Compile-time sanity checks on core types, masks, rotations, and magic constants.
    std.debug.assert(@sizeOf(types.SYMCRYPT_ERROR) == @sizeOf(c_int));
    std.debug.assert(@backingInt(types.SYMCRYPT_ERROR.SYMCRYPT_NO_ERROR) == 0);
    std.debug.assert(@backingInt(types.SYMCRYPT_ERROR.SYMCRYPT_WRONG_KEY_SIZE) == 0x8001);
    std.debug.assert(@backingInt(types.SYMCRYPT_ERROR.SYMCRYPT_HBS_PUBLIC_ROOT_MISMATCH) == 0x8015);
    std.debug.assert(@sizeOf(types.SYMCRYPT_UINT32_MAP) == 8);
    std.debug.assert(@alignOf(types.SYMCRYPT_HASH) == types.SYMCRYPT_ALIGN_VALUE);

    std.debug.assert(macros.MASK32_ZERO(0) == 0xffffffff);
    std.debug.assert(macros.MASK32_ZERO(1) == 0);
    std.debug.assert(macros.MASK32_NONZERO(0) == 0);
    std.debug.assert(macros.MASK32_NONZERO(1) == 0xffffffff);
    std.debug.assert(macros.MASK32_EQ(42, 42) == 0xffffffff);
    std.debug.assert(macros.MASK32_EQ(42, 43) == 0);
    std.debug.assert(macros.MASK32_LT(5, 10) == 0xffffffff);
    std.debug.assert(macros.MASK32_LT(10, 5) == 0);
    std.debug.assert(macros.MASK32_LT(10, 10) == 0);

    std.debug.assert(macros.ROL32(0x12345678, 8) == 0x34567812);
    std.debug.assert(macros.ROR32(0x12345678, 8) == 0x78123456);
    std.debug.assert(macros.multiCharConstant("S1mv") == 0x53316d76);
    std.debug.assert(macros.multiCharConstant("magc") == 0x6d616763);
}
