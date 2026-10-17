// Copyright (c) Microsoft Corporation. Licensed under the MIT license.

const h = @import("main_harness.zig");
const sc = @import("sc_implementations.zig");
const tu = @import("testutil.zig");

extern fn SymCryptDeprecatedServiceIndicator(pbMethodName: ?[*]u8, cbMethodName: usize) callconv(.c) u32;

pub export fn testServiceIndicator() callconv(.c) void {
    var pbMethodName: [1]u8 = .{0};
    if (tu.hasDispatchSym("SymCryptDeprecatedServiceIndicator")) {
        _ = sc.callSymCrypt(
            "SymCryptDeprecatedServiceIndicator",
            *const fn (?[*]u8, usize) callconv(.c) u32,
            SymCryptDeprecatedServiceIndicator,
            .{ &pbMethodName, pbMethodName.len },
        );
        h.ziprint("    Tested SymCryptDeprecatedServiceIndicator.\n", .{});
    }
}
