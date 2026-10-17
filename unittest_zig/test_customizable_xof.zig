// Copyright (c) Microsoft Corporation. Licensed under the MIT license.

const std = @import("std");
const h = @import("main_harness.zig");
const kat = @import("kat.zig");
const rng = @import("rng.zig");
const rm = @import("result_merge.zig");

const MAX_CXOF_RESULT_SIZE: usize = 1024;
const MAX_CXOF_INPUT_BLOCK_SIZE: usize = 200;
const SYMCRYPT_SHA3_256_RESULT_SIZE: usize = 32;

extern fn SymCryptWipe(pbData: [*]u8, cbData: usize) callconv(.c) void;
extern fn SymCryptSha3_256Init(pState: *anyopaque) callconv(.c) void;
extern fn SymCryptSha3_256Append(pState: *anyopaque, pbData: [*]const u8, cbData: usize) callconv(.c) void;
extern fn SymCryptSha3_256Result(pState: *anyopaque, pbResult: [*]u8) callconv(.c) void;

extern fn scTestGetCustomizableXofImps(algNamePtr: [*]const u8, algNameLen: usize, outImps: [*]*anyopaque, maxImps: usize) callconv(.c) usize;
extern fn scTestAlgImpAddErrorKatFailure(pImp: *anyopaque, delta: u64) callconv(.c) void;
extern fn scTestResultMergeAddAlgImp(resMergeHandle: ?*anyopaque, pImp: *anyopaque, pbData: [*]const u8, cbData: usize) callconv(.c) void;

extern fn scTestCXofImpInputBlockLen(pImp: *anyopaque) callconv(.c) usize;
extern fn scTestCXofImpInit(pImp: *anyopaque, pbNstr: ?[*]const u8, cbNstr: usize, pbSstr: ?[*]const u8, cbSstr: usize) callconv(.c) void;
extern fn scTestCXofImpAppend(pImp: *anyopaque, pbData: ?[*]const u8, cbData: usize) callconv(.c) void;
extern fn scTestCXofImpResult(pImp: *anyopaque, pbResult: [*]u8, cbResult: usize) callconv(.c) void;
extern fn scTestCXofImpExtract(pImp: *anyopaque, pbResult: [*]u8, cbResult: usize, bWipe: u8) callconv(.c) void;
extern fn scTestCXofImpXof(pImp: *anyopaque, pbNstr: ?[*]const u8, cbNstr: usize, pbSstr: ?[*]const u8, cbSstr: usize, pbData: ?[*]const u8, cbData: usize, pbResult: [*]u8, cbResult: usize) callconv(.c) void;

const CustomizableXofMultiImp = struct {
    m_algorithmName: []u8,
    m_imps: std.ArrayListUnmanaged(*anyopaque) = .empty,
    m_comps: std.ArrayListUnmanaged(*anyopaque) = .empty,
    m_nErrorKatFailure: u64 = 0,

    fn initNew(algName: []const u8) ?*CustomizableXofMultiImp {
        var imp_buf: [64]*anyopaque = undefined;
        const count = scTestGetCustomizableXofImps(algName.ptr, algName.len, &imp_buf, imp_buf.len);
        if (count == 0) return null;

        const self = std.heap.c_allocator.create(CustomizableXofMultiImp) catch h.fatal("Out of memory", .{});
        self.* = .{
            .m_algorithmName = std.heap.c_allocator.dupe(u8, algName) catch h.fatal("Out of memory", .{}),
        };
        const n = @min(count, imp_buf.len);
        self.m_imps.appendSlice(std.heap.c_allocator, imp_buf[0..n]) catch h.fatal("Out of memory", .{});
        return self;
    }

    fn deinit(self: *CustomizableXofMultiImp) void {
        for (self.m_imps.items) |imp| {
            scTestAlgImpAddErrorKatFailure(imp, self.m_nErrorKatFailure);
        }
        self.m_imps.deinit(std.heap.c_allocator);
        self.m_comps.deinit(std.heap.c_allocator);
        std.heap.c_allocator.free(self.m_algorithmName);
        std.heap.c_allocator.destroy(self);
    }

    fn inputBlockLen(self: *CustomizableXofMultiImp) usize {
        var res: usize = std.math.maxInt(usize);
        for (self.m_imps.items) |imp| {
            const v = scTestCXofImpInputBlockLen(imp);
            h.check(res == std.math.maxInt(usize) or res == v, "Inconsistent input block len");
            res = v;
        }
        return res;
    }

    fn xof(
        self: *CustomizableXofMultiImp,
        pbNstr: ?[*]const u8,
        cbNstr: usize,
        pbSstr: ?[*]const u8,
        cbSstr: usize,
        pbData: ?[*]const u8,
        cbData: usize,
        pbResult: [*]u8,
        cbResult: usize,
    ) void {
        var buf: [MAX_CXOF_RESULT_SIZE]u8 = undefined;
        const res = rm.scTestResultMergeCreate();
        defer rm.scTestResultMergeDestroy(res);

        h.check(cbResult <= MAX_CXOF_RESULT_SIZE, "XOF result too large");

        for (self.m_imps.items) |imp| {
            SymCryptWipe(&buf, cbResult);
            scTestCXofImpXof(imp, pbNstr, cbNstr, pbSstr, cbSstr, pbData, cbData, &buf, cbResult);
            scTestResultMergeAddAlgImp(res, imp, &buf, cbResult);
        }

        rm.scTestResultMergeGetResult(res, pbResult, cbResult, 1);
    }

    fn init(
        self: *CustomizableXofMultiImp,
        pbNstr: ?[*]const u8,
        cbNstr: usize,
        pbSstr: ?[*]const u8,
        cbSstr: usize,
    ) void {
        self.m_comps.clearRetainingCapacity();
        for (self.m_imps.items) |imp| {
            self.m_comps.append(std.heap.c_allocator, imp) catch h.fatal("Out of memory", .{});
            scTestCXofImpInit(imp, pbNstr, cbNstr, pbSstr, cbSstr);
        }
    }

    fn append(self: *CustomizableXofMultiImp, pbData: ?[*]const u8, cbData: usize) void {
        for (self.m_comps.items) |imp| {
            scTestCXofImpAppend(imp, pbData, cbData);
        }
    }

    fn result(self: *CustomizableXofMultiImp, pbResult: [*]u8, cbResult: usize) void {
        var buf: [MAX_CXOF_RESULT_SIZE]u8 = undefined;
        const res = rm.scTestResultMergeCreate();
        defer rm.scTestResultMergeDestroy(res);

        h.check(cbResult <= MAX_CXOF_RESULT_SIZE, "Customizable XOF result too large");

        for (self.m_comps.items) |imp| {
            SymCryptWipe(&buf, cbResult);
            scTestCXofImpResult(imp, &buf, cbResult);
            scTestResultMergeAddAlgImp(res, imp, &buf, cbResult);
        }

        rm.scTestResultMergeGetResult(res, pbResult, cbResult, 1);
    }

    fn extract(self: *CustomizableXofMultiImp, pbResult: [*]u8, cbResult: usize, bWipe: bool) void {
        var buf: [MAX_CXOF_RESULT_SIZE]u8 = undefined;
        const res = rm.scTestResultMergeCreate();
        defer rm.scTestResultMergeDestroy(res);

        h.check(cbResult <= MAX_CXOF_RESULT_SIZE, "Customizable XOF result too large");

        for (self.m_comps.items) |imp| {
            SymCryptWipe(&buf, cbResult);
            scTestCXofImpExtract(imp, &buf, cbResult, if (bWipe) 1 else 0);
            scTestResultMergeAddAlgImp(res, imp, &buf, cbResult);
        }

        rm.scTestResultMergeGetResult(res, pbResult, cbResult, 1);
    }
};

fn testCustomizableXofSingle(
    pXof: *CustomizableXofMultiImp,
    pbNstr: [*]const u8,
    cbNstr: usize,
    pbSstr: [*]const u8,
    cbSstr: usize,
    pbData: [*]const u8,
    cbData: usize,
    pbResult: [*]const u8,
    cbResult: usize,
    line: i64,
) void {
    var res: [MAX_CXOF_RESULT_SIZE]u8 = undefined;
    h.check(cbResult <= MAX_CXOF_RESULT_SIZE, "Result len error");
    @memset(&res, 0);

    pXof.xof(pbNstr, cbNstr, pbSstr, cbSstr, pbData, cbData, &res, cbResult);
    if (!std.mem.eql(u8, res[0..cbResult], pbResult[0..cbResult])) {
        h.zprint("Wrong Customizable XOF result in line {d}. \nExpected ", .{line});
        h.printHex(pbResult[0..cbResult]);
        h.zprint("\nGot      ", .{});
        h.printHex(res[0..cbResult]);
        h.zprint("\n", .{});
        pXof.m_nErrorKatFailure += 1;
    }

    @memset(&res, 0);
    pXof.init(pbNstr, cbNstr, pbSstr, cbSstr);
    var pb: [*]const u8 = pbData;
    var bytesLeft = cbData;

    while (bytesLeft > 0) {
        const todo = rng.scTestRngSizetNonUniform(&rng.g_rng, bytesLeft + 1, 32, 2);
        pXof.append(pb, todo);
        pb += todo;
        bytesLeft -= todo;
    }

    var pbRes: [*]u8 = &res;
    bytesLeft = cbResult;
    while (bytesLeft > 0) {
        const todo = rng.scTestRngSizetNonUniform(&rng.g_rng, bytesLeft + 1, 32, 2);
        pXof.extract(pbRes, todo, false);
        pbRes += todo;
        bytesLeft -= todo;
    }

    if (!std.mem.eql(u8, res[0..cbResult], pbResult[0..cbResult])) {
        h.zprint("Wrong Customizable XOF result in line {d}. \nExpected ", .{line});
        h.printHex(pbResult[0..cbResult]);
        h.zprint("\nGot      ", .{});
        h.printHex(res[0..cbResult]);
        h.zprint("\n", .{});
        pXof.m_nErrorKatFailure += 1;
    }
}

fn testCustomizableXofRange(
    pXof: *CustomizableXofMultiImp,
    cbMessage: usize,
    cbNameStr: usize,
    cbCustomStr: usize,
    cbOutput: usize,
    pbResult: [*]const u8,
    cbResult: usize,
    line: i64,
) void {
    const MAX_INPUT_SIZE: usize = 3 * 200;
    var input: [MAX_INPUT_SIZE]u8 = undefined;
    var nameStr: [MAX_INPUT_SIZE]u8 = undefined;
    var customStr: [MAX_INPUT_SIZE]u8 = undefined;

    for (0..MAX_INPUT_SIZE) |i| {
        input[i] = @as(u8, @truncate(i)) | 0x80;
        nameStr[i] = @truncate('N' + i);
        customStr[i] = @truncate('S' + i);
    }

    h.check(cbMessage <= MAX_INPUT_SIZE, "Max Message size too large");
    h.check(cbNameStr <= MAX_INPUT_SIZE, "Max Function Name string size too large");
    h.check(cbCustomStr <= MAX_INPUT_SIZE, "Max Customization string size too large");
    h.check(cbOutput <= MAX_CXOF_RESULT_SIZE, "Output size too large");
    h.check(cbResult == SYMCRYPT_SHA3_256_RESULT_SIZE, "Result must be a SHA3-256 hash");

    var output: [MAX_CXOF_RESULT_SIZE]u8 = undefined;
    var result: [SYMCRYPT_SHA3_256_RESULT_SIZE]u8 = undefined;

    var sha3state: [512]u8 align(16) = undefined;
    SymCryptSha3_256Init(&sha3state);

    for (0..cbMessage + 1) |mlen| {
        for (0..cbNameStr + 1) |nlen| {
            for (0..cbCustomStr + 1) |slen| {
                pXof.xof(&nameStr, nlen, &customStr, slen, &input, mlen, &output, cbOutput);
                SymCryptSha3_256Append(&sha3state, &output, cbOutput);
            }
        }
    }

    SymCryptSha3_256Result(&sha3state, &result);

    if (!std.mem.eql(u8, result[0..cbResult], pbResult[0..cbResult])) {
        h.zprint("Wrong Customizable XOF Range test result in line {d}. \nExpected ", .{line});
        h.printHex(pbResult[0..cbResult]);
        h.zprint("\nGot      ", .{});
        h.printHex(result[0..cbResult]);
        h.zprint("\n", .{});
        pXof.m_nErrorKatFailure += 1;
    }
}

fn testCustomizableXofStateTransition(pXof: *CustomizableXofMultiImp, line: i64) void {
    const OUTPUT_SIZE: usize = 64;
    const FunctionName = "Function Name\x00";
    const CustomizationString = "Customization\x00";
    const Input = "abc\x00";

    var xofOutput: [OUTPUT_SIZE]u8 = @splat(0);
    var cxofOutput: [OUTPUT_SIZE]u8 = @splat(0);

    pXof.init(null, 0, null, 0);
    pXof.append(Input.ptr, Input.len);
    pXof.extract(&xofOutput, xofOutput.len, true);

    pXof.init(FunctionName.ptr, FunctionName.len, CustomizationString.ptr, CustomizationString.len);
    pXof.append(Input.ptr, Input.len);
    pXof.extract(&cxofOutput, cxofOutput.len, false);
    pXof.append(Input.ptr, Input.len);
    pXof.extract(&cxofOutput, cxofOutput.len, true);

    h.check3(std.mem.eql(u8, &xofOutput, &cxofOutput), "State transition error at line {d}", line);
}

fn testCustomizableXofKats() void {
    var katXof = kat.ZigKatReader.init("kat_cxof.dat");
    var katItem: kat.ZigKatItem = .{};
    defer katItem.deinit();

    var sep: []const u8 = "    ";
    var doneAnything = false;

    var pCXofMultiImp: ?*CustomizableXofMultiImp = null;
    defer if (pCXofMultiImp) |p| p.deinit();
    var skipData = true;

    while (true) {
        katXof.getKatItem(&katItem);
        if (katItem.type == kat.KAT_TYPE_END) break;

        if (katItem.type == kat.KAT_TYPE_CATEGORY) {
            if (pCXofMultiImp) |p| {
                p.deinit();
                pCXofMultiImp = null;
            }
            pCXofMultiImp = CustomizableXofMultiImp.initNew(katItem.categoryName);
            skipData = (pCXofMultiImp == null);
            if (!skipData) {
                h.ziprint("{s}{s}", .{ sep, katItem.categoryName });
                sep = ", ";
                doneAnything = true;

                testCustomizableXofStateTransition(pCXofMultiImp.?, katXof.kat.m_line);
            }
        }

        if (katItem.type == kat.KAT_TYPE_DATASET and !skipData) {
            const pCXof = pCXofMultiImp.?;
            if (katItem.isFieldPresent("range")) {
                var katMaxInputSize: usize = 0;
                var katMaxNameStrSize: usize = 0;
                var katMaxCustomStrSize: usize = 0;

                if (katItem.isFieldPresent("maxinputsize")) {
                    katMaxInputSize = @intCast(katItem.parseInteger("maxinputsize"));
                }
                if (katItem.isFieldPresent("maxnamestrsize")) {
                    katMaxNameStrSize = @intCast(katItem.parseInteger("maxnamestrsize"));
                }
                if (katItem.isFieldPresent("maxcustomstrsize")) {
                    katMaxCustomStrSize = @intCast(katItem.parseInteger("maxcustomstrsize"));
                }

                h.check3((katMaxInputSize != 0 or katMaxNameStrSize != 0 or katMaxCustomStrSize != 0), "Invalid range test record ending at line {d}", katXof.kat.m_line);

                const katOutputSize: usize = @intCast(katItem.parseInteger("outputsize"));
                const katRange = katItem.parseData("range");
                defer std.heap.c_allocator.free(katRange);

                testCustomizableXofRange(pCXof, katMaxInputSize, katMaxNameStrSize, katMaxCustomStrSize, katOutputSize, katRange.ptr, katRange.len, katXof.kat.m_line);
                continue;
            }
            if (katItem.isFieldPresent("output")) {
                h.check3(katItem.dataItems.items.len == 5, "Invalid number of items in KAT record ending at line {d}", katXof.kat.m_line);
                const katMsg = katItem.parseData("msg");
                defer std.heap.c_allocator.free(katMsg);
                const katMD = katItem.parseData("output");
                defer std.heap.c_allocator.free(katMD);
                const katN = katItem.parseData("n");
                defer std.heap.c_allocator.free(katN);
                const katS = katItem.parseData("s");
                defer std.heap.c_allocator.free(katS);

                if (katItem.isFieldPresent("outputlen")) {
                    const katLen = @divTrunc(katItem.parseInteger("outputlen"), 8);
                    h.check3(katLen == @as(i64, @intCast(katMD.len)), "Outputlen does not match the length of the output at line {d}", katXof.kat.m_line);
                }

                testCustomizableXofSingle(pCXof, katN.ptr, katN.len, katS.ptr, katS.len, katMsg.ptr, katMsg.len, katMD.ptr, katMD.len, katXof.kat.m_line);
                continue;
            }
            h.fatal("Unknown data record ending at line {d}", .{katXof.kat.m_line});
        }
    }

    if (doneAnything) {
        h.ziprint("\n", .{});
    }
}

pub export fn testCustomizableXof() callconv(.c) void {
    testCustomizableXofKats();
}

pub export fn testCustomizableXofAlgorithms() callconv(.c) void {
    testCustomizableXof();
}
