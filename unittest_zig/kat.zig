// Copyright (c) Microsoft Corporation. Licensed under the MIT license.

const std = @import("std");
const h = @import("main_harness.zig");

pub const KAT_TYPE_CATEGORY: c_int = 0;
pub const KAT_TYPE_DATASET: c_int = 1;
pub const KAT_TYPE_END: c_int = 2;

pub const KatData = extern struct {
    m_pbStart: [*]const u8,
    m_pbData: [*]const u8,
    m_pbEnd: [*]const u8,
    m_line: i64,
    m_name: [*:0]const u8,

    fn isEmpty(self: *const KatData) bool {
        return @intFromPtr(self.m_pbData) >= @intFromPtr(self.m_pbEnd);
    }

    fn next(self: *const KatData) u8 {
        return self.m_pbData[0];
    }

    fn advance(self: *KatData) void {
        if (!self.isEmpty()) {
            if (self.next() == '\n') {
                self.m_line += 1;
            }
            self.m_pbData += 1;
        }
    }

    fn atEol(self: *const KatData) bool {
        if (self.isEmpty()) {
            return true;
        }
        const cbLookback: usize = @intFromPtr(self.m_pbData) - @intFromPtr(self.m_pbStart);
        const start = self.m_pbStart;

        if (self.next() == '\r' and (cbLookback < 1 or start[cbLookback - 1] != '\\')) {
            return true;
        } else if (self.next() == '\n') {
            if ((cbLookback < 2 or start[cbLookback - 1] != '\r' or start[cbLookback - 2] != '\\') and
                (cbLookback < 1 or start[cbLookback - 1] != '\\'))
            {
                return true;
            }
        }
        return false;
    }

    fn skipSpace(self: *KatData) void {
        while (!self.isEmpty() and (self.next() == ' ' or self.next() == '\t')) {
            self.advance();
        }
        if (!self.isEmpty() and self.next() == '#') {
            while (!self.atEol()) {
                self.advance();
            }
        }
    }

    fn skipNewlines(self: *KatData) void {
        while (!self.isEmpty() and self.atEol()) {
            self.advance();
        }
    }

    pub fn init(name: []const u8, pbData: [*]const u8, cbData: usize) KatData {
        _ = name;
        return .{
            .m_pbStart = pbData,
            .m_pbData = pbData,
            .m_pbEnd = pbData + cbData,
            .m_line = 1,
            .m_name = @constCast(""),
        };
    }

    pub fn getKatItem(self: *KatData, item: *KatItem) void {
        item.deinitDataItems();
        item.itemType = KAT_TYPE_END;
        item.line = self.m_line;
        item.nDataItems = 0;

        var inDataSet = false;
        while (true) {
            self.skipSpace();
            if (self.atEol()) {
                if (inDataSet) {
                    self.skipNewlines();
                    item.itemType = KAT_TYPE_DATASET;
                    item.line = self.m_line;
                    break;
                } else {
                    if (self.isEmpty()) {
                        item.itemType = KAT_TYPE_END;
                        item.line = self.m_line;
                        break;
                    }
                    self.skipNewlines();
                    continue;
                }
            }

            if (self.next() == '[') {
                if (inDataSet) {
                    h.fatal("Missing blank line before category [...] marker on line {d}", .{self.m_line});
                }

                const pbStart = self.m_pbData;
                const startLine = self.m_line;
                while (!self.atEol() and self.next() != ']') {
                    self.advance();
                }

                if (self.atEol()) {
                    h.fatal("Unclosed '[' in line {d}", .{startLine});
                }

                const pbEnd = self.m_pbData;
                self.advance(); // skip ']'

                self.skipSpace();
                if (!self.atEol()) {
                    h.fatal("Extra data after '[...]' in line {d}", .{self.m_line});
                }

                item.itemType = KAT_TYPE_CATEGORY;
                item.line = self.m_line;
                const cat_len = (@intFromPtr(pbEnd) - @intFromPtr(pbStart)) - 1;
                const copy_len = @min(cat_len, item.catBuf.len);
                @memcpy(item.catBuf[0..copy_len], (pbStart + 1)[0..copy_len]);
                item.catLen = copy_len;

                self.skipNewlines();
                break;
            }

            {
                const nameStart = self.m_pbData;
                const startLine = self.m_line;
                while (!self.atEol() and self.next() != '=') {
                    self.advance();
                }

                if (self.atEol()) {
                    h.fatal("Missing = in line {d}", .{startLine});
                }

                const nameEnd = self.m_pbData;
                self.advance(); // skip '='
                const dataStart = self.m_pbData;

                while (!self.atEol()) {
                    self.advance();
                }
                const dataEnd = self.m_pbData;

                const raw_name = nameStart[0 .. @intFromPtr(nameEnd) - @intFromPtr(nameStart)];
                const raw_data = dataStart[0 .. @intFromPtr(dataEnd) - @intFromPtr(dataStart)];

                const name = stripAlloc(raw_name, false);
                defer std.heap.c_allocator.free(name);
                const data = stripAlloc(raw_data, true);

                if (!inDataSet) {
                    inDataSet = true;
                    item.itemType = KAT_TYPE_DATASET;
                    item.line = self.m_line;
                    item.nDataItems = 0;
                }

                for (name) |*ch| {
                    ch.* = charToLower(ch.*);
                }

                if (katIsFieldPresent(item, name)) {
                    h.fatal("Duplicate data field \"{s}\" in data set in line {d}", .{ name, self.m_line });
                }

                h.check(item.nDataItems < item.dataItems.len, "Too many data items in KAT record");
                var di = &item.dataItems[item.nDataItems];
                const nlen = @min(name.len, di.nameBuf.len);
                @memcpy(di.nameBuf[0..nlen], name[0..nlen]);
                di.nameLen = nlen;
                di.dataPtr = data.ptr;
                di.dataLen = data.len;
                di.line = self.m_line;
                item.nDataItems += 1;

                if (!self.isEmpty() and self.next() == '\r') {
                    self.advance();
                }
                if (!self.isEmpty() and self.next() == '\n') {
                    self.advance();
                }
            }
        }
    }
};

pub const BString = struct {
    pbData: [*]u8,
    cbData: usize,

    pub fn deinit(self: *const BString) void {
        scTestKatFreeParsedData(self.pbData, self.cbData);
    }
};

pub const KatDataItem = struct {
    nameBuf: [64]u8 = undefined,
    nameLen: usize = 0,
    dataPtr: [*]u8 = undefined,
    dataLen: usize = 0,
    line: i64 = 0,

    pub fn nameSlice(self: *const KatDataItem) []const u8 {
        return self.nameBuf[0..self.nameLen];
    }

    pub fn dataSlice(self: *const KatDataItem) []const u8 {
        return self.dataPtr[0..self.dataLen];
    }
};

pub const KatItem = struct {
    itemType: c_int = KAT_TYPE_END,
    line: i64 = 0,
    catBuf: [128]u8 = undefined,
    catLen: usize = 0,
    dataItems: [32]KatDataItem = undefined,
    nDataItems: usize = 0,

    pub fn categoryName(self: *const KatItem) []const u8 {
        return self.catBuf[0..self.catLen];
    }

    pub fn deinitDataItems(self: *KatItem) void {
        for (0..self.nDataItems) |i| {
            const di = &self.dataItems[i];
            std.heap.c_allocator.free(di.dataPtr[0..di.dataLen]);
        }
        self.nDataItems = 0;
    }
};

pub fn findDataItem(item: *const KatItem, name: []const u8) ?*const KatDataItem {
    for (0..item.nDataItems) |i| {
        const di = &item.dataItems[i];
        if (std.ascii.eqlIgnoreCase(di.nameSlice(), name)) {
            return di;
        }
    }
    return null;
}

pub fn katIsFieldPresent(item: *const KatItem, name: []const u8) bool {
    return findDataItem(item, name) != null;
}

pub fn katParseData(item: *const KatItem, name: []const u8) BString {
    const di = findDataItem(item, name) orelse {
        h.fatal("Could not find dataset field \"{s}\" in dataset at line {d}", .{ name, item.line });
    };
    var outLen: usize = 0;
    const ptr = scTestKatParseDataRaw(di.dataPtr, di.dataLen, di.line, &outLen);
    return .{ .pbData = ptr, .cbData = outLen };
}

pub fn katParseInteger(item: *const KatItem, name: []const u8) i64 {
    const di = findDataItem(item, name) orelse {
        h.fatal("Could not find dataset field \"{s}\" in dataset at line {d}", .{ name, item.line });
    };
    const s = di.dataSlice();
    if (std.mem.startsWith(u8, s, "0x") or std.mem.startsWith(u8, s, "0X")) {
        const u = std.fmt.parseInt(u64, s[2..], 16) catch 0;
        return @bitCast(u);
    } else {
        return std.fmt.parseInt(i64, s, 10) catch 0;
    }
}

pub export fn charToLower(c: u8) callconv(.c) u8 {
    if (c >= 'A' and c <= 'Z') {
        return c + ('a' - 'A');
    }
    return c;
}

fn stripAlloc(strIn: []const u8, stripAll: bool) []u8 {
    if (stripAll and std.mem.indexOfScalar(u8, strIn, '"') == null) {
        var list: std.ArrayListUnmanaged(u8) = .empty;
        for (strIn) |ch| {
            if (ch != ' ' and ch != '\t' and ch != '\r' and ch != '\n' and ch != '\\') {
                list.append(std.heap.c_allocator, ch) catch h.fatal("Out of memory", .{});
            }
        }
        return list.toOwnedSlice(std.heap.c_allocator) catch h.fatal("Out of memory", .{});
    } else {
        var s = strIn;
        while (s.len > 0 and (s[0] == ' ' or s[0] == '\t')) {
            s = s[1..];
        }
        while (s.len > 0 and (s[s.len - 1] == ' ' or s[s.len - 1] == '\t')) {
            s = s[0 .. s.len - 1];
        }
        return std.heap.c_allocator.dupe(u8, s) catch h.fatal("Out of memory", .{});
    }
}

fn hexToNibble(ch: u8, line: i64) u8 {
    if (ch >= '0' and ch <= '9') {
        return ch - '0';
    }
    if (ch >= 'a' and ch <= 'f') {
        return ch - 'a' + 10;
    }
    if (ch >= 'A' and ch <= 'F') {
        return ch - 'A' + 10;
    }
    h.fatal("Invalid hex character in line {d}", .{line});
}

fn hexToByte(pbStr: [*]const u8, line: i64) u8 {
    return (hexToNibble(pbStr[0], line) << 4) + hexToNibble(pbStr[1], line);
}

fn parseDataSlice(data: []const u8, line: i64) []u8 {
    const len = data.len;
    if (len > 1 and data[0] == '"' and data[len - 1] == '"') {
        return std.heap.c_allocator.dupe(u8, data[1 .. len - 1]) catch h.fatal("Out of memory", .{});
    }

    if (std.mem.startsWith(u8, data, "repeat")) {
        const iOpen = std.mem.indexOfScalar(u8, data, '(');
        const iClose = std.mem.indexOfScalar(u8, data, ')');
        if (iOpen == null or iClose == null or iOpen.? + 1 >= iClose.?) {
            h.fatal("Wrong parenthesis in repeat format, line {d} = {s}", .{ line, data });
        }

        const repeatSub = data[iOpen.? + 1 .. @min(data.len, iOpen.? + 1 + iClose.?)];
        const repeatStr = stripAlloc(repeatSub, true);
        defer std.heap.c_allocator.free(repeatStr);

        var repValue: usize = 0;
        for (repeatStr) |ch| {
            if (ch >= '0' and ch <= '9') {
                repValue = repValue * 10 + (ch - '0');
            } else {
                break;
            }
        }

        const restStr = stripAlloc(data[iClose.? + 1 ..], true);
        defer std.heap.c_allocator.free(restStr);

        const repData = parseDataSlice(restStr, line);
        defer std.heap.c_allocator.free(repData);

        const repLen = repData.len;
        const pResult = std.heap.c_allocator.alloc(u8, repLen * repValue) catch h.fatal("Out of memory", .{});
        for (0..repValue) |i| {
            @memcpy(pResult[i * repLen .. (i + 1) * repLen], repData);
        }
        return pResult;
    }

    if ((len & 1) != 0) {
        h.fatal("Hex data has odd number of characters in line {d}", .{line});
    }

    const result = std.heap.c_allocator.alloc(u8, len / 2) catch h.fatal("Out of memory", .{});
    for (0..len / 2) |i| {
        result[i] = hexToByte(data[2 * i ..].ptr, line);
    }
    return result;
}

pub export fn scTestKatParseDataRaw(
    val_ptr: [*]const u8,
    val_len: usize,
    line: i64,
    out_len: *usize,
) callconv(.c) [*]u8 {
    const parsed = parseDataSlice(val_ptr[0..val_len], line);
    out_len.* = parsed.len;
    if (parsed.len == 0) {
        std.heap.c_allocator.free(parsed);
        const dummy = std.heap.c_allocator.alloc(u8, 1) catch h.fatal("Out of memory", .{});
        return dummy.ptr;
    }
    return parsed.ptr;
}

pub export fn scTestKatFreeParsedData(ptr: [*]u8, len: usize) callconv(.c) void {
    const actual_len = if (len == 0) 1 else len;
    std.heap.c_allocator.free(ptr[0..actual_len]);
}

pub export fn scTestKatParseIntegerRaw(
    data_ptr: [*:0]const u8,
) callconv(.c) i64 {
    const s = std.mem.span(data_ptr);
    if (std.mem.startsWith(u8, s, "0x")) {
        const u = std.fmt.parseInt(u64, s[2..], 16) catch 0;
        return @bitCast(u);
    } else {
        return std.fmt.parseInt(i64, s, 10) catch 0;
    }
}

const EmbeddedKat = struct {
    name: []const u8,
    data: []const u8,
};

const embedded_kats = [_]EmbeddedKat{
    .{ .name = "kat_IEEE802_11SaeCustom.dat", .data = @embedFile("kat_IEEE802_11SaeCustom.dat") },
    .{ .name = "kat_authenc.dat", .data = @embedFile("kat_authenc.dat") },
    .{ .name = "kat_blockcipher.dat", .data = @embedFile("kat_blockcipher.dat") },
    .{ .name = "kat_composite_kem.dat", .data = @embedFile("kat_composite_kem.dat") },
    .{ .name = "kat_composite_mldsa.dat", .data = @embedFile("kat_composite_mldsa.dat") },
    .{ .name = "kat_cxof.dat", .data = @embedFile("kat_cxof.dat") },
    .{ .name = "kat_dh.dat", .data = @embedFile("kat_dh.dat") },
    .{ .name = "kat_dsa.dat", .data = @embedFile("kat_dsa.dat") },
    .{ .name = "kat_ecdsa.dat", .data = @embedFile("kat_ecdsa.dat") },
    .{ .name = "kat_hash.dat", .data = @embedFile("kat_hash.dat") },
    .{ .name = "kat_hash_long.dat", .data = @embedFile("kat_hash_long.dat") },
    .{ .name = "kat_hbs.dat", .data = @embedFile("kat_hbs.dat") },
    .{ .name = "kat_hpke.dat", .data = @embedFile("kat_hpke.dat") },
    .{ .name = "kat_kdf.dat", .data = @embedFile("kat_kdf.dat") },
    .{ .name = "kat_kem.dat", .data = @embedFile("kat_kem.dat") },
    .{ .name = "kat_keywrap.dat", .data = @embedFile("kat_keywrap.dat") },
    .{ .name = "kat_kmac.dat", .data = @embedFile("kat_kmac.dat") },
    .{ .name = "kat_mac.dat", .data = @embedFile("kat_mac.dat") },
    .{ .name = "kat_pqdsa.dat", .data = @embedFile("kat_pqdsa.dat") },
    .{ .name = "kat_rng.dat", .data = @embedFile("kat_rng.dat") },
    .{ .name = "kat_rsaenc.dat", .data = @embedFile("kat_rsaenc.dat") },
    .{ .name = "kat_rsasign.dat", .data = @embedFile("kat_rsasign.dat") },
    .{ .name = "kat_streamcipher.dat", .data = @embedFile("kat_streamcipher.dat") },
    .{ .name = "kat_xof.dat", .data = @embedFile("kat_xof.dat") },
    .{ .name = "kat_xts.dat", .data = @embedFile("kat_xts.dat") },
};

pub export fn scTestNewKatData(name: [*:0]const u8, pbData: [*]const u8, cbData: usize) callconv(.c) *KatData {
    const kd = std.heap.c_allocator.create(KatData) catch h.fatal("Out of memory", .{});
    kd.* = .{
        .m_pbStart = pbData,
        .m_pbData = pbData,
        .m_pbEnd = pbData + cbData,
        .m_line = 1,
        .m_name = name,
    };
    return kd;
}

pub export fn getCustomResource(resourceName: [*:0]const u8, resourceType: [*:0]const u8) callconv(.c) ?*KatData {
    _ = resourceType;
    const req = std.mem.span(resourceName);
    for (embedded_kats) |entry| {
        if (std.ascii.eqlIgnoreCase(req, entry.name)) {
            return scTestNewKatData(resourceName, entry.data.ptr, entry.data.len);
        }
    }
    h.fatal("Could not locate resource {s}", .{req});
}

pub const ZigKatDataItem = struct {
    name: []u8,
    data: []u8,
    line: i64,
};

pub const ZigKatItem = struct {
    type: c_int = KAT_TYPE_END,
    categoryName: []u8 = &.{},
    dataItems: std.ArrayListUnmanaged(ZigKatDataItem) = .empty,
    line: i64 = 1,

    pub fn clearData(self: *ZigKatItem, line: i64) void {
        for (self.dataItems.items) |it| {
            std.heap.c_allocator.free(it.name);
            std.heap.c_allocator.free(it.data);
        }
        self.dataItems.clearRetainingCapacity();
        self.line = line;
        self.type = KAT_TYPE_DATASET;
    }

    pub fn deinit(self: *ZigKatItem) void {
        self.clearData(0);
        self.dataItems.deinit(std.heap.c_allocator);
        if (self.categoryName.len > 0) {
            std.heap.c_allocator.free(self.categoryName);
            self.categoryName = &.{};
        }
    }

    pub fn findDataItem(self: *const ZigKatItem, name: []const u8) ?*const ZigKatDataItem {
        for (self.dataItems.items) |*it| {
            if (std.ascii.eqlIgnoreCase(it.name, name)) {
                return it;
            }
        }
        return null;
    }

    pub fn isFieldPresent(self: *const ZigKatItem, name: []const u8) bool {
        return self.findDataItem(name) != null;
    }

    pub fn parseData(self: *const ZigKatItem, name: []const u8) []u8 {
        const it = self.findDataItem(name) orelse {
            h.fatal("Could not find dataset field \"{s}\" in dataset at line {d}", .{ name, self.line });
        };
        return parseDataSlice(it.data, it.line);
    }

    pub fn parseDataZ(self: *const ZigKatItem, name: []const u8) [:0]u8 {
        const raw = self.parseData(name);
        defer std.heap.c_allocator.free(raw);
        const out = std.heap.c_allocator.allocSentinel(u8, raw.len, 0) catch h.fatal("Out of memory", .{});
        @memcpy(out, raw);
        return out;
    }

    pub fn parseInteger(self: *const ZigKatItem, name: []const u8) i64 {
        const it = self.findDataItem(name) orelse {
            h.fatal("Could not find dataset field \"{s}\" in dataset at line {d}", .{ name, self.line });
        };
        const s = it.data;
        if (std.mem.startsWith(u8, s, "0x")) {
            const u = std.fmt.parseInt(u64, s[2..], 16) catch 0;
            return @bitCast(u);
        } else {
            return std.fmt.parseInt(i64, s, 10) catch 0;
        }
    }
};

pub const ZigKatReader = struct {
    kat: KatData,

    pub fn init(resourceName: []const u8) ZigKatReader {
        for (embedded_kats) |entry| {
            if (std.ascii.eqlIgnoreCase(resourceName, entry.name)) {
                return .{
                    .kat = .{
                        .m_pbStart = entry.data.ptr,
                        .m_pbData = entry.data.ptr,
                        .m_pbEnd = entry.data.ptr + entry.data.len,
                        .m_line = 1,
                        .m_name = @ptrCast(@constCast(entry.name.ptr)),
                    },
                };
            }
        }
        h.fatal("Could not locate resource {s}", .{resourceName});
    }

    pub fn getKatItem(self: *ZigKatReader, item: *ZigKatItem) void {
        var inDataSet = false;
        while (true) {
            self.kat.skipSpace();
            if (self.kat.atEol()) {
                if (inDataSet) {
                    self.kat.skipNewlines();
                    item.type = KAT_TYPE_DATASET;
                    item.line = self.kat.m_line;
                    break;
                } else {
                    if (self.kat.isEmpty()) {
                        item.type = KAT_TYPE_END;
                        item.line = self.kat.m_line;
                        break;
                    }
                    self.kat.skipNewlines();
                    continue;
                }
            }

            if (self.kat.next() == '[') {
                if (inDataSet) {
                    h.fatal("Missing blank line before category [...] marker on line {d}", .{self.kat.m_line});
                }

                const pbStart = self.kat.m_pbData;
                const startLine = self.kat.m_line;
                while (!self.kat.atEol() and self.kat.next() != ']') {
                    self.kat.advance();
                }

                if (self.kat.atEol()) {
                    h.fatal("Unclosed '[' in line {d}", .{startLine});
                }

                const pbEnd = self.kat.m_pbData;
                self.kat.advance(); // skip ']'

                self.kat.skipSpace();
                if (!self.kat.atEol()) {
                    h.fatal("Extra data after '[...]' in line {d}", .{self.kat.m_line});
                }

                item.type = KAT_TYPE_CATEGORY;
                item.line = self.kat.m_line;
                const cat_len = (@intFromPtr(pbEnd) - @intFromPtr(pbStart)) - 1;
                if (item.categoryName.len > 0) {
                    std.heap.c_allocator.free(item.categoryName);
                }
                item.categoryName = std.heap.c_allocator.dupe(u8, (pbStart + 1)[0..cat_len]) catch h.fatal("Out of memory", .{});

                self.kat.skipNewlines();
                break;
            }

            {
                const nameStart = self.kat.m_pbData;
                const startLine = self.kat.m_line;
                while (!self.kat.atEol() and self.kat.next() != '=') {
                    self.kat.advance();
                }

                if (self.kat.atEol()) {
                    h.fatal("Missing = in line {d}", .{startLine});
                }

                const nameEnd = self.kat.m_pbData;
                self.kat.advance(); // skip '='
                const dataStart = self.kat.m_pbData;

                while (!self.kat.atEol()) {
                    self.kat.advance();
                }
                const dataEnd = self.kat.m_pbData;

                const raw_name = nameStart[0 .. @intFromPtr(nameEnd) - @intFromPtr(nameStart)];
                const raw_data = dataStart[0 .. @intFromPtr(dataEnd) - @intFromPtr(dataStart)];

                const name = stripAlloc(raw_name, false);
                const data = stripAlloc(raw_data, true);

                if (!inDataSet) {
                    inDataSet = true;
                    item.clearData(self.kat.m_line);
                }

                for (name) |*ch| {
                    ch.* = charToLower(ch.*);
                }

                if (item.isFieldPresent(name)) {
                    h.fatal("Duplicate data field \"{s}\"in data set in line {d}", .{ name, self.kat.m_line });
                }

                item.dataItems.append(std.heap.c_allocator, .{
                    .name = name,
                    .data = data,
                    .line = self.kat.m_line,
                }) catch h.fatal("Out of memory", .{});

                if (!self.kat.isEmpty() and self.kat.next() == '\r') {
                    self.kat.advance();
                }
                if (!self.kat.isEmpty() and self.kat.next() == '\n') {
                    self.kat.advance();
                }
            }
        }
    }
};

pub fn findEmbeddedResource(name: []const u8) ?h.DataResource {
    const lookup = if (std.ascii.eqlIgnoreCase(name, "kat_rsa_sign.dat")) "kat_rsasign.dat" else name;
    for (embedded_kats) |entry| {
        if (std.ascii.eqlIgnoreCase(lookup, entry.name)) {
            return .{
                .name = entry.name,
                .pbData = entry.data.ptr,
                .cbData = entry.data.len,
            };
        }
    }
    return null;
}

pub export fn scTestKatDestroy(pKat: *KatData) callconv(.c) void {
    std.heap.c_allocator.destroy(pKat);
}

pub export fn scTestKatGetNextItem(pKat: *KatData, pItemVoid: *anyopaque) callconv(.c) void {
    const pItem: *ZigKatItem = @ptrCast(@alignCast(pItemVoid));
    var reader = ZigKatReader{ .kat = pKat.* };
    reader.getKatItem(pItem);
    pKat.* = reader.kat;
}

pub export fn scTestKatReportWrongData(
    algName: [*:0]const u8,
    dataDesc: [*:0]const u8,
    pbExpected: [*]const u8,
    cbExpected: usize,
    pbActual: [*]const u8,
    cbActual: usize,
    line: i64,
) callconv(.c) void {
    h.zprint("\nWrong {s} result ({s}) in line {d}. \nExpected ", .{ std.mem.span(algName), std.mem.span(dataDesc), line });
    h.printHex(pbExpected[0..cbExpected]);
    h.zprint("\nGot      ", .{});
    h.printHex(pbActual[0..cbActual]);
    h.ziprint("\n", .{});
}

pub export fn scTestKatItemCreate() callconv(.c) ?*anyopaque {
    const p = std.heap.c_allocator.create(ZigKatItem) catch return null;
    p.* = .{};
    return p;
}

pub export fn scTestKatItemDestroy(pItemVoid: *anyopaque) callconv(.c) void {
    const pItem: *ZigKatItem = @ptrCast(@alignCast(pItemVoid));
    pItem.deinit();
    std.heap.c_allocator.destroy(pItem);
}

pub export fn scTestKatItemType(pItemVoid: *const anyopaque) callconv(.c) c_int {
    const pItem: *const ZigKatItem = @ptrCast(@alignCast(pItemVoid));
    return pItem.type;
}

pub export fn scTestKatItemLine(pItemVoid: *const anyopaque) callconv(.c) i64 {
    const pItem: *const ZigKatItem = @ptrCast(@alignCast(pItemVoid));
    return pItem.line;
}

pub export fn scTestKatItemCategory(pItemVoid: *const anyopaque, pLen: *usize) callconv(.c) [*]const u8 {
    const pItem: *const ZigKatItem = @ptrCast(@alignCast(pItemVoid));
    pLen.* = pItem.categoryName.len;
    return if (pItem.categoryName.len > 0) pItem.categoryName.ptr else "";
}

pub export fn scTestKatItemDataCount(pItemVoid: *const anyopaque) callconv(.c) usize {
    const pItem: *const ZigKatItem = @ptrCast(@alignCast(pItemVoid));
    return pItem.dataItems.items.len;
}

pub export fn scTestKatIsFieldPresent(pItemVoid: *const anyopaque, name: [*:0]const u8) callconv(.c) u32 {
    const pItem: *const ZigKatItem = @ptrCast(@alignCast(pItemVoid));
    return if (pItem.isFieldPresent(std.mem.span(name))) 1 else 0;
}

pub export fn scTestKatParseInteger(pItemVoid: *const anyopaque, name: [*:0]const u8) callconv(.c) i64 {
    const pItem: *const ZigKatItem = @ptrCast(@alignCast(pItemVoid));
    return pItem.parseInteger(std.mem.span(name));
}

pub export fn scTestKatParseDataAlloc(pItemVoid: *const anyopaque, name: [*:0]const u8, pOutLen: *usize) callconv(.c) [*]u8 {
    const pItem: *const ZigKatItem = @ptrCast(@alignCast(pItemVoid));
    const it = pItem.findDataItem(std.mem.span(name)) orelse {
        h.fatal("Could not find dataset field \"{s}\" in dataset at line {d}", .{ std.mem.span(name), pItem.line });
    };
    return scTestKatParseDataRaw(it.data.ptr, it.data.len, it.line, pOutLen);
}
