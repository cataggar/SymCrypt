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
    m_name: [*:0]u8,

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
};

extern fn scTestKatItemSetType(pKatItem: *anyopaque, itemType: c_int, line: i64) callconv(.c) void;
extern fn scTestKatItemSetCategory(pKatItem: *anyopaque, ptr: [*]const u8, len: usize) callconv(.c) void;
extern fn scTestKatItemClearData(pKatItem: *anyopaque, line: i64) callconv(.c) void;
extern fn scTestKatItemHasField(pKatItem: *const anyopaque, name_ptr: [*]const u8, name_len: usize) callconv(.c) c_int;
extern fn scTestKatItemAddData(
    pKatItem: *anyopaque,
    name_ptr: [*]const u8,
    name_len: usize,
    val_ptr: [*]const u8,
    val_len: usize,
    line: i64,
) callconv(.c) void;

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

pub export fn scTestKatGetItem(kat: *KatData, pKatItem: *anyopaque) callconv(.c) void {
    var inDataSet = false;
    while (true) {
        kat.skipSpace();
        if (kat.atEol()) {
            if (inDataSet) {
                kat.skipNewlines();
                scTestKatItemSetType(pKatItem, KAT_TYPE_DATASET, kat.m_line);
                break;
            } else {
                if (kat.isEmpty()) {
                    scTestKatItemSetType(pKatItem, KAT_TYPE_END, kat.m_line);
                    break;
                }
                kat.skipNewlines();
                continue;
            }
        }

        if (kat.next() == '[') {
            if (inDataSet) {
                h.fatal("Missing blank line before category [...] marker on line {d}", .{kat.m_line});
            }

            const pbStart = kat.m_pbData;
            const startLine = kat.m_line;
            while (!kat.atEol() and kat.next() != ']') {
                kat.advance();
            }

            if (kat.atEol()) {
                h.fatal("Unclosed '[' in line {d}", .{startLine});
            }

            const pbEnd = kat.m_pbData;
            kat.advance(); // skip ']'

            kat.skipSpace();
            if (!kat.atEol()) {
                h.fatal("Extra data after '[...]' in line {d}", .{kat.m_line});
            }

            scTestKatItemSetType(pKatItem, KAT_TYPE_CATEGORY, kat.m_line);
            const cat_len = (@intFromPtr(pbEnd) - @intFromPtr(pbStart)) - 1;
            scTestKatItemSetCategory(pKatItem, pbStart + 1, cat_len);

            kat.skipNewlines();
            break;
        }

        {
            const nameStart = kat.m_pbData;
            const startLine = kat.m_line;
            while (!kat.atEol() and kat.next() != '=') {
                kat.advance();
            }

            if (kat.atEol()) {
                h.fatal("Missing = in line {d}", .{startLine});
            }

            const nameEnd = kat.m_pbData;
            kat.advance(); // skip '='
            const dataStart = kat.m_pbData;

            while (!kat.atEol()) {
                kat.advance();
            }
            const dataEnd = kat.m_pbData;

            const raw_name = nameStart[0 .. @intFromPtr(nameEnd) - @intFromPtr(nameStart)];
            const raw_data = dataStart[0 .. @intFromPtr(dataEnd) - @intFromPtr(dataStart)];

            const name = stripAlloc(raw_name, false);
            defer std.heap.c_allocator.free(name);
            const data = stripAlloc(raw_data, true);
            defer std.heap.c_allocator.free(data);

            if (!inDataSet) {
                inDataSet = true;
                scTestKatItemClearData(pKatItem, kat.m_line);
            }

            for (name) |*ch| {
                ch.* = charToLower(ch.*);
            }

            if (scTestKatItemHasField(pKatItem, name.ptr, name.len) != 0) {
                h.fatal("Duplicate data field \"{s}\"in data set in line {d}", .{ name, kat.m_line });
            }

            scTestKatItemAddData(pKatItem, name.ptr, name.len, data.ptr, data.len, kat.m_line);

            if (!kat.isEmpty() and kat.next() == '\r') {
                kat.advance();
            }
            if (!kat.isEmpty() and kat.next() == '\n') {
                kat.advance();
            }
        }
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

extern fn scTestNewKatData(name: [*:0]u8, pbData: [*]const u8, cbData: usize) callconv(.c) *KatData;

pub export fn getCustomResource(resourceName: [*:0]u8, resourceType: [*:0]u8) callconv(.c) *KatData {
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
            if (std.mem.eql(u8, it.name, name)) {
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
