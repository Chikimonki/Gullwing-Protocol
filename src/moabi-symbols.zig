const std = @import("std");

// ============================================================
// ELF STRUCTURES
// ============================================================

const ELFMAG = [4]u8{ 0x7F, 'E', 'L', 'F' };

const Elf64_Ehdr = extern struct {
    e_ident: [16]u8,
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
};

const Elf64_Shdr = extern struct {
    sh_name: u32,
    sh_type: u32,
    sh_flags: u64,
    sh_addr: u64,
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    sh_info: u32,
    sh_addralign: u64,
    sh_entsize: u64,
};

const Elf64_Sym = extern struct {
    st_name: u32,
    st_info: u8,
    st_other: u8,
    st_shndx: u16,
    st_value: u64,
    st_size: u64,
};

// Section types
const SHT_NULL: u32 = 0;
const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const SHT_DYNSYM: u32 = 11;

// Symbol binding (upper 4 bits of st_info)
const STB_LOCAL: u8 = 0;
const STB_GLOBAL: u8 = 1;
const STB_WEAK: u8 = 2;

// Symbol type (lower 4 bits of st_info)
const STT_NOTYPE: u8 = 0;
const STT_OBJECT: u8 = 1;
const STT_FUNC: u8 = 2;
const STT_SECTION: u8 = 3;
const STT_FILE: u8 = 4;

// Special section indices
const SHN_UNDEF: u16 = 0;
const SHN_ABS: u16 = 0xfff1;
const SHN_COMMON: u16 = 0xfff2;

// ============================================================
// CAPABILITY CATEGORIES
// ============================================================

const Capability = enum {
    MEMORY,
    PROCESS,
    NETWORK,
    FILE_IO,
    CRYPTO,
    DYN_LOAD,
    PRIVILEGE,
    INFO_LEAK,
    SIGNAL,
    TIME,
    OTHER,

    fn label(self: Capability) []const u8 {
        return switch (self) {
            .MEMORY => "MEMORY    ",
            .PROCESS => "PROCESS   ",
            .NETWORK => "NETWORK   ",
            .FILE_IO => "FILE-IO   ",
            .CRYPTO => "CRYPTO    ",
            .DYN_LOAD => "DYN-LOAD  ",
            .PRIVILEGE => "PRIVILEGE ",
            .INFO_LEAK => "INFO-LEAK ",
            .SIGNAL => "SIGNAL    ",
            .TIME => "TIME      ",
            .OTHER => "          ",
        };
    }

    fn riskWeight(self: Capability) u8 {
        return switch (self) {
            .MEMORY => 2,
            .PROCESS => 3,
            .NETWORK => 3,
            .FILE_IO => 1,
            .CRYPTO => 1,
            .DYN_LOAD => 4,
            .PRIVILEGE => 4,
            .INFO_LEAK => 2,
            .SIGNAL => 1,
            .TIME => 0,
            .OTHER => 0,
        };
    }
};

const CapPattern = struct {
    prefix: []const u8,
    capability: Capability,
    description: []const u8,
};

const cap_patterns = [_]CapPattern{
    // Memory manipulation
    .{ .prefix = "mmap", .capability = .MEMORY, .description = "memory mapping" },
    .{ .prefix = "mprotect", .capability = .MEMORY, .description = "change memory protection" },
    .{ .prefix = "munmap", .capability = .MEMORY, .description = "unmap memory" },
    .{ .prefix = "brk", .capability = .MEMORY, .description = "change data segment size" },
    .{ .prefix = "mremap", .capability = .MEMORY, .description = "remap memory" },
    .{ .prefix = "malloc", .capability = .MEMORY, .description = "heap allocation" },
    .{ .prefix = "calloc", .capability = .MEMORY, .description = "heap allocation (zeroed)" },
    .{ .prefix = "realloc", .capability = .MEMORY, .description = "heap reallocation" },
    .{ .prefix = "free", .capability = .MEMORY, .description = "heap deallocation" },
    .{ .prefix = "memcpy", .capability = .MEMORY, .description = "memory copy" },
    .{ .prefix = "memmove", .capability = .MEMORY, .description = "memory move" },
    .{ .prefix = "memset", .capability = .MEMORY, .description = "memory set" },

    // Process control
    .{ .prefix = "fork", .capability = .PROCESS, .description = "create child process" },
    .{ .prefix = "vfork", .capability = .PROCESS, .description = "create child (shared memory)" },
    .{ .prefix = "clone", .capability = .PROCESS, .description = "create process/thread" },
    .{ .prefix = "execve", .capability = .PROCESS, .description = "execute program" },
    .{ .prefix = "execvp", .capability = .PROCESS, .description = "execute program (PATH)" },
    .{ .prefix = "execl", .capability = .PROCESS, .description = "execute program" },
    .{ .prefix = "system", .capability = .PROCESS, .description = "shell command execution" },
    .{ .prefix = "popen", .capability = .PROCESS, .description = "pipe to shell command" },
    .{ .prefix = "waitpid", .capability = .PROCESS, .description = "wait for child" },
    .{ .prefix = "kill", .capability = .PROCESS, .description = "send signal to process" },
    .{ .prefix = "ptrace", .capability = .PROCESS, .description = "process trace/debug" },
    .{ .prefix = "prctl", .capability = .PROCESS, .description = "process control" },

    // Network
    .{ .prefix = "socket", .capability = .NETWORK, .description = "create socket" },
    .{ .prefix = "connect", .capability = .NETWORK, .description = "connect to remote" },
    .{ .prefix = "bind", .capability = .NETWORK, .description = "bind to address" },
    .{ .prefix = "listen", .capability = .NETWORK, .description = "listen for connections" },
    .{ .prefix = "accept", .capability = .NETWORK, .description = "accept connection" },
    .{ .prefix = "sendto", .capability = .NETWORK, .description = "send data" },
    .{ .prefix = "recvfrom", .capability = .NETWORK, .description = "receive data" },
    .{ .prefix = "sendmsg", .capability = .NETWORK, .description = "send message" },
    .{ .prefix = "recvmsg", .capability = .NETWORK, .description = "receive message" },
    .{ .prefix = "getaddrinfo", .capability = .NETWORK, .description = "DNS resolution" },
    .{ .prefix = "gethostbyname", .capability = .NETWORK, .description = "DNS lookup" },
    .{ .prefix = "inet_", .capability = .NETWORK, .description = "IP address conversion" },
    .{ .prefix = "htons", .capability = .NETWORK, .description = "byte order conversion" },
    .{ .prefix = "ntohs", .capability = .NETWORK, .description = "byte order conversion" },

    // File I/O
    .{ .prefix = "open", .capability = .FILE_IO, .description = "open file" },
    .{ .prefix = "close", .capability = .FILE_IO, .description = "close descriptor" },
    .{ .prefix = "read", .capability = .FILE_IO, .description = "read from descriptor" },
    .{ .prefix = "write", .capability = .FILE_IO, .description = "write to descriptor" },
    .{ .prefix = "lseek", .capability = .FILE_IO, .description = "seek in file" },
    .{ .prefix = "stat", .capability = .FILE_IO, .description = "file status" },
    .{ .prefix = "fstat", .capability = .FILE_IO, .description = "file status (fd)" },
    .{ .prefix = "lstat", .capability = .FILE_IO, .description = "file status (link)" },
    .{ .prefix = "unlink", .capability = .FILE_IO, .description = "delete file" },
    .{ .prefix = "rename", .capability = .FILE_IO, .description = "rename file" },
    .{ .prefix = "chmod", .capability = .FILE_IO, .description = "change permissions" },
    .{ .prefix = "chown", .capability = .FILE_IO, .description = "change ownership" },
    .{ .prefix = "mkdir", .capability = .FILE_IO, .description = "create directory" },
    .{ .prefix = "rmdir", .capability = .FILE_IO, .description = "remove directory" },
    .{ .prefix = "opendir", .capability = .FILE_IO, .description = "open directory" },
    .{ .prefix = "readdir", .capability = .FILE_IO, .description = "read directory" },
    .{ .prefix = "fopen", .capability = .FILE_IO, .description = "open file (stdio)" },
    .{ .prefix = "fclose", .capability = .FILE_IO, .description = "close file (stdio)" },
    .{ .prefix = "fread", .capability = .FILE_IO, .description = "read file (stdio)" },
    .{ .prefix = "fwrite", .capability = .FILE_IO, .description = "write file (stdio)" },

    // Crypto / SSL
    .{ .prefix = "EVP_", .capability = .CRYPTO, .description = "OpenSSL crypto" },
    .{ .prefix = "SSL_", .capability = .CRYPTO, .description = "OpenSSL TLS" },
    .{ .prefix = "AES_", .capability = .CRYPTO, .description = "AES encryption" },
    .{ .prefix = "RSA_", .capability = .CRYPTO, .description = "RSA crypto" },
    .{ .prefix = "SHA1", .capability = .CRYPTO, .description = "SHA1 hash" },
    .{ .prefix = "SHA256", .capability = .CRYPTO, .description = "SHA256 hash" },
    .{ .prefix = "MD5", .capability = .CRYPTO, .description = "MD5 hash" },
    .{ .prefix = "HMAC", .capability = .CRYPTO, .description = "HMAC" },
    .{ .prefix = "crypt", .capability = .CRYPTO, .description = "password hashing" },

    // Dynamic loading — code injection vector
    .{ .prefix = "dlopen", .capability = .DYN_LOAD, .description = "load shared library at runtime" },
    .{ .prefix = "dlsym", .capability = .DYN_LOAD, .description = "resolve symbol at runtime" },
    .{ .prefix = "dlclose", .capability = .DYN_LOAD, .description = "unload shared library" },

    // Privilege
    .{ .prefix = "setuid", .capability = .PRIVILEGE, .description = "set user ID" },
    .{ .prefix = "setgid", .capability = .PRIVILEGE, .description = "set group ID" },
    .{ .prefix = "seteuid", .capability = .PRIVILEGE, .description = "set effective UID" },
    .{ .prefix = "setegid", .capability = .PRIVILEGE, .description = "set effective GID" },
    .{ .prefix = "setreuid", .capability = .PRIVILEGE, .description = "set real/effective UID" },
    .{ .prefix = "chroot", .capability = .PRIVILEGE, .description = "change root directory" },
    .{ .prefix = "capset", .capability = .PRIVILEGE, .description = "set capabilities" },

    // Information leak potential
    .{ .prefix = "getenv", .capability = .INFO_LEAK, .description = "read environment variable" },
    .{ .prefix = "getuid", .capability = .INFO_LEAK, .description = "get user ID" },
    .{ .prefix = "getpid", .capability = .INFO_LEAK, .description = "get process ID" },
    .{ .prefix = "uname", .capability = .INFO_LEAK, .description = "system information" },
    .{ .prefix = "gethostname", .capability = .INFO_LEAK, .description = "get hostname" },
    .{ .prefix = "getcwd", .capability = .INFO_LEAK, .description = "get working directory" },

    // Signals
    .{ .prefix = "signal", .capability = .SIGNAL, .description = "signal handler" },
    .{ .prefix = "sigaction", .capability = .SIGNAL, .description = "signal action" },
    .{ .prefix = "sigprocmask", .capability = .SIGNAL, .description = "signal mask" },
};

// ============================================================
// HELPERS
// ============================================================

fn ptrCast(comptime T: type, data: []const u8, offset: usize) ?*const T {
    if (offset + @sizeOf(T) > data.len) return null;
    return @ptrCast(@alignCast(data[offset..].ptr));
}

fn getSecName(data: []const u8, strtab_offset: u64, name_offset: u32) []const u8 {
    const start = @as(usize, @intCast(strtab_offset)) + @as(usize, name_offset);
    if (start >= data.len) return "<invalid>";
    var end = start;
    while (end < data.len and data[end] != 0) : (end += 1) {}
    if (end == start) return "<empty>";
    return data[start..end];
}

fn getSymName(data: []const u8, strtab_offset: usize, name_offset: u32) []const u8 {
    const start = strtab_offset + @as(usize, name_offset);
    if (start >= data.len) return "<invalid>";
    var end = start;
    while (end < data.len and data[end] != 0) : (end += 1) {}
    if (end == start) return "";
    return data[start..end];
}

fn symBinding(info: u8) u8 {
    return info >> 4;
}

fn symType(info: u8) u8 {
    return info & 0xf;
}

fn bindingStr(b: u8) []const u8 {
    return switch (b) {
        STB_LOCAL => "LOCAL ",
        STB_GLOBAL => "GLOBAL",
        STB_WEAK => "WEAK  ",
        else => "OTHER ",
    };
}

fn symTypeStr(t: u8) []const u8 {
    return switch (t) {
        STT_NOTYPE => "NOTYPE ",
        STT_OBJECT => "OBJECT ",
        STT_FUNC => "FUNC   ",
        STT_SECTION => "SECTION",
        STT_FILE => "FILE   ",
        else => "OTHER  ",
    };
}

fn startsWith(s: []const u8, prefix: []const u8) bool {
    if (s.len < prefix.len) return false;
    return std.mem.eql(u8, s[0..prefix.len], prefix);
}

fn classifySymbol(name: []const u8) ?CapPattern {
    for (cap_patterns) |pat| {
        if (startsWith(name, pat.prefix)) return pat;
    }
    return null;
}

// ============================================================
// MAIN
// ============================================================

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const stdout = std.io.getStdOut().writer();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var show_all = false;
    var path: ?[]const u8 = null;

    for (args[1..]) |arg| {
        if (std.mem.eql(u8, arg, "--all") or std.mem.eql(u8, arg, "-a")) {
            show_all = true;
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            try stdout.writeAll(
                \\Usage: moabi-symbols [options] <elf-binary>
                \\
                \\Options:
                \\  --all, -a    Show all symbols (not just categorised)
                \\  --help, -h   Show this help
                \\
            );
            return;
        } else {
            path = arg;
        }
    }

    if (path == null) {
        try stdout.writeAll("Error: No file specified. Use --help for usage.\n");
        std.process.exit(1);
    }

    // Read file
    const file = std.fs.cwd().openFile(path.?, .{}) catch |err| {
        try stdout.print("Error: Cannot open '{s}' ({s})\n", .{ path.?, @errorName(err) });
        std.process.exit(1);
    };
    defer file.close();

    const stat = try file.stat();
    const fsize = @as(usize, @intCast(stat.size));
    const data = try allocator.alloc(u8, fsize);
    defer allocator.free(data);
    _ = try file.readAll(data);

    // Validate
    if (data.len < @sizeOf(Elf64_Ehdr) or !std.mem.eql(u8, data[0..4], &ELFMAG)) {
        try stdout.writeAll("Error: Not a valid ELF file\n");
        std.process.exit(1);
    }

    const ehdr = ptrCast(Elf64_Ehdr, data, 0) orelse {
        try stdout.writeAll("Error: Cannot read ELF header\n");
        std.process.exit(1);
    };

    // Get section name string table
    var sec_strtab_offset: u64 = 0;
    if (ehdr.e_shstrndx < ehdr.e_shnum) {
        const off = @as(usize, @intCast(ehdr.e_shoff)) +
            @as(usize, ehdr.e_shstrndx) * @as(usize, ehdr.e_shentsize);
        if (ptrCast(Elf64_Shdr, data, off)) |shdr| {
            sec_strtab_offset = shdr.sh_offset;
        }
    }

    try stdout.writeAll("\n====================================================\n");
    try stdout.writeAll("  MOABI SYMBOL ANALYSER v0.1 (Zig 0.13.0)\n");
    try stdout.writeAll("====================================================\n\n");
    try stdout.print("File: {s}\n", .{path.?});
    try stdout.print("Size: {d} bytes\n\n", .{fsize});

    // Find symbol tables and their string tables
    var dynsym_shdr: ?*const Elf64_Shdr = null;
    var symtab_shdr: ?*const Elf64_Shdr = null;

    // We need to collect all sections to find linked string tables
    const SectionRef = struct {
        shdr: *const Elf64_Shdr,
        index: u16,
    };
    var all_sections = std.ArrayList(SectionRef).init(allocator);
    defer all_sections.deinit();

    var si: u16 = 0;
    while (si < ehdr.e_shnum) : (si += 1) {
        const off = @as(usize, @intCast(ehdr.e_shoff)) +
            @as(usize, si) * @as(usize, ehdr.e_shentsize);
        const shdr = ptrCast(Elf64_Shdr, data, off) orelse continue;

        try all_sections.append(.{ .shdr = shdr, .index = si });

        if (shdr.sh_type == SHT_DYNSYM) dynsym_shdr = shdr;
        if (shdr.sh_type == SHT_SYMTAB) symtab_shdr = shdr;
    }

    // Helper to get string table for a symbol table section
    const getLinkedStrtab = struct {
        fn call(sections: []const SectionRef, link: u32) ?usize {
            for (sections) |sec| {
                if (sec.index == @as(u16, @intCast(link)) and sec.shdr.sh_type == SHT_STRTAB) {
                    return @intCast(sec.shdr.sh_offset);
                }
            }
            return null;
        }
    }.call;

    // Track capabilities
    var cap_counts = [_]u32{0} ** 11;
    var total_imported: u32 = 0;
    var total_exported: u32 = 0;
    var total_local: u32 = 0;
    var dangerous_imports = std.ArrayList([]const u8).init(allocator);
    defer dangerous_imports.deinit();

    // Process a symbol table
    const processSymtab = struct {
        fn call(
            w: anytype,
            d: []const u8,
            shdr: *const Elf64_Shdr,
            sym_strtab_off: usize,
            table_name: []const u8,
            all: bool,
            caps: *[11]u32,
            imported: *u32,
            exported: *u32,
            local: *u32,
            dangerous: *std.ArrayList([]const u8),
        ) !void {
            const entry_size = if (shdr.sh_entsize > 0) @as(usize, @intCast(shdr.sh_entsize)) else @sizeOf(Elf64_Sym);
            const count = @as(usize, @intCast(shdr.sh_size)) / entry_size;

            try w.print("--- {s} ({d} symbols) ---\n", .{ table_name, count });
            try w.print("{s:<6} {s:<8} {s:<8} {s:<18} {s:<11} {s}\n", .{
                "Idx", "Bind", "Type", "Value", "Category", "Name",
            });
            try w.writeAll("-" ** 90 ++ "\n");

            var idx: usize = 0;
            while (idx < count) : (idx += 1) {
                const sym_off = @as(usize, @intCast(shdr.sh_offset)) + idx * entry_size;
                const sym = ptrCast(Elf64_Sym, d, sym_off) orelse continue;

                const name = getSymName(d, sym_strtab_off, sym.st_name);
                if (name.len == 0) continue;

                const binding = symBinding(sym.st_info);
                const stype = symType(sym.st_info);
                const is_import = (sym.st_shndx == SHN_UNDEF and binding == STB_GLOBAL);
                const is_export = (sym.st_shndx != SHN_UNDEF and binding == STB_GLOBAL);

                if (is_import) imported.* += 1;
                if (is_export) exported.* += 1;
                if (binding == STB_LOCAL) local.* += 1;

                // Classify
                const cap = classifySymbol(name);
                var cap_label: []const u8 = "";

                if (cap) |c| {
                    const ci: usize = switch (c.capability) {
                        .MEMORY => 0,
                        .PROCESS => 1,
                        .NETWORK => 2,
                        .FILE_IO => 3,
                        .CRYPTO => 4,
                        .DYN_LOAD => 5,
                        .PRIVILEGE => 6,
                        .INFO_LEAK => 7,
                        .SIGNAL => 8,
                        .TIME => 9,
                        .OTHER => 10,
                    };
                    caps[ci] += 1;
                    cap_label = c.capability.label();

                    // Track dangerous imports
                    if (is_import and c.capability.riskWeight() >= 3) {
                        try dangerous.append(name);
                    }
                }

                // Print
                const should_print = all or (cap != null) or is_import;
                if (should_print) {
                    const marker: []const u8 = if (is_import) ">> " else if (is_export) "<< " else "   ";
                    try w.print("{s}{d:<4} {s} {s} 0x{x:0>16} {s} {s}\n", .{
                        marker,
                        idx,
                        bindingStr(binding),
                        symTypeStr(stype),
                        sym.st_value,
                        cap_label,
                        name,
                    });
                }
            }
            try w.writeAll("\n");
        }
    }.call;

    // ---- DYNAMIC SYMBOL TABLE ----
    if (dynsym_shdr) |shdr| {
        const strtab_off = getLinkedStrtab(all_sections.items, shdr.sh_link) orelse 0;
        try processSymtab(
            stdout,
            data,
            shdr,
            strtab_off,
            "Dynamic Symbol Table (.dynsym)",
            show_all,
            &cap_counts,
            &total_imported,
            &total_exported,
            &total_local,
            &dangerous_imports,
        );
    } else {
        try stdout.writeAll("--- Dynamic Symbol Table ---\n");
        try stdout.writeAll("  NOT FOUND (statically linked?)\n\n");
    }

    // ---- STATIC SYMBOL TABLE ----
    if (symtab_shdr) |shdr| {
        const strtab_off = getLinkedStrtab(all_sections.items, shdr.sh_link) orelse 0;
        try processSymtab(
            stdout,
            data,
            shdr,
            strtab_off,
            "Static Symbol Table (.symtab)",
            show_all,
            &cap_counts,
            &total_imported,
            &total_exported,
            &total_local,
            &dangerous_imports,
        );
    } else {
        try stdout.writeAll("--- Static Symbol Table (.symtab) ---\n");
        try stdout.writeAll("  NOT FOUND — binary is STRIPPED\n");
        try stdout.writeAll("  ⚠  Stripped binaries hide internal function names.\n");
        try stdout.writeAll("     CRA compliance may require symbol information.\n\n");
    }

    // ---- CAPABILITY PROFILE ----
    try stdout.writeAll("--- Capability Profile ---\n");

    const cap_names = [_][]const u8{
        "Memory",    "Process",   "Network",  "File I/O",
        "Crypto",    "Dyn-Load",  "Privilege", "Info-Leak",
        "Signal",    "Time",      "Other",
    };
    const cap_enums = [_]Capability{
        .MEMORY, .PROCESS, .NETWORK, .FILE_IO,
        .CRYPTO, .DYN_LOAD, .PRIVILEGE, .INFO_LEAK,
        .SIGNAL, .TIME, .OTHER,
    };

    for (cap_names, 0..) |name, idx| {
        if (cap_counts[idx] > 0) {
            const weight = cap_enums[idx].riskWeight();
            const bar_len = @min(cap_counts[idx], 30);
            try stdout.print("  {s:<12} {d:>3} ", .{ name, cap_counts[idx] });
            var bi: u32 = 0;
            while (bi < bar_len) : (bi += 1) {
                const ch: u8 = if (weight >= 3) '!' else if (weight >= 2) '#' else '=';
                try stdout.writeByte(ch);
            }
            if (weight >= 3) {
                try stdout.writeAll(" ⚠ HIGH RISK");
            }
            try stdout.writeAll("\n");
        }
    }

    // ---- STATISTICS ----
    try stdout.writeAll("\n--- Symbol Statistics ---\n");
    try stdout.print("Imported (undefined):  {d}\n", .{total_imported});
    try stdout.print("Exported (defined):    {d}\n", .{total_exported});
    try stdout.print("Local:                 {d}\n", .{total_local});
    try stdout.print("Has .dynsym:           {s}\n", .{if (dynsym_shdr != null) "yes" else "NO"});
    try stdout.print("Has .symtab:           {s}\n", .{if (symtab_shdr != null) "yes" else "NO (stripped)"});

    // ---- DANGEROUS IMPORTS ----
    if (dangerous_imports.items.len > 0) {
        try stdout.writeAll("\n--- High-Risk Imports ---\n");
        for (dangerous_imports.items) |name| {
            const cap = classifySymbol(name);
            if (cap) |c| {
                try stdout.print("  ⚠  {s:<24} ({s})\n", .{ name, c.description });
            }
        }
    }

    // ---- RISK ASSESSMENT ----
    try stdout.writeAll("\n--- Risk Assessment ---\n");
    var risk_score: u32 = 0;

    if (symtab_shdr == null) {
        try stdout.writeAll("⚠  Binary is stripped — internal symbols hidden\n");
        risk_score += 2;
    }

    if (cap_counts[5] > 0) { // DYN_LOAD
        try stdout.writeAll("⚠  Dynamic loading capability (dlopen/dlsym) — can load arbitrary code\n");
        risk_score += 4;
    }

    if (cap_counts[6] > 0) { // PRIVILEGE
        try stdout.writeAll("⚠  Privilege manipulation functions imported\n");
        risk_score += 3;
    }

    if (cap_counts[1] > 0 and cap_counts[2] > 0) { // PROCESS + NETWORK
        try stdout.writeAll("⚠  Process control + Network = potential remote execution\n");
        risk_score += 3;
    }

    if (cap_counts[1] > 0 and cap_counts[0] > 0) { // PROCESS + MEMORY
        try stdout.writeAll("⚠  Process control + Memory manipulation = code injection potential\n");
        risk_score += 2;
    }

    if (cap_counts[2] > 0 and cap_counts[4] > 0) { // NETWORK + CRYPTO
        try stdout.writeAll("   Network + Crypto detected (may be legitimate TLS usage)\n");
        risk_score += 1;
    }

    try stdout.writeAll("\n");
    if (risk_score == 0) {
        try stdout.writeAll("Status: CLEAN — minimal capability footprint\n");
    } else if (risk_score <= 3) {
        try stdout.writeAll("Status: LOW RISK — standard capabilities for most binaries\n");
    } else if (risk_score <= 6) {
        try stdout.writeAll("Status: MEDIUM RISK — elevated capabilities, review recommended\n");
    } else {
        try stdout.writeAll("Status: HIGH RISK — significant capability surface, audit required\n");
    }

    try stdout.writeAll("\n");
}
