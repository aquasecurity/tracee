//! syscaller — a low-noise, self-isolating syscall-EVENT trigger for tracee integration tests.
//!
//! It sets its own comm (so policies can scope by comm=) and then issues the requested syscalls.
//! A tracee syscall-name event fires at raw_tracepoint/sys_enter on ENTRY, before the syscall runs
//! and with no success check, so merely CALLING a syscall triggers its event - even with invalid
//! arguments that make the syscall fail harmlessly. That is what lets this tool trigger
//! destructive syscall events (reboot, delete_module, ...) safely: it calls them with arguments
//! that fail at validation (EINVAL/EFAULT/EBADF) so the destructive effect never lands, while the
//! event is still captured.
//!
//! Written against the raw std.os.linux syscall interface (no libc init, no threads) so its own
//! syscall footprint is tiny - unlike a Go binary, whose runtime does hundreds of clone/futex/mmap
//! syscalls that a comm-scoped policy would capture as noise.
//!
//! CLI (backward compatible with the previous Go tool):
//!   syscaller [--unshare] [--cgroup] [--fork-each] <comm> <spec>...
//!     <spec>       = <n>            issue syscall n with ZERO args (fires the syscall-name event)
//!                  = <n>:<strategy> strategy-driven args; strategy = zero | invalid | file
//!     --unshare    run in throwaway user/mount/pid/net/uts/ipc/cgroup namespaces (host-safe)
//!     --fork-each  run EVERY spec in its own fork+watchdog child (contains side effects; used by
//!                  the coverage sweep that triggers the whole syscall table)
//!
//! <n> is the ARCH-NATIVE syscall number (the Go test side resolves event name -> number via the
//! build-tagged pkg/events/core_{amd64,arm64}.go tables, so this tool does no translation).

const std = @import("std");
const linux = std.os.linux;

const Strategy = enum { zero, invalid, file };

// A poison value that is invalid as a pointer (non-canonical on x86_64), as an fd (-1 => EBADF),
// and as most flag/count args (=> EINVAL). Used by the `invalid` strategy so a destructive syscall
// fails at validation instead of doing anything.
const POISON: usize = std.math.maxInt(usize);

// rawSyscall6 issues syscall `number` with six args via std's arch-portable raw-syscall helper.
// std.os.linux.syscall6 is typed to the SYS enum, but the tool's whole purpose is to issue an
// arbitrary NUMBER (resolved on the Go side from tracee's arch syscall tables), so we @enumFromInt it
// - SYS is enum(usize) whose tag values ARE the syscall numbers, so every real syscall maps through.
// A number this Zig's SYS enum does not know (a syscall newer than the toolchain) is a safety-checked
// panic in ReleaseSafe: a clear abort, acceptable for a test tool driven by tracee's own table.
fn rawSyscall6(number: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize) usize {
    return linux.syscall6(@enumFromInt(number), a1, a2, a3, a4, a5, a6);
}

const Spec = struct {
    number: usize,
    strategy: Strategy,
};

const Options = struct {
    unshare: bool = false,
    cgroup: bool = false,
    fork_each: bool = false,
    comm: []const u8 = "",
    specs: []Spec = &.{},
};

fn die(comptime fmt: []const u8, args: anytype) noreturn {
    std.debug.print("syscaller: " ++ fmt ++ "\n", args);
    linux.exit(1);
}

// parseStrategy maps a CLI strategy name to a Strategy. The names ARE the enum tag names, so
// std.meta.stringToEnum does the lookup (and rejects anything else) with no hand-written table.
fn parseStrategy(s: []const u8) ?Strategy {
    return std.meta.stringToEnum(Strategy, s);
}

// setComm sets the calling thread's comm via prctl(PR_SET_NAME) so policies can scope by comm=.
// The name is truncated to 15 bytes + NUL by the kernel (TASK_COMM_LEN).
fn setComm(comm: []const u8) void {
    var buf: [16]u8 = std.mem.zeroes([16]u8);
    const n = @min(comm.len, 15);
    @memcpy(buf[0..n], comm[0..n]);
    _ = linux.prctl(@intFromEnum(linux.PR.SET_NAME), @intFromPtr(&buf), 0, 0, 0);
}

// MaxSpecs bounds the number of syscall specs one invocation carries. A fixed buffer keeps the tool
// allocator-free (no heap, matching its no-libc/no-runtime footprint). Sized above the full arch
// syscall table so the coverage sweep (every syscall event tracee defines) fits in one invocation.
const MaxSpecs = 1024;

// main takes std.process.Init.Minimal (Zig 0.16's entry model): argv arrives as init.args.vector.
// On Linux that Vector is []const [*:0]const u8, so we index it directly and std.mem.span each arg.
pub fn main(init: std.process.Init.Minimal) void {
    const argv = init.args.vector;

    var opts = Options{};
    var specs_buf: [MaxSpecs]Spec = undefined;
    var nspecs: usize = 0;

    var i: usize = 1;
    while (i < argv.len) : (i += 1) {
        const arg = std.mem.span(argv[i]);
        if (!std.mem.startsWith(u8, arg, "--")) break;
        if (std.mem.eql(u8, arg, "--unshare")) {
            opts.unshare = true;
        } else if (std.mem.eql(u8, arg, "--cgroup")) {
            opts.cgroup = true;
        } else if (std.mem.eql(u8, arg, "--fork-each")) {
            opts.fork_each = true;
        } else {
            die("unknown flag {s}", .{arg});
        }
    }
    if (i >= argv.len) {
        die("usage: syscaller [--unshare] [--cgroup] [--fork-each] <comm> <n[:strategy]>...", .{});
    }
    opts.comm = std.mem.span(argv[i]);
    i += 1;

    while (i < argv.len) : (i += 1) {
        const arg = std.mem.span(argv[i]);
        var strategy: Strategy = .zero;
        var numStr: []const u8 = arg;
        if (std.mem.indexOfScalar(u8, arg, ':')) |colon| {
            numStr = arg[0..colon];
            strategy = parseStrategy(arg[colon + 1 ..]) orelse die("unknown strategy in {s}", .{arg});
        }
        const number = std.fmt.parseInt(usize, numStr, 10) catch die("invalid syscall number {s}", .{numStr});
        if (nspecs >= specs_buf.len) die("too many syscalls (max {d})", .{specs_buf.len});
        specs_buf[nspecs] = .{ .number = number, .strategy = strategy };
        nspecs += 1;
    }
    opts.specs = specs_buf[0..nspecs];

    run(&opts);
    linux.exit(0);
}

// failed reports whether a raw linux syscall return encodes an error, decoding it with std's
// linux.errno (correctly limited to the -4095..-1 errno range - a naive `< 0` test would misread a
// high-address success return as failure). The fixed ops below use std.os.linux raw wrappers, which
// return the raw syscall result rather than an error union - matching the tool's no-libc design.
fn failed(rc: usize) bool {
    return linux.errno(rc) != .SUCCESS;
}

// writeStr writes s to fd, best-effort (the buffers here are tiny, so short writes are irrelevant).
fn writeStr(fd: i32, s: []const u8) void {
    _ = linux.write(fd, s.ptr, s.len);
}

// scratch holds the path to a scratch file used by the `file` strategy. Set up BEFORE setComm so
// the setup syscalls (mkdir/open/write) land under the ORIGINAL comm, not the scoped one.
var scratch_path: [64:0]u8 = undefined;
var scratch_ready = false;

fn setupScratch() void {
    const pid = linux.getpid();
    _ = std.fmt.bufPrintZ(&scratch_path, "/tmp/syscaller-scratch.{d}", .{pid}) catch return;
    // Create the file (so the file strategy's O_RDONLY openat succeeds and drives security_file_open).
    const rc = linux.openat(linux.AT.FDCWD, &scratch_path, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
    if (failed(rc)) return;
    const fd: i32 = @intCast(rc);
    writeStr(fd, "syscaller-scratch\n");
    _ = linux.close(fd);
    scratch_ready = true;
}

// doUnshare confines the process before it issues (possibly destructive) syscalls: a new user
// namespace plus fresh mount, pid, net, uts, ipc and cgroup namespaces. In the user namespace the
// caller is a mapped root with no privilege over the host, so a stray mount / kill / network op - or
// a sethostname / IPC op contained by the uts/ipc namespaces - cannot affect the host. The extra uts/
// ipc/cgroup namespaces matter for the coverage sweep, which triggers the whole syscall table.
// Entering the pid namespace requires a fork (the unsharing task stays in the old pid ns); the child
// runs the workload, the parent waits.
fn doUnshare() void {
    const uid = linux.getuid();
    const gid = linux.getgid();
    const flags: usize = linux.CLONE.NEWUSER | linux.CLONE.NEWNS | linux.CLONE.NEWPID |
        linux.CLONE.NEWNET | linux.CLONE.NEWUTS | linux.CLONE.NEWIPC | linux.CLONE.NEWCGROUP;
    if (failed(linux.unshare(flags))) {
        // Isolation is best-effort defense-in-depth; the invalid-args safety stands without it.
        std.debug.print("syscaller: unshare failed, continuing without isolation\n", .{});
        return;
    }
    writeFile("/proc/self/setgroups", "deny");
    writeFileFmt("/proc/self/uid_map", "0 {d} 1", .{uid});
    writeFileFmt("/proc/self/gid_map", "0 {d} 1", .{gid});

    // Fork to actually enter the new pid namespace; the child becomes pid 1 there.
    const forkrc = linux.fork();
    if (failed(forkrc)) return;
    if (forkrc != 0) {
        var status: u32 = 0;
        _ = linux.waitpid(@intCast(forkrc), &status, 0);
        linux.exit(0);
    }
    // child continues in the new namespaces
}

fn writeFile(path: [*:0]const u8, data: []const u8) void {
    const rc = linux.openat(linux.AT.FDCWD, path, .{ .ACCMODE = .WRONLY }, 0);
    if (failed(rc)) return;
    const fd: i32 = @intCast(rc);
    writeStr(fd, data);
    _ = linux.close(fd);
}

fn writeFileFmt(path: [*:0]const u8, comptime fmt: []const u8, args: anytype) void {
    var buf: [64]u8 = undefined;
    const s = std.fmt.bufPrint(&buf, fmt, args) catch return;
    writeFile(path, s);
}

// argsFor builds the six syscall arguments for a strategy.
fn argsFor(strategy: Strategy) [6]usize {
    return switch (strategy) {
        .zero => .{ 0, 0, 0, 0, 0, 0 },
        // Poison all args: bad as a pointer (EFAULT), an fd (-1 => EBADF) and most flag/count args
        // (EINVAL) - so a destructive syscall fails at validation and the effect never lands.
        .invalid => .{ POISON, POISON, POISON, POISON, POISON, POISON },
        // openat-shaped valid file open (AT_FDCWD, scratch path, O_RDONLY) - drives derived events
        // like security_file_open. AT_FDCWD (std's linux.AT.FDCWD) bit-cast to the usize the ABI passes.
        .file => .{ @as(usize, @bitCast(@as(isize, linux.AT.FDCWD))), @intFromPtr(&scratch_path), 0, 0, 0, 0 },
    };
}

// run drives the whole flow; split out so it can be exercised without linux.exit at the top level.
fn run(opts: *const Options) void {
    var needScratch = false;
    for (opts.specs) |s| {
        if (s.strategy == .file) needScratch = true;
    }
    if (needScratch) setupScratch();

    if (opts.unshare) doUnshare();

    setComm(opts.comm);

    for (opts.specs) |s| {
        const args = argsFor(s.strategy);
        // The invalid strategy ALWAYS forks (destructive/blocking/exit-class safety). --fork-each
        // extends that to every strategy, so the coverage sweep can trigger the whole syscall table:
        // a syscall with a process-local side effect (seccomp, close, umask, setsid, ptrace) is then
        // contained to a throwaway child and cannot poison the specs that follow. Without --fork-each,
        // zero/file run inline (matches the previous tool; no extra clone/exit under the comm).
        if (opts.fork_each or s.strategy == .invalid) {
            execWatched(s.number, args);
        } else {
            _ = rawSyscall6(s.number, args[0], args[1], args[2], args[3], args[4], args[5]);
        }
    }

    if (scratch_ready) _ = linux.unlink(&scratch_path);
}

// execWatched forks a child that issues the syscall and exits; the parent reaps it, killing it if
// it does not return within a short budget (any accidental blocker). exit-class syscalls are safe
// here too: only the child exits.
fn execWatched(number: usize, args: [6]usize) void {
    const forkrc = linux.fork();
    if (failed(forkrc)) {
        // Can't fork: fall back to inline (the invalid args still make it fail safely for the
        // common destructive syscalls; a rare blocker would hang - acceptable degradation).
        _ = rawSyscall6(number, args[0], args[1], args[2], args[3], args[4], args[5]);
        return;
    }
    if (forkrc == 0) {
        _ = rawSyscall6(number, args[0], args[1], args[2], args[3], args[4], args[5]);
        linux.exit(0);
    }
    // Parent: poll for up to ~100ms, then SIGKILL a stuck child.
    const pid: i32 = @intCast(forkrc);
    var waited_ns: u64 = 0;
    const budget_ns: u64 = 100 * std.time.ns_per_ms;
    const step_ns: u64 = 5 * std.time.ns_per_ms;
    while (waited_ns < budget_ns) : (waited_ns += step_ns) {
        var status: u32 = 0;
        if (linux.waitpid(pid, &status, linux.W.NOHANG) == @as(usize, @intCast(pid))) return;
        var ts = linux.timespec{ .sec = 0, .nsec = @intCast(step_ns) };
        _ = linux.nanosleep(&ts, null);
    }
    _ = linux.kill(pid, .KILL);
    var status: u32 = 0;
    _ = linux.waitpid(pid, &status, 0);
}

// --- unit tests (pure logic only; no syscalls issued, no root needed): `zig build test` ---

test "parseStrategy accepts the known names and rejects the rest" {
    try std.testing.expectEqual(Strategy.zero, parseStrategy("zero").?);
    try std.testing.expectEqual(Strategy.invalid, parseStrategy("invalid").?);
    try std.testing.expectEqual(Strategy.file, parseStrategy("file").?);
    try std.testing.expect(parseStrategy("bogus") == null);
    try std.testing.expect(parseStrategy("") == null);
}

test "argsFor: zero is all-zero, invalid is all-poison" {
    try std.testing.expectEqual([6]usize{ 0, 0, 0, 0, 0, 0 }, argsFor(.zero));
    try std.testing.expectEqual([6]usize{ POISON, POISON, POISON, POISON, POISON, POISON }, argsFor(.invalid));
}

test "argsFor: file is openat-shaped (AT_FDCWD, path, O_RDONLY)" {
    const a = argsFor(.file);
    try std.testing.expectEqual(@as(usize, @bitCast(@as(isize, linux.AT.FDCWD))), a[0]);
    try std.testing.expectEqual(@intFromPtr(&scratch_path), a[1]);
    try std.testing.expectEqual(@as(usize, 0), a[2]); // O_RDONLY
}

test "spec parse: <n> defaults to zero, <n>:<strategy> is honored" {
    // Mirror the arg-splitting done in main() without spawning a process.
    const cases = .{
        .{ .arg = "257", .num = 257, .strat = Strategy.zero },
        .{ .arg = "169:invalid", .num = 169, .strat = Strategy.invalid },
        .{ .arg = "257:file", .num = 257, .strat = Strategy.file },
        .{ .arg = "0:zero", .num = 0, .strat = Strategy.zero },
    };
    inline for (cases) |c| {
        var strategy: Strategy = .zero;
        var numStr: []const u8 = c.arg;
        if (std.mem.indexOfScalar(u8, c.arg, ':')) |colon| {
            numStr = c.arg[0..colon];
            strategy = parseStrategy(c.arg[colon + 1 ..]).?;
        }
        const number = try std.fmt.parseInt(usize, numStr, 10);
        try std.testing.expectEqual(@as(usize, c.num), number);
        try std.testing.expectEqual(c.strat, strategy);
    }
}
