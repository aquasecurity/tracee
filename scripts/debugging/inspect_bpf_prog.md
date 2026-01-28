# eBPF Program Inspector

`inspect_bpf_prog.sh` is a comprehensive tool for inspecting, measuring, and analyzing eBPF programs in compiled BPF object files. It's particularly useful for understanding program sizes, tracking size changes between builds, and examining program assembly.

## Features

- **Measure program sizes** - Get instruction counts, slot usage, and byte sizes
- **Dump assembly** - View disassembled eBPF bytecode with optional source and line numbers
- **Compare builds** - Track size changes between baseline and new builds
- **Filter sections** - Focus on specific program types (e.g., all kprobes, XDP programs)
- **Section type reference** - List all BPF program types with their kernel constants and flags

## Quick Start

```bash
# Measure all eBPF programs (requires building tracee.bpf.o first)
./scripts/debugging/inspect_bpf_prog.sh

# Measure a specific program
./scripts/debugging/inspect_bpf_prog.sh kprobe/security_task_prctl

# Dump assembly for a program
./scripts/debugging/inspect_bpf_prog.sh -d kprobe/security_task_prctl

# Compare two builds
./scripts/debugging/inspect_bpf_prog.sh --compare old/tracee.bpf.o dist/tracee.bpf.o
```

## Common Workflows

### 1. Tracking Program Size During Development

When optimizing eBPF programs to fit within kernel verifier limits:

```bash
# Get baseline measurement
make bpf
./scripts/debugging/inspect_bpf_prog.sh kprobe/my_program > baseline.txt

# Make changes to your BPF code...

# Rebuild and measure again
make bpf
./scripts/debugging/inspect_bpf_prog.sh kprobe/my_program

# Or use the compare feature
./scripts/debugging/inspect_bpf_prog.sh --compare \
    baseline/tracee.bpf.o \
    dist/tracee.bpf.o \
    --match-section kprobe/my_program
```

**Example output:**
```
Section: kprobe/my_program
  Status: MODIFIED
  Size:            12345 -> 11890 (-455 bytes, -3.7%)
  Instruction cnt:   1543 ->  1486 (-57, -3.7%)
  Instruction slt:   1543 ->  1486 (-57, -3.7%)
```

### 2. Understanding Overall BPF Object Size

Get a summary of all programs and their contribution to the total size:

```bash
# Summary view with breakdown by program type
./scripts/debugging/inspect_bpf_prog.sh --summary

# Summary for specific program types
./scripts/debugging/inspect_bpf_prog.sh --summary --match-section kprobe
./scripts/debugging/inspect_bpf_prog.sh --summary --match-section raw_tracepoint
```

**Example output:**
```
=== Summary ===
Processed sections: 42
 - kprobe: 28 (892.5KiB)
 - raw_tracepoint: 10 (234.7KiB)
 - tracepoint: 4 (98.3KiB)
Total program size: 1254896 bytes (1.2MiB)
Total instruction count: 156862
Total instruction slots: 156862
Object file size: 2547392 bytes (2.4MiB)
```

### 3. Debugging Verifier Rejections

When the verifier rejects a program due to complexity limits:

```bash
# Get detailed size and instruction count
./scripts/debugging/inspect_bpf_prog.sh kprobe/problematic_program

# View assembly to understand program structure
./scripts/debugging/inspect_bpf_prog.sh -d kprobe/problematic_program | less

# View with source code context (requires debug info)
./scripts/debugging/inspect_bpf_prog.sh -d -s -l kprobe/problematic_program | less
```

The output shows:
- Total instructions vs. kernel limit (typically 1 million)
- Multi-slot instructions (e.g., ldimm64)
- Section size in bytes

### 4. Analyzing Size Impact of Changes

Before and after code refactoring or adding features:

```bash
# Build main branch version as baseline
git fetch origin main
git checkout origin/main
make bpf
cp dist/tracee.bpf.o /tmp/main-tracee.bpf.o

# Return to your branch, rebuild, and compare
git checkout -
make bpf
./scripts/debugging/inspect_bpf_prog.sh --compare \
    /tmp/main-tracee.bpf.o \
    dist/tracee.bpf.o
```

This shows which programs changed compared to main and by how much, helping you understand the size impact of your changes.

### 5. Exploring Kprobe or Other Program Types

List and analyze specific program types:

```bash
# List all available section types
./scripts/debugging/inspect_bpf_prog.sh --list-sections

# Measure all kprobe programs (includes kprobe, kretprobe, kprobe.multi, etc.)
./scripts/debugging/inspect_bpf_prog.sh --match-section 'kprobe/*'

# Measure just standard kprobe programs
./scripts/debugging/inspect_bpf_prog.sh --match-section kprobe

# Compare kprobe programs between builds
./scripts/debugging/inspect_bpf_prog.sh --compare \
    old/tracee.bpf.o \
    dist/tracee.bpf.o \
    --match-section 'kprobe/*'
```


## Command Reference

### Options

| Option | Description |
|--------|-------------|
| `-d, --dump` | Dump assembly/disassembly of the program |
| `-m, --measure` | Measure program size (explicit, default behavior) |
| `-a, --all` | Both dump and measure |
| `-s, --source` | Include source code in dump (requires debug info) |
| `-l, --lines` | Include line numbers in dump (requires debug info) |
| `--summary` | Show only summary (requires measuring all sections) |
| `--match-section PATTERN` | Filter sections by pattern (e.g., 'xdp', 'xdp/*', 'xdp/cpumap') |
| `--list-sections` | List all available BPF section types with program/attach types |
| `-c, --compare BASE NEW` | Compare measurements between two BPF object files |
| `-h, --help` | Show help message |

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `BPF_OBJ` | Path to BPF object file | `dist/tracee.bpf.o` |

### Pattern Matching

The `--match-section` option supports:
- **Simple patterns**: `xdp` matches all sections starting with "xdp" including aliases
- **Wildcard patterns**: `xdp/*` matches all XDP variants (xdp/cpumap, xdp/devmap, etc.)
- **Specific patterns**: `xdp/cpumap` matches only that specific section and its aliases

The tool handles libbpf section name aliases automatically (e.g., `tp` is an alias for `tracepoint`).

## Understanding the Output

### Measurement Output

```
=== Measurement of section: kprobe/security_task_prctl ===
Object file: dist/tracee.bpf.o
Program type: BPF_PROG_TYPE_KPROBE
Flags:        SEC_NONE

Results:
  Section size: 0x13010 (77840 bytes)
  Instruction count: 9730
  Total instruction slots: 9730 (section_size / 8)
```

- **Section size**: Bytes used by the program in the ELF file
- **Instruction count**: Number of instruction lines in disassembly
- **Instruction slots**: Actual 8-byte slots used (accounts for multi-slot instructions)
- **Program type**: Kernel BPF program type constant
- **Flags**: libbpf section definition flags (SEC_NONE, SEC_SLEEPABLE, etc.)

### Comparison Output

```
Section: kprobe/my_program
  Status: MODIFIED
  Size:            12345 -> 11890 (-455 bytes, -3.7%)
  Instruction cnt:   1543 ->  1486 (-57, -3.7%)
  Instruction slt:   1543 ->  1486 (-57, -3.7%)
```

- **Status**: NEW (only in new file), REMOVED (only in baseline), or MODIFIED
- **Size**: Change in bytes with percentage
- **Instruction cnt/slt**: Change in instruction count and slots

## Troubleshooting

### "BPF object file not found"

Build the BPF object first:
```bash
make bpf
```

### "Section not found"

List all available sections:
```bash
./scripts/debugging/inspect_bpf_prog.sh --summary
```

Or check section names in the object:
```bash
llvm-objdump -h dist/tracee.bpf.o | grep -E "kprobe|tracepoint|raw_tp"
```

### Source/line numbers not showing

The BPF object needs to be built with debug info:
```bash
# Check if debug info is present
llvm-objdump --section-headers dist/tracee.bpf.o | grep debug

# Ensure DEBUG=1 or similar build flag is set when building
```

## Required Tools

The script requires the following tools to be installed:

| Tool | Purpose | Installation |
|------|---------|--------------|
| `llvm-objdump` | Disassemble BPF object files and extract section information | Part of LLVM/Clang toolchain (`apt install llvm` or `dnf install llvm`) |
| `stat` | Get file sizes (cross-platform) | Pre-installed on most Linux systems (coreutils) |
| `awk` | Text processing and calculations | Pre-installed on most Linux systems (gawk) |
| `grep` | Pattern matching for section filtering | Pre-installed on most Linux systems |
| `sort` | Sort section names alphabetically | Pre-installed on most Linux systems (coreutils) |
| `tail` | Extract last lines for offset calculations | Pre-installed on most Linux systems (coreutils) |
| `numfmt` | Format byte sizes (optional, falls back to plain bytes) | Part of coreutils |

**Note**: The script automatically checks for required tools at startup and will exit with an error if any are missing.

### Related Tools

For additional BPF inspection and debugging:

- `bpftool prog dump xlated` - Dump loaded programs from kernel (runtime)
- `bpftool prog show` - Show currently loaded BPF programs
- `bpftool prog dump jited` - Dump JIT-compiled native code
