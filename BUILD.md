## Prerequisites

SymCrypt is built using the [Zig](https://ziglang.org/) build system (`build.zig`):

- **Zig** >= 0.17.0
- **Python 3** (required to translate `.symcryptasm` assembly sources via `scripts/symcryptasm_processor.py`)

## Platform and Architecture Support

SymCrypt has portable C implementations of all supported functionality as well as hand-written assembly and SIMD intrinsic implementations of performance-critical functions.

### Supported Configurations

| Operating Environment | Architecture      | ASM enabled | Static libs (`symcrypt`, `symcrypt_plus`) | Unit tests (`symcryptunittest`) |
| --------------------- | ----------------- | ----------- | ----------------------------------------- | ------------------------------- |
| Linux user mode       | AMD64, ARM64      | ✅          | ✅                                        | ✅                              |
| Linux user mode       | x86               | ❌          | ✅                                        | ✅                              |
| macOS                 | ARM64             | ✅          | ✅                                        | ✅                              |
| macOS                 | AMD64             | ❌          | ✅                                        | ✅                              |
| Windows user mode     | AMD64, ARM64, x86 | ❌          | ✅                                        | ❌                              |

The ability to build SymCrypt on any particular platform or architecture, with or without ASM optimizations, does not
imply that it has been tested for or is actively supported by Microsoft on that platform/architecture. While we make
every effort to ensure that SymCrypt is reliable, stable and bug-free on every platform we run on, the code in this
repository and the binaries we release are provided *as is*, without warranty of any kind, express or implied, including
but not limited to the warranties of merchantability, fitness for a particular purpose and noninfringement
(see our [LICENSE](./LICENSE.txt)).

## Build Instructions

To build the SymCrypt static libraries (`libsymcrypt.a`, `libsymcrypt_plus.a`) and unit test executable (`symcryptunittest`) for the host platform:

```bash
zig build
```

For an optimized release build:

```bash
zig build -Doptimize=ReleaseSafe
```

After a successful build, artifacts are installed under `zig-out/` (or the directory passed to `--prefix`):

- `zig-out/lib/` — `libsymcrypt.a` and `libsymcrypt_plus.a` (or `.lib` on Windows targets)
- `zig-out/bin/` — `symcryptunittest` (built by default on Linux and native macOS)

### Build Options

Run `zig build --help` to view all project-specific options:

| Option | Default | Description |
|--------|---------|-------------|
| `-Doptimize=<mode>` | `Debug` | Optimization mode (`Debug`, `ReleaseSafe`, `ReleaseFast`, `ReleaseSmall`) |
| `-Dtarget=<triple>` | Host target | Target triple for native or cross-compilation |
| `-Dasm=<bool>` | `true` | Enable hand-written `.symcryptasm` assembly optimizations |
| `-Dfips=<bool>` | `true` | Enable FIPS self-test and entropy defines |
| `-Dunit-tests=<bool>` | `true` (Linux / native macOS) | Build the `symcryptunittest` executable |
| `-Dtest-args=<arg>` | Fast functional suite | Arguments forwarded to `symcryptunittest` during `zig build test` (repeatable) |

### Cross-Compilation

Zig's bundled C/C++ cross-compiler and sysroots allow cross-compiling SymCrypt static libraries from any host:

```bash
# Linux targets (static libraries + unit test executable)
zig build -Dtarget=x86_64-linux-gnu
zig build -Dtarget=aarch64-linux-gnu

# macOS targets (static libraries)
zig build -Dtarget=aarch64-macos
zig build -Dtarget=x86_64-macos

# Windows targets (static libraries)
zig build -Dtarget=x86_64-windows-gnu
zig build -Dtarget=aarch64-windows-gnu
```

## Running Tests

To build and run the functional unit test suite:

```bash
zig build test
```

To run the unit test suite in `ReleaseSafe` mode (which also enables asymmetric self-test stress loops):

```bash
zig build test -Doptimize=ReleaseSafe
```

To pass custom arguments to `symcryptunittest` (such as algorithm filters or `noperftests`):

```bash
zig build test -Dtest-args=noperftests -Dtest-args=+Sha256 -Dtest-args=+Aes
```

You can also invoke `./zig-out/bin/symcryptunittest` directly after running `zig build`. Run `./zig-out/bin/symcryptunittest -?` to list all supported flags, implementations, and algorithms.
