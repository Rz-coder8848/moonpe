# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-10-21

First stable release. The completion checklist in the README is fully met.

### Added

- Runtime-function table (`Pe::function_table`): entry count and RVA span from
  the exception directory.
- Bound-import module names (`Pe::bound_imports`).
- `entropy_range` and an in-place `Pe::section_entropy`, so a packed section is
  scanned without copying it first.
- Mutation fuzz test: 200 deterministic rewrites of a valid image must produce
  `PeError` or a parse, never a panic.
- `examples/release_check`: a runnable example that gates a release on the
  verdict.
- `docs/架构说明.md`: module map, data flow, invariants, performance numbers and
  known limitations.

### Changed

- 29 tests in total.
## [0.4.0] - 2026-10-21

### Added

- TLS directory (`Pe::tls`): callback count, zero-fill and raw-data sizes.
  Addresses are rebased in `Int64` because 64-bit image bases do not fit in a
  32-bit `Int`.
- CLR header (`Pe::clr`): runtime version string from the metadata root, plus
  metadata size, flags and entry-point token. `.NET` assemblies are recognised
  without decoding the metadata tables.
- Application manifest (`Pe::manifest`, `Pe::manifest_execution_level`): the
  raw XML and the `requestedExecutionLevel` value, so a release check can answer
  "does this binary ask for administrator rights".
- Three more tests: TLS callback counting, CLR runtime string, manifest
  execution level. 26 tests total.
## [0.3.0] - 2026-10-21

### Added

- Section entropy (`Pe::section_entropy`, `byte_entropy`): Shannon entropy in
  bits per byte, the cheapest signal that a section is packed or encrypted.
- `Pe::check`: a release / triage report that turns the parsed data into
  findings and a verdict (`ok`, `review`, `suspicious`).
  - writable-and-executable sections (high);
  - high-entropy sections (warning);
  - missing ASLR, NX, CFG and HIGH_ENTROPY_VA;
  - absence of an embedded certificate table (worded so catalog signing is not
    misreported);
  - delay-loaded dependency count;
  - loader / process-manipulation imports, reported as a capability, and only
    escalated when combined with writable-executable code or high entropy —
    `kernel32.dll` imports most of that list and must still come out `ok`;
  - TLS directory and CLR header presence.
- CLI `check` command.
- Three tests covering a hardened image (`ok`), a writable-executable section
  (`suspicious`) and a uniformly distributed section (`review`).
## [0.2.0] - 2026-10-21

### Added

- **Delay-load imports** (data directory 13), including both descriptor forms:
  RVA-based (`dlattrRva` set) and virtual-address-based (fields rebased against
  the image base). `shell32.dll` reports 138 delay-loaded libraries against 79
  static ones, so this is not an optional extra for dependency checks.
- Named, mapped data directories: all 16 slots with address, size and whether
  the range maps to file bytes (`Pe::resolved_directories`).
- Debug directory with CodeView `RSDS` / `NB10` decoding: PDB path, age and
  signature (`Pe::debug_entries`).
- Base relocation summary by fixup type (`Pe::relocations`).
- Resource tree enumeration (type / name / language) and `VERSIONINFO`
  decoding, including the `VS_FIXEDFILEINFO` version and the string table
  (`Pe::resources`, `Pe::version_info`).
- CLI commands: `debug`, `relocations`, `resources`; `imports` now also lists
  delay-loaded libraries and `info` shows PDB and version.
- `docs/对比说明.md`: the relationship to `xmyd0915/moonar`, a same-input
  comparison, the PE32/PE32+ scope table and the definition of "complete".

### Changed

- The README now lists a seven-item completion checklist instead of an open
  ended feature list.

## [0.1.0] - 2026-10-20

Initial development. The parser covered DOS/NT headers, the optional header for
PE32 and PE32+, the section table, RVA mapping, imports and exports, with 13
tests and a real `kernel32.dll` validation.
## [0.1.0] - 2026-10-20

Initial development.

### Added

- `Pe::parse`: reads a PE image from memory with bounds-checked reads.
  - DOS header (`MZ`, `e_lfanew`) and NT signature (`PE\0\0`).
  - COFF header (machine, section count, timestamp, characteristics).
  - Optional header for both PE32 (`0x10B`) and PE32+ (`0x20B`), including the
    64-bit image base and the widened stack/heap fields.
  - Data directories, capped by both the declared count and the declared
    optional-header size.
  - Section table with names, virtual/raw sizes, addresses and characteristics.
- `Pe::rva_to_offset`: RVA-to-file-offset mapping that rejects the zero-filled
  tail of a section instead of reading unrelated bytes.
- `Pe::imports`: import directory with per-library symbols, supporting both
  import-by-name and import-by-ordinal.
- `Pe::exports`: export directory including ordinal-only exports.
- `Pe::section`, `Pe::section_for_rva`, `Pe::section_bytes`, `Pe::bits`,
  `Pe::machine`, `Pe::subsystem`.
- `PeError` with byte offsets for every structural failure.
- `moonpe` CLI: `info`, `sections`, `imports`, `exports`, `all`.

### Notes

- The library package has no dependencies; only the CLI uses `moonbitlang/x`
  for file reading.
- Validated against the real `kernel32.dll` (PE64, 8 sections, 104 import
  libraries, 1697 exports).