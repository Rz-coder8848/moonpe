# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.8.1] - 2026-10-24

### Added

- `--summary-only` for large recursive scans. JSON reports omit the per-file
  array and include `files_omitted: true`.
- Scan summaries distinguish skipped non-PE32/PE32+ images (including Win16 NE)
  from read or parse errors.
- The suite now contains 44 tests, including summary-only and skipped-file
  classification checks.

### Validated

- Full `System32` scan: 6584 files, 348 PE32, 6236 PE64, zero errors.
- Full `SysWOW64` scan: 3029 files, 3020 PE32, 3 PE64, 6 Win16 files skipped,
  zero errors.

## [0.8.0] - 2026-10-23

### Added

- Stable `--json` output for every single-file command. Address-like fields use
  hexadecimal strings so large values survive JavaScript consumers.
- Recursive `scan` command for `.exe`, `.dll`, `.sys`, `.ocx`, `.cpl` and
  `.scr` files, with per-file findings and PE32/PE64/error totals.
- ECMA-335 metadata decoding: `#~`/`#-` stream directories, table row counts,
  assembly identity, assembly references, type definitions/references, method
  definitions and member-reference names.
- Resource content decoding for `RT_STRING`, bitmap/icon dimensions,
  `GROUP_ICON` members, manifests and per-entry `VERSIONINFO`.
- All public table parsers are now exercised by truncation and 500-round
  mutation tests. The suite contains 42 tests on wasm and wasm-gc, including
  JSON and scan-report checks.

### Fixed

- COFF timestamps and PE32 image bases are unsigned bit patterns. Values above
  2 GiB no longer reject otherwise valid PE64 images.
- Metadata coded-index widths now reserve their tag bits, preventing table-row
  offsets from drifting in larger assemblies.

## [0.7.0] - 2026-10-23

### Added

- Every standard PE32 and PE32+ optional-header field is exposed, including the
  linker, OS/image/subsystem versions, checksum, stack/heap sizes, loader flags
  and the original data-directory count. PE32-only `BaseOfData` is represented
  as `None` on PE32+.
- `Pe::iat` walks each static and delay-load descriptor's IAT, returning the
  library, slot RVA, raw pointer-sized value and matching lookup-table symbol.
  This preserves the symbol-to-slot mapping and on-disk ordinal/VA bits.
- CLI `iat` command, and `all` now includes IAT output.
- Tests for PE32 and PE32+ IAT slots, an unbacked IAT table, and the complete
  optional-header layout; 35 tests total.

### Fixed

- Removed stray NUL bytes and a duplicated 0.1.0 heading from the changelog.

## [0.6.0] - 2026-10-22

### Added

- LoadConfig directory (`Pe::load_config`): security cookie, SafeSEH table and
  count, CFG check/dispatch/table pointers and `GuardFlags`, heap flags, code
  integrity entry. Every field is read through the declared `Size`, so older
  structures read as zero instead of running past the end.
- SafeSEH handler table (`Pe::safe_seh_handlers`): on x86 the handler RVAs are
  resolved from the recorded table; on x64 the API returns `None` rather than
  pretending the count is zero.
- Certificate table (`Pe::certificates`): `WIN_CERTIFICATE` entries with length,
  revision and type. Slot 4 is the one directory that stores a file offset
  instead of an RVA, and `resolved_directories` now handles that.
- `check` reports SafeSEH, CFG table size and certificate entry count.
- CLI `loadconfig` command; `info` shows the certificate entry count.
- Two tests for LoadConfig decoding and SafeSEH handler resolution; 31 total.

### Changed

- The README scope table no longer describes any standard directory as
  "address only": each of the 16 slots now has a declared semantic level.
## [0.5.0] - 2026-10-21

Feature-complete against the v1.0 checklist in the README. The numeric prefix
stays 0.x because mooncakes.io currently rejects 1.x versions.

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
