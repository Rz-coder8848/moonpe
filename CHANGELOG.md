# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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