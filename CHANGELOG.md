# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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