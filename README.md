# moonpe

[![CI](https://github.com/Rz-coder8848/moonpe/actions/workflows/ci.yml/badge.svg)](https://github.com/Rz-coder8848/moonpe/actions)
[![mooncakes.io](https://img.shields.io/badge/mooncakes.io-Rz--coder8848%2Fmoonpe-8A2BE2)](https://mooncakes.io/packages/Rz-coder8848/moonpe)

A pure-MoonBit reader for **Windows PE/COFF images** — the format behind every
`.exe`, `.dll` and `.sys` on Windows. It reads the DOS/NT headers, the section
table, the import directory and the export directory, and reports malformed
input with the exact byte offset instead of panicking.

## Why this exists

MoonBit can already read Linux executables: `moonbit-community/elf` parses ELF
object files. There is nothing for the other half of the world. Every Windows
binary is a PE image, and tooling around those binaries — dependency checks,
plugin validation, supply-chain triage — currently has no MoonBit building block.

PE is also a format where "roughly right" is not enough. Offsets are relative to
sections rather than the file, some bytes exist in memory but not on disk, and
import tables mix name-based and ordinal-based references. Each of those is a
place where a naive reader silently returns wrong data.

## What is parsed

| Layer | Status |
| --- | --- |
| DOS header (`MZ`, `e_lfanew`) | ✅ |
| NT signature (`PE\0\0`) | ✅ |
| COFF header (machine, sections, timestamp, characteristics) | ✅ |
| Optional header, PE32 and PE32+ | ✅ |
| Data directories (up to 16) | ✅ |
| Section table (name, sizes, addresses, permissions) | ✅ |
| RVA → file offset (with zero-filled tail detection) | ✅ |
| Import directory, by name and by ordinal | ✅ |
| Export directory, named and ordinal-only | ✅ |
| CLI: `info`, `sections`, `imports`, `exports`, `all` | ✅ |

Explicitly **not** implemented in 0.1.0: execution, disassembly, signature
verification, `.NET` metadata, resources, delay-load imports, TLS callbacks and
relocations. They are listed here so the boundary is a decision rather than a
surprise.

## Install

```sh
moon add Rz-coder8848/moonpe
```

```moonbit
import { "Rz-coder8848/moonpe" @pe }
```

## Library usage

```moonbit
let pe = @pe.Pe::parse(bytes)

pe.bits()                 // 64
pe.machine()              // "AMD64"
pe.subsystem()            // "windows-console"
pe.optional.entry_point   // 0x2c5d0
pe.optional.image_base    // 0x180000000

for section in pe.sections {
  println(section.name + " " + section.permissions())   // ".text r-x"
}

for library in pe.imports() {
  println(library.name)                                 // "KERNEL32.dll"
  for entry in library.entries {
    match entry.name {
      Some(name) => println("  " + name)
      None => println("  ordinal " + entry.ordinal.unwrap())
    }
  }
}
```

Every function that can fail raises `PeError`, whose `message()` includes the
offset. There is no "best effort" mode: a truncated or inconsistent file is
rejected, because a partially parsed import table is worse than a loud failure.

## CLI

The command uses `moonbitlang/x` to read the file — the library itself has no
dependencies.

```sh
moon run cmd/moonpe --target js -- info C:/Windows/System32/kernel32.dll
```

```
file:      C:/Windows/System32/kernel32.dll
format:    PE64 at offset 0x80
machine:   AMD64
subsystem: windows-console (3)
image:     base 0x180000000
           size 0xcb000
entry:     0x2c5d0
sections:  8
imports:   104 libraries
exports:   1697 symbols
```

```sh
moon run cmd/moonpe --target js -- sections C:/Windows/System32/kernel32.dll
```

```
NAME             VADDR     VSIZE    RAWPTR   RAWSIZE  PERM
.text           0x1000   0x85014    0x1000   0x86000  r-x
.rdata         0x88000   0x385b0   0x88000   0x39000  r--
.data          0xc1000    0x16b8   0xc1000    0x1000  rw-
...
```

## Design notes

**Bounds-checked reads carry the offset.** `Reader::need` turns every overrun
into `OutOfBounds { offset, needed, available }`. The same applies to a bad
`e_lfanew`, a bogus optional-header magic, or a section table that declares more
entries than the file can hold.

**RVA mapping is not `rva + image_base`.** A section's `VirtualSize` and
`RawSize` differ; the bytes between them exist in memory (zero-filled by the
loader) but not in the file. `rva_to_offset` returns `None` for that tail rather
than reading whatever follows the section on disk.

**Ordinals are preserved.** Real DLLs export and import symbols by ordinal, and
a reader that only understands names drops those entries while reporting
success. Both directions support ordinal references.

**32-bit fields are read through `Int64` and range-checked.** The same source
must behave identically when compiled for a 32-bit `Int` target and a 64-bit
one; the reader rejects values above 2 GiB instead of letting them wrap
differently on each platform.

## Testing

Nine tests, all offline:

- A hand-built PE32 image with two sections, one import library (one named and
  one ordinal import) and an export directory with two named and one
  ordinal-only export.
- A hand-built PE32+ image exercising the widened optional header.
- Malformed inputs: missing `MZ`, missing `PE\0\0`, truncated headers, an
  `e_lfanew` pointing outside the file, empty input.
- A blackbox test that builds its own minimal image and only touches the public
  API.

```sh
moon test --target wasm-gc
```

The parser is also checked by hand against the real `kernel32.dll`
(PE64, 8 sections, 104 import libraries, 1697 exports).

## References

moonpe is an original implementation, not a port, and contains no third-party
code. Its behaviour is aligned with the published format documentation and with
the behaviour of established readers:

| Reference | Used for | License |
| --- | --- | --- |
| [PE format specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format) | header, section, import and export layouts | Microsoft documentation |
| [goblin](https://github.com/m4b/goblin) → `pe` module | behaviour cross-check (documentation only) | MIT |
| [pefile](https://github.com/erocarrera/pefile) | behaviour cross-check (documentation only) | MIT |

## License

Apache-2.0. See `LICENSE`.