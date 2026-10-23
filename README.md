# moonpe

[![CI](https://github.com/Rz-coder8848/moonpe/actions/workflows/ci.yml/badge.svg)](https://github.com/Rz-coder8848/moonpe/actions)
[![mooncakes.io](https://img.shields.io/badge/mooncakes.io-Rz--coder8848%2Fmoonpe-8A2BE2)](https://mooncakes.io/packages/Rz-coder8848/moonpe)

A pure-MoonBit reader for **Windows PE/COFF images** — the format behind every
`.exe`, `.dll` and `.sys` on Windows. It reads the DOS/NT headers, the section
table, imports (including **delay-loaded** ones), exports, debug records with
their PDB path, base relocations, the resource tree and `VERSIONINFO`, and it
reports malformed input with the exact byte offset instead of panicking.

## Why this exists

MoonBit can already read Linux executables: `moonbit-community/elf` parses ELF
object files. There is nothing for the other half of the world. Every Windows
binary is a PE image, and tooling around those binaries — dependency checks,
plugin validation, supply-chain triage — currently has no MoonBit building block.

PE is also a format where "roughly right" is not enough. Offsets are relative to
sections rather than the file, some bytes exist in memory but not on disk, and
import tables mix name-based and ordinal-based references. Each of those is a
place where a naive reader silently returns wrong data.

## Relationship to `xmyd0915/moonar`

`moonar` is an **ar / COFF archive** library: it handles `.a`, GNU thin archives
and Microsoft `.lib` static or import libraries. moonpe handles **PE images**
(`.exe` / `.dll` / `.sys`). They share only the 20-byte COFF file header and
40-byte section header that the format itself mandates; PE's DOS stub, optional
header, data directories, import/export tables and RVA mapping are absent from
moonar, and archive containers are absent from moonpe.

| Input | moonar 0.6.1 | moonpe |
| --- | --- | --- |
| `kernel32.dll` | `AR001 at byte 0: expected ar archive magic` | PE64, 8 sections, 104 import libraries, 3 delay-loaded, 1697 exports |
| `demo.a` | `0  118560  "bcheck.o"` | `bad signature at 0x0: expected the 'MZ' DOS signature` |

The full comparison, including the decisions a user can make from each output,
is in [`docs/对比说明.md`](docs/对比说明.md). The module layout and design
decisions are in [`docs/架构说明.md`](docs/架构说明.md), and
[`examples/release_check`](examples/release_check) is a runnable release gate.

## What is parsed

| Area | Status |
| --- | --- |
| DOS header (`MZ`, `e_lfanew`) and `PE\0\0` | ✅ |
| COFF header and every standard optional-header field, PE32 and PE32+ | ✅ |
| All 16 data directories, named and mapped to file offsets | ✅ |
| Section table (name, sizes, addresses, permissions) | ✅ |
| RVA → file offset, rejecting the zero-filled tail | ✅ |
| Imports by name and by ordinal | ✅ |
| Static and delay-loaded IAT slots with library, raw value and matching import | ✅ |
| **Delay-load imports**, RVA and VA descriptor forms | ✅ |
| Exports, including ordinal-only entries | ✅ |
| Debug directory, CodeView `RSDS`/`NB10`, PDB path and age | ✅ |
| Base relocations, counted by fixup type | ✅ |
| Section entropy and a release/triage check with a verdict | ✅ |
| TLS directory and callback count | ✅ |
| CLR header and .NET runtime version | ✅ |
| Application manifest and equestedExecutionLevel | ✅ |
| Resource tree (type / name / language) | ✅ |
| `VERSIONINFO`: file/product version and string table | ✅ |
| LoadConfig: security cookie, SafeSEH, CFG tables and flags | ✅ |
| Certificate table entries (presence and type, not verification) | ✅ |
| Exception function table and bound imports | ✅ summary |
| Architecture, GlobalPtr and the reserved slot | reserved by the PE specification |

Every directory the PE specification defines now has a declared semantic level:
fully parsed, summarised, or reserved by the specification itself. What is
**not** implemented at all: execution, disassembly, signature verification,
`.NET` metadata table decoding, and writing or patching images.

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

for library in pe.imports() {
  println(library.name)
}
for slot in pe.iat() {
  println(slot.library + " " + slot.slot_rva.to_string())
}
for library in pe.delay_imports() {     // the dependencies a naive reader misses
  println("delay: " + library.name)
}
for entry in pe.debug_entries() {
  println(entry.kind_name)
}
for resource in pe.resources() {
  println(resource.language.to_string())
}
match pe.version_info() {
  Some(info) => println(info.file_version)
  None => ()
}
```
## CLI

The command uses `moonbitlang/x` to read the file — the library itself has no
dependencies.

```sh
moon run cmd/moonpe --target js -- info C:/Windows/System32/kernel32.dll
```

```
file:      C:/Windows/System32/kernel32.dll
format:    PE64
machine:   AMD64
subsystem: windows-console
image:     base 0x180000000
           size 0xcb000
entry:     0x2c5d0
sections:  8
imports:   104 libraries
delay:     3 libraries
exports:   1697 symbols
pdb:       kernel32.pdb
version:   Microsoft® Windows® Operating System 10.0.26100.9444
```

Commands: `info`, `sections`, `imports`, `iat`, `exports`, `debug`,
`relocations`, `resources`, `loadconfig`, `check`, `all`.

```
$ moon run cmd/moonpe --target js -- resources C:/Windows/System32/kernel32.dll
TYPE              NAME          LANG  RVA/SIZE
MUI               1            0x409  0xc9458/200
VERSION           1            0x409  0xc90b0/932

$ moon run cmd/moonpe --target js -- relocations C:/Windows/System32/kernel32.dll
        PAGE  ENTRIES  DIR64  HIGHLOW  OTHER
     0x88000      218    217        0      0
     0x89000      222    222        0      0
...
```

$ moon run cmd/moonpe --target js -- check C:/Windows/System32/kernel32.dll
verdict:   ok
max entropy: 625 / 800
  [INFO] DELAY_IMPORTS     3 delay-loaded libraries; static-only dependency checks miss these
  [INFO] CAPABILITIES      imports CreateRemoteThreadEx, VirtualAllocEx, ... (loader APIs)
```

The check deliberately treats those imports as a *capability*, not a verdict:
`kernel32.dll` imports most of the list and still comes out `ok`. It only
escalates when the imports appear together with writable-executable code or a
high-entropy section.
## Design notes

**Bounds-checked reads carry the offset.** `Reader::need` turns every overrun
into `OutOfBounds { offset, needed, available }`. The same applies to a bad
`e_lfanew`, a bogus optional-header magic, or a section table that declares more
entries than the file can hold.

**RVA mapping is not `rva + image_base`.** A section's `VirtualSize` and
`RawSize` differ; the bytes between them exist in memory (zero-filled by the
loader) but not in the file. `rva_to_offset` returns `None` for that tail rather
than reading whatever follows the section on disk.

**Ordinals and delay-load are preserved.** Real DLLs import and export symbols
by ordinal, and many ship a large delay-load table: `shell32.dll` has 79 static
imports and **138 delay-loaded** ones. A reader that only walks slot 1 reports
less than half of that file's dependencies while still claiming success.

**IAT values are exposed as raw bits, not guessed addresses.** An unbound
static IAT may still contain the lookup-table RVA or ordinal bit pattern, while
a bound or delay-loaded image may contain a full virtual address. `Pe::iat`
therefore returns the slot RVA, raw pointer-sized value, matching symbol and a
`delayed` flag instead of assuming every slot is already resolved.

**32-bit fields are read through `Int64` and range-checked.** The same source
must behave identically when compiled for a 32-bit `Int` target and a 64-bit
one; the reader rejects address-like values above 2 GiB instead of letting them
wrap differently on each platform. Pure constants such as the `VS_FIXEDFILEINFO`
signature go through a separate raw read, because they are not addresses.

## Testing

Thirty-five tests, all offline: hand-built PE32 and PE32+ images with every
optional-header field, imports and IAT slots, delay imports (both descriptor
forms), exports, debug records, relocations, a resource tree and `VERSIONINFO`;
plus malformed inputs and a test that truncates a valid image at every possible
length and requires a clean error every time.

```sh
moon test --target wasm-gc
```

Real-binary validation (output compared against system tools):

| File | Result |
| --- | --- |
| `System32\kernel32.dll` | PE64, 8 sections, 104 imports, 1292 IAT slots (18 delay), 1697 exports |
| `SysWOW64\kernel32.dll` | **PE32**, 6 sections, 102 imports, 1283 IAT slots (18 delay), 1669 exports |
| `System32\shell32.dll` | PE64, 79 imports, 138 delay, 843 exports |
| `System32\notepad.exe` | PE64, 50 imports, 6 delay, 0 exports |

## Completion criteria for v1.0

This project defines "complete format support" as a checklist rather than a
feeling:

1. all PE32 and PE32+ optional-header fields readable, with cross-width tests;
2. all 16 data directories named, addressed, mapped and given a semantic level;
3. imports, delay imports, exports and the IAT readable;
4. sections, relocations, debug/PDB, resources, `VERSIONINFO`, LoadConfig/SafeSEH and certificates readable;
5. arbitrary truncation and malformed input raise `PeError`, never panic;
6. at least three real system binaries (PE32 and PE32+) validated;
7. this README documents the boundary, including summary-only and
   specification-reserved slots.

All seven are met in 0.7.0.

## References

moonpe is an original implementation, not a port, and contains no third-party
code. Its behaviour is aligned with the published format documentation and with
the behaviour of established readers:

| Reference | Used for | License |
| --- | --- | --- |
| [PE format specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format) | header, section, import, export, resource layouts | Microsoft documentation |
| [goblin](https://github.com/m4b/goblin) → `pe` module | behaviour cross-check | MIT |
| [pefile](https://github.com/erocarrera/pefile) | behaviour cross-check | MIT |
| `xmyd0915/moonar` | adjacent archive library; relationship documented above | Apache-2.0 |

## License

Apache-2.0. See `LICENSE`.
