///|
/// Whitebox tests: real parsing against hand-built images.

///|
fn try_parse(bytes : Bytes) -> Pe? {
  Some(Pe::parse(bytes)) catch {
    _ => None
  }
}

///|
fn parses(bytes : Bytes) -> Bool {
  try {
    let _ = Pe::parse(bytes)
    true
  } catch {
    _ => false
  }
}

///|
/// `dll:name@name;#ordinal;` per library, so a wrong entry shows up in the diff.
fn import_summary(bytes : Bytes) -> String {
  try {
    let pe = Pe::parse(bytes)
    let libs = pe.imports()
    let sb = StringBuilder()
    for lib in libs {
      sb.write_string(lib.name + ":")
      for entry in lib.entries {
        match entry.name {
          Some(name) => sb.write_string(name + "@name;")
          None =>
            match entry.ordinal {
              Some(ordinal) => sb.write_string("#" + ordinal.to_string() + ";")
              None => sb.write_string("?;")
            }
        }
      }
    }
    sb.to_string()
  } catch {
    e => "error:" + e.message()
  }
}

///|
/// `dll|name#ordinal@rva|...` for every export, named ones first.
fn export_summary(bytes : Bytes) -> String {
  try {
    let pe = Pe::parse(bytes)
    match pe.exports() {
      None => "none"
      Some(table) => {
        let sb = StringBuilder()
        sb.write_string(table.dll_name)
        for entry in table.exports {
          sb.write_char('|')
          match entry.name {
            Some(name) => sb.write_string(name)
            None => sb.write_string("-")
          }
          sb.write_string(
            "#" + entry.ordinal.to_string() + "@0x" + hex(entry.rva),
          )
        }
        sb.to_string()
      }
    }
  } catch {
    e => "error:" + e.message()
  }
}

///|
/// The PE32 fixture parses into the values that were written into it.
test "pe32 headers" {
  match try_parse(build_pe32()) {
    None => assert_true(false)
    Some(pe) => {
      assert_eq(pe.bits(), 32)
      assert_eq(pe.coff.machine, 0x014C)
      assert_eq(pe.machine(), "i386")
      assert_eq(pe.subsystem(), "windows-console")
      assert_eq(pe.optional.entry_point, 0x1000)
      assert_eq(pe.optional.image_base, 0x400000L)
      assert_eq(pe.optional.section_alignment, 0x1000)
      assert_eq(pe.optional.file_alignment, 0x200)
      assert_eq(pe.optional.size_of_image, 0x3000)
      assert_eq(pe.optional.size_of_headers, 0x200)
      assert_eq(pe.optional.directories.length(), 16)
      assert_eq(pe.coff.number_of_sections, 2)
    }
  }
}

///|
/// Section names, permissions and the RVA-to-file-offset mapping.
test "pe32 sections" {
  match try_parse(build_pe32()) {
    None => assert_true(false)
    Some(pe) => {
      assert_eq(pe.sections.length(), 2)
      assert_eq(pe.sections[0].name, ".text")
      assert_eq(pe.sections[0].permissions(), "r-x")
      assert_eq(pe.sections[0].virtual_address, 0x1000)
      assert_eq(pe.sections[0].raw_pointer, 0x200)
      assert_eq(pe.sections[1].name, ".rdata")
      assert_eq(pe.sections[1].permissions(), "r--")
      assert_eq(pe.rva_to_offset(0x1000), Some(0x200))
      assert_eq(pe.rva_to_offset(0x2000), Some(0x400))
      assert_eq(pe.rva_to_offset(0x1001), Some(0x201))
      assert_eq(pe.rva_to_offset(0x3000), None)
      assert_eq(pe.rva_to_offset(-1), None)
      assert_eq(
        pe.section_for_rva(0x2010).map(fn(s) { s.name }),
        Some(".rdata"),
      )
      assert_eq(pe.section("missing").map(fn(s) { s.name }), None)
    }
  }
}

///|
/// A named import and an ordinal import from the same library.
test "pe32 imports" {
  assert_eq(import_summary(build_pe32()), "KERNEL32.dll:ExitProcess@name;#7;")
}

///|
/// Two named exports plus one reachable only by ordinal.
test "pe32 exports" {
  assert_eq(
    export_summary(build_pe32()),
    "demo.dll|demo_init#1@0x1000|demo_run#3@0x1020|-#2@0x1010",
  )
}

///|
/// The PE32+ fixture proves the widened optional header is read correctly.
test "pe64 headers" {
  match try_parse(build_pe64()) {
    None => assert_true(false)
    Some(pe) => {
      assert_eq(pe.bits(), 64)
      assert_eq(pe.coff.machine, 0x8664)
      assert_eq(pe.machine(), "AMD64")
      assert_eq(pe.optional.image_base, 0x140000000L)
      assert_eq(pe.optional.entry_point, 0x1000)
      assert_eq(pe.sections.length(), 1)
      assert_eq(pe.sections[0].name, ".text")
      assert_eq(pe.rva_to_offset(0x1000), Some(0x200))
    }
  }
}

///|
/// An image with no import or export directory reports nothing rather than
/// failing.
test "pe64 without imports or exports" {
  assert_eq(import_summary(build_pe64()), "")
  assert_eq(export_summary(build_pe64()), "none")
}

///|
/// Malformed files are rejected instead of being partially parsed.
test "malformed images are rejected" {
  assert_eq(parses(build_not_mz()), false)
  assert_eq(parses(build_bad_signature()), false)
  assert_eq(parses(build_truncated()), false)
  assert_eq(parses(build_bad_lfanew()), false)
  assert_eq(parses(b""), false)
  assert_eq(parses(b"MZ"), false)
}

///|
/// Truncating a valid image at every possible length must produce a clean
/// error. This is the cheapest way to catch an unguarded index in a format
/// parser: any missed bounds check shows up as a panic instead of a `PeError`.
test "truncated images never panic" {
  let full = build_pe32()
  let mut length = 0
  while length < full.length() {
    let prefix : Array[Byte] = []
    let mut i = 0
    while i < length {
      prefix.push(full[i])
      i = i + 1
    }
    let _ = try {
      let _ = Pe::parse(Bytes::from_array(prefix))
    } catch {
      _ => ()
    }
    length = length + 1
  }
  assert_true(true)
}

///|
/// A section table larger than the file is rejected, not read past the end.
test "oversized section table is rejected" {
  assert_eq(parses(build_bad_section_count()), false)
}

///|
/// The 64-bit import path: eight-byte thunks with the ordinal flag in bit 63.
test "pe64 imports" {
  assert_eq(
    import_summary(build_pe64_with_imports()),
    "KERNEL32.dll:Sleep@name;#5;",
  )
}

///|
/// `section_bytes` returns the file-backed bytes of a section and refuses a
/// range that lies outside the file.
test "section bytes" {
  match try_parse(build_pe32()) {
    None => assert_true(false)
    Some(pe) =>
      match pe.section_bytes(pe.sections[0]) {
        None => assert_true(false)
        Some(bytes) => {
          assert_eq(bytes.length(), 0x200)
          assert_eq(bytes[0].to_int(), 0xC3)
        }
      }
  }
}

///|
/// Delay-load imports, modern descriptor: address fields are RVAs.
test "delay imports with rva descriptors" {
  match try_parse(build_delay_imports(true)) {
    None => assert_true(false)
    Some(pe) => {
      let libraries = pe.delay_imports()
      assert_eq(libraries.length(), 1)
      assert_eq(libraries[0].name, "USER32.dll")
      assert_eq(libraries[0].rva_based, true)
      assert_eq(libraries[0].entries.length(), 1)
      assert_eq(libraries[0].entries[0].name, Some("MessageBoxW"))
    }
  }
}

///|
/// Delay-load imports, legacy descriptor: address fields are virtual addresses
/// and must be rebased against the image base.
test "delay imports with virtual-address descriptors" {
  match try_parse(build_delay_imports(false)) {
    None => assert_true(false)
    Some(pe) => {
      let libraries = pe.delay_imports()
      assert_eq(libraries.length(), 1)
      assert_eq(libraries[0].name, "USER32.dll")
      assert_eq(libraries[0].rva_based, false)
      assert_eq(libraries[0].entries[0].name, Some("MessageBoxW"))
    }
  }
}

///|
/// Every declared data directory gets a documented name and a file mapping.
test "data directories are named and resolved" {
  match try_parse(build_with_debug()) {
    None => assert_true(false)
    Some(pe) => {
      let dirs = pe.resolved_directories()
      assert_eq(dirs.length(), 16)
      assert_eq(dirs[0].name, "Export")
      assert_eq(dirs[1].name, "Import")
      assert_eq(dirs[6].name, "Debug")
      assert_eq(dirs[13].name, "DelayImport")
      assert_eq(dirs[6].virtual_address, 0x2000)
      assert_eq(dirs[6].size, 28)
      assert_eq(dirs[6].file_offset, Some(0x400))
      assert_eq(dirs[0].file_offset, None)
      assert_eq(directory_name(0), "Export")
      assert_eq(directory_name(15), "Reserved")
    }
  }
}

///|
/// The CodeView record yields the PDB path, age and signature.
test "debug directory exposes the pdb path" {
  match try_parse(build_with_debug()) {
    None => assert_true(false)
    Some(pe) => {
      let entries = pe.debug_entries()
      assert_eq(entries.length(), 1)
      assert_eq(entries[0].kind_name, "CodeView")
      assert_eq(entries[0].pdb_signature, Some("RSDS"))
      assert_eq(entries[0].pdb_age, Some(7))
      assert_eq(entries[0].pdb_path, Some("C:\\build\\demo.pdb"))
    }
  }
}

///|
/// Relocation blocks are counted per fixup type.
test "relocations are summarised" {
  match try_parse(build_with_relocations()) {
    None => assert_true(false)
    Some(pe) => {
      let summary = pe.relocations()
      assert_eq(summary.blocks.length(), 1)
      assert_eq(summary.blocks[0].page_rva, 0x1000)
      assert_eq(summary.total_entries, 4)
      assert_eq(summary.dir64, 2)
      assert_eq(summary.highlow, 1)
      assert_eq(summary.absolute, 1)
      assert_eq(relocation_type_name(10), "DIR64")
    }
  }
}

///|
/// The resource tree yields the RT_VERSION leaf.
test "resources enumerate the version entry" {
  match try_parse(build_with_version_info()) {
    None => assert_true(false)
    Some(pe) => {
      let entries = pe.resources()
      assert_eq(entries.length(), 1)
      assert_eq(entries[0].type_id, Some(16))
      assert_eq(entries[0].type_name, None)
      assert_eq(entries[0].name_id, Some(1))
      assert_eq(entries[0].language, 0x409)
      assert_eq(resource_type_name(16), "VERSION")
    }
  }
}

///|
/// VERSIONINFO decoding: fixed version plus the string table.
test "version info is decoded" {
  match try_parse(build_with_version_info()) {
    None => assert_true(false)
    Some(pe) =>
      match pe.version_info() {
        None => assert_true(false)
        Some(info) => {
          assert_eq(info.file_version, "1.2.3.4")
          assert_eq(info.product_version, "1.2.3.4")
          assert_eq(info.company_name, Some("Demo Corp"))
          assert_eq(info.product_name, Some("Moon Demo"))
        }
      }
  }
}
