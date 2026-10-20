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
