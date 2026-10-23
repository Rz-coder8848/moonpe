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
fn copy_bytes(bytes : Bytes) -> Array[Byte] {
  let out : Array[Byte] = []
  let mut i = 0
  while i < bytes.length() {
    out.push(bytes[i])
    i = i + 1
  }
  out
}

///|
/// Exercise every public table/parser entry point. The fuzz tests call this so
/// that bounds bugs outside the header parser are caught as well.
fn exercise_all_parsers(pe : Pe) -> Unit raise PeError {
  let _ = pe.imports()
  let _ = pe.iat()
  let _ = pe.delay_imports()
  let _ = pe.exports()
  let _ = pe.debug_entries()
  let _ = pe.relocations()
  let _ = pe.resources()
  let _ = pe.version_info()
  let _ = pe.manifest()
  let _ = pe.tls()
  let _ = pe.clr()
  let _ = pe.clr_metadata()
  let _ = pe.function_table()
  let _ = pe.bound_imports()
  let _ = pe.load_config()
  let _ = pe.safe_seh_handlers()
  let _ = pe.certificates()
  for entry in pe.resources() {
    let _ = pe.decode_resource(entry)
  }
  let _ = pe.check()
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
/// `dll|symbol@slot=raw|...`, for deterministic IAT assertions.
fn iat_summary(bytes : Bytes) -> String {
  try {
    let pe = Pe::parse(bytes)
    let slots = pe.iat()
    let sb = StringBuilder()
    for entry in slots {
      if sb.to_string().length() > 0 {
        sb.write_char('|')
      }
      sb.write_string(entry.library + "|")
      sb.write_string(if entry.delayed { "delay:" } else { "static:" })
      match entry.symbol.name {
        Some(name) => sb.write_string(name)
        None =>
          match entry.symbol.ordinal {
            Some(ordinal) => sb.write_string("#" + ordinal.to_string())
            None => sb.write_string("?")
          }
      }
      sb.write_string(
        "@0x" + hex(entry.slot_rva) + "=0x" + hex64(entry.raw_value),
      )
    }
    sb.to_string()
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
      assert_eq(pe.optional.major_linker_version, 14)
      assert_eq(pe.optional.minor_linker_version, 0)
      assert_eq(pe.optional.size_of_code, 0x200)
      assert_eq(pe.optional.size_of_initialized_data, 0x200)
      assert_eq(pe.optional.size_of_uninitialized_data, 0)
      assert_eq(pe.optional.base_of_code, 0x1000)
      assert_eq(pe.optional.base_of_data, Some(0x2000))
      assert_eq(pe.optional.major_operating_system_version, 5)
      assert_eq(pe.optional.minor_operating_system_version, 1)
      assert_eq(pe.optional.major_image_version, 2)
      assert_eq(pe.optional.minor_image_version, 3)
      assert_eq(pe.optional.major_subsystem_version, 6)
      assert_eq(pe.optional.win32_version_value, 0x1234)
      assert_eq(pe.optional.checksum, 0x12345678)
      assert_eq(pe.optional.size_of_stack_reserve, 0x200000L)
      assert_eq(pe.optional.size_of_stack_commit, 0x2000L)
      assert_eq(pe.optional.size_of_heap_reserve, 0x300000L)
      assert_eq(pe.optional.size_of_heap_commit, 0x3000L)
      assert_eq(pe.optional.loader_flags, 1)
      assert_eq(pe.optional.number_of_rva_and_sizes, 16)
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
/// Bit-pattern timestamps and PE32 image bases above 2 GiB are valid unsigned
/// values; they must not be rejected as overflowing addresses.
test "unsigned header fields are widened losslessly" {
  let buf = copy_bytes(build_pe32())
  set_u32(buf, 0x88, -1)
  set_u32(buf, 0xB4, -1)
  match try_parse(Bytes::from_array(buf)) {
    None => assert_true(false)
    Some(pe) => {
      assert_eq(pe.coff.timestamp, 0xFFFFFFFFL)
      assert_eq(pe.optional.image_base, 0xFFFFFFFFL)
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
      assert_eq(pe.optional.major_linker_version, 14)
      assert_eq(pe.optional.base_of_code, 0x1000)
      assert_eq(pe.optional.base_of_data, None)
      assert_eq(pe.optional.size_of_stack_reserve, 0x100000L)
      assert_eq(pe.optional.size_of_heap_commit, 0x1000L)
      assert_eq(pe.optional.number_of_rva_and_sizes, 16)
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
/// Truncating a valid image at every possible length must never crash, and any
/// prefix that still parses must survive every table parser.
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
      let pe = Pe::parse(Bytes::from_array(prefix))
      exercise_all_parsers(pe)
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
/// PE32 IAT slots retain their library and lookup-table symbol, while exposing
/// the raw 32-bit value stored in each `FirstThunk` slot.
test "pe32 iat maps slots to imported symbols" {
  assert_eq(
    iat_summary(build_pe32()),
    "KERNEL32.dll|static:ExitProcess@0x2060=0x2090|KERNEL32.dll|static:#7@0x2064=0x80000007",
  )
}

///|
/// A FirstThunk that points outside the file is an error, not a silently empty
/// IAT.
test "iat rejects an unbacked slot table" {
  let image = build_pe32()
  let copy : Array[Byte] = []
  let mut i = 0
  while i < image.length() {
    copy.push(image[i])
    i = i + 1
  }
  // Import descriptor FirstThunk is at file offset 0x410.
  set_u32(copy, 0x410, 0x7FFFF000)
  let rejected = try {
    let pe = Pe::parse(Bytes::from_array(copy))
    let _ = pe.iat()
    false
  } catch {
    _ => true
  }
  assert_true(rejected)
}

///|
/// Delay-loaded libraries have their own IAT in slot 13. It must be returned
/// together with the normal IAT and marked as delayed.
test "delay iat is included and labelled" {
  match try_parse(build_delay_imports(true)) {
    None => assert_true(false)
    Some(pe) => {
      let slots = pe.iat()
      assert_eq(slots.length(), 1)
      assert_eq(slots[0].library, "USER32.dll")
      assert_eq(slots[0].delayed, true)
      assert_eq(slots[0].slot_rva, 0x2040)
      assert_eq(slots[0].raw_value, 0x2080L)
      assert_eq(slots[0].symbol.name, Some("MessageBoxW"))
    }
  }
  match try_parse(build_delay_imports(false)) {
    None => assert_true(false)
    Some(pe) => {
      let slots = pe.iat()
      assert_eq(slots.length(), 1)
      assert_eq(slots[0].delayed, true)
      assert_eq(slots[0].slot_rva, 0x2040)
      assert_eq(slots[0].raw_value, 0x2080L)
    }
  }
}

///|
/// The PE32+ path reads eight-byte IAT slots and preserves the ordinal bit in
/// the raw value.
test "pe64 iat uses eight-byte slots" {
  match try_parse(build_pe64_with_imports()) {
    None => assert_true(false)
    Some(pe) => {
      let slots = pe.iat()
      assert_eq(slots.length(), 2)
      assert_eq(slots[0].delayed, false)
      assert_eq(slots[0].slot_rva, 0x2060)
      assert_eq(slots[0].raw_value, 0x2090L)
      assert_eq(slots[1].slot_rva, 0x2068)
      assert_eq(slots[1].raw_value & 0xFFFFL, 5L)
    }
  }
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
      assert_eq(libraries[0].iat_rva, Some(0x2040))
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
      assert_eq(libraries[0].iat_rva, Some(0x2040))
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
          let resource = pe.resources()[0]
          let decoded = pe.decode_resource(resource)
          assert_eq(decoded.kind, "version-info")
          match decoded.version {
            Some(value) => assert_eq(value.file_version, "1.2.3.4")
            None => assert_true(false)
          }
        }
      }
  }
}

///|
/// A hardened image with read-only sections produces no findings.
test "check passes a hardened image" {
  match try_parse(build_check_image(0x60000020, 0x0140, 0)) {
    None => assert_true(false)
    Some(pe) => assert_eq(pe.check().verdict, "ok")
  }
}

///|
/// A writable-and-executable section is a high-severity finding.
test "check flags writable-executable sections" {
  match try_parse(build_check_image(0xE0000020, 0x0140, 0)) {
    None => assert_true(false)
    Some(pe) => {
      let report = pe.check()
      assert_eq(report.verdict, "suspicious")
      let mut found = false
      for finding in report.findings {
        if finding.code == "WX_SECTION" {
          found = true
        }
      }
      assert_true(found)
    }
  }
}

///|
/// A section whose bytes are uniformly distributed is reported as packed.
test "check flags high entropy" {
  match try_parse(build_check_image(0x60000020, 0x0140, 1)) {
    None => assert_true(false)
    Some(pe) => {
      let report = pe.check()
      assert_eq(report.verdict, "review")
      let mut found = false
      for finding in report.findings {
        if finding.code == "HIGH_ENTROPY" {
          found = true
        }
      }
      assert_true(found)
    }
  }
}

///|
/// TLS callbacks are counted through the virtual addresses in the directory.
test "tls callbacks are counted" {
  match try_parse(build_with_tls()) {
    None => assert_true(false)
    Some(pe) =>
      match pe.tls() {
        None => assert_true(false)
        Some(info) => {
          assert_eq(info.callbacks, 2)
          assert_eq(info.raw_data_size, 16)
        }
      }
  }
}

///|
/// The CLR header exposes the runtime version string.
test "clr header is decoded" {
  match try_parse(build_with_clr()) {
    None => assert_true(false)
    Some(pe) =>
      match pe.clr() {
        None => assert_true(false)
        Some(info) => {
          assert_eq(info.runtime_version, "v4.0.30319")
          assert_eq(info.metadata_size, 0x1A0)
        }
      }
  }
}

///|
/// The CLR metadata streams and table rows expose assembly identity, references,
/// types and methods rather than only the runtime version string.
test "clr metadata tables are decoded" {
  match try_parse(build_with_clr()) {
    None => assert_true(false)
    Some(pe) =>
      match pe.clr_metadata() {
        None => assert_true(false)
        Some(metadata) => {
          assert_eq(metadata.streams.length(), 2)
          assert_eq(metadata.streams[0].name, "#~")
          assert_eq(metadata.streams[1].name, "#Strings")
          assert_eq(metadata.tables.length(), 5)
          assert_eq(metadata.tables[0].name, "Module")
          assert_eq(metadata.tables[0].rows, 1)
          assert_eq(metadata.module_name, Some("demo.exe"))
          assert_eq(metadata.assembly_name, Some("Demo.Assembly"))
          assert_eq(metadata.assembly_version, Some("1.2.3.4"))
          assert_eq(metadata.assembly_references.length(), 1)
          assert_eq(metadata.assembly_references[0].name, "System.Runtime")
          assert_eq(metadata.type_definitions.length(), 1)
          assert_eq(metadata.type_definitions[0].namespace_name, "Demo")
          assert_eq(metadata.type_definitions[0].name, "DemoType")
          assert_eq(metadata.method_definitions.length(), 1)
          assert_eq(metadata.method_definitions[0].name, "Run")
          assert_eq(metadata.method_definitions[0].rva, 0x1000)
        }
      }
  }
}

///|
/// Coded-index width depends on the number of tag bits, not only on the total
/// row count. This catches the classic metadata-table offset error.
test "coded metadata indexes reserve their tag bits" {
  let rows = zero_rows()
  rows[6] = 2047
  assert_eq(metadata_coded_width(2, rows, false), 2)
  rows[6] = 2048
  assert_eq(metadata_coded_width(2, rows, false), 4)
  rows[6] = 0
  rows[2] = 8191
  assert_eq(metadata_coded_width(5, rows, false), 2)
  rows[2] = 8192
  assert_eq(metadata_coded_width(5, rows, false), 4)
}

///|
/// Common resource payloads expose usable data: STRING entries, bitmap/icon
/// dimensions, GROUP_ICON members and manifest text.
test "common resource content is decoded" {
  let image = build_pe32()
  let buf = copy_bytes(image)
  // STRING block: ID 0 = "Hi", followed by empty slots.
  set_u16(buf, 0x4A0, 2)
  set_u16(buf, 0x4A2, 0x48)
  set_u16(buf, 0x4A4, 0x69)
  // BITMAPINFOHEADER: 32x32, 32 bpp (stored height is doubled).
  set_u32(buf, 0x4C8, 40)
  set_u32(buf, 0x4CC, 32)
  set_u32(buf, 0x4D0, 64)
  set_u16(buf, 0x4D4, 1)
  set_u16(buf, 0x4D6, 32)
  // PNG icon: signature and IHDR dimensions 48x64.
  set_u8(buf, 0x4F0, 0x89)
  set_u8(buf, 0x4F1, 0x50)
  set_u8(buf, 0x4F2, 0x4E)
  set_u8(buf, 0x4F3, 0x47)
  set_u8(buf, 0x4F4, 0x0D)
  set_u8(buf, 0x4F5, 0x0A)
  set_u8(buf, 0x4F6, 0x1A)
  set_u8(buf, 0x4F7, 0x0A)
  set_u8(buf, 0x4FB, 13)
  set_u8(buf, 0x4FC, 0x49)
  set_u8(buf, 0x4FD, 0x48)
  set_u8(buf, 0x4FE, 0x44)
  set_u8(buf, 0x4FF, 0x52)
  set_u8(buf, 0x503, 48)
  set_u8(buf, 0x507, 64)
  // GROUP_ICON with one 256x256 member pointing at resource 3.
  set_u16(buf, 0x520, 0)
  set_u16(buf, 0x522, 1)
  set_u16(buf, 0x524, 1)
  set_u8(buf, 0x526, 0)
  set_u8(buf, 0x527, 0)
  set_u16(buf, 0x52A, 1)
  set_u16(buf, 0x52C, 32)
  set_u32(buf, 0x52E, 40)
  set_u16(buf, 0x532, 3)
  // MANIFEST text.
  let manifest = "<assembly><trustInfo/></assembly>"
  let _ = set_ascii(buf, 0x540, manifest)
  let pe = Pe::parse(Bytes::from_array(buf)) catch {
    _ => {
      assert_true(false)
      return
    }
  }
  let string_entry : ResourceEntry = {
    type_id: Some(6),
    type_name: None,
    name_id: Some(1),
    name_name: None,
    language: 0x409,
    rva: 0x20A0,
    size: 16,
    code_page: 1200,
  }
  let strings = pe.decode_resource(string_entry)
  assert_eq(strings.strings.length(), 1)
  assert_eq(strings.strings[0].id, 0)
  assert_eq(strings.strings[0].text, "Hi")
  let bitmap_entry : ResourceEntry = {
    type_id: Some(2),
    type_name: None,
    name_id: Some(1),
    name_name: None,
    language: 0x409,
    rva: 0x20C8,
    size: 40,
    code_page: 0,
  }
  let bitmap = pe.decode_resource(bitmap_entry)
  assert_eq(bitmap.width, Some(32))
  assert_eq(bitmap.height, Some(32))
  assert_eq(bitmap.bit_count, Some(32))
  let icon_entry : ResourceEntry = {
    type_id: Some(3),
    type_name: None,
    name_id: Some(1),
    name_name: None,
    language: 0x409,
    rva: 0x20F0,
    size: 24,
    code_page: 0,
  }
  let icon = pe.decode_resource(icon_entry)
  assert_eq(icon.png, true)
  assert_eq(icon.width, Some(48))
  assert_eq(icon.height, Some(64))
  let group_entry : ResourceEntry = {
    type_id: Some(14),
    type_name: None,
    name_id: Some(1),
    name_name: None,
    language: 0x409,
    rva: 0x2120,
    size: 20,
    code_page: 0,
  }
  let group = pe.decode_resource(group_entry)
  assert_eq(group.group_icons.length(), 1)
  assert_eq(group.group_icons[0].width, 256)
  assert_eq(group.group_icons[0].resource_id, 3)
  let manifest_entry : ResourceEntry = {
    type_id: Some(24),
    type_name: None,
    name_id: Some(1),
    name_name: None,
    language: 0x409,
    rva: 0x2140,
    size: manifest.length(),
    code_page: 65001,
  }
  let decoded_manifest = pe.decode_resource(manifest_entry)
  assert_eq(decoded_manifest.text, Some(manifest))
}

///|
/// The manifest text and its requested execution level are readable.
test "manifest execution level is decoded" {
  match try_parse(build_with_manifest()) {
    None => assert_true(false)
    Some(pe) => {
      match pe.manifest() {
        None => assert_true(false)
        Some(text) => assert_true(text.contains("requireAdministrator"))
      }
      assert_eq(pe.manifest_execution_level(), Some("requireAdministrator"))
    }
  }
}

///|
/// The runtime-function table reports its entry count and RVA span.
test "function table is summarised" {
  match try_parse(build_with_tables()) {
    None => assert_true(false)
    Some(pe) =>
      match pe.function_table() {
        None => assert_true(false)
        Some(table) => {
          assert_eq(table.entries, 2)
          assert_eq(table.first_rva, 0x1000)
          assert_eq(table.last_rva, 0x1090)
        }
      }
  }
}

///|
/// Bound-import module names are readable.
test "bound imports are listed" {
  match try_parse(build_with_tables()) {
    None => assert_true(false)
    Some(pe) => {
      let names = pe.bound_imports()
      assert_eq(names.length(), 1)
      assert_eq(names[0], "KERNEL32.dll")
    }
  }
}

///|
/// Deterministically mutate several valid PE layouts and exercise every parser
/// on each successfully parsed candidate. A panic fails the test immediately.
test "mutated images never panic" {
  let bases = [
    build_pe32(),
    build_with_version_info(),
    build_with_load_config(),
    build_with_clr(),
    build_delay_imports(true),
  ]
  let mut seed = 0x12345678
  let mut round = 0
  while round < 500 {
    let base = bases[round % bases.length()]
    let copy = copy_bytes(base)
    let mut k = 0
    while k < 4 {
      seed = (seed * 1103515245 + 12345) & 0x7FFFFFFF
      let position = seed % copy.length()
      seed = (seed * 1103515245 + 12345) & 0x7FFFFFFF
      copy[position] = Int32::to_byte(seed & 0xFF)
      k = k + 1
    }
    let _ = try {
      let pe = Pe::parse(Bytes::from_array(copy))
      exercise_all_parsers(pe)
    } catch {
      _ => ()
    }
    round = round + 1
  }
  assert_true(true)
}

///|
/// LoadConfig exposes the security cookie, SafeSEH metadata and CFG flags.
test "load config is decoded" {
  match try_parse(build_with_load_config()) {
    None => assert_true(false)
    Some(pe) =>
      match pe.load_config() {
        None => assert_true(false)
        Some(info) => {
          assert_eq(info.size, 0x5C)
          assert_eq(info.security_cookie, 0x403000L)
          assert_eq(info.seh_handler_count, 2L)
          assert_eq(info.guard_flags, 0x100)
        }
      }
  }
}

///|
/// SafeSEH handlers are resolved from the table pointer into real RVAs.
test "safe seh handlers are resolved" {
  match try_parse(build_with_load_config()) {
    None => assert_true(false)
    Some(pe) =>
      match pe.safe_seh_handlers() {
        None => assert_true(false)
        Some(handlers) => {
          assert_eq(handlers.length(), 2)
          assert_eq(handlers[0], 0x1010)
          assert_eq(handlers[1], 0x1020)
        }
      }
  }
}
