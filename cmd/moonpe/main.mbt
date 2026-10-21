///|
/// `moonpe` — inspect a Windows PE image.
///
/// The library is deliberately IO-free; this command is the only place that
/// touches the filesystem, so the parser stays testable in memory.

///|
fn main {
  run()
}

///|
fn print_usage() -> Unit {
  println("moonpe - inspect Windows PE images")
  println("")
  println("usage: moonpe <command> <file>")
  println("")
  println("commands:")
  println("  info         headers, machine, subsystem, dependency counts")
  println("  sections     section table with permissions")
  println("  imports      imported DLLs, including delay-loaded ones")
  println("  exports      exported symbols")
  println("  debug        debug directory entries and PDB paths")
  println("  relocations  relocation blocks by fixup type")
  println("  resources    resource tree and VERSIONINFO")
  println("  check        release and triage findings with a verdict")
  println("  all          everything")
}

///|
fn fail(message : String) -> Unit {
  println("moonpe: " + message)
}

///|
fn run() -> Unit {
  let args = @env.args()
  // Under the JS target the runtime hands over node and the script path
  // first, so the real arguments start two slots in.
  let mut base = 1
  if args.length() >= 2 && args[1].contains(".js") {
    base = 2
  }
  if args.length() <= base {
    print_usage()
    return
  }
  let command = args[base]
  if command == "-h" || command == "--help" || command == "help" {
    print_usage()
    return
  }
  if args.length() <= base + 1 {
    fail("missing file argument")
    print_usage()
    return
  }
  let path = args[base + 1]
  let bytes = @fs.read_file_to_bytes(path) catch {
    _ => {
      fail("cannot read " + path)
      return
    }
  }
  let pe = @pe.Pe::parse(bytes) catch {
    e => {
      fail(e.message())
      return
    }
  }
  if command == "info" {
    print_info(path, pe)
  } else if command == "sections" {
    print_sections(pe)
  } else if command == "imports" {
    print_imports(pe)
  } else if command == "exports" {
    print_exports(pe)
  } else if command == "debug" {
    print_debug(pe)
  } else if command == "relocations" {
    print_relocations(pe)
  } else if command == "resources" {
    print_resources(pe)
  } else if command == "check" {
    print_check(pe)
  } else if command == "all" {
    print_info(path, pe)
    println("")
    print_sections(pe)
    println("")
    print_imports(pe)
    println("")
    print_exports(pe)
    println("")
    print_debug(pe)
    println("")
    print_relocations(pe)
    println("")
    print_resources(pe)
    println("")
    print_check(pe)
  } else {
    fail("unknown command '" + command + "'")
    print_usage()
  }
}

///|
fn pad_right(text : String, width : Int32) -> String {
  let sb = StringBuilder()
  sb.write_string(text)
  let mut i = text.length()
  while i < width {
    sb.write_char(' ')
    i = i + 1
  }
  sb.to_string()
}

///|
fn pad_left(text : String, width : Int32) -> String {
  let sb = StringBuilder()
  let mut i = text.length()
  while i < width {
    sb.write_char(' ')
    i = i + 1
  }
  sb.write_string(text)
  sb.to_string()
}

///|
fn print_info(path : String, pe : @pe.Pe) -> Unit {
  let libraries = pe.imports().length() catch { _ => 0 }
  let delay_libraries = pe.delay_imports().length() catch { _ => 0 }
  let exports = try {
    match pe.exports() {
      Some(table) => table.exports.length()
      None => 0
    }
  } catch {
    _ => 0
  }
  println("file:      " + path)
  println("format:    PE" + pe.bits().to_string())
  println("machine:   " + pe.machine())
  println("subsystem: " + pe.subsystem())
  println("image:     base 0x" + @pe.hex64(pe.optional.image_base))
  println("           size 0x" + @pe.hex(pe.optional.size_of_image))
  println("entry:     0x" + @pe.hex(pe.optional.entry_point))
  println("sections:  " + pe.sections.length().to_string())
  println("imports:   " + libraries.to_string() + " libraries")
  println("delay:     " + delay_libraries.to_string() + " libraries")
  println("exports:   " + exports.to_string() + " symbols")
  print_pdb_line(pe)
  print_version_line(pe)
  print_extra_lines(pe)
}

///|
fn print_sections(pe : @pe.Pe) -> Unit {
  println(
    pad_right("NAME", 12) +
    pad_left("VADDR", 10) +
    pad_left("VSIZE", 10) +
    pad_left("RAWPTR", 10) +
    pad_left("RAWSIZE", 10) +
    "  PERM",
  )
  for section in pe.sections {
    println(
      pad_right(section.name, 12) +
      pad_left("0x" + @pe.hex(section.virtual_address), 10) +
      pad_left("0x" + @pe.hex(section.virtual_size), 10) +
      pad_left("0x" + @pe.hex(section.raw_pointer), 10) +
      pad_left("0x" + @pe.hex(section.raw_size), 10) +
      "  " +
      section.permissions(),
    )
  }
}

///|
fn print_imports(pe : @pe.Pe) -> Unit {
  let libraries = Some(pe.imports()) catch {
    e => {
      fail(e.message())
      None
    }
  }
  match libraries {
    None => ()
    Some(libs) =>
      if libs.length() == 0 {
        println("(no imports)")
      } else {
        for library in libs {
          println(library.name)
          for entry in library.entries {
            println("  " + entry_label(entry))
          }
        }
      }
  }
  let delayed = Some(pe.delay_imports()) catch {
    e => {
      fail(e.message())
      None
    }
  }
  match delayed {
    None => ()
    Some(libs) =>
      if libs.length() > 0 {
        println("delay-loaded:")
        for library in libs {
          println(library.name)
          for entry in library.entries {
            println("  " + entry_label(entry))
          }
        }
      }
  }
}

///|
fn entry_label(entry : @pe.ImportEntry) -> String {
  match entry.name {
    Some(name) => name
    None =>
      match entry.ordinal {
        Some(ordinal) => "#" + ordinal.to_string() + " (ordinal)"
        None => "?"
      }
  }
}

///|
fn print_exports(pe : @pe.Pe) -> Unit {
  let table = Some(pe.exports()) catch {
    e => {
      fail(e.message())
      None
    }
  }
  match table {
    None => ()
    Some(value) =>
      match value {
        None => println("(no exports)")
        Some(exports) => {
          println(exports.dll_name)
          for entry in exports.exports {
            let label = match entry.name {
              Some(name) => name
              None => "-"
            }
            println(
              "  " +
              pad_right(label, 32) +
              " ordinal " +
              pad_left(entry.ordinal.to_string(), 5) +
              "  rva 0x" +
              @pe.hex(entry.rva),
            )
          }
        }
      }
  }
}

///|
fn print_pdb_line(pe : @pe.Pe) -> Unit {
  let entries = Some(pe.debug_entries()) catch { _ => None }
  match entries {
    None => ()
    Some(list) => {
      let mut found = false
      for entry in list {
        match entry.pdb_path {
          Some(path) =>
            if !found {
              println("pdb:       " + path)
              found = true
            }
          None => ()
        }
      }
      if !found {
        println("pdb:       (none)")
      }
    }
  }
}

///|
fn print_version_line(pe : @pe.Pe) -> Unit {
  let info = Some(pe.version_info()) catch { _ => None }
  match info {
    None => ()
    Some(value) =>
      match value {
        None => println("version:   (no version resource)")
        Some(version) => {
          let product = match version.product_name {
            Some(name) => name
            None => "-"
          }
          println("version:   " + product + " " + version.file_version)
        }
      }
  }
}

///|
fn print_debug(pe : @pe.Pe) -> Unit {
  let entries = Some(pe.debug_entries()) catch {
    e => {
      fail(e.message())
      None
    }
  }
  match entries {
    None => ()
    Some(list) =>
      if list.length() == 0 {
        println("(no debug directory)")
      } else {
        println(pad_right("TYPE", 24) + pad_left("AGE", 6) + "  PDB")
        for entry in list {
          let age = match entry.pdb_age {
            Some(value) => value.to_string()
            None => "-"
          }
          let path = match entry.pdb_path {
            Some(value) => value
            None => "-"
          }
          println(
            pad_right(entry.kind_name, 24) + pad_left(age, 6) + "  " + path,
          )
        }
      }
  }
}

///|
fn print_relocations(pe : @pe.Pe) -> Unit {
  let summary = Some(pe.relocations()) catch {
    e => {
      fail(e.message())
      None
    }
  }
  match summary {
    None => ()
    Some(value) =>
      if value.blocks.length() == 0 {
        println("(no relocations)")
      } else {
        println(
          pad_left("PAGE", 12) +
          pad_left("ENTRIES", 9) +
          pad_left("DIR64", 7) +
          pad_left("HIGHLOW", 9) +
          pad_left("OTHER", 7),
        )
        for block in value.blocks {
          println(
            pad_left("0x" + @pe.hex(block.page_rva), 12) +
            pad_left(block.entries.to_string(), 9) +
            pad_left(block.dir64.to_string(), 7) +
            pad_left(block.highlow.to_string(), 9) +
            pad_left((block.other + block.high + block.low).to_string(), 7),
          )
        }
        println(
          "total: " +
          value.total_entries.to_string() +
          " entries (DIR64 " +
          value.dir64.to_string() +
          ", HIGHLOW " +
          value.highlow.to_string() +
          ")",
        )
      }
  }
}

///|
fn print_resources(pe : @pe.Pe) -> Unit {
  let entries = Some(pe.resources()) catch {
    e => {
      fail(e.message())
      None
    }
  }
  match entries {
    None => ()
    Some(list) =>
      if list.length() == 0 {
        println("(no resources)")
      } else {
        println(
          pad_right("TYPE", 18) +
          pad_right("NAME", 10) +
          pad_left("LANG", 8) +
          "  RVA/SIZE",
        )
        for entry in list {
          let kind = match entry.type_id {
            Some(id) => @pe.resource_type_name(id)
            None =>
              match entry.type_name {
                Some(name) => name
                None => "?"
              }
          }
          let name = match entry.name_id {
            Some(id) => id.to_string()
            None =>
              match entry.name_name {
                Some(value) => value
                None => "?"
              }
          }
          println(
            pad_right(kind, 18) +
            pad_right(name, 10) +
            pad_left("0x" + @pe.hex(entry.language), 8) +
            "  0x" +
            @pe.hex(entry.rva) +
            "/" +
            entry.size.to_string(),
          )
        }
      }
  }
}

///|
fn print_check(pe : @pe.Pe) -> Unit {
  let report = pe.check()

  println("verdict:   " + report.verdict)
  println(
    "max entropy: " +
    (report.max_section_entropy * 100.0).to_int().to_string() +
    " / 800",
  )
  if report.findings.length() == 0 {
    println("  (no findings)")
  } else {
    for finding in report.findings {
      let tag = match finding.severity {
        @pe.Info => "INFO"
        @pe.Warning => "WARN"
        @pe.High => "HIGH"
      }
      println(
        "  [" +
        pad_right(tag, 4) +
        "] " +
        pad_right(finding.code, 18) +
        finding.message,
      )
    }
  }
}

///|
fn print_extra_lines(pe : @pe.Pe) -> Unit {
  let clr = pe.clr() catch { _ => None }
  match clr {
    Some(info) => println("runtime:   .NET " + info.runtime_version)
    None => ()
  }
  let level = pe.manifest_execution_level() catch { _ => None }
  match level {
    Some(value) => println("manifest:  requestedExecutionLevel=" + value)
    None => ()
  }
  let tls = pe.tls() catch { _ => None }
  match tls {
    Some(info) =>
      println("tls:       " + info.callbacks.to_string() + " callback(s)")
    None => ()
  }
}
