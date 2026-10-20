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
  println("  info       headers, machine, subsystem, counts")
  println("  sections   section table with permissions")
  println("  imports    imported DLLs and symbols")
  println("  exports    exported symbols")
  println("  all        everything")
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
  } else if command == "all" {
    print_info(path, pe)
    println("")
    print_sections(pe)
    println("")
    print_imports(pe)
    println("")
    print_exports(pe)
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
  let import_libraries = pe.imports().length() catch { _ => 0 }
  let export_count = try {
    match pe.exports() {
      Some(table) => table.exports.length()
      None => 0
    }
  } catch {
    _ => 0
  }
  println("file:      " + path)
  println(
    "format:    PE" + pe.bits().to_string() + " at offset 0x" + @pe.hex(0x80),
  )
  println("machine:   " + pe.machine())
  println(
    "subsystem: " +
    pe.subsystem() +
    " (" +
    pe.optional.subsystem.to_string() +
    ")",
  )
  println("image:     base 0x" + @pe.hex64(pe.optional.image_base))
  println("           size 0x" + @pe.hex(pe.optional.size_of_image))
  println("entry:     0x" + @pe.hex(pe.optional.entry_point))
  println("sections:  " + pe.sections.length().to_string())
  println("imports:   " + import_libraries.to_string() + " libraries")
  println("exports:   " + export_count.to_string() + " symbols")
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
    Some(libs) => {
      if libs.length() == 0 {
        println("(no imports)")
        return
      }
      for library in libs {
        println(library.name)
        for entry in library.entries {
          match entry.name {
            Some(name) => println("  " + name)
            None =>
              match entry.ordinal {
                Some(ordinal) =>
                  println("  #" + ordinal.to_string() + " (ordinal)")
                None => println("  ?")
              }
          }
        }
      }
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
