///|
/// One exported symbol.
///
/// `name` is `None` for exports that are reachable by ordinal only, which real
/// DLLs use for internal helpers. Keeping them in the list means the reported
/// count matches what the loader sees.

///|
pub(all) struct Export {
  name : String?
  ordinal : Int32
  rva : Int32
} derive(@debug.Debug)

///|
/// A parsed export directory.
pub(all) struct ExportTable {
  dll_name : String
  exports : Array[Export]
} derive(@debug.Debug)

///|
/// Read the export directory.
///
/// Returns `None` when the image exports nothing, which is the normal case for
/// executables and for many DLLs.
pub fn Pe::exports(self : Pe) -> ExportTable? raise PeError {
  let directory = match self.directory(0) {
    None => return None
    Some(directory) => directory
  }
  if directory.virtual_address == 0 || directory.size == 0 {
    return None
  }
  let r = match self.reader_at_rva(directory.virtual_address) {
    Some(r) => r
    None =>
      raise PeError::Malformed(
        "export directory RVA " +
        hex(directory.virtual_address) +
        " is not backed by file bytes",
        0,
      )
  }
  r.skip(4)
  r.skip(4)
  r.skip(4)
  let name_rva = r.u32()
  let ordinal_base = r.u32()
  let number_of_functions = r.u32()
  let number_of_names = r.u32()
  let functions_rva = r.u32()
  let names_rva = r.u32()
  let ordinals_rva = r.u32()
  let dll_name = self.string_at_rva(name_rva, 4096)
  let names = self.export_names(names_rva, number_of_names)
  let ordinals = self.export_name_ordinals(ordinals_rva, number_of_names)
  let functions = self.export_function_rvas(functions_rva, number_of_functions)
  let table : Array[Export] = []
  let mut i = 0
  while i < names.length() && i < ordinals.length() {
    let index = ordinals[i]
    if index >= 0 && index < functions.length() {
      table.push({
        name: Some(names[i]),
        ordinal: ordinal_base + index,
        rva: functions[index],
      })
    } else {
      raise PeError::Malformed(
        "export name " +
        i.to_string() +
        " points at function index " +
        index.to_string() +
        ", outside the function table",
        0,
      )
    }
    i = i + 1
  }
  // Ordinal-only exports: every function slot not covered by a name.
  let mut slot = 0
  while slot < functions.length() {
    if functions[slot] != 0 && !contains_index(ordinals, slot) {
      table.push({
        name: None,
        ordinal: ordinal_base + slot,
        rva: functions[slot],
      })
    }
    slot = slot + 1
  }
  Some({ dll_name, exports: table, })
}

///|
fn contains_index(indices : Array[Int32], needle : Int32) -> Bool {
  for index in indices {
    if index == needle {
      return true
    }
  }
  false
}

///|
/// Read the export name-pointer array as a list of strings.
fn Pe::export_names(
  self : Pe,
  rva : Int32,
  count : Int32,
) -> Array[String] raise PeError {
  let out : Array[String] = []
  if count == 0 {
    return out
  }
  let r = match self.reader_at_rva(rva) {
    Some(r) => r
    None =>
      raise PeError::Malformed(
        "export name table RVA " + hex(rva) + " is not backed by file bytes",
        0,
      )
  }
  let mut i = 0
  while i < count {
    let name_rva = r.u32()
    out.push(self.string_at_rva(name_rva, 4096))
    i = i + 1
  }
  out
}

///|
fn Pe::export_name_ordinals(
  self : Pe,
  rva : Int32,
  count : Int32,
) -> Array[Int32] raise PeError {
  let out : Array[Int32] = []
  if count == 0 {
    return out
  }
  let r = match self.reader_at_rva(rva) {
    Some(r) => r
    None =>
      raise PeError::Malformed(
        "export ordinal table RVA " + hex(rva) + " is not backed by file bytes",
        0,
      )
  }
  let mut i = 0
  while i < count {
    out.push(r.u16())
    i = i + 1
  }
  out
}

///|
fn Pe::export_function_rvas(
  self : Pe,
  rva : Int32,
  count : Int32,
) -> Array[Int32] raise PeError {
  let out : Array[Int32] = []
  if count == 0 {
    return out
  }
  let r = match self.reader_at_rva(rva) {
    Some(r) => r
    None =>
      raise PeError::Malformed(
        "export address table RVA " + hex(rva) + " is not backed by file bytes",
        0,
      )
  }
  let mut i = 0
  while i < count {
    out.push(r.u32())
    i = i + 1
  }
  out
}
