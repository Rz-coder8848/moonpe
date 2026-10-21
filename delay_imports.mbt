///|
/// Delay-loaded imports (data-directory slot 13).
///
/// A delay-load entry is a real dependency: the DLL is named in the image and
/// will be loaded the first time one of its functions is called. Dependency
/// inspection that only reads slot 1 therefore misses a whole class of
/// libraries, which is why this module exists.
///
/// The descriptor comes in two flavours, distinguished by bit 0 of its first
/// field (`dlattrRva`):
///
/// * bit set: every address field is an RVA;
/// * bit clear: every address field is a virtual address and must be rebased
///   against the image base.

///|
pub(all) struct DelayImportLibrary {
  name : String
  entries : Array[ImportEntry]
  // True when the descriptor used RVA-based address fields.
  rva_based : Bool
} derive(@debug.Debug)

///|
/// Read the delay-load import directory.
pub fn Pe::delay_imports(self : Pe) -> Array[DelayImportLibrary] raise PeError {
  let out : Array[DelayImportLibrary] = []
  let directory = match self.directory(13) {
    None => return out
    Some(directory) => directory
  }
  if directory.virtual_address == 0 || directory.size == 0 {
    return out
  }
  let reader = match self.reader_at_rva(directory.virtual_address) {
    Some(reader) => reader
    None =>
      raise PeError::Malformed(
        "delay-import directory RVA " +
        hex(directory.virtual_address) +
        " is not backed by file bytes",
        0,
      )
  }
  let mut count = 0
  let mut finished = false
  while !finished && count < 4096 {
    let attributes = reader.u32_raw()
    let name = reader.u32()
    let module_handle = reader.u32()
    let iat = reader.u32()
    let int_table = reader.u32()
    let bound_iat = reader.u32()
    let unload_iat = reader.u32()
    let _timestamp = reader.u32()
    if attributes == 0 &&
      name == 0 &&
      module_handle == 0 &&
      iat == 0 &&
      int_table == 0 &&
      bound_iat == 0 &&
      unload_iat == 0 {
      finished = true
    } else {
      let rva_based = (attributes.to_int64() & 1) != 0
      let name_rva = self.delay_rva(name, rva_based)
      let table = if int_table != 0 {
        self.delay_rva(int_table, rva_based)
      } else {
        self.delay_rva(iat, rva_based)
      }
      let library_name = self.string_at_rva(name_rva, 4096)
      let entries = self.read_thunks(table)
      out.push({ name: library_name, entries, rva_based, })
      count = count + 1
    }
  }
  out
}

///|
/// Convert a delay-import address field to an RVA.
fn Pe::delay_rva(
  self : Pe,
  value : Int32,
  rva_based : Bool,
) -> Int32 raise PeError {
  if value == 0 {
    return 0
  }
  if rva_based {
    return value
  }
  let base = self.optional.image_base
  let address = value.to_int64()
  if address < base {
    raise PeError::Malformed(
      "delay-import address 0x" + hex(value) + " lies below the image base",
      0,
    )
  }
  let delta = address - base
  if delta > 2147483647 {
    raise PeError::Malformed(
      "delay-import RVA exceeds the supported 2 GiB range", 0,
    )
  }
  delta.to_int()
}
