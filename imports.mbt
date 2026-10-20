///|
/// One imported symbol.
///
/// PE import tables can reference a symbol either by name or by ordinal. Both
/// are common: system DLLs frequently use ordinals for undocumented exports,
/// and a parser that only understands names silently drops those entries.

///|
pub(all) struct ImportEntry {
  name : String?
  ordinal : Int32?
} derive(@debug.Debug)

///|
/// One DLL and everything imported from it.
pub(all) struct ImportLibrary {
  name : String
  entries : Array[ImportEntry]
} derive(@debug.Debug)

///|
/// Read the import directory.
///
/// Returns an empty array when the image has no imports. Structural problems —
/// a descriptor or thunk table that points outside the file — are reported as
/// errors rather than skipped, because a silently truncated import list is worse
/// than a loud failure.
pub fn Pe::imports(self : Pe) -> Array[ImportLibrary] raise PeError {
  let out : Array[ImportLibrary] = []
  match self.directory(1) {
    None => return out
    Some(directory) => {
      if directory.virtual_address == 0 || directory.size == 0 {
        return out
      }
      let descriptor = match self.reader_at_rva(directory.virtual_address) {
        Some(r) => r
        None =>
          raise PeError::Malformed(
            "import directory RVA " +
            hex(directory.virtual_address) +
            " is not backed by file bytes",
            0,
          )
      }
      let mut index = 0
      let mut finished = false
      while !finished && index < 4096 {
        let original_thunk = descriptor.u32()
        let _timestamp = descriptor.u32()
        let _forwarder = descriptor.u32()
        let name_rva = descriptor.u32()
        let first_thunk = descriptor.u32()
        if name_rva == 0 && original_thunk == 0 && first_thunk == 0 {
          finished = true
        } else {
          let library_name = self.string_at_rva(name_rva, 4096)
          let thunk_rva = if original_thunk != 0 {
            original_thunk
          } else {
            first_thunk
          }
          let entries = self.read_thunks(thunk_rva)
          out.push({ name: library_name, entries, })
          index = index + 1
        }
      }
      out
    }
  }
}

///|
/// The data directory with the given slot number, if the header declares it.
pub fn Pe::directory(self : Pe, index : Int32) -> DataDirectory? {
  for directory in self.optional.directories {
    if directory.index == index {
      return Some(directory)
    }
  }
  None
}

///|
/// Read a NUL-terminated ASCII string located at an RVA.
pub fn Pe::string_at_rva(
  self : Pe,
  rva : Int32,
  limit : Int32,
) -> String raise PeError {
  match self.reader_at_rva(rva) {
    Some(r) => r.cstring(limit)
    None =>
      raise PeError::Malformed(
        "string RVA " + hex(rva) + " is not backed by file bytes",
        0,
      )
  }
}

///|
/// Walk one import lookup table.
fn Pe::read_thunks(self : Pe, rva : Int32) -> Array[ImportEntry] raise PeError {
  let out : Array[ImportEntry] = []
  let reader = match self.reader_at_rva(rva) {
    Some(r) => r
    None =>
      raise PeError::Malformed(
        "import lookup table RVA " + hex(rva) + " is not backed by file bytes",
        0,
      )
  }
  let wide = self.bits() == 64
  let mut count = 0
  let mut done = false
  while !done && count < 65536 {
    if wide {
      let value = reader.u64()
      if value == 0 {
        done = true
      } else if value < 0 {
        // The high bit marks an ordinal import.
        out.push({ name: None, ordinal: Some((value & 0xFFFF).to_int()), })
      } else {
        if value > 2147483647 {
          raise PeError::Malformed(
            "import-by-name RVA exceeds the supported 2 GiB range",
            reader.position(),
          )
        }
        let name = self.import_name(value.to_int())
        out.push({ name: Some(name), ordinal: None, })
      }
    } else {
      let value = reader.u32_raw()
      if value == 0 {
        done = true
      } else if (value.to_int64() & 0x80000000) != 0 {
        out.push({
          name: None,
          ordinal: Some((value.to_int64() & 0xFFFF).to_int()),
        })
      } else {
        let name = self.import_name(value)
        out.push({ name: Some(name), ordinal: None, })
      }
    }
    count = count + 1
  }
  out
}

///|
/// Read the name of an import, which lives behind a two-byte hint in an
/// `IMAGE_IMPORT_BY_NAME` structure.
fn Pe::import_name(self : Pe, rva : Int32) -> String raise PeError {
  match self.reader_at_rva(rva) {
    Some(r) => {
      r.skip(2)
      r.cstring(4096)
    }
    None =>
      raise PeError::Malformed(
        "import name RVA " + hex(rva) + " is not backed by file bytes",
        0,
      )
  }
}
