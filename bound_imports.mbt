///|
/// Bound imports (slot 11).
///
/// A bound-import table records the DLL versions an image was linked against.
/// It is advisory and often stripped, but when present it tells a release check
/// which system libraries the build was pinned to.

///|
/// The module names listed in the bound-import directory.
pub fn Pe::bound_imports(self : Pe) -> Array[String] raise PeError {
  let out : Array[String] = []
  let directory = match self.directory(11) {
    None => return out
    Some(directory) => directory
  }
  if directory.virtual_address == 0 || directory.size == 0 {
    return out
  }
  let base = match self.rva_to_offset(directory.virtual_address) {
    Some(offset) => offset
    None =>
      raise PeError::Malformed(
        "bound-import directory RVA " +
        hex(directory.virtual_address) +
        " is not backed by file bytes",
        0,
      )
  }
  let reader = Reader::at(self.bytes, base)
  let mut count = 0
  let mut done = false
  while !done && count < 4096 {
    let timestamp = reader.u32()
    let name_offset = reader.u16()
    let forwarders = reader.u16()
    if timestamp == 0 && name_offset == 0 && forwarders == 0 {
      done = true
    } else {
      reader.skip(forwarders * 8)
      if name_offset != 0 {
        let name_reader = Reader::at(self.bytes, base + name_offset)
        let name = name_reader.cstring(512)
        out.push(name)
      }
      count = count + 1
    }
  }
  out
}
