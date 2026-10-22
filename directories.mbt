///|
/// Names and resolution state for the 16 data directories.
///
/// The optional header only stores an RVA and a size per slot. Naming them and
/// reporting whether the range actually maps to file bytes turns "there are 16
/// numbers" into something a caller can act on.

///|
pub fn directory_name(index : Int32) -> String {
  match index {
    0 => "Export"
    1 => "Import"
    2 => "Resource"
    3 => "Exception"
    4 => "Security"
    5 => "BaseReloc"
    6 => "Debug"
    7 => "Architecture"
    8 => "GlobalPtr"
    9 => "TLS"
    10 => "LoadConfig"
    11 => "BoundImport"
    12 => "IAT"
    13 => "DelayImport"
    14 => "CLR"
    _ => "Reserved"
  }
}

///|
/// One data directory together with its name and file mapping.
pub(all) struct ResolvedDirectory {
  index : Int32
  name : String
  virtual_address : Int32
  size : Int32
  // `None` when the directory is empty or its RVA is not backed by file bytes.
  file_offset : Int32?
} derive(@debug.Debug)

///|
/// Every declared data directory, in slot order.
pub fn Pe::resolved_directories(self : Pe) -> Array[ResolvedDirectory] {
  let out : Array[ResolvedDirectory] = []
  for directory in self.optional.directories {
    let file_offset = if directory.virtual_address == 0 || directory.size == 0 {
      None
    } else if directory.index == 4 {
      // The security directory stores a file offset rather than an RVA.
      if directory.virtual_address + directory.size <= self.bytes.length() {
        Some(directory.virtual_address)
      } else {
        None
      }
    } else {
      self.rva_to_offset(directory.virtual_address)
    }
    out.push({
      index: directory.index,
      name: directory_name(directory.index),
      virtual_address: directory.virtual_address,
      size: directory.size,
      file_offset,
    })
  }
  out
}
