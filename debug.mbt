///|
/// The debug directory (slot 6), including CodeView records that carry the PDB
/// path.
///
/// The PDB path is what lets a tool go from a stripped release binary back to
/// its symbols, so it is worth exposing even though the debug data itself is
/// not interpreted.

///|
pub(all) struct DebugEntry {
  kind : Int32
  kind_name : String
  timestamp : Int32
  size : Int32
  address : Int32
  pdb_signature : String?
  pdb_age : Int32?
  pdb_path : String?
} derive(@debug.Debug)

///|
/// The documented name of a debug-directory type.
pub fn debug_type_name(kind : Int32) -> String {
  match kind {
    0 => "Unknown"
    1 => "Coff"
    2 => "CodeView"
    3 => "FPO"
    4 => "Misc"
    5 => "Exception"
    6 => "Fixup"
    9 => "Borland"
    10 => "Reserved10"
    11 => "Clsid"
    12 => "VCFeature"
    13 => "POGO"
    14 => "ILTCG"
    15 => "MPX"
    16 => "Repro"
    17 => "EmbeddedPortablePDB"
    19 => "PdbChecksum"
    20 => "ExDllCharacteristics"
    _ => "Unknown(" + kind.to_string() + ")"
  }
}

///|
/// Read every debug-directory entry.
pub fn Pe::debug_entries(self : Pe) -> Array[DebugEntry] raise PeError {
  let out : Array[DebugEntry] = []
  let directory = match self.directory(6) {
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
        "debug directory RVA " +
        hex(directory.virtual_address) +
        " is not backed by file bytes",
        0,
      )
  }
  let count = directory.size / 28
  let mut i = 0
  while i < count {
    reader.skip(4)
    let timestamp = reader.u32()
    reader.skip(4)
    let kind = reader.u32()
    let size = reader.u32()
    let address = reader.u32()
    let pointer = reader.u32()
    let mut pdb_signature : String? = None
    let mut pdb_age : Int32? = None
    let mut pdb_path : String? = None
    if kind == 2 && address != 0 {
      let (signature, age, path) = self.read_codeview(address, size)
      pdb_signature = Some(signature)
      pdb_age = Some(age)
      pdb_path = path
    } else if kind == 2 && pointer != 0 {
      let (signature, age, path) = self.read_codeview_at_offset(pointer, size)
      pdb_signature = Some(signature)
      pdb_age = Some(age)
      pdb_path = path
    }
    out.push({
      kind,
      kind_name: debug_type_name(kind),
      timestamp,
      size,
      address,
      pdb_signature,
      pdb_age,
      pdb_path,
    })
    i = i + 1
  }
  out
}

///|
fn Pe::read_codeview(
  self : Pe,
  rva : Int32,
  size : Int32,
) -> (String, Int32, String?) raise PeError {
  match self.rva_to_offset(rva) {
    Some(offset) => self.read_codeview_at_offset(offset, size)
    None =>
      raise PeError::Malformed(
        "CodeView record RVA " + hex(rva) + " is not backed by file bytes",
        0,
      )
  }
}

///|
/// Decode an `RSDS` (PDB 7.0) or `NB10` (PDB 2.0) record.
fn Pe::read_codeview_at_offset(
  self : Pe,
  offset : Int32,
  size : Int32,
) -> (String, Int32, String?) raise PeError {
  let reader = match self.reader_at(offset) {
    Some(reader) => reader
    None =>
      raise PeError::Malformed(
        "CodeView record offset is outside the file", offset,
      )
  }
  let signature = reader.ascii(4)
  if signature == "RSDS" {
    reader.skip(16)
    let age = reader.u32()
    let path = reader.cstring(if size > 24 { size - 24 } else { 512 })
    ("RSDS", age, Some(path))
  } else if signature == "NB10" {
    reader.skip(4)
    reader.skip(4)
    let age = reader.u32()
    let path = reader.cstring(if size > 16 { size - 16 } else { 512 })
    ("NB10", age, Some(path))
  } else {
    (signature, 0, None)
  }
}
