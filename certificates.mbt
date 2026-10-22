///|
/// The certificate table (data-directory slot 4).
///
/// This is the one directory whose `VirtualAddress` is a **file offset**, not an
/// RVA — a documented PE quirk that a naive reader gets wrong. Each entry is a
/// `WIN_CERTIFICATE`: length, revision and type, padded to eight bytes.
///
/// The certificate bytes are not verified here; that would require a full
/// Authenticode implementation. Reading the table answers "is a signature
/// embedded, and what kind".

///|
pub(all) struct Certificate {
  length : Int32
  revision : Int32
  kind : Int32
} derive(@debug.Debug)

///|
/// Walk the certificate table.
pub fn Pe::certificates(self : Pe) -> Array[Certificate] raise PeError {
  let out : Array[Certificate] = []
  let directory = match self.directory(4) {
    None => return out
    Some(directory) => directory
  }
  if directory.size == 0 || directory.virtual_address == 0 {
    return out
  }
  // Slot 4 stores a file offset in the address field.
  let mut offset = directory.virtual_address
  let end = offset + directory.size
  if end > self.bytes.length() {
    raise PeError::Malformed(
      "certificate table extends past the end of the file", offset,
    )
  }
  let mut count = 0
  while offset + 8 <= end && count < 1024 {
    let reader = Reader::at(self.bytes, offset)
    let length = reader.u32()
    let revision = reader.u16()
    let kind = reader.u16()
    if length < 8 {
      break
    }
    out.push({ length, revision, kind, })
    let advance = (length + 7) / 8 * 8
    offset = offset + advance
    count = count + 1
  }
  out
}
