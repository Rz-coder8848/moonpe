///|
/// The CLR header (data-directory slot 14) and the metadata root it points at.
///
/// This is enough to answer "is this a managed assembly, and which runtime was
/// it built for" without decoding the full .NET metadata tables.

///|
pub(all) struct ClrInfo {
  runtime_version : String
  metadata_size : Int32
  flags : Int32
  entry_point_token : Int32
} derive(@debug.Debug)

///|
/// Read the CLR header, or `None` for a native image.
pub fn Pe::clr(self : Pe) -> ClrInfo? raise PeError {
  let directory = match self.directory(14) {
    None => return None
    Some(directory) => directory
  }
  if directory.virtual_address == 0 || directory.size == 0 {
    return None
  }
  let header = match self.reader_at_rva(directory.virtual_address) {
    Some(reader) => reader
    None =>
      raise PeError::Malformed(
        "CLR header RVA " +
        hex(directory.virtual_address) +
        " is not backed by file bytes",
        0,
      )
  }
  header.skip(4)
  header.skip(4)
  let metadata_rva = header.u32()
  let metadata_size = header.u32()
  let flags = header.u32()
  let entry_point_token = header.u32()
  let metadata = match self.reader_at_rva(metadata_rva) {
    Some(reader) => reader
    None => return None
  }
  let signature = metadata.u32_raw()
  if signature != 0x424A5342 {
    return None
  }
  metadata.skip(4)
  metadata.skip(4)
  let version_length = metadata.u32()
  if version_length > 255 {
    return None
  }
  let runtime_version = metadata.ascii(version_length)
  Some({ runtime_version, metadata_size, flags, entry_point_token, })
}
