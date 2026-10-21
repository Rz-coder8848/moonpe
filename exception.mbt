///|
/// The exception directory (slot 3).
///
/// On x64 and ARM64 this is a table of `IMAGE_RUNTIME_FUNCTION_ENTRY` records
/// (12 bytes: begin RVA, end RVA, unwind-info RVA). Its entry count is a good
/// proxy for "how much unwind information this image carries", and the same
/// table is what a debugger consults to walk a stack.

///|
pub(all) struct FunctionTable {
  entries : Int32
  first_rva : Int32
  last_rva : Int32
} derive(@debug.Debug)

///|
/// Read the runtime-function table, if the image has one.
pub fn Pe::function_table(self : Pe) -> FunctionTable? raise PeError {
  let directory = match self.directory(3) {
    None => return None
    Some(directory) => directory
  }
  if directory.virtual_address == 0 || directory.size == 0 {
    return None
  }
  let entries = directory.size / 12
  if entries == 0 {
    return None
  }
  let reader = match self.reader_at_rva(directory.virtual_address) {
    Some(reader) => reader
    None =>
      raise PeError::Malformed(
        "exception directory RVA " +
        hex(directory.virtual_address) +
        " is not backed by file bytes",
        0,
      )
  }
  let mut first = 0
  let mut last = 0
  let mut i = 0
  while i < entries {
    let begin = reader.u32()
    let end = reader.u32()
    reader.skip(4)
    if i == 0 {
      first = begin
    }
    if end > last {
      last = end
    }
    i = i + 1
  }
  Some({ entries, first_rva: first, last_rva: last, })
}
