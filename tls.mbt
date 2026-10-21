///|
/// The TLS directory (slot 9).
///
/// TLS callbacks run *before* the entry point, which makes them a classic place
/// to hide anti-debugging or unpacking code. Counting them is the useful part;
/// the addresses themselves are reported through the section map.

///|
pub(all) struct TlsInfo {
  callbacks : Int32
  zero_fill_size : Int32
  raw_data_size : Int32
} derive(@debug.Debug)

///|
/// Read the TLS directory, or `None` when the image has none.
pub fn Pe::tls(self : Pe) -> TlsInfo? raise PeError {
  let directory = match self.directory(9) {
    None => return None
    Some(directory) => directory
  }
  if directory.virtual_address == 0 || directory.size == 0 {
    return None
  }
  let reader = match self.reader_at_rva(directory.virtual_address) {
    Some(reader) => reader
    None =>
      raise PeError::Malformed(
        "TLS directory RVA " +
        hex(directory.virtual_address) +
        " is not backed by file bytes",
        0,
      )
  }
  let wide = self.bits() == 64
  // Addresses are virtual addresses and can exceed 32 bits, so they are read
  // and rebased in Int64 before anything is narrowed.
  let start_address = if wide { reader.u64() } else { reader.u32().to_int64() }
  let end_address = if wide { reader.u64() } else { reader.u32().to_int64() }
  let _index_address = if wide { reader.u64() } else { reader.u32().to_int64() }
  let callbacks_address = if wide {
    reader.u64()
  } else {
    reader.u32().to_int64()
  }
  let zero_fill_size = reader.u32()
  reader.skip(4)
  let size = if end_address > start_address {
    end_address - start_address
  } else {
    0L
  }
  let raw_data_size = if size > 2147483647L {
    2147483647
  } else {
    size.to_int()
  }
  let base = self.optional.image_base
  let mut callbacks = 0
  if callbacks_address > base {
    let delta = callbacks_address - base
    if delta <= 2147483647L {
      match self.reader_at_rva(delta.to_int()) {
        Some(table) => {
          let mut done = false
          while !done && callbacks < 4096 {
            let entry = if wide { table.u64() } else { table.u32().to_int64() }
            if entry == 0L {
              done = true
            } else {
              callbacks = callbacks + 1
            }
          }
        }
        None => ()
      }
    }
  }
  Some({ callbacks, zero_fill_size, raw_data_size, })
}
