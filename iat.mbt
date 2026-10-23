///|
/// The Import Address Table (data-directory slot 12).
///
/// The lookup table and the IAT normally start with the same hint/name RVAs,
/// but they serve different purposes: the loader overwrites IAT slots with
/// resolved function addresses. A dependency checker needs the slot location
/// and its on-disk value, while a security tool may need to distinguish an
/// unbound image from one carrying pre-bound virtual addresses.

///|
pub(all) struct IatEntry {
  library : String
  delayed : Bool
  slot_rva : Int32
  // Raw slot bits as stored on disk. For PE32+ this can have bit 63 set.
  raw_value : Int64
  symbol : ImportEntry
} derive(@debug.Debug)

///|
/// Read every current IAT slot in descriptor order.
///
/// Static imports use data-directory slot 12, but delay-loaded libraries carry
/// independent IATs inside slot 13. Both are returned and distinguished by
/// `delayed`; reading only the normal IAT silently misses the latter.
pub fn Pe::iat(self : Pe) -> Array[IatEntry] raise PeError {
  let out : Array[IatEntry] = []
  let wide = self.bits() == 64
  for descriptor in self.import_descriptors() {
    let library = self.string_at_rva(descriptor.name_rva, 4096)
    let lookup_rva = if descriptor.original_thunk != 0 {
      descriptor.original_thunk
    } else {
      descriptor.first_thunk
    }
    let symbols = self.read_thunks(lookup_rva)
    let slots = match self.reader_at_rva(descriptor.first_thunk) {
      Some(reader) => reader
      None =>
        raise PeError::Malformed(
          "IAT RVA " +
          hex(descriptor.first_thunk) +
          " is not backed by file bytes",
          0,
        )
    }
    let mut index = 0
    for symbol in symbols {
      // The ordinal bit makes a PE32 slot look like a value above 2 GiB, so this
      // deliberate bit-pattern read must bypass the address-range guard.
      let raw_value = if wide {
        slots.u64()
      } else {
        slots.u32_raw().to_int64() & 0xFFFFFFFFL
      }
      out.push({
        library,
        delayed: false,
        slot_rva: descriptor.first_thunk + index * (if wide { 8 } else { 4 }),
        raw_value,
        symbol,
      })
      index = index + 1
    }
  }
  for library in self.delay_imports() {
    let iat_rva = match library.iat_rva {
      Some(rva) => rva
      None =>
        raise PeError::Malformed(
          "delay-import descriptor for " + library.name + " has no IAT RVA",
          0,
        )
    }
    let slots = match self.reader_at_rva(iat_rva) {
      Some(reader) => reader
      None =>
        raise PeError::Malformed(
          "delay-IAT RVA " + hex(iat_rva) + " is not backed by file bytes",
          0,
        )
    }
    let mut index = 0
    for symbol in library.entries {
      let raw_value = if wide {
        slots.u64()
      } else {
        slots.u32_raw().to_int64() & 0xFFFFFFFFL
      }
      out.push({
        library: library.name,
        delayed: true,
        slot_rva: iat_rva + index * (if wide { 8 } else { 4 }),
        raw_value,
        symbol,
      })
      index = index + 1
    }
  }
  out
}
