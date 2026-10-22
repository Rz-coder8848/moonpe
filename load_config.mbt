///|
/// The load-configuration directory (slot 10).
///
/// This is where the linker records the process-wide mitigations an image was
/// built with: the security cookie, the SafeSEH handler table, Control Flow
/// Guard tables and flags, the heap flags and the code-integrity entry.
///
/// The structure grew over many linkers, so every field is read through the
/// declared `Size`: a field that the producer did not emit reads as zero rather
/// than running past the structure.

///|
pub(all) struct LoadConfig {
  size : Int32
  timestamp : Int32
  global_flags_clear : Int32
  global_flags_set : Int32
  critical_section_timeout : Int32
  process_heap_flags : Int32
  csd_version : Int32
  dependent_load_flags : Int32
  security_cookie : Int64
  seh_handler_table : Int64
  seh_handler_count : Int64
  guard_cf_check : Int64
  guard_cf_dispatch : Int64
  guard_cf_function_table : Int64
  guard_cf_function_count : Int64
  guard_flags : Int32
  code_integrity_flags : Int32
  code_integrity_catalog : Int32
} derive(@debug.Debug)

///|
/// Read the load-configuration directory, or `None` when absent.
pub fn Pe::load_config(self : Pe) -> LoadConfig? raise PeError {
  let directory = match self.directory(10) {
    None => return None
    Some(directory) => directory
  }
  if directory.virtual_address == 0 || directory.size == 0 {
    return None
  }
  let base = match self.rva_to_offset(directory.virtual_address) {
    Some(offset) => offset
    None =>
      raise PeError::Malformed(
        "load-config directory RVA " +
        hex(directory.virtual_address) +
        " is not backed by file bytes",
        0,
      )
  }
  let head = Reader::at(self.bytes, base)
  let size = head.u32()
  if size < 4 {
    return None
  }
  let wide = self.bits() == 64
  let timestamp = load_read(self, base, size, 4, false).to_int()
  let global_flags_clear = load_read(self, base, size, 12, false).to_int()
  let global_flags_set = load_read(self, base, size, 16, false).to_int()
  let critical_section_timeout = load_read(self, base, size, 20, false).to_int()
  let heap_offset = if wide { 72 } else { 48 }
  let affinity_offset = if wide { 64 } else { 44 }
  let process_heap_flags = load_read(self, base, size, heap_offset, false).to_int()
  let csd_version = load_read(self, base, size, heap_offset + 4, false).to_int()
  let dependent_load_flags = load_read(self, base, size, heap_offset + 6, false).to_int()
  let cookie_offset = if wide { 88 } else { 60 }
  let seh_offset = if wide { 96 } else { 64 }
  let guard_offset = if wide { 112 } else { 72 }
  let guard_flags_offset = if wide { 144 } else { 88 }
  let code_integrity_offset = if wide { 148 } else { 92 }
  let security_cookie = load_read(self, base, size, cookie_offset, true)
  let seh_handler_table = load_read(self, base, size, seh_offset, true)
  let seh_handler_count = load_read(
    self,
    base,
    size,
    seh_offset + (if wide { 8 } else { 4 }),
    true,
  )
  let guard_cf_check = load_read(self, base, size, guard_offset, true)
  let guard_cf_dispatch = load_read(
    self,
    base,
    size,
    guard_offset + (if wide { 8 } else { 4 }),
    true,
  )
  let guard_cf_function_table = load_read(
    self,
    base,
    size,
    guard_offset + (if wide { 16 } else { 8 }),
    true,
  )
  let guard_cf_function_count = load_read(
    self,
    base,
    size,
    guard_offset + (if wide { 24 } else { 12 }),
    true,
  )
  let guard_flags = load_read(self, base, size, guard_flags_offset, false).to_int()
  let code_integrity_flags = load_read(
    self, base, size, code_integrity_offset, false,
  ).to_int()
  let code_integrity_catalog = load_read(
    self,
    base,
    size,
    code_integrity_offset + 2,
    false,
  ).to_int()
  let _ = affinity_offset
  Some({
    size,
    timestamp,
    global_flags_clear,
    global_flags_set,
    critical_section_timeout,
    process_heap_flags,
    csd_version,
    dependent_load_flags,
    security_cookie,
    seh_handler_table,
    seh_handler_count,
    guard_cf_check,
    guard_cf_dispatch,
    guard_cf_function_table,
    guard_cf_function_count,
    guard_flags,
    code_integrity_flags,
    code_integrity_catalog,
  })
}

///|
/// Read a load-config field, returning zero when the declared structure size
/// says the field is not present.
fn load_read(
  pe : Pe,
  base : Int32,
  size : Int32,
  field_offset : Int32,
  pointer_sized : Bool,
) -> Int64 raise PeError {
  let width = if pointer_sized && pe.bits() == 64 {
    8
  } else if pointer_sized {
    4
  } else {
    4
  }
  if field_offset + width > size ||
    base + field_offset + width > pe.bytes.length() {
    return 0L
  }
  let reader = Reader::at(pe.bytes, base + field_offset)
  if width == 8 {
    reader.u64()
  } else {
    reader.u32().to_int64()
  }
}

///|
/// The SafeSEH handler table: the RVAs of the exception handlers the image was
/// built with.
///
/// SafeSEH is an x86 mitigation. On x64 the table is unused, so this returns
/// `None`; on x86 it returns `Some([])` when the image has a load config but
/// records no handlers, which is exactly the state a mitigation check wants to
/// distinguish from "no load config at all".
pub fn Pe::safe_seh_handlers(self : Pe) -> Array[Int32]? raise PeError {
  if self.bits() != 32 {
    return None
  }
  let config = match self.load_config() {
    None => return None
    Some(config) => config
  }
  if config.seh_handler_count <= 0L || config.seh_handler_table == 0L {
    return Some([])
  }
  let count = if config.seh_handler_count > 65536L {
    65536
  } else {
    config.seh_handler_count.to_int()
  }
  let table_rva = match self.va_to_rva(config.seh_handler_table.to_int()) {
    Some(rva) => rva
    None => return Some([])
  }
  let reader = match self.reader_at_rva(table_rva) {
    Some(reader) => reader
    None => return Some([])
  }
  let handlers : Array[Int32] = []
  let mut i = 0
  while i < count {
    handlers.push(reader.u32())
    i = i + 1
  }
  Some(handlers)
}
