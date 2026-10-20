///|
/// A parsed PE image: the headers, the section table, and the bytes they were
/// parsed from.
///
/// Parsing is eager for the headers and lazy for the tables: imports and
/// exports are only walked when they are asked for, so `moonpe info` on a large
/// DLL does not pay for work it will not use.

///|
pub(all) struct Pe {
  bytes : Bytes
  coff : CoffHeader
  optional : OptionalHeader
  sections : Array[Section]
}

///|
/// Parse a PE image from memory.
///
/// Every failure is a `PeError` carrying the offset it was detected at; the
/// parser never panics on hostile input.
pub fn Pe::parse(bytes : Bytes) -> Pe raise PeError {
  if bytes.length() < 64 {
    raise PeError::OutOfBounds(0, 64, bytes.length())
  }
  let head = Reader::new(bytes)
  let mz = head.u16()
  if mz != 0x5A4D {
    raise PeError::BadMagic("expected the 'MZ' DOS signature", 0)
  }
  let at = Reader::seek(bytes, 0x3C)
  let pe_offset = at.u32()
  if pe_offset < 64 || pe_offset + 24 > bytes.length() {
    raise PeError::Malformed(
      "e_lfanew points outside the file (" + hex(pe_offset) + ")",
      0x3C,
    )
  }
  let r = Reader::seek(bytes, pe_offset)
  let signature = r.u32()
  if signature != 0x00004550 {
    raise PeError::BadMagic("expected the 'PE\\0\\0' NT signature", pe_offset)
  }
  let machine = r.u16()
  let number_of_sections = r.u16()
  let timestamp = r.u32()
  r.skip(8)
  let size_of_optional_header = r.u16()
  let characteristics = r.u16()
  let coff : CoffHeader = {
    machine,
    number_of_sections,
    timestamp,
    characteristics,
  }
  if size_of_optional_header == 0 {
    raise PeError::Malformed(
      "PE image without an optional header",
      r.position(),
    )
  }
  let optional_start = r.position()
  let optional = parse_optional_header(r, size_of_optional_header)
  let table = Reader::seek(bytes, optional_start + size_of_optional_header)
  let sections = parse_sections(table, number_of_sections)
  { bytes, coff, optional, sections, }
}

///|
fn parse_optional_header(
  r : Reader,
  size : Int32,
) -> OptionalHeader raise PeError {
  let start = r.position()
  if size < 96 {
    raise PeError::Malformed("optional header is too short to be valid", start)
  }
  let magic = r.u16()
  let kind = if magic == 0x10B {
    Pe32
  } else if magic == 0x20B {
    Pe32Plus
  } else {
    raise PeError::BadMagic(
      "unknown optional header magic 0x" + hex(magic),
      start,
    )
  }
  r.skip(2)
  r.skip(4)
  r.skip(4)
  r.skip(4)
  let entry_point = r.u32()
  r.skip(4)
  if kind == Pe32 {
    r.skip(4)
  }
  let image_base = if kind == Pe32 { r.u32().to_int64() } else { r.u64() }
  let section_alignment = r.u32()
  let file_alignment = r.u32()
  r.skip(8)
  r.skip(4)
  r.skip(4)
  let size_of_image = r.u32()
  let size_of_headers = r.u32()
  r.skip(4)
  let subsystem = r.u16()
  let dll_characteristics = r.u16()
  r.skip(16)
  if kind == Pe32Plus {
    r.skip(16)
  }
  r.skip(4)
  let number_of_rva_and_sizes = r.u32()
  let consumed = r.position() - start
  let available = size - consumed
  let capacity = if available > 0 { available / 8 } else { 0 }
  let mut count = number_of_rva_and_sizes
  if count > 16 {
    count = 16
  }
  if count > capacity {
    count = capacity
  }
  let directories : Array[DataDirectory] = []
  let mut i = 0
  while i < count {
    let virtual_address = r.u32()
    let directory_size = r.u32()
    directories.push({ index: i, virtual_address, size: directory_size, })
    i = i + 1
  }
  {
    kind,
    entry_point,
    image_base,
    section_alignment,
    file_alignment,
    size_of_image,
    size_of_headers,
    subsystem,
    dll_characteristics,
    directories,
  }
}

///|
fn parse_sections(r : Reader, count : Int32) -> Array[Section] raise PeError {
  let start = r.position()
  let available = r.remaining()
  if count < 0 || count * 40 > available {
    raise PeError::Malformed(
      "section table declares " +
      count.to_string() +
      " entries but only " +
      (available / 40).to_string() +
      " fit in the file",
      start,
    )
  }
  let out : Array[Section] = []
  let mut i = 0
  while i < count {
    let name = r.ascii(8)
    let virtual_size = r.u32()
    let virtual_address = r.u32()
    let raw_size = r.u32()
    let raw_pointer = r.u32()
    r.skip(12)
    let characteristics = r.u32_raw()
    out.push({
      name,
      virtual_size,
      virtual_address,
      raw_size,
      raw_pointer,
      characteristics,
    })
    i = i + 1
  }
  out
}

///|
/// `32` or `64`.
pub fn Pe::bits(self : Pe) -> Int32 {
  self.optional.kind.bits()
}

///|
/// The CPU architecture name.
pub fn Pe::machine(self : Pe) -> String {
  machine_name(self.coff.machine)
}

///|
/// The subsystem name.
pub fn Pe::subsystem(self : Pe) -> String {
  subsystem_name(self.optional.subsystem)
}

///|
/// Look a section up by its (NUL-trimmed) name.
pub fn Pe::section(self : Pe, name : String) -> Section? {
  for section in self.sections {
    if section.name == name {
      return Some(section)
    }
  }
  None
}

///|
/// The section that contains an RVA, if any.
pub fn Pe::section_for_rva(self : Pe, rva : Int32) -> Section? {
  for section in self.sections {
    let span = if section.virtual_size > section.raw_size {
      section.virtual_size
    } else {
      section.raw_size
    }
    if rva >= section.virtual_address && rva < section.virtual_address + span {
      return Some(section)
    }
  }
  None
}

///|
/// Map a relative virtual address to an offset in the file.
///
/// Returns `None` for addresses inside a section's zero-filled tail: those
/// bytes exist in memory but not on disk, and reading them would return
/// whatever happened to be next in the file.
pub fn Pe::rva_to_offset(self : Pe, rva : Int32) -> Int32? {
  if rva < 0 {
    return None
  }
  if rva < self.optional.size_of_headers {
    if rva < self.bytes.length() {
      return Some(rva)
    }
    return None
  }
  match self.section_for_rva(rva) {
    Some(section) => {
      let delta = rva - section.virtual_address
      if delta >= section.raw_size {
        return None
      }
      let offset = section.raw_pointer + delta
      if offset < self.bytes.length() {
        Some(offset)
      } else {
        None
      }
    }
    None => None
  }
}

///|
/// The raw bytes backing a section, or `None` when the section has no file
/// contents (`.bss`-style) or its declared range lies outside the file.
pub fn Pe::section_bytes(self : Pe, section : Section) -> Bytes? {
  if section.raw_size <= 0 {
    return None
  }
  if section.raw_pointer < 0 ||
    section.raw_pointer + section.raw_size > self.bytes.length() {
    return None
  }
  let out : Array[Byte] = []
  let mut i = 0
  while i < section.raw_size {
    out.push(self.bytes[section.raw_pointer + i])
    i = i + 1
  }
  Some(Bytes::from_array(out))
}

///|
/// A reader positioned at an absolute file offset.
fn Pe::reader_at(self : Pe, offset : Int32) -> Reader? {
  if offset < 0 || offset > self.bytes.length() {
    None
  } else {
    Some(Reader::at(self.bytes, offset))
  }
}

///|
/// A reader positioned at an RVA, or `None` when that address is not backed by
/// file bytes.
fn Pe::reader_at_rva(self : Pe, rva : Int32) -> Reader? {
  match self.rva_to_offset(rva) {
    Some(offset) => self.reader_at(offset)
    None => None
  }
}
