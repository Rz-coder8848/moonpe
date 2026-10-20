///|
/// Blackbox tests: the library as an external consumer sees it, with a
/// minimal image built from scratch inside this file.

///|
fn byte_at(value : Int32) -> Byte {
  Int32::to_byte(value & 0xFF)
}

///|
fn put16(buf : Array[Byte], at : Int32, value : Int32) -> Unit {
  buf[at] = byte_at(value)
  buf[at + 1] = byte_at(value >> 8)
}

///|
fn put32(buf : Array[Byte], at : Int32, value : Int32) -> Unit {
  buf[at] = byte_at(value)
  buf[at + 1] = byte_at(value >> 8)
  buf[at + 2] = byte_at(value >> 16)
  buf[at + 3] = byte_at(value >> 24)
}

///|
/// The smallest image this library accepts: DOS header, NT headers, one
/// section, no data directories.
fn minimal_image() -> Bytes {
  let buf : Array[Byte] = []
  let mut i = 0
  while i < 0x300 {
    buf.push(byte_at(0))
    i = i + 1
  }
  buf[0] = byte_at(0x4D)
  buf[1] = byte_at(0x5A)
  put32(buf, 0x3C, 0x40)
  buf[0x40] = byte_at(0x50)
  buf[0x41] = byte_at(0x45)
  put16(buf, 0x44, 0x014C)
  put16(buf, 0x46, 1)
  put16(buf, 0x54, 0xE0)
  put16(buf, 0x56, 0x0102)
  let mut p = 0x58
  put16(buf, p, 0x10B)
  p = p + 2
  buf[p] = byte_at(14)
  p = p + 2
  p = p + 12
  put32(buf, p, 0x1000)
  p = p + 4
  put32(buf, p, 0x1000)
  p = p + 4
  put32(buf, p, 0x2000)
  p = p + 4
  put32(buf, p, 0x400000)
  p = p + 4
  put32(buf, p, 0x1000)
  p = p + 4
  put32(buf, p, 0x200)
  p = p + 4
  p = p + 12
  p = p + 4
  put32(buf, p, 0x2000)
  p = p + 4
  put32(buf, p, 0x200)
  p = p + 4
  p = p + 4
  put16(buf, p, 3)
  p = p + 4
  p = p + 16
  p = p + 4
  put32(buf, p, 16)
  let table = 0x138
  let mut t = 0
  for c in ".text" {
    buf[table + t] = byte_at(Char::to_int(c))
    t = t + 1
  }
  put32(buf, table + 8, 0x100)
  put32(buf, table + 12, 0x1000)
  put32(buf, table + 16, 0x100)
  put32(buf, table + 20, 0x200)
  put32(buf, table + 36, 0x60000020)
  buf[0x200] = byte_at(0xC3)
  Bytes::from_array(buf)
}

///|
/// The public API parses a minimal image and exposes its headers and sections.
test "public api parses a minimal image" {
  let image = minimal_image()
  let pe = @moonpe.Pe::parse(image) catch {
    _ => {
      assert_true(false)
      @moonpe.Pe::parse(minimal_image())
    }
  }
  assert_eq(pe.bits(), 32)
  assert_eq(pe.machine(), "i386")
  assert_eq(pe.subsystem(), "windows-console")
  assert_eq(pe.sections.length(), 1)
  assert_eq(pe.sections[0].name, ".text")
  assert_eq(pe.sections[0].permissions(), "r-x")
  assert_eq(pe.rva_to_offset(0x1000), Some(0x200))
  assert_eq(pe.rva_to_offset(0x2000), None)
}

///|
/// Malformed input is rejected through the public API.
test "public api rejects a non-PE buffer" {
  let ok = try {
    let _ = @moonpe.Pe::parse(b"not a pe file")
    false
  } catch {
    _ => true
  }
  assert_true(ok)
}
