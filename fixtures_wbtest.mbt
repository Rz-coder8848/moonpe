///|
/// Test fixtures: build valid PE images in memory.
///
/// Hand-built images are the only way to test a file-format parser without
/// shipping third-party binaries: every byte is accounted for, and a failing
/// test points at something this repository controls.

///|
fn blank(size : Int32) -> Array[Byte] {
  let out : Array[Byte] = []
  let mut i = 0
  while i < size {
    out.push(Int32::to_byte(0))
    i = i + 1
  }
  out
}

///|
fn set_u8(buf : Array[Byte], offset : Int32, value : Int32) -> Unit {
  buf[offset] = Int32::to_byte(value & 0xFF)
}

///|
fn set_u16(buf : Array[Byte], offset : Int32, value : Int32) -> Unit {
  let mut v = value
  let mut i = 0
  while i < 2 {
    set_u8(buf, offset + i, v & 0xFF)
    v = v >> 8
    i = i + 1
  }
}

///|
fn set_u32(buf : Array[Byte], offset : Int32, value : Int32) -> Unit {
  let mut v = value
  let mut i = 0
  while i < 4 {
    set_u8(buf, offset + i, v & 0xFF)
    v = v >> 8
    i = i + 1
  }
}

///|
fn set_ascii(buf : Array[Byte], offset : Int32, text : String) -> Int32 {
  let mut i = 0
  for c in text {
    set_u8(buf, offset + i, Char::to_int(c) & 0xFF)
    i = i + 1
  }
  i
}

///|
fn set_cstr(buf : Array[Byte], offset : Int32, text : String) -> Int32 {
  let n = set_ascii(buf, offset, text)
  set_u8(buf, offset + n, 0)
  n + 1
}

///|
/// Build a complete PE32 image: two sections, one import library with a named
/// and an ordinal import, and an export directory with two named and one
/// ordinal-only export.
fn build_pe32() -> Bytes {
  let buf = blank(0x600)
  // DOS header: 'MZ' plus e_lfanew = 0x80.
  set_u8(buf, 0, 0x4D)
  set_u8(buf, 1, 0x5A)
  set_u32(buf, 0x3C, 0x80)
  // NT signature.
  set_u8(buf, 0x80, 0x50)
  set_u8(buf, 0x81, 0x45)
  // COFF header at 0x84.
  set_u16(buf, 0x84, 0x014C)
  set_u16(buf, 0x86, 2)
  set_u32(buf, 0x88, 0x5F000000)
  set_u16(buf, 0x94, 0xE0)
  set_u16(buf, 0x96, 0x0102)
  // Optional header at 0x98.
  let mut p = 0x98
  set_u16(buf, p, 0x10B)
  p = p + 2
  set_u8(buf, p, 14)
  set_u8(buf, p + 1, 0)
  p = p + 2
  set_u32(buf, p, 0x200)
  p = p + 4
  set_u32(buf, p, 0x200)
  p = p + 4
  set_u32(buf, p, 0)
  p = p + 4
  set_u32(buf, p, 0x1000)
  p = p + 4
  set_u32(buf, p, 0x1000)
  p = p + 4
  set_u32(buf, p, 0x2000)
  p = p + 4
  set_u32(buf, p, 0x400000)
  p = p + 4
  set_u32(buf, p, 0x1000)
  p = p + 4
  set_u32(buf, p, 0x200)
  p = p + 4
  set_u16(buf, p, 6)
  set_u16(buf, p + 2, 0)
  set_u16(buf, p + 4, 0)
  set_u16(buf, p + 6, 0)
  set_u16(buf, p + 8, 6)
  set_u16(buf, p + 10, 0)
  p = p + 12
  set_u32(buf, p, 0)
  p = p + 4
  set_u32(buf, p, 0x3000)
  p = p + 4
  set_u32(buf, p, 0x200)
  p = p + 4
  set_u32(buf, p, 0)
  p = p + 4
  set_u16(buf, p, 3)
  p = p + 2
  set_u16(buf, p, 0)
  p = p + 2
  set_u32(buf, p, 0x100000)
  set_u32(buf, p + 4, 0x1000)
  set_u32(buf, p + 8, 0x100000)
  set_u32(buf, p + 12, 0x1000)
  p = p + 16
  set_u32(buf, p, 0)
  p = p + 4
  set_u32(buf, p, 16)
  p = p + 4
  // Data directories: export at 0x2100, import at 0x2000.
  set_u32(buf, p, 0x2100)
  set_u32(buf, p + 4, 0x100)
  set_u32(buf, p + 8, 0x2000)
  set_u32(buf, p + 12, 0x28)
  // Section table at 0x98 + 0xE0 = 0x178.
  let t1 = 0x178
  let _ = set_ascii(buf, t1, ".text")
  set_u32(buf, t1 + 8, 0x100)
  set_u32(buf, t1 + 12, 0x1000)
  set_u32(buf, t1 + 16, 0x200)
  set_u32(buf, t1 + 20, 0x200)
  set_u32(buf, t1 + 36, 0x60000020)
  let t2 = t1 + 40
  let _ = set_ascii(buf, t2, ".rdata")
  set_u32(buf, t2 + 8, 0x300)
  set_u32(buf, t2 + 12, 0x2000)
  set_u32(buf, t2 + 16, 0x200)
  set_u32(buf, t2 + 20, 0x400)
  set_u32(buf, t2 + 36, 0x40000040)
  // .text body.
  set_u8(buf, 0x200, 0xC3)
  // Import descriptor at file 0x400.
  set_u32(buf, 0x400, 0x2040)
  set_u32(buf, 0x40C, 0x2080)
  set_u32(buf, 0x410, 0x2060)
  // Import lookup table at 0x440: named, ordinal 7, terminator.
  set_u32(buf, 0x440, 0x2090)
  set_u8(buf, 0x444, 7)
  set_u8(buf, 0x447, 0x80)
  // Import address table at 0x460 mirrors it.
  set_u32(buf, 0x460, 0x2090)
  set_u8(buf, 0x464, 7)
  set_u8(buf, 0x467, 0x80)
  let _ = set_cstr(buf, 0x480, "KERNEL32.dll")
  set_u16(buf, 0x490, 0)
  let _ = set_cstr(buf, 0x492, "ExitProcess")
  // Export directory at 0x500.
  set_u32(buf, 0x50C, 0x2170)
  set_u32(buf, 0x510, 1)
  set_u32(buf, 0x514, 3)
  set_u32(buf, 0x518, 2)
  set_u32(buf, 0x51C, 0x2140)
  set_u32(buf, 0x520, 0x2150)
  set_u32(buf, 0x524, 0x2160)
  set_u32(buf, 0x540, 0x1000)
  set_u32(buf, 0x544, 0x1010)
  set_u32(buf, 0x548, 0x1020)
  set_u32(buf, 0x550, 0x2180)
  set_u32(buf, 0x554, 0x2190)
  set_u16(buf, 0x560, 0)
  set_u16(buf, 0x562, 2)
  let _ = set_cstr(buf, 0x570, "demo.dll")
  let _ = set_cstr(buf, 0x580, "demo_init")
  let _ = set_cstr(buf, 0x590, "demo_run")
  Bytes::from_array(buf)
}

///|
fn set_u64(buf : Array[Byte], offset : Int32, value : Int64) -> Unit {
  let mut v = value
  let mut i = 0
  while i < 8 {
    set_u8(buf, offset + i, (v & 0xFF).to_int())
    v = v >> 8
    i = i + 1
  }
}

///|
/// Build a PE32+ image: headers and sections only, which is enough to exercise
/// the widened optional header (64-bit image base, 8-byte stack and heap
/// fields) and the 64-bit section layout.
fn build_pe64() -> Bytes {
  let buf = blank(0x400)
  set_u8(buf, 0, 0x4D)
  set_u8(buf, 1, 0x5A)
  set_u32(buf, 0x3C, 0x80)
  set_u8(buf, 0x80, 0x50)
  set_u8(buf, 0x81, 0x45)
  set_u16(buf, 0x84, 0x8664)
  set_u16(buf, 0x86, 1)
  set_u32(buf, 0x88, 0x5F000000)
  set_u16(buf, 0x94, 0xF0)
  set_u16(buf, 0x96, 0x0022)
  let mut p = 0x98
  set_u16(buf, p, 0x20B)
  p = p + 2
  set_u8(buf, p, 14)
  set_u8(buf, p + 1, 0)
  p = p + 2
  set_u32(buf, p, 0x200)
  p = p + 4
  set_u32(buf, p, 0)
  p = p + 4
  set_u32(buf, p, 0)
  p = p + 4
  set_u32(buf, p, 0x1000)
  p = p + 4
  set_u32(buf, p, 0x1000)
  p = p + 4
  set_u64(buf, p, 0x140000000L)
  p = p + 8
  set_u32(buf, p, 0x1000)
  p = p + 4
  set_u32(buf, p, 0x200)
  p = p + 4
  set_u16(buf, p, 6)
  set_u16(buf, p + 2, 0)
  set_u16(buf, p + 4, 0)
  set_u16(buf, p + 6, 0)
  set_u16(buf, p + 8, 6)
  set_u16(buf, p + 10, 0)
  p = p + 12
  set_u32(buf, p, 0)
  p = p + 4
  set_u32(buf, p, 0x2000)
  p = p + 4
  set_u32(buf, p, 0x200)
  p = p + 4
  set_u32(buf, p, 0)
  p = p + 4
  set_u16(buf, p, 3)
  p = p + 2
  set_u16(buf, p, 0)
  p = p + 2
  set_u64(buf, p, 0x100000L)
  set_u64(buf, p + 8, 0x1000L)
  set_u64(buf, p + 16, 0x100000L)
  set_u64(buf, p + 24, 0x1000L)
  p = p + 32
  set_u32(buf, p, 0)
  p = p + 4
  set_u32(buf, p, 16)
  p = p + 4
  // One section, `.text` at RVA 0x1000 backed by file offset 0x200.
  let t1 = 0x188
  let _ = set_ascii(buf, t1, ".text")
  set_u32(buf, t1 + 8, 0x100)
  set_u32(buf, t1 + 12, 0x1000)
  set_u32(buf, t1 + 16, 0x200)
  set_u32(buf, t1 + 20, 0x200)
  set_u32(buf, t1 + 36, 0x60000020)
  set_u8(buf, 0x200, 0xC3)
  Bytes::from_array(buf)
}

///|
/// A file whose DOS signature is missing.
fn build_not_mz() -> Bytes {
  let buf = blank(0x100)
  set_u32(buf, 0x3C, 0x80)
  Bytes::from_array(buf)
}

///|
/// A file with a valid DOS header but no `PE\0\0` signature.
fn build_bad_signature() -> Bytes {
  let buf = blank(0x200)
  set_u8(buf, 0, 0x4D)
  set_u8(buf, 1, 0x5A)
  set_u32(buf, 0x3C, 0x80)
  Bytes::from_array(buf)
}

///|
/// A file truncated in the middle of the NT headers.
fn build_truncated() -> Bytes {
  let buf = blank(0x90)
  set_u8(buf, 0, 0x4D)
  set_u8(buf, 1, 0x5A)
  set_u32(buf, 0x3C, 0x80)
  set_u8(buf, 0x80, 0x50)
  set_u8(buf, 0x81, 0x45)
  Bytes::from_array(buf)
}

///|
/// A file whose `e_lfanew` points outside itself.
fn build_bad_lfanew() -> Bytes {
  let buf = blank(0x100)
  set_u8(buf, 0, 0x4D)
  set_u8(buf, 1, 0x5A)
  set_u32(buf, 0x3C, 0x10000)
  Bytes::from_array(buf)
}

///|
/// A file whose section table claims far more entries than the file can hold.
fn build_bad_section_count() -> Bytes {
  let buf = blank(0x200)
  set_u8(buf, 0, 0x4D)
  set_u8(buf, 1, 0x5A)
  set_u32(buf, 0x3C, 0x80)
  set_u8(buf, 0x80, 0x50)
  set_u8(buf, 0x81, 0x45)
  set_u16(buf, 0x84, 0x014C)
  set_u16(buf, 0x86, 0xFFFF)
  set_u16(buf, 0x94, 0xE0)
  set_u16(buf, 0x96, 0x0102)
  set_u16(buf, 0x98, 0x10B)
  Bytes::from_array(buf)
}

///|
/// A PE32+ image with an import directory. The 64-bit thunk table is eight
/// bytes per entry with the ordinal flag in bit 63, which is a different code
/// path from the 32-bit one.
fn build_pe64_with_imports() -> Bytes {
  let buf = blank(0x600)
  set_u8(buf, 0, 0x4D)
  set_u8(buf, 1, 0x5A)
  set_u32(buf, 0x3C, 0x80)
  set_u8(buf, 0x80, 0x50)
  set_u8(buf, 0x81, 0x45)
  set_u16(buf, 0x84, 0x8664)
  set_u16(buf, 0x86, 2)
  set_u16(buf, 0x94, 0xF0)
  set_u16(buf, 0x96, 0x0022)
  let mut p = 0x98
  set_u16(buf, p, 0x20B)
  p = p + 2
  set_u8(buf, p, 14)
  p = p + 2
  p = p + 12
  set_u32(buf, p, 0x1000)
  p = p + 4
  set_u32(buf, p, 0x1000)
  p = p + 4
  set_u64(buf, p, 0x140000000L)
  p = p + 8
  set_u32(buf, p, 0x1000)
  p = p + 4
  set_u32(buf, p, 0x200)
  p = p + 4
  p = p + 12
  p = p + 4
  set_u32(buf, p, 0x3000)
  p = p + 4
  set_u32(buf, p, 0x200)
  p = p + 4
  p = p + 4
  set_u16(buf, p, 3)
  p = p + 4
  p = p + 32
  p = p + 4
  set_u32(buf, p, 16)
  p = p + 4
  // Import directory (slot 1) at RVA 0x2000.
  set_u32(buf, p + 8, 0x2000)
  set_u32(buf, p + 12, 0x28)
  let t1 = 0x188
  let _ = set_ascii(buf, t1, ".text")
  set_u32(buf, t1 + 8, 0x100)
  set_u32(buf, t1 + 12, 0x1000)
  set_u32(buf, t1 + 16, 0x200)
  set_u32(buf, t1 + 20, 0x200)
  set_u32(buf, t1 + 36, 0x60000020)
  let t2 = t1 + 40
  let _ = set_ascii(buf, t2, ".rdata")
  set_u32(buf, t2 + 8, 0x200)
  set_u32(buf, t2 + 12, 0x2000)
  set_u32(buf, t2 + 16, 0x200)
  set_u32(buf, t2 + 20, 0x400)
  set_u32(buf, t2 + 36, 0x40000040)
  set_u8(buf, 0x200, 0xC3)
  // Import descriptor.
  set_u32(buf, 0x400, 0x2040)
  set_u32(buf, 0x40C, 0x2080)
  set_u32(buf, 0x410, 0x2060)
  // Thunk tables: named import, ordinal 5, terminator (8 bytes each).
  set_u64(buf, 0x440, 0x2090L)
  set_u8(buf, 0x448, 5)
  set_u8(buf, 0x44F, 0x80)
  set_u64(buf, 0x460, 0x2090L)
  set_u8(buf, 0x468, 5)
  set_u8(buf, 0x46F, 0x80)
  let _ = set_cstr(buf, 0x480, "KERNEL32.dll")
  set_u16(buf, 0x490, 0)
  let _ = set_cstr(buf, 0x492, "Sleep")
  Bytes::from_array(buf)
}
