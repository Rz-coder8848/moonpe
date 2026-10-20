///|
/// One entry of the section table.
///
/// `virtual_size` is how much memory the section occupies; `raw_size` is how
/// many bytes are actually stored in the file. The two differ for the `.bss`
/// tail of a section, where the loader zero-fills the remainder. Code that maps
/// an RVA to a file offset must use the larger of the two for the span and reject
/// offsets inside the zero-filled tail.

///|
pub(all) struct Section {
  name : String
  virtual_size : Int32
  virtual_address : Int32
  raw_size : Int32
  raw_pointer : Int32
  characteristics : Int32
} derive(@debug.Debug)

///|
/// `IMAGE_SCN_MEM_EXECUTE`.
pub fn Section::is_executable(self : Section) -> Bool {
  has_flag(self.characteristics, 0x20000000)
}

///|
/// `IMAGE_SCN_MEM_READ`.
pub fn Section::is_readable(self : Section) -> Bool {
  has_flag(self.characteristics, 0x40000000)
}

///|
/// `IMAGE_SCN_MEM_WRITE`.
pub fn Section::is_writable(self : Section) -> Bool {
  (self.characteristics.to_int64() & 0x80000000) != 0
}

///|
/// A short `rwx` rendering of the section permissions, the way `objdump`
/// prints them. A section that is both writable and executable deserves a
/// second look, which is why `w` and `x` are shown together rather than
/// collapsed into a single "flags" number.
pub fn Section::permissions(self : Section) -> String {
  let sb = StringBuilder()
  if self.is_readable() {
    sb.write_char('r')
  } else {
    sb.write_char('-')
  }
  if self.is_writable() {
    sb.write_char('w')
  } else {
    sb.write_char('-')
  }
  if self.is_executable() {
    sb.write_char('x')
  } else {
    sb.write_char('-')
  }
  sb.to_string()
}
