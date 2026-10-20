///|
/// Errors produced while reading a PE file.
///
/// Every variant that can be caused by the input carries the byte offset it was
/// detected at. A malformed download then produces "bad signature at 0x3c"
/// instead of a generic failure, which is the difference between a tool you can
/// debug with and one you cannot.

///|
pub(all) suberror PeError {
  // Read past end of file: offset, bytes needed, bytes available.
  OutOfBounds(Int32, Int32, Int32)
  // Wrong or missing signature: description, offset.
  BadMagic(String, Int32)
  // Structurally inconsistent file: description, offset.
  Malformed(String, Int32)
  // A recognised feature this version does not implement.
  Unsupported(String)
}

///|
/// A one-line description with the offset rendered in hex.
pub fn PeError::message(self : PeError) -> String {
  match self {
    OutOfBounds(offset, need, have) =>
      "unexpected end of file at 0x" +
      hex(offset) +
      ": needed " +
      need.to_string() +
      " byte(s), " +
      have.to_string() +
      " available"
    BadMagic(what, offset) => "bad signature at 0x" + hex(offset) + ": " + what
    Malformed(what, offset) => "malformed PE at 0x" + hex(offset) + ": " + what
    Unsupported(what) => "unsupported PE feature: " + what
  }
}

///|
/// Lowercase hexadecimal without the `0x` prefix. Offsets are never negative.
pub fn hex(value : Int32) -> String {
  if value == 0 {
    return "0"
  }
  let digits = "0123456789abcdef"
  let table : Array[Char] = []
  for c in digits {
    table.push(c)
  }
  let out : Array[Char] = []
  let mut v = value
  while v > 0 {
    out.push(table[v % 16])
    v = v / 16
  }
  let sb = StringBuilder()
  let mut i = out.length() - 1
  while i >= 0 {
    sb.write_char(out[i])
    i = i - 1
  }
  sb.to_string()
}

///|
/// Uppercase hexadecimal, for machine names such as `AMD64`.
pub fn hex_upper(value : Int32) -> String {
  let text = hex(value)
  let sb = StringBuilder()
  for c in text {
    if c >= 'a' && c <= 'f' {
      sb.write_char(Int32::unsafe_to_char(c.to_int() - 32))
    } else {
      sb.write_char(c)
    }
  }
  sb.to_string()
}

///|
/// Trimmed lowercase hexadecimal for a 64-bit value, used for image bases.
pub fn hex64(value : Int64) -> String {
  let digits = "0123456789abcdef"
  let table : Array[Char] = []
  for c in digits {
    table.push(c)
  }
  let out : Array[Char] = []
  let mut v = value
  let mut i = 0
  while i < 16 {
    out.push(table[(v & 0xF).to_int()])
    v = v >> 4
    i = i + 1
  }
  let sb = StringBuilder()
  let mut j = out.length() - 1
  let mut started = false
  while j >= 0 {
    let c = out[j]
    if c != '0' || started || j == 0 {
      started = true
      sb.write_char(c)
    }
    j = j - 1
  }
  sb.to_string()
}
