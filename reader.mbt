///|
/// A bounds-checked little-endian reader over a `Bytes`.
///
/// PE is a little-endian, offset-based format: every header field is a fixed
/// width at a fixed place, and a malicious or truncated file will happily claim
/// a length that runs off the end. All reads therefore go through `need`, which
/// turns that into a precise `OutOfBounds` error.

///|
priv struct Reader {
  bytes : Bytes
  mut pos : Int32
}

///|
fn Reader::new(bytes : Bytes) -> Reader {
  { bytes, pos: 0, }
}

///|
/// A reader positioned at `pos` without validating it; the first read reports
/// an out-of-bounds error if the position is unusable.
fn Reader::at(bytes : Bytes, pos : Int32) -> Reader {
  { bytes, pos, }
}

///|
/// Position a reader at ``pos``, failing if that is already past the end.
fn Reader::seek(bytes : Bytes, pos : Int32) -> Reader raise PeError {
  if pos < 0 || pos > bytes.length() {
    raise PeError::OutOfBounds(pos, 0, bytes.length())
  }
  { bytes, pos, }
}

///|
fn Reader::position(self : Reader) -> Int32 {
  self.pos
}

///|
fn Reader::remaining(self : Reader) -> Int32 {
  self.bytes.length() - self.pos
}

///|
fn Reader::need(self : Reader, count : Int32) -> Unit raise PeError {
  if count < 0 || self.pos + count > self.bytes.length() {
    raise PeError::OutOfBounds(self.pos, count, self.remaining())
  }
}

///|
fn Reader::u8(self : Reader) -> Int32 raise PeError {
  self.need(1)
  let value = self.bytes[self.pos].to_int()
  self.pos = self.pos + 1
  value
}

///|
fn Reader::u16(self : Reader) -> Int32 raise PeError {
  self.need(2)
  let b0 = self.bytes[self.pos].to_int()
  let b1 = self.bytes[self.pos + 1].to_int()
  self.pos = self.pos + 2
  b0 | (b1 << 8)
}

///|
/// Little-endian 32-bit value.
///
/// The result is computed in `Int64` and range-checked, so a file cannot smuggle
/// a value that behaves differently on a 32-bit and a 64-bit target: anything
/// above `0x7fffffff` is reported as malformed rather than silently wrapping.
fn Reader::u32(self : Reader) -> Int32 raise PeError {
  self.need(4)
  let b0 = self.bytes[self.pos].to_int64()
  let b1 = self.bytes[self.pos + 1].to_int64()
  let b2 = self.bytes[self.pos + 2].to_int64()
  let b3 = self.bytes[self.pos + 3].to_int64()
  let value = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
  if value > 2147483647 {
    raise PeError::Malformed(
      "32-bit field exceeds the supported 2 GiB range",
      self.pos,
    )
  }
  self.pos = self.pos + 4
  value.to_int()
}

///|
/// Little-endian 32-bit value without the 2 GiB guard.
///
/// Section characteristics legitimately use the top bit (`0x80000000` is
/// `IMAGE_SCN_MEM_WRITE`), so they cannot go through `u32`. The returned value
/// is a raw bit pattern: it may read as negative on a 32-bit target and as a
/// large positive number on a 64-bit one, which is why every consumer uses bit
/// tests rather than arithmetic.
fn Reader::u32_raw(self : Reader) -> Int32 raise PeError {
  self.need(4)
  let b0 = self.bytes[self.pos].to_int()
  let b1 = self.bytes[self.pos + 1].to_int()
  let b2 = self.bytes[self.pos + 2].to_int()
  let b3 = self.bytes[self.pos + 3].to_int()
  self.pos = self.pos + 4
  b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
}

///|
/// Little-endian unsigned 32-bit value widened losslessly into `Int64`.
fn Reader::u32_unsigned(self : Reader) -> Int64 raise PeError {
  self.u32_raw().to_int64() & 0xFFFFFFFFL
}

///|
/// Little-endian 64-bit value, returned as `Int64`.
fn Reader::u64(self : Reader) -> Int64 raise PeError {
  self.need(8)
  let b0 = self.bytes[self.pos].to_int64()
  let b1 = self.bytes[self.pos + 1].to_int64()
  let b2 = self.bytes[self.pos + 2].to_int64()
  let b3 = self.bytes[self.pos + 3].to_int64()
  let b4 = self.bytes[self.pos + 4].to_int64()
  let b5 = self.bytes[self.pos + 5].to_int64()
  let b6 = self.bytes[self.pos + 6].to_int64()
  let b7 = self.bytes[self.pos + 7].to_int64()
  let value = b0 |
    (b1 << 8) |
    (b2 << 16) |
    (b3 << 24) |
    (b4 << 32) |
    (b5 << 40) |
    (b6 << 48) |
    (b7 << 56)
  self.pos = self.pos + 8
  value
}

///|
fn Reader::skip(self : Reader, count : Int32) -> Unit raise PeError {
  self.need(count)
  self.pos = self.pos + count
}

///|
/// Read `count` bytes as a NUL-trimmed ASCII string.
fn Reader::ascii(self : Reader, count : Int32) -> String raise PeError {
  self.need(count)
  let sb = StringBuilder()
  let mut i = 0
  while i < count {
    let value = self.bytes[self.pos + i].to_int()
    if value == 0 {
      break
    }
    if value < 128 {
      sb.write_char(Int32::unsafe_to_char(value))
    } else {
      sb.write_char('?')
    }
    i = i + 1
  }
  self.pos = self.pos + count
  sb.to_string()
}

///|
/// Read a NUL-terminated ASCII string, failing if no terminator is found within
/// `limit` bytes.
fn Reader::cstring(self : Reader, limit : Int32) -> String raise PeError {
  let sb = StringBuilder()
  let mut i = 0
  while i < limit {
    if self.pos + i >= self.bytes.length() {
      raise PeError::OutOfBounds(self.pos + i, 1, 0)
    }
    let value = self.bytes[self.pos + i].to_int()
    if value == 0 {
      self.pos = self.pos + i + 1
      return sb.to_string()
    }
    if value < 128 {
      sb.write_char(Int32::unsafe_to_char(value))
    } else {
      sb.write_char('?')
    }
    i = i + 1
  }
  raise PeError::Malformed(
    "unterminated string (no NUL within " + limit.to_string() + " bytes)",
    self.pos,
  )
}
