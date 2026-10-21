///|
/// Shannon entropy of a byte range, in bits per byte (0.0 to 8.0).
///
/// This is the cheapest useful signal for "is this section packed or
/// encrypted": compiled code and data usually land between 4 and 6.5, while
/// compressed or encrypted payloads cluster near 8.

///|
pub fn byte_entropy(bytes : Bytes) -> Double? {
  if bytes.length() == 0 {
    return None
  }
  let counts : Array[Int32] = []
  let mut i = 0
  while i < 256 {
    counts.push(0)
    i = i + 1
  }
  let mut j = 0
  while j < bytes.length() {
    let value = bytes[j].to_int()
    if value >= 0 && value < 256 {
      counts[value] = counts[value] + 1
    }
    j = j + 1
  }
  let total = bytes.length().to_double()
  let mut entropy = 0.0
  let mut k = 0
  while k < 256 {
    let count = counts[k]
    if count > 0 {
      let p = count.to_double() / total
      entropy = entropy - p * @math.log2(p)
    }
    k = k + 1
  }
  Some(entropy)
}

///|
/// Entropy of a section's file-backed bytes.
///
/// The range is scanned in place: a packed section can be hundreds of
/// megabytes, and copying it just to count bytes would dominate the scan.
pub fn Pe::section_entropy(self : Pe, section : Section) -> Double? {
  if section.raw_size <= 0 {
    return None
  }
  let start = section.raw_pointer
  let end = start + section.raw_size
  if start < 0 || end > self.bytes.length() {
    return None
  }
  Some(entropy_range(self.bytes, start, end))
}

///|
/// Entropy over `bytes[start..end)`.
pub fn entropy_range(bytes : Bytes, start : Int32, end : Int32) -> Double {
  let counts : Array[Int32] = []
  let mut i = 0
  while i < 256 {
    counts.push(0)
    i = i + 1
  }
  let limit = if end > bytes.length() { bytes.length() } else { end }
  let mut j = start
  while j < limit && j >= 0 {
    let value = bytes[j].to_int()
    if value >= 0 && value < 256 {
      counts[value] = counts[value] + 1
    }
    j = j + 1
  }
  let total = (limit - start).to_double()
  if total <= 0.0 {
    return 0.0
  }
  let mut entropy = 0.0
  let mut k = 0
  while k < 256 {
    let count = counts[k]
    if count > 0 {
      let p = count.to_double() / total
      entropy = entropy - p * @math.log2(p)
    }
    k = k + 1
  }
  entropy
}
