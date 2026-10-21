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
pub fn Pe::section_entropy(self : Pe, section : Section) -> Double? {
  match self.section_bytes(section) {
    Some(bytes) => byte_entropy(bytes)
    None => None
  }
}
