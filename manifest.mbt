///|
/// The application manifest (`RT_MANIFEST`, resource type 24).
///
/// The manifest is where an executable declares its UAC level, DPI awareness and
/// side-by-side dependencies, so reading it turns "is this app going to ask for
/// administrator rights" into a string comparison.

///|
/// The raw manifest text, if the image carries one.
pub fn Pe::manifest(self : Pe) -> String? raise PeError {
  let resources = self.resources()
  for entry in resources {
    let is_manifest = match entry.type_id {
      Some(id) => id == 24
      None =>
        match entry.type_name {
          Some(name) => name == "MANIFEST"
          None => false
        }
    }
    if is_manifest {
      match self.rva_to_offset(entry.rva) {
        Some(offset) => {
          let end = offset + entry.size
          if end <= self.bytes.length() {
            return Some(decode_utf8(self.bytes, offset, end))
          }
          return None
        }
        None => return None
      }
    }
  }
  None
}

///|
/// The `requestedExecutionLevel` value from the manifest, e.g. `asInvoker`,
/// `highestAvailable` or `requireAdministrator`.
pub fn Pe::manifest_execution_level(self : Pe) -> String? raise PeError {
  match self.manifest() {
    None => None
    Some(text) => extract_attribute(text, "requestedExecutionLevel", "level")
  }
}

///|
/// Find `needle`, then the `attribute="value"` that follows it.
fn extract_attribute(
  text : String,
  needle : String,
  attribute : String,
) -> String? {
  let chars : Array[Char] = []
  for c in text {
    chars.push(c)
  }
  let start = find_text(chars, needle, 0)
  if start < 0 {
    return None
  }
  let marker = attribute + "=\""
  let attr_start = find_text(chars, marker, start)
  if attr_start < 0 {
    return None
  }
  let value_start = attr_start + marker.length()
  let mut i = value_start
  let sb = StringBuilder()
  while i < chars.length() && chars[i] != '"' {
    sb.write_char(chars[i])
    i = i + 1
  }
  Some(sb.to_string())
}

///|
fn find_text(chars : Array[Char], needle : String, from : Int32) -> Int32 {
  let target : Array[Char] = []
  for c in needle {
    target.push(c)
  }
  if target.length() == 0 || chars.length() < target.length() {
    return -1
  }
  let mut i = from
  while i + target.length() <= chars.length() {
    let mut j = 0
    let mut same = true
    while j < target.length() {
      if chars[i + j] != target[j] {
        same = false
        j = target.length()
      } else {
        j = j + 1
      }
    }
    if same {
      return i
    }
    i = i + 1
  }
  -1
}

///|
/// Decode UTF-8 into a string, replacing code points outside the BMP with `?`.
fn decode_utf8(bytes : Bytes, start : Int32, end : Int32) -> String {
  let sb = StringBuilder()
  let mut i = start
  while i < end && i < bytes.length() {
    let b0 = bytes[i].to_int()
    if b0 < 0x80 {
      sb.write_char(Int32::unsafe_to_char(b0))
      i = i + 1
    } else if b0 < 0xE0 && i + 1 < end {
      let b1 = bytes[i + 1].to_int()
      let code = ((b0 & 0x1F) << 6) | (b1 & 0x3F)
      sb.write_char(Int32::unsafe_to_char(code))
      i = i + 2
    } else if b0 < 0xF0 && i + 2 < end {
      let b1 = bytes[i + 1].to_int()
      let b2 = bytes[i + 2].to_int()
      let code = ((b0 & 0x0F) << 12) | ((b1 & 0x3F) << 6) | (b2 & 0x3F)
      sb.write_char(Int32::unsafe_to_char(code))
      i = i + 3
    } else if i + 3 < end {
      sb.write_char('?')
      i = i + 4
    } else {
      sb.write_char('?')
      i = i + 1
    }
  }
  sb.to_string()
}
