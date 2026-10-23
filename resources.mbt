///|
/// The resource directory (data-directory slot 2).
///
/// Resources form a three-level tree: type, name, language, with a data entry
/// at each leaf. Enumerating the leaves is what makes it possible to find
/// `RT_VERSION` (type 16) and read the product name and version out of an
/// otherwise opaque binary.

///|
pub(all) struct ResourceEntry {
  // The type as a numeric id (16 is RT_VERSION) or as a name.
  type_id : Int32?
  type_name : String?
  name_id : Int32?
  name_name : String?
  language : Int32
  rva : Int32
  size : Int32
  code_page : Int32
} derive(@debug.Debug)

///|
/// The documented name of a well-known resource type id.
pub fn resource_type_name(id : Int32) -> String {
  match id {
    1 => "CURSOR"
    2 => "BITMAP"
    3 => "ICON"
    4 => "MENU"
    5 => "DIALOG"
    6 => "STRING"
    7 => "FONTDIR"
    8 => "FONT"
    9 => "ACCELERATOR"
    10 => "RCDATA"
    11 => "MESSAGETABLE"
    12 => "GROUP_CURSOR"
    14 => "GROUP_ICON"
    16 => "VERSION"
    17 => "DLGINCLUDE"
    19 => "PLUGPLAY"
    20 => "VXD"
    21 => "ANICURSOR"
    22 => "ANIICON"
    23 => "HTML"
    24 => "MANIFEST"
    _ => "ID(" + id.to_string() + ")"
  }
}

///|
/// Every resource leaf in the image.
pub fn Pe::resources(self : Pe) -> Array[ResourceEntry] raise PeError {
  let out : Array[ResourceEntry] = []
  let directory = match self.directory(2) {
    None => return out
    Some(directory) => directory
  }
  if directory.virtual_address == 0 || directory.size == 0 {
    return out
  }
  let base = match self.rva_to_offset(directory.virtual_address) {
    Some(offset) => offset
    None =>
      raise PeError::Malformed(
        "resource directory RVA " +
        hex(directory.virtual_address) +
        " is not backed by file bytes",
        0,
      )
  }
  let empty : ResourceLevel = {
    type_id: None,
    type_name: None,
    name_id: None,
    name_name: None,
    language: None,
  }
  self.walk_resources(base, 0, 0, empty, out)
  out
}

///|
/// State carried while descending the resource tree.
priv struct ResourceLevel {
  type_id : Int32?
  type_name : String?
  name_id : Int32?
  name_name : String?
  language : Int32?
}

///|
/// Recursively walk a resource directory.
fn Pe::walk_resources(
  self : Pe,
  base : Int32,
  directory_offset : Int32,
  depth : Int32,
  level : ResourceLevel,
  out : Array[ResourceEntry],
) -> Unit raise PeError {
  if depth > 2 {
    return
  }
  let reader = Reader::at(self.bytes, base + directory_offset)
  reader.skip(12)
  let named = reader.u16()
  let ids = reader.u16()
  let count = named + ids
  let mut i = 0
  while i < count {
    let name_field = reader.u32_raw()
    let data_field = reader.u32_raw()
    let (entry_id, entry_name) = self.resource_name(base, name_field)
    let mut next = level
    if depth == 0 {
      next = {
        type_id: entry_id,
        type_name: entry_name,
        name_id: None,
        name_name: None,
        language: None,
      }
    } else if depth == 1 {
      next = {
        type_id: level.type_id,
        type_name: level.type_name,
        name_id: entry_id,
        name_name: entry_name,
        language: None,
      }
    } else {
      next = {
        type_id: level.type_id,
        type_name: level.type_name,
        name_id: level.name_id,
        name_name: level.name_name,
        language: Some(if entry_id is Some(id) { id } else { 0 }),
      }
    }
    if (data_field.to_int64() & 0x80000000) != 0 {
      let child = (data_field.to_int64() & 0x7FFFFFFF).to_int()
      self.walk_resources(base, child, depth + 1, next, out)
    } else {
      let entry = Reader::at(self.bytes, base + data_field)
      let rva = entry.u32()
      let size = entry.u32()
      let code_page = entry.u32()
      out.push({
        type_id: next.type_id,
        type_name: next.type_name,
        name_id: next.name_id,
        name_name: next.name_name,
        language: match next.language {
          Some(language) => language
          None => 0
        },
        rva,
        size,
        code_page,
      })
    }
    i = i + 1
  }
}

///|
/// Decode a resource directory name field: either a numeric id or a pointer to
/// a length-prefixed UTF-16 string, both relative to the resource base.
fn Pe::resource_name(
  self : Pe,
  base : Int32,
  field : Int32,
) -> (Int32?, String?) raise PeError {
  if (field.to_int64() & 0x80000000) == 0 {
    (Some(field), None)
  } else {
    let offset = base + (field.to_int64() & 0x7FFFFFFF).to_int()
    let reader = Reader::at(self.bytes, offset)
    let length = reader.u16()
    let text = read_utf16(self.bytes, offset + 2, offset + 2 + length * 2)
    (None, Some(text))
  }
}

///|
/// Read a UTF-16LE string of exactly `count` code units (no terminator).
fn read_utf16(bytes : Bytes, start : Int32, end : Int32) -> String {
  let sb = StringBuilder()
  let mut i = start
  while i + 1 < end && i + 1 < bytes.length() {
    let code = bytes[i].to_int() | (bytes[i + 1].to_int() << 8)
    if code >= 0xD800 && code <= 0xDFFF {
      sb.write_char('?')
    } else {
      sb.write_char(Int32::unsafe_to_char(code))
    }
    i = i + 2
  }
  sb.to_string()
}

///|
/// The fields a caller usually wants out of a `VS_VERSIONINFO` resource.
pub(all) struct VersionInfo {
  file_version : String
  product_version : String
  company_name : String?
  product_name : String?
  file_description : String?
  original_filename : String?
} derive(@debug.Debug)

///|
/// Read the version resource, if the image has one.
///
/// The string table is checked first; the numeric fixed-file-info version is
/// used as the fallback for `file_version`, because some build systems omit the
/// `FileVersion` string.
pub fn Pe::version_info(self : Pe) -> VersionInfo? raise PeError {
  let resources = self.resources()
  let mut target : ResourceEntry? = None
  for entry in resources {
    if entry.type_id == Some(16) {
      target = Some(entry)
      break
    }
  }
  match target {
    None => None
    Some(entry) => self.version_info_for_entry(entry)
  }
}

///|
fn Pe::version_info_for_entry(
  self : Pe,
  entry : ResourceEntry,
) -> VersionInfo? raise PeError {
  let offset = match self.rva_to_offset(entry.rva) {
    Some(offset) => offset
    None => return None
  }
  let end = offset + entry.size
  if end > self.bytes.length() || entry.size < 40 {
    return None
  }
  let root = Reader::at(self.bytes, offset)
  let length = root.u16()
  let value_length = root.u16()
  root.skip(2)
  let (key, after_key) = read_utf16_z(self.bytes, offset + 6, offset + length)
  if key != "VS_VERSION_INFO" || length < 40 {
    return None
  }
  let value_offset = align4(after_key)
  let mut file_version = "0.0.0.0"
  let mut product_version = "0.0.0.0"
  if value_length >= 52 && value_offset + 52 <= end {
    let fixed = Reader::at(self.bytes, value_offset)
    let signature = fixed.u32_raw()
    fixed.skip(4)
    let file_ms = fixed.u32()
    let file_ls = fixed.u32()
    let product_ms = fixed.u32()
    let product_ls = fixed.u32()
    if signature == 0xFEEF04BD {
      file_version = version_text(file_ms, file_ls)
      product_version = version_text(product_ms, product_ls)
    }
  }
  let pairs : Array[(String, String)] = []
  let child_start = align4(value_offset + value_length)
  collect_version_strings(self.bytes, child_start, end, 0, pairs)
  let mut company : String? = None
  let mut product : String? = None
  let mut description : String? = None
  let mut filename : String? = None
  let mut string_file_version : String? = None
  for pair in pairs {
    if pair.0 == "CompanyName" {
      company = Some(pair.1)
    } else if pair.0 == "ProductName" {
      product = Some(pair.1)
    } else if pair.0 == "FileDescription" {
      description = Some(pair.1)
    } else if pair.0 == "OriginalFilename" {
      filename = Some(pair.1)
    } else if pair.0 == "FileVersion" {
      string_file_version = Some(pair.1)
    }
  }
  match string_file_version {
    Some(text) => file_version = text
    None => ()
  }
  Some({
    file_version,
    product_version,
    company_name: company,
    product_name: product,
    file_description: description,
    original_filename: filename,
  })
}

///|
/// Walk `VS_VERSIONINFO` nodes, collecting string key/value pairs.
fn collect_version_strings(
  bytes : Bytes,
  start : Int32,
  end : Int32,
  depth : Int32,
  pairs : Array[(String, String)],
) -> Unit raise PeError {
  if depth > 4 {
    return
  }
  let mut offset = start
  while offset + 6 <= end {
    let node = Reader::at(bytes, offset)
    let length = node.u16()
    let value_length = node.u16()
    let value_type = node.u16()
    if length < 6 || offset + length > end {
      return
    }
    let node_end = offset + length
    let (key, after_key) = read_utf16_z(bytes, offset + 6, node_end)
    let value_offset = align4(after_key)
    if key == "VS_VERSION_INFO" {
      let child = align4(value_offset + value_length)
      collect_version_strings(bytes, child, node_end, depth + 1, pairs)
    } else if value_length > 0 && value_type == 1 {
      let value_end = value_offset + value_length * 2
      if value_end <= node_end {
        let (text, _) = read_utf16_z(bytes, value_offset, value_end)
        pairs.push((key, text))
      }
    } else {
      collect_version_strings(bytes, value_offset, node_end, depth + 1, pairs)
    }
    offset = align4(node_end)
  }
}

///|
/// Render a version pair, e.g. `1.2.3.4`.
fn version_text(ms : Int32, ls : Int32) -> String {
  (ms >> 16).to_string() +
  "." +
  (ms & 0xFFFF).to_string() +
  "." +
  (ls >> 16).to_string() +
  "." +
  (ls & 0xFFFF).to_string()
}

///|
fn align4(value : Int32) -> Int32 {
  (value + 3) / 4 * 4
}

///|
/// Read a NUL-terminated UTF-16LE string, returning the text and the offset just
/// past the terminator.
fn read_utf16_z(bytes : Bytes, start : Int32, end : Int32) -> (String, Int32) {
  let sb = StringBuilder()
  let mut i = start
  while i + 1 < end && i + 1 < bytes.length() {
    let code = bytes[i].to_int() | (bytes[i + 1].to_int() << 8)
    if code == 0 {
      return (sb.to_string(), i + 2)
    }
    if code >= 0xD800 && code <= 0xDFFF {
      sb.write_char('?')
    } else {
      sb.write_char(Int32::unsafe_to_char(code))
    }
    i = i + 2
  }
  (sb.to_string(), i)
}
