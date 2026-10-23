///|
/// Decoded content for the common Windows resource types.
///
/// The fields are deliberately flat: a caller can ask the same structure for
/// string-table entries, bitmap dimensions, icon members or manifest text
/// without first matching a large, format-specific enum.

///|
pub(all) struct ResourceString {
  id : Int32
  text : String
} derive(@debug.Debug)

///|
pub(all) struct GroupIconMember {
  width : Int32
  height : Int32
  color_count : Int32
  planes : Int32
  bit_count : Int32
  resource_id : Int32
  bytes : Int32
} derive(@debug.Debug)

///|
pub(all) struct ResourceContent {
  kind : String
  summary : String
  mut strings : Array[ResourceString]
  mut group_icons : Array[GroupIconMember]
  mut width : Int32?
  mut height : Int32?
  mut bit_count : Int32?
  mut image_bytes : Int32?
  mut png : Bool
  mut text : String?
  mut version : VersionInfo?
} derive(@debug.Debug)

///|
fn empty_resource_content(kind : String, summary : String) -> ResourceContent {
  {
    kind,
    summary,
    strings: [],
    group_icons: [],
    width: None,
    height: None,
    bit_count: None,
    image_bytes: None,
    png: false,
    text: None,
    version: None,
  }
}

///|
fn resource_is_type(entry : ResourceEntry, id : Int32, name : String) -> Bool {
  match entry.type_id {
    Some(value) => value == id
    None =>
      match entry.type_name {
        Some(value) => value == name
        None => false
      }
  }
}

///|
fn abs32(value : Int32) -> Int32 {
  if value < 0 {
    0 - value
  } else {
    value
  }
}

///|
fn be_u32(bytes : Bytes, offset : Int32) -> Int32 raise PeError {
  if offset < 0 || offset + 4 > bytes.length() {
    raise PeError::OutOfBounds(offset, 4, bytes.length() - offset)
  }
  (bytes[offset].to_int() << 24) |
  (bytes[offset + 1].to_int() << 16) |
  (bytes[offset + 2].to_int() << 8) |
  bytes[offset + 3].to_int()
}

///|
/// Decode one resource leaf. Unsupported data content is returned as `raw`
/// with its byte size, while malformed data for a recognised type is an error.
pub fn Pe::decode_resource(
  self : Pe,
  entry : ResourceEntry,
) -> ResourceContent raise PeError {
  if entry.size < 0 {
    raise PeError::Malformed("negative resource size", 0)
  }
  let offset = match self.rva_to_offset(entry.rva) {
    Some(value) => value
    None =>
      raise PeError::Malformed(
        "resource RVA " + hex(entry.rva) + " is not backed by file bytes",
        0,
      )
  }
  let end = offset + entry.size
  if end > self.bytes.length() {
    raise PeError::Malformed(
      "resource extends past the end of the file", offset,
    )
  }
  if resource_is_type(entry, 6, "STRING") {
    return self.decode_string_resource(entry, offset, end)
  }
  if resource_is_type(entry, 2, "BITMAP") {
    return self.decode_bitmap_resource(entry.size, offset, end)
  }
  if resource_is_type(entry, 3, "ICON") {
    return self.decode_icon_resource(entry.size, offset, end)
  }
  if resource_is_type(entry, 14, "GROUP_ICON") {
    return self.decode_group_icon_resource(offset, end)
  }
  if resource_is_type(entry, 16, "VERSION") {
    let version = self.version_info_for_entry(entry)
    let content = empty_resource_content(
      "version-info",
      match version {
        Some(info) =>
          "file " + info.file_version + ", product " + info.product_version
        None => "VERSIONINFO present but incomplete"
      },
    )
    content.version = version
    return content
  }
  if resource_is_type(entry, 24, "MANIFEST") {
    let content = empty_resource_content("manifest", "UTF-8 manifest text")
    content.text = Some(decode_utf8(self.bytes, offset, end))
    return content
  }
  empty_resource_content(
    "raw",
    entry.size.to_string() + " byte(s), not decoded for this resource type",
  )
}

///|
fn Pe::decode_string_resource(
  self : Pe,
  entry : ResourceEntry,
  offset : Int32,
  end : Int32,
) -> ResourceContent raise PeError {
  let strings : Array[ResourceString] = []
  let block = match entry.name_id {
    Some(id) => if id > 0 { id - 1 } else { 0 }
    None => 0
  }
  let reader = Reader::at(self.bytes, offset)
  let mut slot = 0
  while slot < 16 && reader.position() + 2 <= end {
    let length = reader.u16()
    let text_end = reader.position() + length * 2
    if text_end > end {
      raise PeError::Malformed(
        "STRING resource entry extends past its data block",
        reader.position(),
      )
    }
    if length > 0 {
      let text = read_utf16(self.bytes, reader.position(), text_end)
      strings.push({ id: block * 16 + slot, text, })
      reader.skip(length * 2)
    }
    slot = slot + 1
  }
  let content = empty_resource_content(
    "string-table",
    strings.length().to_string() + " non-empty string(s)",
  )
  content.strings = strings
  content
}

///|
fn Pe::decode_bitmap_resource(
  self : Pe,
  size : Int32,
  offset : Int32,
  end : Int32,
) -> ResourceContent raise PeError {
  if size < 16 {
    raise PeError::Malformed(
      "BITMAP resource is shorter than its header", offset,
    )
  }
  let reader = Reader::at(self.bytes, offset)
  let header_size = reader.u32()
  if header_size < 16 || offset + header_size > end {
    raise PeError::Malformed("invalid BITMAPINFOHEADER size", offset)
  }
  let width = reader.u32_raw()
  let stored_height = reader.u32_raw()
  let planes = reader.u16()
  let bit_count = reader.u16()
  let content = empty_resource_content(
    "bitmap",
    abs32(width).to_string() +
    " x " +
    abs32(stored_height / 2).to_string() +
    ", " +
    bit_count.to_string() +
    " bpp",
  )
  content.width = Some(abs32(width))
  content.height = Some(abs32(stored_height / 2))
  content.bit_count = Some(bit_count)
  content.image_bytes = Some(size)
  let _ = planes
  content
}

///|
fn Pe::decode_icon_resource(
  self : Pe,
  size : Int32,
  offset : Int32,
  end : Int32,
) -> ResourceContent raise PeError {
  if offset + 8 <= end &&
    self.bytes[offset].to_int() == 0x89 &&
    self.bytes[offset + 1].to_int() == 0x50 &&
    self.bytes[offset + 2].to_int() == 0x4E &&
    self.bytes[offset + 3].to_int() == 0x47 &&
    self.bytes[offset + 4].to_int() == 0x0D &&
    self.bytes[offset + 5].to_int() == 0x0A &&
    self.bytes[offset + 6].to_int() == 0x1A &&
    self.bytes[offset + 7].to_int() == 0x0A {
    if offset + 24 > end ||
      self.bytes[offset + 12].to_int() != 0x49 ||
      self.bytes[offset + 13].to_int() != 0x48 ||
      self.bytes[offset + 14].to_int() != 0x44 ||
      self.bytes[offset + 15].to_int() != 0x52 {
      raise PeError::Malformed("PNG icon is missing its IHDR header", offset)
    }
    let width = be_u32(self.bytes, offset + 16)
    let height = be_u32(self.bytes, offset + 20)
    let content = empty_resource_content(
      "icon",
      "PNG " + width.to_string() + " x " + height.to_string(),
    )
    content.width = Some(width)
    content.height = Some(height)
    content.image_bytes = Some(size)
    content.png = true
    return content
  }
  if size < 16 {
    raise PeError::Malformed("ICON resource is shorter than its header", offset)
  }
  let reader = Reader::at(self.bytes, offset)
  let header_size = reader.u32()
  if header_size < 16 || offset + header_size > end {
    raise PeError::Malformed("invalid icon BITMAPINFOHEADER size", offset)
  }
  let width = abs32(reader.u32_raw())
  let height = abs32(reader.u32_raw() / 2)
  let planes = reader.u16()
  let bit_count = reader.u16()
  let content = empty_resource_content(
    "icon",
    "DIB " +
    width.to_string() +
    " x " +
    height.to_string() +
    ", " +
    bit_count.to_string() +
    " bpp",
  )
  content.width = Some(width)
  content.height = Some(height)
  content.bit_count = Some(bit_count)
  content.image_bytes = Some(size)
  content.png = false
  let _ = planes
  content
}

///|
fn Pe::decode_group_icon_resource(
  self : Pe,
  offset : Int32,
  end : Int32,
) -> ResourceContent raise PeError {
  if offset + 6 > end {
    raise PeError::Malformed("GROUP_ICON resource is too short", offset)
  }
  let reader = Reader::at(self.bytes, offset)
  reader.skip(2)
  let kind = reader.u16()
  let count = reader.u16()
  if kind != 1 {
    raise PeError::Malformed("GROUP_ICON type is not 1", offset + 2)
  }
  if count > 4096 {
    raise PeError::Malformed("GROUP_ICON has too many members", offset + 4)
  }
  let members : Array[GroupIconMember] = []
  let mut i = 0
  while i < count {
    if reader.position() + 14 > end {
      raise PeError::Malformed(
        "GROUP_ICON entry is truncated",
        reader.position(),
      )
    }
    let stored_width = reader.u8()
    let stored_height = reader.u8()
    let color_count = reader.u8()
    reader.skip(1)
    let planes = reader.u16()
    let bit_count = reader.u16()
    let bytes = reader.u32()
    let resource_id = reader.u16()
    members.push({
      width: if stored_width == 0 {
        256
      } else {
        stored_width
      },
      height: if stored_height == 0 {
        256
      } else {
        stored_height
      },
      color_count,
      planes,
      bit_count,
      resource_id,
      bytes,
    })
    i = i + 1
  }
  let content = empty_resource_content(
    "group-icon",
    count.to_string() + " icon member(s)",
  )
  content.group_icons = members
  content
}
