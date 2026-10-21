///|
/// Base relocations (data-directory slot 5).
///
/// A relocation block names a 4 KiB page and lists the offsets inside it that
/// the loader must patch when the image is not loaded at its preferred base.
/// Counting them is enough for the questions this library targets: does the
/// image need relocation at all, and is it mostly 32-bit or 64-bit fixups.

///|
pub(all) struct RelocationBlock {
  page_rva : Int32
  entries : Int32
  absolute : Int32
  high : Int32
  low : Int32
  highlow : Int32
  dir64 : Int32
  other : Int32
} derive(@debug.Debug)

///|
pub(all) struct RelocationSummary {
  blocks : Array[RelocationBlock]
  total_entries : Int32
  absolute : Int32
  high : Int32
  low : Int32
  highlow : Int32
  dir64 : Int32
  other : Int32
} derive(@debug.Debug)

///|
/// The documented name of a relocation type.
pub fn relocation_type_name(kind : Int32) -> String {
  match kind {
    0 => "ABSOLUTE"
    1 => "HIGH"
    2 => "LOW"
    3 => "HIGHLOW"
    4 => "HIGHADJ"
    5 => "MIPS_JMPADDR"
    7 => "THUMB_MOV32"
    9 => "MIPS_JMPADDR16"
    10 => "DIR64"
    _ => "UNKNOWN(" + kind.to_string() + ")"
  }
}

///|
/// Read and summarise the relocation directory.
pub fn Pe::relocations(self : Pe) -> RelocationSummary raise PeError {
  let blocks : Array[RelocationBlock] = []
  let mut total = 0
  let mut total_absolute = 0
  let mut total_high = 0
  let mut total_low = 0
  let mut total_highlow = 0
  let mut total_dir64 = 0
  let mut total_other = 0
  let directory = match self.directory(5) {
    None =>
      return {
        blocks,
        total_entries: 0,
        absolute: 0,
        high: 0,
        low: 0,
        highlow: 0,
        dir64: 0,
        other: 0,
      }
    Some(directory) => directory
  }
  if directory.virtual_address == 0 || directory.size == 0 {
    return {
      blocks,
      total_entries: 0,
      absolute: 0,
      high: 0,
      low: 0,
      highlow: 0,
      dir64: 0,
      other: 0,
    }
  }
  let reader = match self.reader_at_rva(directory.virtual_address) {
    Some(reader) => reader
    None =>
      raise PeError::Malformed(
        "relocation directory RVA " +
        hex(directory.virtual_address) +
        " is not backed by file bytes",
        0,
      )
  }
  let mut block_count = 0
  while reader.remaining() >= 8 && block_count < 65536 {
    let page_rva = reader.u32()
    let block_size = reader.u32()
    if page_rva == 0 && block_size == 0 {
      break
    }
    if block_size < 8 || block_size > reader.remaining() + 8 {
      raise PeError::Malformed(
        "relocation block at 0x" +
        hex(page_rva) +
        " declares an impossible size",
        reader.position(),
      )
    }
    let entries = (block_size - 8) / 2
    let mut absolute = 0
    let mut high = 0
    let mut low = 0
    let mut highlow = 0
    let mut dir64 = 0
    let mut other = 0
    let mut i = 0
    while i < entries {
      let entry = reader.u16()
      let kind = entry >> 12
      if kind == 0 {
        absolute = absolute + 1
      } else if kind == 1 {
        high = high + 1
      } else if kind == 2 {
        low = low + 1
      } else if kind == 3 {
        highlow = highlow + 1
      } else if kind == 10 {
        dir64 = dir64 + 1
      } else {
        other = other + 1
      }
      i = i + 1
    }
    blocks.push({
      page_rva,
      entries,
      absolute,
      high,
      low,
      highlow,
      dir64,
      other,
    })
    total = total + entries
    total_absolute = total_absolute + absolute
    total_high = total_high + high
    total_low = total_low + low
    total_highlow = total_highlow + highlow
    total_dir64 = total_dir64 + dir64
    total_other = total_other + other
    block_count = block_count + 1
  }
  {
    blocks,
    total_entries: total,
    absolute: total_absolute,
    high: total_high,
    low: total_low,
    highlow: total_highlow,
    dir64: total_dir64,
    other: total_other,
  }
}
