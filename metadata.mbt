///|
/// .NET metadata (ECMA-335) decoded from the CLR metadata root.
///
/// This is not a decompiler: method bodies and IL stay untouched. It reads the
/// stream directory, counts every present metadata table, and decodes the rows
/// used to identify an assembly, its references, types and methods.

///|
pub(all) struct MetadataStream {
  name : String
  offset : Int32
  size : Int32
} derive(@debug.Debug)

///|
pub(all) struct MetadataTable {
  id : Int32
  name : String
  rows : Int32
} derive(@debug.Debug)

///|
pub(all) struct MetadataType {
  namespace_name : String
  name : String
  flags : Int32
} derive(@debug.Debug)

///|
pub(all) struct MetadataMethod {
  name : String
  rva : Int32
  flags : Int32
  impl_flags : Int32
} derive(@debug.Debug)

///|
pub(all) struct MetadataAssemblyReference {
  name : String
  version : String
  flags : Int32
  public_key_or_token : Int32
} derive(@debug.Debug)

///|
pub(all) struct ClrMetadata {
  streams : Array[MetadataStream]
  tables : Array[MetadataTable]
  module_name : String?
  assembly_name : String?
  assembly_version : String?
  assembly_flags : Int32
  assembly_references : Array[MetadataAssemblyReference]
  type_definitions : Array[MetadataType]
  type_references : Array[MetadataType]
  method_definitions : Array[MetadataMethod]
  member_reference_names : Array[String]
} derive(@debug.Debug)

///|
pub fn metadata_table_name(id : Int32) -> String {
  match id {
    0 => "Module"
    1 => "TypeRef"
    2 => "TypeDef"
    3 => "FieldPtr"
    4 => "Field"
    5 => "MethodPtr"
    6 => "MethodDef"
    7 => "ParamPtr"
    8 => "Param"
    9 => "InterfaceImpl"
    10 => "MemberRef"
    11 => "Constant"
    12 => "CustomAttribute"
    13 => "FieldMarshal"
    14 => "DeclSecurity"
    15 => "ClassLayout"
    16 => "FieldLayout"
    17 => "StandAloneSig"
    18 => "EventMap"
    19 => "EventPtr"
    20 => "Event"
    21 => "PropertyMap"
    22 => "PropertyPtr"
    23 => "Property"
    24 => "MethodSemantics"
    25 => "MethodImpl"
    26 => "ModuleRef"
    27 => "TypeSpec"
    28 => "ImplMap"
    29 => "FieldRVA"
    30 => "ENCLog"
    31 => "ENCMap"
    32 => "Assembly"
    33 => "AssemblyProcessor"
    34 => "AssemblyOS"
    35 => "AssemblyRef"
    36 => "AssemblyRefProcessor"
    37 => "AssemblyRefOS"
    38 => "File"
    39 => "ExportedType"
    40 => "ManifestResource"
    41 => "NestedClass"
    42 => "GenericParam"
    43 => "MethodSpec"
    44 => "GenericParamConstraint"
    _ => "Table(" + id.to_string() + ")"
  }
}

///|
/// Read and decode the CLR metadata root and its `#~` / `#-` tables.
pub fn Pe::clr_metadata(self : Pe) -> ClrMetadata? raise PeError {
  let directory = match self.directory(14) {
    None => return None
    Some(directory) => directory
  }
  if directory.virtual_address == 0 || directory.size == 0 {
    return None
  }
  let header = match self.reader_at_rva(directory.virtual_address) {
    Some(reader) => reader
    None =>
      raise PeError::Malformed(
        "CLR header RVA " +
        hex(directory.virtual_address) +
        " is not backed by file bytes",
        0,
      )
  }
  header.skip(8)
  let metadata_rva = header.u32()
  let metadata_size = header.u32()
  let metadata_offset = match self.rva_to_offset(metadata_rva) {
    Some(offset) => offset
    None =>
      raise PeError::Malformed(
        "CLR metadata RVA " + hex(metadata_rva) + " is not backed by file bytes",
        0,
      )
  }
  let metadata_end = metadata_offset + metadata_size
  if metadata_size < 32 || metadata_end > self.bytes.length() {
    raise PeError::Malformed(
      "CLR metadata root extends past the end of the file", metadata_offset,
    )
  }
  let root = Reader::at(self.bytes, metadata_offset)
  if root.u32_raw() != 0x424A5342 {
    raise PeError::BadMagic(
      "expected the BSJB CLR metadata signature", metadata_offset,
    )
  }
  root.skip(4)
  root.skip(4)
  let version_length = root.u32()
  if version_length > 4096 || root.position() + version_length > metadata_end {
    raise PeError::Malformed(
      "invalid CLR metadata version length",
      root.position(),
    )
  }
  let _runtime_version = root.ascii(version_length)
  root.skip(align4(root.position()) - root.position())
  let _flags = root.u16()
  let stream_count = root.u16()
  if stream_count > 64 {
    raise PeError::Malformed(
      "too many CLR metadata streams",
      root.position() - 2,
    )
  }
  let streams : Array[MetadataStream] = []
  let mut stream_index = 0
  while stream_index < stream_count {
    let stream_offset = root.u32()
    let stream_size = root.u32()
    let name_start = root.position()
    let name = root.cstring(32)
    root.skip(
      align4(root.position() - name_start) - (root.position() - name_start),
    )
    if stream_offset.to_int64() + stream_size.to_int64() >
      metadata_size.to_int64() {
      raise PeError::Malformed(
        "CLR metadata stream extends past the metadata root", name_start,
      )
    }
    streams.push({ name, offset: stream_offset, size: stream_size, })
    stream_index = stream_index + 1
  }
  let table_stream = match find_metadata_stream(streams, "#~") {
    Some(value) => Some(value)
    None => find_metadata_stream(streams, "#-")
  }
  let table_stream = match table_stream {
    Some(value) => value
    None =>
      return Some({
        streams,
        tables: [],
        module_name: None,
        assembly_name: None,
        assembly_version: None,
        assembly_flags: 0,
        assembly_references: [],
        type_definitions: [],
        type_references: [],
        method_definitions: [],
        member_reference_names: [],
      })
  }
  let string_stream = find_metadata_stream(streams, "#Strings")
  let string_stream = match string_stream {
    Some(value) => value
    None =>
      raise PeError::Malformed(
        "CLR metadata has no #Strings stream", metadata_offset,
      )
  }
  let uncompressed = table_stream.name == "#-"
  let table_offset = metadata_offset + table_stream.offset
  let table_end = table_offset + table_stream.size
  if table_stream.size < 24 || table_end > metadata_end {
    raise PeError::Malformed("invalid CLR table stream", table_offset)
  }
  let tables = Reader::at(self.bytes, table_offset)
  tables.skip(4)
  let _major = tables.u8()
  let _minor = tables.u8()
  let heap_sizes = tables.u8()
  tables.skip(1)
  let valid = tables.u64()
  let _sorted = tables.u64()
  let rows = zero_rows()
  let mut table_id = 0
  while table_id < 64 {
    if table_present(valid, table_id) {
      rows[table_id] = tables.u32()
    }
    table_id = table_id + 1
  }
  let first_row_offset = tables.position()
  let table_offsets = zero_offsets()
  let table_infos : Array[MetadataTable] = []
  let mut current_offset = first_row_offset.to_int64()
  table_id = 0
  while table_id < 64 {
    if table_present(valid, table_id) {
      if rows[table_id] > 1000000 {
        raise PeError::Unsupported(
          "CLR metadata table " +
          metadata_table_name(table_id) +
          " has more than one million rows",
        )
      }
      table_offsets[table_id] = current_offset
      table_infos.push({
        id: table_id,
        name: metadata_table_name(table_id),
        rows: rows[table_id],
      })
      let row_size = metadata_row_size(table_id, rows, heap_sizes, uncompressed)
      current_offset = current_offset +
        row_size.to_int64() * rows[table_id].to_int64()
    }
    table_id = table_id + 1
  }
  if current_offset > table_end.to_int64() {
    raise PeError::Malformed(
      "CLR metadata tables extend past the table stream", table_end,
    )
  }
  let string_start = metadata_offset + string_stream.offset
  let string_end = string_start + string_stream.size
  if string_end > metadata_end {
    raise PeError::Malformed("invalid CLR #Strings stream", string_start)
  }
  let module_name = if rows[0] > 0 {
    let row = Reader::at(self.bytes, table_offsets[0].to_int())
    row.skip(2)
    let index = read_metadata_index(
      row,
      metadata_heap_width(heap_sizes, 1, uncompressed),
    )
    Some(
      read_metadata_string(
        self.bytes,
        string_start,
        string_end,
        index,
        "Module name",
      ),
    )
  } else {
    None
  }
  let mut assembly_name : String? = None
  let mut assembly_version : String? = None
  let mut assembly_flags = 0
  if rows[32] > 0 {
    let row = Reader::at(self.bytes, table_offsets[32].to_int())
    row.skip(4)
    let major = row.u16()
    let minor = row.u16()
    let build = row.u16()
    let revision = row.u16()
    assembly_flags = row.u32()
    let blob_size = metadata_heap_width(heap_sizes, 4, uncompressed)
    row.skip(blob_size)
    let name_index = read_metadata_index(
      row,
      metadata_heap_width(heap_sizes, 1, uncompressed),
    )
    assembly_version = Some(
      version_text((major << 16) | minor, (build << 16) | revision),
    )
    assembly_name = Some(
      read_metadata_string(
        self.bytes,
        string_start,
        string_end,
        name_index,
        "Assembly name",
      ),
    )
  }
  let type_definitions = read_type_definitions(
    self.bytes,
    rows,
    table_offsets,
    heap_sizes,
    uncompressed,
    string_start,
    string_end,
  )
  let type_references = read_type_references(
    self.bytes,
    rows,
    table_offsets,
    heap_sizes,
    uncompressed,
    string_start,
    string_end,
  )
  let method_definitions = read_method_definitions(
    self.bytes,
    rows,
    table_offsets,
    heap_sizes,
    uncompressed,
    string_start,
    string_end,
  )
  let assembly_references = read_assembly_references(
    self.bytes,
    rows,
    table_offsets,
    heap_sizes,
    uncompressed,
    string_start,
    string_end,
  )
  let member_reference_names = read_member_reference_names(
    self.bytes,
    rows,
    table_offsets,
    heap_sizes,
    uncompressed,
    string_start,
    string_end,
  )
  Some({
    streams,
    tables: table_infos,
    module_name,
    assembly_name,
    assembly_version,
    assembly_flags,
    assembly_references,
    type_definitions,
    type_references,
    method_definitions,
    member_reference_names,
  })
}

///|
fn find_metadata_stream(
  streams : Array[MetadataStream],
  name : String,
) -> MetadataStream? {
  for stream in streams {
    if stream.name == name {
      return Some(stream)
    }
  }
  None
}

///|
fn zero_rows() -> Array[Int32] {
  let rows : Array[Int32] = []
  let mut i = 0
  while i < 64 {
    rows.push(0)
    i = i + 1
  }
  rows
}

///|
fn zero_offsets() -> Array[Int64] {
  let offsets : Array[Int64] = []
  let mut i = 0
  while i < 64 {
    offsets.push(0L)
    i = i + 1
  }
  offsets
}

///|
fn table_present(valid : Int64, id : Int32) -> Bool {
  ((valid >> id) & 1L) != 0L
}

///|
fn metadata_heap_width(heap_sizes : Int32, mask : Int32, wide : Bool) -> Int32 {
  if wide || (heap_sizes & mask) != 0 {
    4
  } else {
    2
  }
}

///|
fn metadata_table_width(
  table : Int32,
  rows : Array[Int32],
  wide : Bool,
) -> Int32 {
  if wide || rows[table] >= 65536 {
    4
  } else {
    2
  }
}

///|
fn metadata_coded_width(
  kind : Int32,
  rows : Array[Int32],
  wide : Bool,
) -> Int32 {
  if wide {
    return 4
  }
  let targets : Array[Int32] = match kind {
    0 => [2, 1, 27]
    1 => [4, 8, 23]
    2 =>
      [
        6, 4, 1, 2, 8, 9, 10, 0, 14, 23, 20, 17, 26, 27, 32, 35, 38, 39, 40, 42,
        44, 43,
      ]
    3 => [4, 8]
    4 => [2, 6, 32]
    5 => [2, 1, 26, 6, 27]
    6 => [20, 23]
    7 => [6, 10]
    8 => [4, 6]
    9 => [38, 35, 39]
    10 => [6, 10]
    11 => [0, 26, 35, 1]
    12 => [2, 6]
    _ => []
  }
  let mut largest = 0
  for target in targets {
    if rows[target] > largest {
      largest = rows[target]
    }
  }
  let tag_bits = match kind {
    0 => 2
    1 => 2
    2 => 5
    3 => 1
    4 => 2
    5 => 3
    6 => 1
    7 => 1
    8 => 1
    9 => 2
    10 => 3
    11 => 2
    12 => 1
    _ => 16
  }
  if largest >= 1 << (16 - tag_bits) {
    4
  } else {
    2
  }
}

///|
fn metadata_row_size(
  id : Int32,
  rows : Array[Int32],
  heap_sizes : Int32,
  wide : Bool,
) -> Int32 raise PeError {
  let string_size = metadata_heap_width(heap_sizes, 1, wide)
  let guid_size = metadata_heap_width(heap_sizes, 2, wide)
  let blob_size = metadata_heap_width(heap_sizes, 4, wide)
  let table = fn(target) { metadata_table_width(target, rows, wide) }
  let coded = fn(kind) { metadata_coded_width(kind, rows, wide) }
  match id {
    0 => 2 + string_size + guid_size * 3
    1 => coded(11) + string_size * 2
    2 => 4 + string_size * 2 + coded(0) + table(4) + table(6)
    3 => table(4)
    4 => 2 + string_size + blob_size
    5 => table(6)
    6 => 4 + 4 + string_size + blob_size + table(8)
    7 => table(8)
    8 => 4 + string_size
    9 => table(2) + coded(0)
    10 => coded(5) + string_size + blob_size
    11 => 2 + coded(1) + blob_size
    12 => coded(2) + coded(10) + blob_size
    13 => coded(3) + blob_size
    14 => 2 + coded(4) + blob_size
    15 => 6 + table(2)
    16 => 4 + table(4)
    17 => blob_size
    18 => table(2) + table(20)
    19 => table(20)
    20 => 2 + string_size + coded(0)
    21 => table(2) + table(23)
    22 => table(23)
    23 => 2 + string_size + blob_size
    24 => 2 + table(6) + coded(6)
    25 => table(2) + coded(7) * 2
    26 => string_size
    27 => blob_size
    28 => 2 + coded(8) + string_size + table(26)
    29 => 4 + table(4)
    30 => 8
    31 => 4
    32 => 16 + blob_size + string_size * 2
    33 => 4
    34 => 12
    35 => 12 + blob_size + string_size * 2 + blob_size
    36 => 4 + table(35)
    37 => 12 + table(35)
    38 => 4 + string_size + blob_size
    39 => 8 + string_size * 2 + coded(9)
    40 => 8 + string_size + coded(9)
    41 => table(2) * 2
    42 => 4 + coded(12) + string_size
    43 => coded(7) + blob_size
    44 => table(42) + coded(0)
    _ =>
      raise PeError::Unsupported(
        "unsupported CLR metadata table " + metadata_table_name(id),
      )
  }
}

///|
fn read_metadata_string(
  bytes : Bytes,
  start : Int32,
  end : Int32,
  index : Int32,
  label : String,
) -> String raise PeError {
  if index == 0 {
    return ""
  }
  if index < 0 || start + index >= end {
    raise PeError::Malformed(
      "CLR " +
      label +
      " index " +
      index.to_string() +
      " lies outside #Strings (size " +
      (end - start).to_string() +
      ")",
      start,
    )
  }
  let reader = Reader::at(bytes, start + index)
  reader.cstring(end - start - index)
}

///|
fn read_metadata_index(reader : Reader, width : Int32) -> Int32 raise PeError {
  if width == 4 {
    reader.u32()
  } else {
    reader.u16()
  }
}

///|
fn read_type_definitions(
  bytes : Bytes,
  rows : Array[Int32],
  offsets : Array[Int64],
  heap_sizes : Int32,
  wide : Bool,
  string_start : Int32,
  string_end : Int32,
) -> Array[MetadataType] raise PeError {
  let out : Array[MetadataType] = []
  let row_size = metadata_row_size(2, rows, heap_sizes, wide)
  let string_size = metadata_heap_width(heap_sizes, 1, wide)
  let mut i = 0
  while i < rows[2] {
    let row = Reader::at(bytes, offsets[2].to_int() + row_size * i)
    let flags = row.u32()
    let name_index = read_metadata_index(row, string_size)
    let namespace_index = read_metadata_index(row, string_size)
    out.push({
      namespace_name: read_metadata_string(
        bytes, string_start, string_end, namespace_index, "TypeDef namespace",
      ),
      name: read_metadata_string(
        bytes, string_start, string_end, name_index, "TypeDef name",
      ),
      flags,
    })
    i = i + 1
  }
  out
}

///|
fn read_type_references(
  bytes : Bytes,
  rows : Array[Int32],
  offsets : Array[Int64],
  heap_sizes : Int32,
  wide : Bool,
  string_start : Int32,
  string_end : Int32,
) -> Array[MetadataType] raise PeError {
  let out : Array[MetadataType] = []
  let row_size = metadata_row_size(1, rows, heap_sizes, wide)
  let scope_size = metadata_coded_width(11, rows, wide)
  let string_size = metadata_heap_width(heap_sizes, 1, wide)
  let mut i = 0
  while i < rows[1] {
    let row = Reader::at(bytes, offsets[1].to_int() + row_size * i)
    row.skip(scope_size)
    let name_index = read_metadata_index(row, string_size)
    let namespace_index = read_metadata_index(row, string_size)
    out.push({
      namespace_name: read_metadata_string(
        bytes, string_start, string_end, namespace_index, "TypeRef namespace",
      ),
      name: read_metadata_string(
        bytes, string_start, string_end, name_index, "TypeRef name",
      ),
      flags: 0,
    })
    i = i + 1
  }
  out
}

///|
fn read_method_definitions(
  bytes : Bytes,
  rows : Array[Int32],
  offsets : Array[Int64],
  heap_sizes : Int32,
  wide : Bool,
  string_start : Int32,
  string_end : Int32,
) -> Array[MetadataMethod] raise PeError {
  let out : Array[MetadataMethod] = []
  let row_size = metadata_row_size(6, rows, heap_sizes, wide)
  let string_size = metadata_heap_width(heap_sizes, 1, wide)
  let mut i = 0
  while i < rows[6] {
    let row = Reader::at(bytes, offsets[6].to_int() + row_size * i)
    let rva = row.u32()
    let impl_flags = row.u16()
    let flags = row.u16()
    let name_index = read_metadata_index(row, string_size)
    out.push({
      name: read_metadata_string(
        bytes, string_start, string_end, name_index, "MethodDef name",
      ),
      rva,
      flags,
      impl_flags,
    })
    i = i + 1
  }
  out
}

///|
fn read_assembly_references(
  bytes : Bytes,
  rows : Array[Int32],
  offsets : Array[Int64],
  heap_sizes : Int32,
  wide : Bool,
  string_start : Int32,
  string_end : Int32,
) -> Array[MetadataAssemblyReference] raise PeError {
  let out : Array[MetadataAssemblyReference] = []
  let row_size = metadata_row_size(35, rows, heap_sizes, wide)
  let blob_size = metadata_heap_width(heap_sizes, 4, wide)
  let string_size = metadata_heap_width(heap_sizes, 1, wide)
  let mut i = 0
  while i < rows[35] {
    let row = Reader::at(bytes, offsets[35].to_int() + row_size * i)
    let major = row.u16()
    let minor = row.u16()
    let build = row.u16()
    let revision = row.u16()
    let flags = row.u32()
    let public_key_or_token = read_metadata_index(row, blob_size)
    let name_index = read_metadata_index(row, string_size)
    out.push({
      name: read_metadata_string(
        bytes, string_start, string_end, name_index, "AssemblyRef name",
      ),
      version: version_text((major << 16) | minor, (build << 16) | revision),
      flags,
      public_key_or_token,
    })
    i = i + 1
  }
  out
}

///|
fn read_member_reference_names(
  bytes : Bytes,
  rows : Array[Int32],
  offsets : Array[Int64],
  heap_sizes : Int32,
  wide : Bool,
  string_start : Int32,
  string_end : Int32,
) -> Array[String] raise PeError {
  let out : Array[String] = []
  let row_size = metadata_row_size(10, rows, heap_sizes, wide)
  let class_size = metadata_coded_width(5, rows, wide)
  let string_size = metadata_heap_width(heap_sizes, 1, wide)
  let mut i = 0
  while i < rows[10] {
    let row = Reader::at(bytes, offsets[10].to_int() + row_size * i)
    row.skip(class_size)
    let name_index = read_metadata_index(row, string_size)
    out.push(
      read_metadata_string(
        bytes, string_start, string_end, name_index, "MemberRef name",
      ),
    )
    i = i + 1
  }
  out
}
