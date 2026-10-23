///|
/// Stable JSON reporting used by both single-file and directory scans.
///
/// Address-like values are strings in hexadecimal form so that JavaScript
/// consumers do not lose precision above 2^53.

///|
fn json_number(value : Int32) -> Json {
  Json::number(value.to_double())
}

///|
fn json_number64(value : Int64) -> Json {
  Json::number(value.to_double())
}

///|
fn json_hex(value : Int32) -> Json {
  Json::string("0x" + @pe.hex64(value.to_int64() & 0xFFFFFFFFL))
}

///|
fn json_hex64(value : Int64) -> Json {
  Json::string("0x" + @pe.hex64(value))
}

///|
fn json_error(error : @pe.PeError) -> Json {
  Json::object({ "error": Json::string(error.message()) })
}

///|
fn json_optional_string(value : String?) -> Json {
  match value {
    Some(text) => Json::string(text)
    None => Json::null()
  }
}

///|
fn json_optional_number(value : Int32?) -> Json {
  match value {
    Some(number) => json_number(number)
    None => Json::null()
  }
}

///|
fn json_import_entries(entries : Array[@pe.ImportEntry]) -> Json {
  Json::array(
    entries.map(fn(entry) {
      {
        "name": json_optional_string(entry.name),
        "ordinal": json_optional_number(entry.ordinal),
      }
    }),
  )
}

///|
fn json_info(path : String, pe : @pe.Pe) -> Json {
  let export_count = try {
    match pe.exports() {
      Some(table) => table.exports.length()
      None => 0
    }
  } catch {
    _ => 0
  }
  let iat_count = pe.iat().length() catch { _ => 0 }
  Json::object({
    "file": Json::string(path),
    "format": json_number(pe.bits()),
    "machine": Json::string(pe.machine()),
    "subsystem": Json::string(pe.subsystem()),
    "image_base": json_hex64(pe.optional.image_base),
    "image_size": json_hex(pe.optional.size_of_image),
    "entry_point": json_hex(pe.optional.entry_point),
    "checksum": json_hex(pe.optional.checksum),
    "sections": json_number(pe.sections.length()),
    "import_libraries": json_number(pe.imports().length() catch { _ => 0 }),
    "delay_import_libraries": json_number(
      pe.delay_imports().length() catch {
        _ => 0
      },
    ),
    "iat_entries": json_number(iat_count),
    "exports": json_number(export_count),
  })
}

///|
fn json_sections(pe : @pe.Pe) -> Json {
  Json::array(
    pe.sections.map(fn(section) {
      {
        "name": Json::string(section.name),
        "virtual_address": json_hex(section.virtual_address),
        "virtual_size": json_hex(section.virtual_size),
        "raw_pointer": json_hex(section.raw_pointer),
        "raw_size": json_hex(section.raw_size),
        "characteristics": json_hex(section.characteristics),
        "permissions": Json::string(section.permissions()),
      }
    }),
  )
}

///|
fn json_imports(pe : @pe.Pe) -> Json raise @pe.PeError {
  let normal : Array[Json] = []
  for library in pe.imports() {
    normal.push({
      "library": Json::string(library.name),
      "entries": json_import_entries(library.entries),
    })
  }
  let delayed : Array[Json] = []
  for library in pe.delay_imports() {
    delayed.push({
      "library": Json::string(library.name),
      "rva_based": Json::boolean(library.rva_based),
      "iat_rva": match library.iat_rva {
        Some(rva) => json_hex(rva)
        None => Json::null()
      },
      "entries": json_import_entries(library.entries),
    })
  }
  { "static": Json::array(normal), "delay_loaded": Json::array(delayed) }
}

///|
fn json_iat(pe : @pe.Pe) -> Json raise @pe.PeError {
  Json::array(
    pe
    .iat()
    .map(fn(entry) {
      {
        "library": Json::string(entry.library),
        "delayed": Json::boolean(entry.delayed),
        "slot_rva": json_hex(entry.slot_rva),
        "raw_value": json_hex64(entry.raw_value),
        "symbol": {
          "name": json_optional_string(entry.symbol.name),
          "ordinal": json_optional_number(entry.symbol.ordinal),
        },
      }
    }),
  )
}

///|
fn json_exports(pe : @pe.Pe) -> Json raise @pe.PeError {
  match pe.exports() {
    None => Json::null()
    Some(table) =>
      {
        "dll_name": Json::string(table.dll_name),
        "entries": Json::array(
          table.exports.map(fn(entry) {
            {
              "name": json_optional_string(entry.name),
              "ordinal": json_number(entry.ordinal),
              "rva": json_hex(entry.rva),
            }
          }),
        ),
      }
  }
}

///|
fn json_debug(pe : @pe.Pe) -> Json raise @pe.PeError {
  Json::array(
    pe
    .debug_entries()
    .map(fn(entry) {
      {
        "type": json_number(entry.kind),
        "type_name": Json::string(entry.kind_name),
        "timestamp": json_number(entry.timestamp),
        "size": json_number(entry.size),
        "address": json_hex(entry.address),
        "pdb_signature": json_optional_string(entry.pdb_signature),
        "pdb_age": json_optional_number(entry.pdb_age),
        "pdb_path": json_optional_string(entry.pdb_path),
      }
    }),
  )
}

///|
fn json_relocations(pe : @pe.Pe) -> Json raise @pe.PeError {
  let summary = pe.relocations()
  {
    "blocks": Json::array(
      summary.blocks.map(fn(block) {
        {
          "page_rva": json_hex(block.page_rva),
          "entries": json_number(block.entries),
          "dir64": json_number(block.dir64),
          "highlow": json_number(block.highlow),
          "absolute": json_number(block.absolute),
          "other": json_number(block.other),
          "high": json_number(block.high),
          "low": json_number(block.low),
        }
      }),
    ),
    "total_entries": json_number(summary.total_entries),
    "dir64": json_number(summary.dir64),
    "highlow": json_number(summary.highlow),
  }
}

///|
fn json_resource_content(content : @pe.ResourceContent) -> Json {
  {
    "kind": Json::string(content.kind),
    "summary": Json::string(content.summary),
    "strings": Json::array(
      content.strings.map(fn(item) {
        { "id": json_number(item.id), "text": Json::string(item.text) }
      }),
    ),
    "group_icons": Json::array(
      content.group_icons.map(fn(item) {
        {
          "width": json_number(item.width),
          "height": json_number(item.height),
          "color_count": json_number(item.color_count),
          "planes": json_number(item.planes),
          "bit_count": json_number(item.bit_count),
          "bytes": json_number(item.bytes),
          "resource_id": json_number(item.resource_id),
        }
      }),
    ),
    "width": json_optional_number(content.width),
    "height": json_optional_number(content.height),
    "bit_count": json_optional_number(content.bit_count),
    "image_bytes": json_optional_number(content.image_bytes),
    "png": Json::boolean(content.png),
    "text": json_optional_string(content.text),
    "version": match content.version {
      Some(info) =>
        Json::object({
          "file_version": Json::string(info.file_version),
          "product_version": Json::string(info.product_version),
          "company_name": json_optional_string(info.company_name),
          "product_name": json_optional_string(info.product_name),
          "file_description": json_optional_string(info.file_description),
          "original_filename": json_optional_string(info.original_filename),
        })
      None => Json::null()
    },
  }
}

///|
fn json_resources(pe : @pe.Pe) -> Json raise @pe.PeError {
  Json::array(
    pe
    .resources()
    .map(fn(entry) {
      let decoded = json_resource_content(pe.decode_resource(entry)) catch {
        e => json_error(e)
      }
      {
        "type_id": json_optional_number(entry.type_id),
        "type_name": json_optional_string(entry.type_name),
        "name_id": json_optional_number(entry.name_id),
        "name_name": json_optional_string(entry.name_name),
        "language": json_hex(entry.language),
        "rva": json_hex(entry.rva),
        "size": json_number(entry.size),
        "code_page": json_number(entry.code_page),
        "decoded": decoded,
      }
    }),
  )
}

///|
fn json_load_config(pe : @pe.Pe) -> Json raise @pe.PeError {
  match pe.load_config() {
    None => Json::null()
    Some(info) => {
      let handlers = pe.safe_seh_handlers()
      let safe_seh = match handlers {
        None => Json::string("not-applicable")
        Some(list) => Json::array(list.map(fn(rva) { json_hex(rva) }))
      }
      {
        "size": json_hex(info.size),
        "security_cookie": json_hex64(info.security_cookie),
        "safe_seh": safe_seh,
        "seh_handler_count": json_number64(info.seh_handler_count),
        "guard_flags": json_hex(info.guard_flags),
        "cfg_table": json_hex64(info.guard_cf_function_table),
        "cfg_count": json_number64(info.guard_cf_function_count),
        "heap_flags": json_hex(info.process_heap_flags),
      }
    }
  }
}

///|
fn json_check(pe : @pe.Pe) -> Json {
  let report = pe.check()
  {
    "verdict": Json::string(report.verdict),
    "max_section_entropy": Json::number(report.max_section_entropy),
    "findings": Json::array(
      report.findings.map(fn(finding) {
        let severity = match finding.severity {
          @pe.Info => "info"
          @pe.Warning => "warning"
          @pe.High => "high"
        }
        {
          "severity": Json::string(severity),
          "code": Json::string(finding.code),
          "message": Json::string(finding.message),
        }
      }),
    ),
  }
}

///|
fn json_dotnet(pe : @pe.Pe) -> Json raise @pe.PeError {
  match pe.clr_metadata() {
    None => Json::null()
    Some(info) =>
      {
        "module": json_optional_string(info.module_name),
        "assembly": json_optional_string(info.assembly_name),
        "version": json_optional_string(info.assembly_version),
        "flags": json_hex(info.assembly_flags),
        "streams": Json::array(
          info.streams.map(fn(stream) {
            {
              "name": Json::string(stream.name),
              "offset": json_hex(stream.offset),
              "size": json_number(stream.size),
            }
          }),
        ),
        "tables": Json::array(
          info.tables.map(fn(table) {
            {
              "name": Json::string(table.name),
              "rows": json_number(table.rows),
            }
          }),
        ),
        "assembly_references": Json::array(
          info.assembly_references.map(fn(reference) {
            {
              "name": Json::string(reference.name),
              "version": Json::string(reference.version),
              "flags": json_hex(reference.flags),
              "public_key_or_token": json_hex(reference.public_key_or_token),
            }
          }),
        ),
        "types": Json::array(
          info.type_definitions.map(fn(item) {
            {
              "namespace": Json::string(item.namespace_name),
              "name": Json::string(item.name),
              "flags": json_hex(item.flags),
            }
          }),
        ),
        "type_references": Json::array(
          info.type_references.map(fn(item) {
            {
              "namespace": Json::string(item.namespace_name),
              "name": Json::string(item.name),
              "flags": json_hex(item.flags),
            }
          }),
        ),
        "methods": Json::array(
          info.method_definitions.map(fn(method_info) {
            {
              "name": Json::string(method_info.name),
              "rva": json_hex(method_info.rva),
              "flags": json_hex(method_info.flags),
              "impl_flags": json_hex(method_info.impl_flags),
            }
          }),
        ),
        "member_references": Json::array(
          info.member_reference_names.map(fn(name) { Json::string(name) }),
        ),
      }
  }
}

///|
fn json_for_command(path : String, command : String, pe : @pe.Pe) -> Json {
  let (data, ok) = try {
    let value = if command == "info" {
      json_info(path, pe)
    } else if command == "sections" {
      json_sections(pe)
    } else if command == "imports" {
      json_imports(pe)
    } else if command == "iat" {
      json_iat(pe)
    } else if command == "exports" {
      json_exports(pe)
    } else if command == "debug" {
      json_debug(pe)
    } else if command == "relocations" {
      json_relocations(pe)
    } else if command == "resources" {
      json_resources(pe)
    } else if command == "loadconfig" {
      json_load_config(pe)
    } else if command == "dotnet" {
      json_dotnet(pe)
    } else if command == "check" {
      json_check(pe)
    } else {
      Json::object({
        "info": json_info(path, pe),
        "sections": json_sections(pe),
        "imports": json_imports(pe),
        "iat": json_iat(pe),
        "exports": json_exports(pe),
        "debug": json_debug(pe),
        "relocations": json_relocations(pe),
        "resources": json_resources(pe),
        "loadconfig": json_load_config(pe),
        "dotnet": json_dotnet(pe),
        "check": json_check(pe),
      })
    }
    (value, true)
  } catch {
    e => (json_error(e), false)
  }
  {
    "schema": Json::string("moonpe/1"),
    "command": Json::string(command),
    "file": Json::string(path),
    "ok": Json::boolean(ok),
    "data": data,
  }
}

///|
fn print_json(value : Json) -> Unit {
  println(value.stringify())
}

///|
fn fail_json(message : String) -> Unit {
  print_json({
    "schema": Json::string("moonpe/1"),
    "ok": Json::boolean(false),
    "error": Json::string(message),
  })
}
