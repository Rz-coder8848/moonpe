///|
/// Recursive release scan over directories of Windows PE images.

///|
priv struct ScanStats {
  mut files : Int32
  mut ok : Int32
  mut review : Int32
  mut suspicious : Int32
  mut skipped : Int32
  mut errors : Int32
  mut pe32 : Int32
  mut pe64 : Int32
}

///|
fn empty_scan_stats() -> ScanStats {
  {
    files: 0,
    ok: 0,
    review: 0,
    suspicious: 0,
    skipped: 0,
    errors: 0,
    pe32: 0,
    pe64: 0,
  }
}

///|
fn scan_unsupported_reason(bytes : Bytes) -> String? {
  if bytes.length() < 64 ||
    bytes[0].to_int() != 0x4D ||
    bytes[1].to_int() != 0x5A {
    return Some("not a PE32/PE32+ image")
  }
  let pe_offset = bytes[0x3C].to_int() |
    (bytes[0x3D].to_int() << 8) |
    (bytes[0x3E].to_int() << 16) |
    (bytes[0x3F].to_int() << 24)
  if pe_offset < 0 || pe_offset + 4 > bytes.length() {
    return None
  }
  let signature = bytes[pe_offset].to_int() |
    (bytes[pe_offset + 1].to_int() << 8)
  if signature == 0x454E {
    Some("16-bit NE image")
  } else if signature == 0x454C {
    Some("16-bit LE image")
  } else if signature == 0x584C {
    Some("16/32-bit LX image")
  } else {
    None
  }
}

///|
fn pe_extension(name : String) -> Bool {
  let lower = name.to_lower()
  lower.has_suffix(".exe") ||
  lower.has_suffix(".dll") ||
  lower.has_suffix(".sys") ||
  lower.has_suffix(".ocx") ||
  lower.has_suffix(".cpl") ||
  lower.has_suffix(".scr")
}

///|
fn scan_json_entry(path : String, json_mode : Bool, verbose : Bool) -> Json {
  let bytes = @fs.read_file_to_bytes(path) catch {
    _ =>
      return {
        "path": Json::string(path),
        "ok": Json::boolean(false),
        "error": Json::string("cannot read file"),
      }
  }
  match scan_unsupported_reason(bytes) {
    Some(reason) => {
      if !json_mode && verbose {
        println("skipped    " + pad_right(reason, 24) + "  " + path)
      }
      return {
        "path": Json::string(path),
        "ok": Json::boolean(true),
        "skipped": Json::boolean(true),
        "reason": Json::string(reason),
      }
    }
    None => ()
  }
  let pe = @pe.Pe::parse(bytes) catch {
    e =>
      return {
        "path": Json::string(path),
        "ok": Json::boolean(false),
        "error": Json::string(e.message()),
      }
  }
  let report = pe.check()
  let imports = pe.imports().length() catch { _ => 0 }
  let delay = pe.delay_imports().length() catch { _ => 0 }
  let iat = pe.iat().length() catch { _ => 0 }
  let config = pe.load_config() catch { _ => None }
  let cfg_count = match config {
    Some(info) => info.guard_cf_function_count
    None => 0L
  }
  let metadata = pe.clr_metadata() catch { _ => None }
  if !json_mode && verbose {
    let assembly = match metadata {
      Some(info) =>
        match info.assembly_name {
          Some(name) => " managed=" + name
          None => " managed"
        }
      None => ""
    }
    println(
      pad_right(report.verdict, 10) +
      " PE" +
      pe.bits().to_string() +
      "  imports=" +
      imports.to_string() +
      " delay=" +
      delay.to_string() +
      " iat=" +
      iat.to_string() +
      " cfg=" +
      cfg_count.to_string() +
      assembly +
      "  " +
      path,
    )
  }
  {
    "path": Json::string(path),
    "ok": Json::boolean(true),
    "skipped": Json::boolean(false),
    "verdict": Json::string(report.verdict),
    "format": json_number(pe.bits()),
    "machine": Json::string(pe.machine()),
    "imports": json_number(imports),
    "delay_imports": json_number(delay),
    "iat_entries": json_number(iat),
    "cfg_entries": json_number64(cfg_count),
    "managed": Json::boolean(metadata is Some(_)),
    "assembly": match metadata {
      Some(info) => json_optional_string(info.assembly_name)
      None => Json::null()
    },
  }
}

///|
fn update_scan_stats(stats : ScanStats, entry : Json) -> Unit {
  stats.files = stats.files + 1
  match entry {
    Object(values) => {
      match values.get("ok") {
        Some(True) => ()
        _ => {
          stats.errors = stats.errors + 1
          return
        }
      }
      match values.get("verdict") {
        Some(String("ok")) => stats.ok = stats.ok + 1
        Some(String("review")) => stats.review = stats.review + 1
        Some(String("suspicious")) => stats.suspicious = stats.suspicious + 1
        _ => ()
      }
      match values.get("skipped") {
        Some(True) => stats.skipped = stats.skipped + 1
        _ => ()
      }
      match values.get("format") {
        Some(Number(value, ..)) =>
          if value.to_int() == 32 {
            stats.pe32 = stats.pe32 + 1
          } else if value.to_int() == 64 {
            stats.pe64 = stats.pe64 + 1
          }
        _ => ()
      }
    }
    _ => stats.errors = stats.errors + 1
  }
}

///|
fn walk_scan_dir(
  path : String,
  depth : Int32,
  json_mode : Bool,
  summary_only : Bool,
  entries : Array[Json],
  stats : ScanStats,
) -> Unit {
  if depth > 32 || stats.files >= 100000 {
    return
  }
  let names = @fs.read_dir(path) catch {
    _ => {
      if !json_mode {
        fail("cannot read directory " + path)
      }
      return
    }
  }
  for name in names {
    let child_name = name.to_string()
    let joined = @path.Path::join(path, child_name)
    let child = joined.to_string()
    let is_dir = @fs.is_dir(child) catch { _ => false }
    if is_dir {
      if child_name != "$RECYCLE.BIN" &&
        child_name != "System Volume Information" {
        walk_scan_dir(child, depth + 1, json_mode, summary_only, entries, stats)
      }
    } else if pe_extension(child_name) {
      let entry = scan_json_entry(child, json_mode, !summary_only)
      update_scan_stats(stats, entry)
      if !summary_only {
        entries.push(entry)
      }
    }
  }
}

///|
fn scan_report(
  path : String,
  entries : Array[Json],
  stats : ScanStats,
  summary_only : Bool,
) -> Json {
  {
    "schema": Json::string("moonpe-scan/1"),
    "path": Json::string(path),
    "summary": {
      "files": json_number(stats.files),
      "ok": json_number(stats.ok),
      "review": json_number(stats.review),
      "suspicious": json_number(stats.suspicious),
      "skipped": json_number(stats.skipped),
      "errors": json_number(stats.errors),
      "pe32": json_number(stats.pe32),
      "pe64": json_number(stats.pe64),
    },
    "files": if summary_only {
      Json::null()
    } else {
      Json::array(entries)
    },
    "files_omitted": Json::boolean(summary_only),
  }
}

///|
fn run_scan(path : String, json_mode : Bool, summary_only : Bool) -> Unit {
  let exists = @fs.path_exists(path)
  if !exists {
    if json_mode {
      fail_json("path does not exist: " + path)
    } else {
      fail("path does not exist: " + path)
    }
    return
  }
  let is_dir = @fs.is_dir(path) catch { _ => false }
  let entries : Array[Json] = []
  let stats = empty_scan_stats()
  if is_dir {
    walk_scan_dir(path, 0, json_mode, summary_only, entries, stats)
  } else {
    let entry = scan_json_entry(path, json_mode, !summary_only)
    update_scan_stats(stats, entry)
    if !summary_only {
      entries.push(entry)
    }
  }
  if json_mode {
    print_json(scan_report(path, entries, stats, summary_only))
  } else {
    println("")
    println(
      "summary: " +
      stats.files.to_string() +
      " files, ok=" +
      stats.ok.to_string() +
      ", review=" +
      stats.review.to_string() +
      ", suspicious=" +
      stats.suspicious.to_string() +
      ", skipped=" +
      stats.skipped.to_string() +
      ", errors=" +
      stats.errors.to_string() +
      ", PE32/PE64=" +
      stats.pe32.to_string() +
      "/" +
      stats.pe64.to_string(),
    )
  }
}
