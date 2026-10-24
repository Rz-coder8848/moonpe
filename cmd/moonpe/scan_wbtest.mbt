///|
test "json hex preserves unsigned 32-bit bits" {
  assert_eq(json_hex(-1).stringify(), "\"0xffffffff\"")
  assert_eq(json_hex(0x7FFFFFFF).stringify(), "\"0x7fffffff\"")
}

///|
test "scan filters supported binary extensions" {
  assert_true(pe_extension("Notepad.EXE"))
  assert_true(pe_extension("driver.sys"))
  assert_true(pe_extension("plugin.dll"))
  assert_false(pe_extension("README.md"))
  assert_false(pe_extension("archive.dll.bak"))
}

///|
test "scan distinguishes non-PE data from malformed PE" {
  match scan_unsupported_reason(b"not a PE image") {
    Some(reason) => assert_true(reason.contains("not a PE"))
    None => assert_true(false)
  }
}

///|
test "scan report tracks verdicts and architecture" {
  let entries : Array[Json] = []
  let stats = empty_scan_stats()
  let ok_entry = Json::object({
    "ok": Json::boolean(true),
    "verdict": Json::string("ok"),
    "format": Json::number(64.0),
  })
  update_scan_stats(stats, ok_entry)
  entries.push(ok_entry)
  let review_entry = Json::object({
    "ok": Json::boolean(true),
    "verdict": Json::string("review"),
    "format": Json::number(32.0),
  })
  update_scan_stats(stats, review_entry)
  entries.push(review_entry)
  let report = scan_report("fixtures", entries, stats, false)
  let text = report.stringify()
  assert_true(text.contains("\"files\":2"))
  assert_true(text.contains("\"ok\":1"))
  assert_true(text.contains("\"review\":1"))
  assert_true(text.contains("\"pe64\":1"))
}

///|
test "summary-only scan omits individual files" {
  let entries : Array[Json] = []
  let stats = empty_scan_stats()
  let report = scan_report("fixtures", entries, stats, true)
  let text = report.stringify()
  assert_true(text.contains("\"files\":null"))
  assert_true(text.contains("\"files_omitted\":true"))
}
