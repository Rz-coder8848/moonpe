///|
/// A release / triage check built on top of the parsed structures.
///
/// Everything here is a *finding*, not a verdict on malware: the goal is to
/// turn "here are 1697 exports and 8 sections" into the handful of facts a
/// person actually needs before shipping or trusting a binary.

///|
pub(all) enum Severity {
  Info
  Warning
  High
} derive(Eq, @debug.Debug)

///|
pub(all) struct Finding {
  severity : Severity
  code : String
  message : String
} derive(@debug.Debug)

///|
pub(all) struct CheckReport {
  findings : Array[Finding]
  verdict : String
  max_section_entropy : Double
} derive(@debug.Debug)

///|
/// Run the built-in checks.
pub fn Pe::check(self : Pe) -> CheckReport {
  let findings : Array[Finding] = []
  let mut max_entropy = 0.0
  let mut has_wx = false
  for section in self.sections {
    if section.is_writable() && section.is_executable() {
      has_wx = true
      findings.push({
        severity: High,
        code: "WX_SECTION",
        message: "section " +
        section.name +
        " is both writable and executable (common in unpacked or patched code)",
      })
    }
    match self.section_entropy(section) {
      Some(entropy) => {
        if entropy > max_entropy {
          max_entropy = entropy
        }
        if entropy >= 7.2 && section.raw_size >= 512 {
          findings.push({
            severity: Warning,
            code: "HIGH_ENTROPY",
            message: "section " +
            section.name +
            " has entropy " +
            fixed2(entropy) +
            " (packed or encrypted)",
          })
        }
      }
      None => ()
    }
  }
  let dll = self.optional.dll_characteristics
  if !has_flag(dll, 0x0040) {
    findings.push({
      severity: Warning,
      code: "NO_ASLR",
      message: "DYNAMIC_BASE is not set; the image cannot be randomised",
    })
  }
  if !has_flag(dll, 0x0100) {
    findings.push({
      severity: Warning,
      code: "NO_NX",
      message: "NX_COMPAT is not set; the stack and heap are not marked non-executable",
    })
  }
  if !has_flag(dll, 0x4000) {
    findings.push({
      severity: Info,
      code: "NO_CFG",
      message: "Control Flow Guard is not enabled",
    })
  }
  if self.bits() == 64 && !has_flag(dll, 0x0020) {
    findings.push({
      severity: Info,
      code: "NO_HIGH_ENTROPY_VA",
      message: "HIGH_ENTROPY_VA is not set; ASLR gets 8 bits less entropy",
    })
  }
  if self.bits() == 32 {
    let handlers = self.safe_seh_handlers() catch { _ => None }
    match handlers {
      Some(list) =>
        if list.length() == 0 {
          findings.push({
            severity: Warning,
            code: "NO_SAFESEH",
            message: "x86 image records no SafeSEH handlers; structured exception handlers are not validated",
          })
        } else {
          findings.push({
            severity: Info,
            code: "SAFESEH",
            message: list.length().to_string() + " SafeSEH handler(s) recorded",
          })
        }
      None => ()
    }
  }
  let config = self.load_config() catch { _ => None }
  match config {
    Some(info) =>
      if info.guard_cf_function_count > 0L {
        findings.push({
          severity: Info,
          code: "CFG_TABLE",
          message: "Control Flow Guard table with " +
          info.guard_cf_function_count.to_string() +
          " entries",
        })
      }
    None => ()
  }
  let certificates = self.certificates() catch { _ => [] }
  let signed = certificates.length() > 0
  if !signed {
    findings.push({
      severity: Info,
      code: "UNSIGNED",
      message: "no embedded certificate table; the image may still be catalog-signed",
    })
  }
  let delayed = Some(self.delay_imports()) catch { _ => None }
  match delayed {
    Some(libraries) =>
      if libraries.length() > 0 {
        findings.push({
          severity: Info,
          code: "DELAY_IMPORTS",
          message: libraries.length().to_string() +
          " delay-loaded libraries; static-only dependency checks miss these",
        })
      }
    None => ()
  }
  let suspicious = self.suspicious_imports()
  if suspicious.length() > 0 {
    findings.push({
      severity: Info,
      code: "CAPABILITIES",
      message: "imports " +
      join_names(suspicious) +
      " (loader / process-manipulation APIs)",
    })
    if suspicious.length() >= 4 && (has_wx || max_entropy >= 7.2) {
      findings.push({
        severity: Warning,
        code: "INJECTION_PATTERN",
        message: "several loader/injection APIs together with writable-executable code or high entropy",
      })
    }
  }
  let tls = self.tls() catch { _ => None }
  match tls {
    Some(info) =>
      if info.callbacks > 0 {
        findings.push({
          severity: Info,
          code: "TLS_CALLBACKS",
          message: info.callbacks.to_string() +
          " TLS callback(s); they run before the entry point",
        })
      }
    None => ()
  }
  let clr = self.clr() catch { _ => None }
  match clr {
    Some(info) =>
      findings.push({
        severity: Info,
        code: "MANAGED",
        message: ".NET runtime " + info.runtime_version,
      })
    None => ()
  }
  let mut high = false
  let mut warning = false
  for finding in findings {
    if finding.severity == High {
      high = true
    } else if finding.severity == Warning {
      warning = true
    }
  }
  let verdict = if high {
    "suspicious"
  } else if warning {
    "review"
  } else {
    "ok"
  }
  { findings, verdict, max_section_entropy: max_entropy, }
}

///|
/// Imported function names that are common in loader and injection code.
pub fn Pe::suspicious_imports(self : Pe) -> Array[String] {
  let watchlist = [
    "LoadLibraryA", "LoadLibraryW", "GetProcAddress", "VirtualAlloc", "VirtualAllocEx",
    "VirtualProtect", "VirtualProtectEx", "WriteProcessMemory", "ReadProcessMemory",
    "CreateRemoteThread", "CreateRemoteThreadEx", "SetWindowsHookExA", "SetWindowsHookExW",
    "WinExec", "ShellExecuteA", "ShellExecuteW", "URLDownloadToFileA", "URLDownloadToFileW",
    "AdjustTokenPrivileges",
  ]
  let found : Array[String] = []
  let names = self.all_import_names()
  for name in names {
    for watched in watchlist {
      if name == watched && !contains_name(found, name) {
        found.push(name)
      }
    }
  }
  found
}

///|
fn contains_name(names : Array[String], needle : String) -> Bool {
  for name in names {
    if name == needle {
      return true
    }
  }
  false
}

///|
/// Every imported symbol name, from both the static and the delay-load tables.
fn Pe::all_import_names(self : Pe) -> Array[String] {
  let out : Array[String] = []
  let normal = Some(self.imports()) catch { _ => None }
  match normal {
    Some(libraries) =>
      for library in libraries {
        for entry in library.entries {
          match entry.name {
            Some(name) => out.push(name)
            None => ()
          }
        }
      }
    None => ()
  }
  let delayed = Some(self.delay_imports()) catch { _ => None }
  match delayed {
    Some(libraries) =>
      for library in libraries {
        for entry in library.entries {
          match entry.name {
            Some(name) => out.push(name)
            None => ()
          }
        }
      }
    None => ()
  }
  out
}

///|
/// Two-decimal rendering for entropy values.
fn fixed2(value : Double) -> String {
  let scaled = (value * 100.0).to_int()
  let whole = scaled / 100
  let fraction = scaled % 100
  let tail = if fraction < 10 {
    "0" + fraction.to_string()
  } else {
    fraction.to_string()
  }
  whole.to_string() + "." + tail
}

///|
fn join_names(names : Array[String]) -> String {
  let sb = StringBuilder()
  let mut first = true
  for name in names {
    if !first {
      sb.write_string(", ")
    }
    first = false
    sb.write_string(name)
  }
  sb.to_string()
}
