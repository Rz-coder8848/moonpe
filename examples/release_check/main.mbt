///|
/// Example: use moonpe as a library to gate a release.
///
/// Run with:
///   moon run examples/release_check --target js -- <file.exe>

///|
fn main {
  let args = @env.args()
  let mut base = 1
  if args.length() >= 2 && args[1].contains(".js") {
    base = 2
  }
  if args.length() <= base {
    println("usage: release_check <file.exe>")
    return
  }
  let path = args[base]
  let bytes = @fs.read_file_to_bytes(path) catch {
    _ => {
      println("cannot read " + path)
      return
    }
  }
  let pe = @pe.Pe::parse(bytes) catch {
    e => {
      println("not a PE image: " + e.message())
      return
    }
  }
  let report = pe.check()
  println(path + ": " + report.verdict)
  for finding in report.findings {
    println("  " + finding.code + ": " + finding.message)
  }
  if report.verdict != "ok" {
    println("release blocked; review the findings above")
  } else {
    println("release may proceed")
  }
}
