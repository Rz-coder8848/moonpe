// moonpe - a pure-MoonBit reader for Windows PE/COFF images.

name = "Rz-coder8848/moonpe"

version = "0.8.0"

readme = "README.md"

repository = "https://github.com/Rz-coder8848/moonpe"

license = "Apache-2.0"

keywords = [
  "pe",
  "coff",
  "windows",
  "executable",
  "dll",
  "binary",
  "parser",
  "dotnet",
  "json",
  "security",
  "reverse-engineering",
]

preferred_target = "wasm"

description = "Pure-MoonBit Windows PE32/PE32+ reader: IAT, resources, .NET metadata tables, LoadConfig, JSON and recursive scanning, with precise errors instead of panics."

import {
  "moonbitlang/x@0.5.6",
}
