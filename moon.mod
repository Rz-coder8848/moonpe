// moonpe - a pure-MoonBit reader for Windows PE/COFF images.

name = "Rz-coder8848/moonpe"

version = "0.3.0"

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
  "reverse-engineering",
]

preferred_target = "wasm"

description = "Pure-MoonBit reader for Windows PE/COFF images: headers, section table, imports and exports, with precise byte-offset errors instead of panics."

import {
  "moonbitlang/x@0.5.6",
}
