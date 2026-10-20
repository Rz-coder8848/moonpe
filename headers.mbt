///|
/// The two optional-header layouts. Everything before the image base is
/// identical between them; PE32+ widens the image base and the four stack/heap
/// sizes from 4 to 8 bytes.
pub(all) enum PeKind {
  Pe32
  Pe32Plus
} derive(Eq, @debug.Debug)

///|
/// The COFF file header that follows the `PE\0\0` signature.
pub(all) struct CoffHeader {
  machine : Int32
  number_of_sections : Int32
  timestamp : Int32
  characteristics : Int32
} derive(@debug.Debug)

///|
/// One entry of the optional header's data-directory array. `index` is the
/// documented slot number (0 = export table, 1 = import table, ...).
pub(all) struct DataDirectory {
  index : Int32
  virtual_address : Int32
  size : Int32
} derive(@debug.Debug)

///|
/// The parsed optional header fields this library cares about.
pub(all) struct OptionalHeader {
  kind : PeKind
  entry_point : Int32
  image_base : Int64
  section_alignment : Int32
  file_alignment : Int32
  size_of_image : Int32
  size_of_headers : Int32
  subsystem : Int32
  dll_characteristics : Int32
  directories : Array[DataDirectory]
} derive(@debug.Debug)

///|
/// 32 or 64, the question every loader asks first.
pub fn PeKind::bits(self : PeKind) -> Int32 {
  match self {
    Pe32 => 32
    Pe32Plus => 64
  }
}

///|
/// The processor the image was built for.
pub fn machine_name(machine : Int32) -> String {
  match machine {
    0x014c => "i386"
    0x0162 => "MIPS R3000"
    0x0166 => "MIPS R4000"
    0x0169 => "MIPS WCE v2"
    0x01c0 => "ARM"
    0x01c2 => "Thumb"
    0x01c4 => "ARMv7"
    0x01d3 => "AM33"
    0x01f0 => "PowerPC"
    0x0200 => "IA64"
    0x0266 => "MIPS16"
    0x0284 => "Alpha"
    0x0366 => "MIPS FPU"
    0x0466 => "MIPS FPU16"
    0x0520 => "TriCore"
    0x0ebc => "EBC"
    0x8664 => "AMD64"
    0x9041 => "M32R"
    0xaa64 => "ARM64"
    0xc0ee => "CEE"
    _ => "unknown (0x" + hex(machine) + ")"
  }
}

///|
/// The subsystem the image targets.
pub fn subsystem_name(subsystem : Int32) -> String {
  match subsystem {
    0 => "unknown"
    1 => "native"
    2 => "windows-gui"
    3 => "windows-console"
    5 => "os2-console"
    7 => "posix-console"
    8 => "native-windows"
    9 => "windows-ce-gui"
    10 => "efi-application"
    11 => "efi-boot-service"
    12 => "efi-runtime"
    13 => "efi-rom"
    14 => "xbox"
    16 => "windows-boot"
    _ => "unknown (" + subsystem.to_string() + ")"
  }
}

///|
/// Machine-independent helper for the COFF characteristic bits.
pub fn has_flag(flags : Int32, mask : Int32) -> Bool {
  (flags & mask) != 0
}

///|
/// `IMAGE_FILE_DLL` — the image is a library, not an executable.
pub fn CoffHeader::is_dll(self : CoffHeader) -> Bool {
  has_flag(self.characteristics, 0x2000)
}

///|
/// `IMAGE_FILE_EXECUTABLE_IMAGE`.
pub fn CoffHeader::is_executable(self : CoffHeader) -> Bool {
  has_flag(self.characteristics, 0x0002)
}

///|
/// `IMAGE_FILE_32BIT_MACHINE`.
pub fn CoffHeader::is_32bit_machine(self : CoffHeader) -> Bool {
  has_flag(self.characteristics, 0x0100)
}
