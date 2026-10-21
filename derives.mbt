///|
/// Explicit method-promotion declarations.
///
/// Newer MoonBit toolchains warn when a derived trait implementation is
/// implicitly promoted to a regular method of the type. Naming the promoted
/// methods here keeps the build warning-free on both the old and the new
/// compiler, without changing the public surface.

///|
pub extend PeKind with Eq::{equal, not_equal}

///|
pub extend PeKind with @debug.Debug::{to_repr}

///|
pub extend CoffHeader with @debug.Debug::{to_repr}

///|
pub extend DataDirectory with @debug.Debug::{to_repr}

///|
pub extend OptionalHeader with @debug.Debug::{to_repr}

///|
pub extend Section with @debug.Debug::{to_repr}

///|
pub extend ImportEntry with @debug.Debug::{to_repr}

///|
pub extend ImportLibrary with @debug.Debug::{to_repr}

///|
pub extend Export with @debug.Debug::{to_repr}

///|
pub extend ExportTable with @debug.Debug::{to_repr}

///|
pub extend DelayImportLibrary with @debug.Debug::{to_repr}

///|
pub extend ResolvedDirectory with @debug.Debug::{to_repr}

///|
pub extend DebugEntry with @debug.Debug::{to_repr}

///|
pub extend RelocationBlock with @debug.Debug::{to_repr}

///|
pub extend RelocationSummary with @debug.Debug::{to_repr}

///|
pub extend ResourceEntry with @debug.Debug::{to_repr}

///|
pub extend VersionInfo with @debug.Debug::{to_repr}
