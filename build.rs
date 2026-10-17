//! Freeze the size and mtime of `assets/index.html` into constants at build time.
//!
//! Why this is needed: nginx derives both `Last-Modified` and `ETag` for a
//! static file from the **file's size and mtime on disk**, and from nothing
//! else. Once the asset is compiled into the binary there is no file left, so
//! we read its mtime once at build time as an equivalent source.

use std::path::Path;
use std::time::UNIX_EPOCH;

fn main() {
    let asset = Path::new("assets/index.html");
    println!("cargo:rerun-if-changed=assets/index.html");

    let meta = std::fs::metadata(asset).expect("assets/index.html is missing");
    let size = meta.len();
    let mtime = meta
        .modified()
        .expect("cannot read the mtime of index.html")
        .duration_since(UNIX_EPOCH)
        .expect("mtime is before the Unix epoch")
        .as_secs();

    println!("cargo:rustc-env=INDEX_SIZE={size}");
    println!("cargo:rustc-env=INDEX_MTIME={mtime}");
}
