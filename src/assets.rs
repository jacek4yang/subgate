//! The static-response impersonation layer for a default nginx install.
//!
//! Reference implementation: the `/var/www/html/index.nginx-debian.html` file
//! shipped by the Ubuntu 26.04 nginx package (615 bytes), plus the built-in
//! error page templates in `src/http/ngx_http_special_response.c`.
//!
//! Goal: be indistinguishable from a default Ubuntu nginx install at the
//! application layer.

/// The verbatim Ubuntu default page, embedded byte for byte.
pub const INDEX_HTML: &str = include_str!("../assets/index.html");

/// Computed by `build.rs`; equivalent to the size / mtime nginx would see for
/// the static file.
pub const INDEX_SIZE: usize = {
    match usize::from_str_radix(env!("INDEX_SIZE"), 10) {
        Ok(v) => v,
        Err(_) => 0,
    }
};

pub const INDEX_MTIME: u64 = {
    match u64::from_str_radix(env!("INDEX_MTIME"), 10) {
        Ok(v) => v,
        Err(_) => 0,
    }
};
