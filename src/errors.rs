//! nginx built-in error pages.
//!
//! Transcribed verbatim from `src/http/ngx_http_special_response.c`:
//!
//! ```c
//! static char ngx_http_error_404_page[] =
//! "<html>" CRLF
//! "<head><title>404 Not Found</title></head>" CRLF
//! "<body>" CRLF
//! "<center><h1>404 Not Found</h1></center>" CRLF
//! ;
//! ```
//!
//! The tail is controlled by `server_tokens`; here it always comes from the
//! configured `server_token`.
//!
//! Important: `ngx_http_send_special_response()` explicitly clears
//! `Accept-Ranges`, `Last-Modified` and `ETag`, so built-in error pages carry
//! **none** of them. `Content-Type` is a bare `text/html`, with no charset.

fn page(title: &str, server_token: &str) -> String {
    format!(
        "<html>\r\n<head><title>{title}</title></head>\r\n<body>\r\n\
         <center><h1>{title}</h1></center>\r\n<hr><center>{server_token}</center>\r\n\
         </body>\r\n</html>\r\n"
    )
}

pub fn page_400(token: &str) -> String {
    page("400 Bad Request", token)
}

pub fn page_404(token: &str) -> String {
    page("404 Not Found", token)
}

pub fn page_405(token: &str) -> String {
    page("405 Not Allowed", token)
}

pub fn page_416(token: &str) -> String {
    page("416 Requested Range Not Satisfiable", token)
}

pub fn page_503(token: &str) -> String {
    page("503 Service Temporarily Unavailable", token)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "nginx/1.28.3 (Ubuntu)";

    #[test]
    fn not_found_matches_golden_bytes() {
        let body = page_404(TOKEN);
        assert_eq!(body.len(), 162);
        assert_eq!(
            body,
            "<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n\
             <center><h1>404 Not Found</h1></center>\r\n\
             <hr><center>nginx/1.28.3 (Ubuntu)</center>\r\n</body>\r\n</html>\r\n"
        );
        assert_eq!(body.as_bytes(), include_bytes!("../tests/golden/404.body"));
    }

    #[test]
    fn method_not_allowed_matches_golden_bytes() {
        assert_eq!(
            page_405(TOKEN).as_bytes(),
            include_bytes!("../tests/golden/405.body")
        );
    }

    #[test]
    fn range_not_satisfiable_matches_golden_bytes() {
        assert_eq!(
            page_416(TOKEN).as_bytes(),
            include_bytes!("../tests/golden/416.body")
        );
    }

    #[test]
    fn token_is_used_in_tail() {
        assert!(page_404("nginx").ends_with("<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n"));
    }
}
