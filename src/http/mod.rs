//! # Esp32-Minreq
//!
//! Simple, minimal-dependency HTTP client.  The library has a very
//! minimal API, so you'll probably know everything you need to after
//! reading a few examples.
//!
//! Note: as a minimal library, minreq has been written with the
//! assumption that servers are well-behaved. This means that there is
//! little error-correction for incoming data, which may cause some
//! requests to fail unexpectedly. If you're writing an application or
//! library that connects to servers you can't test beforehand,
//! consider using a more robust library, such as
//! [curl](https://crates.io/crates/curl).
//!
//! # Additional features
//!
//! Since the crate is supposed to be minimal in terms of
//! dependencies, there are no default features, and optional
//! functionality can be enabled by specifying features for `minreq`
//! dependency in `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! minreq = { version = "2.11.1-alpha", features = ["punycode"] }
//! ```
//!
//! Below is the list of all available features.
//!
//! ## `json`
//!
//! This feature allows both serialize and deserialize JSON payload
//! using the [`serde_json`](https://crates.io/crates/serde_json)
//! crate.
//!
//! [`Request`](struct.Request.html) and
//! [`Response`](struct.Response.html) expose
//! [`with_json()`](struct.Request.html#method.with_json) and
//! [`json()`](struct.Response.html#method.json) for constructing the
//! struct from JSON and extracting the JSON body out, respectively.
//!
//! ## `punycode`
//!
//! This feature enables requests to non-ascii domains: the
//! [`punycode`](https://crates.io/crates/punycode) crate is used to
//! convert the non-ascii parts into their punycode representations
//! before making the request. If you try to make a request to 㯙㯜㯙
//! 㯟.net or i❤.ws for example, with this feature disabled (as it is
//! by default), your request will fail with a
//! [`PunycodeFeatureNotEnabled`](enum.Error.html#variant.PunycodeFeatureNotEnabled)
//! error.
//!
//! ## `proxy`
//!
//! This feature enables HTTP proxy support. See [Proxy].
//!
//! ## `urlencoding`
//!
//! This feature enables percent-encoding for the URL resource when
//! creating a request and any subsequently added parameters from
//! [`Request::with_param`].
//!
//! # Examples
//!
//! ## Get
//!
//! This is a simple example of sending a GET request and printing out
//! the response's body, status code, and reason phrase. The `?` are
//! needed because the server could return invalid UTF-8 in the body,
//! or something could go wrong during the download.
//!
//! ```
//! # async fn main() -> Result<(), esp32_minreq::Error> {
//! let response = esp32_minreq::get("http://example.com").send().await?;
//! assert!(response.as_str()?.contains("</html>"));
//! assert_eq!(200, response.status_code);
//! assert_eq!("OK", response.reason_phrase);
//! # Ok(()) }
//! ```
//!
//! Note: you could change the `get` function to `head` or `put` or
//! any other HTTP request method: the api is the same for all of
//! them, it just changes what is sent to the server.
//!
//! ## Body (sending)
//!
//! To include a body, add `with_body("<body contents>")` before
//! `send()`.
//!
//! ```
//! # fn main() -> Result<(), esp32_minreq::Error>  {
//! let response = esp32_minreq::post("http://example.com")
//!     .with_body("Foobar")
//!     .send()?;
//! # Ok(()) }
//! ```
//!
//! ## Headers (sending)
//!
//! To add a header, add `with_header("Key", "Value")` before
//! `send()`.
//!
//! ```
//! # fn main() -> Result<(), esp32_minreq::Error> {
//! let response = esp32_minreq::get("http://example.com")
//!     .with_header("Accept", "text/html")
//!     .send()?;
//! # Ok(()) }
//! ```
//!
//! ## Headers (receiving)
//!
//! Reading the headers sent by the servers is done via the
//! [`headers`](struct.Response.html#structfield.headers) field of the
//! [`Response`](struct.Response.html). Note: the header field names
//! (that is, the *keys* of the `HashMap`) are all lowercase: this is
//! because the names are case-insensitive according to the spec, and
//! this unifies the casings for easier `get()`ing.
//!
//! ```
//! # fn main() -> Result<(), esp32_minreq::Error> {
//! let response = esp32_minreq::get("http://example.com").send()?;
//! assert!(response.headers.get("content-type").unwrap().starts_with("text/html"));
//! # Ok(()) }
//! ```
//!
//! ## Proxy
//!
//! To use a proxy server, simply create a `Proxy` instance and use
//! `.with_proxy()` on your request.
//!
//! Supported proxy formats are `host:port` and
//! `user:password@proxy:host`. Only HTTP CONNECT proxies are
//! supported at this time.
//!
//! ```no_run
//! # fn main() -> Result<(), esp32_minreq::Error> {
//! #[cfg(feature = "proxy")]
//! {
//!     let proxy = esp32_minreq::Proxy::new("localhost:8080")?;
//!     let response = esp32_minreq::post("http://example.com")
//!         .with_proxy(proxy)
//!         .send()?;
//!     println!("{}", response.as_str()?);
//! }
//! # Ok(()) }
//! ```

#![deny(missing_docs)]

#[cfg(feature = "json")]
extern crate serde;
#[cfg(feature = "json")]
extern crate serde_json;

mod connection;
mod error;
mod http_url;
#[cfg(feature = "proxy")]
mod proxy;
mod request;
mod response;

pub use error::*;
#[cfg(feature = "proxy")]
pub use proxy::*;
pub use request::*;
pub use response::*;
