use crate::http::request::ParsedRequest;
use crate::http::{Error, Method, ResponseLazy};
use alloc::string::String;
use esp_idf_hal::io::EspIOError;

// use std::io::{self, BufReader, BufWriter, Read, Write};
// use std::net::{TcpStream, ToSocketAddrs};
// use std::time::{Duration, Instant};
use crate::tcp::TcpConnect;

/// A connection to the server for sending
/// [`Request`](struct.Request.html)s.
pub struct Connection {
    request: ParsedRequest,
}

impl Connection {
    /// Creates a new `Connection`. See [Request] and [ParsedRequest]
    /// for specifics about *what* is being sent.
    pub(crate) fn new(request: ParsedRequest) -> Connection {
        Connection { request }
    }

    /// Sends the [`Request`](struct.Request.html), consumes this
    /// connection, and returns a [`Response`](struct.Response.html).
    pub(crate) async fn send<C: TcpConnect>(mut self) -> Result<ResponseLazy<C>, Error>
    where
        C::Error: Into<Error>,
    {
        self.request.url.host = ensure_ascii_host(self.request.url.host)?;
        let bytes = self.request.as_bytes();

        log::trace!("Establishing TCP connection to {}.", self.request.url.host);
        let mut tcp: C = self.connect().await.map_err(Into::into)?;

        // Send request
        log::trace!("Writing HTTP request.");
        tcp.write_all(&bytes).await.map_err(Into::into)?;

        // Receive response
        log::trace!("Reading HTTP response.");
        let response = ResponseLazy::from_stream(
            tcp,
            self.request.config.max_headers_size,
            self.request.config.max_status_line_len,
        )
        .await?;
        handle_redirects(self, response).await
    }

    async fn connect<C: TcpConnect>(&self) -> Result<C, Error> {
        #[cfg(feature = "proxy")]
        match self.request.config.proxy {
            Some(ref proxy) => {
                // do proxy things
                let mut tcp = tcp_connect(&proxy.server, proxy.port)?;

                write!(tcp, "{}", proxy.connect(&self.request)).unwrap();
                tcp.flush()?;

                let mut proxy_response = Vec::new();

                loop {
                    let mut buf = vec![0; 256];
                    let total = tcp.read(&mut buf)?;
                    proxy_response.append(&mut buf);
                    if total < 256 {
                        break;
                    }
                }

                crate::Proxy::verify_response(&proxy_response)?;

                Ok(tcp)
            }
            None => tcp_connect(&self.request.url.host, self.request.url.port.port()),
        }

        #[cfg(not(feature = "proxy"))]
        C::connect_http(&self.request.url.raw_url, !self.request.url.https)
            .await
            .map_err(|e| Error::IoError(EspIOError(e)))
    }
}

async fn handle_redirects<C: TcpConnect>(
    connection: Connection,
    mut response: ResponseLazy<C>,
) -> Result<ResponseLazy<C>, Error>
where
    C::Error: Into<Error>,
{
    let status_code = response.status_code;
    let url = response.headers.get("location");
    match get_redirect(connection, status_code, url) {
        NextHop::Redirect(connection) => {
            let connection = connection?;
            connection.send().await
        }
        NextHop::Destination(connection) => {
            let dst_url = connection.request.url;
            dst_url.write_base_url_to(&mut response.url).unwrap();
            dst_url.write_resource_to(&mut response.url).unwrap();
            Ok(response)
        }
    }
}

enum NextHop {
    Redirect(Result<Connection, Error>),
    Destination(Connection),
}

fn get_redirect(mut connection: Connection, status_code: i32, url: Option<&String>) -> NextHop {
    match status_code {
        301 | 302 | 303 | 307 => {
            let url = match url {
                Some(url) => url,
                None => return NextHop::Redirect(Err(Error::RedirectLocationMissing)),
            };
            log::debug!("Redirecting ({}) to: {}", status_code, url);

            match connection.request.redirect_to(url.as_str()) {
                Ok(()) => {
                    if status_code == 303 {
                        match connection.request.config.method {
                            Method::Post | Method::Put | Method::Delete => {
                                connection.request.config.method = Method::Get;
                            }
                            _ => {}
                        }
                    }

                    NextHop::Redirect(Ok(connection))
                }
                Err(err) => NextHop::Redirect(Err(err)),
            }
        }
        _ => NextHop::Destination(connection),
    }
}

fn ensure_ascii_host(host: String) -> Result<String, Error> {
    if host.is_ascii() {
        Ok(host)
    } else {
        #[cfg(not(feature = "punycode"))]
        {
            Err(Error::PunycodeFeatureNotEnabled)
        }

        #[cfg(feature = "punycode")]
        {
            let mut result = String::with_capacity(host.len() * 2);
            for s in host.split('.') {
                if s.is_ascii() {
                    result += s;
                } else {
                    match punycode::encode(s) {
                        Ok(s) => result = result + "xn--" + &s,
                        Err(_) => return Err(Error::PunycodeConversionFailed),
                    }
                }
                result += ".";
            }
            result.truncate(result.len() - 1); // Remove the trailing dot
            Ok(result)
        }
    }
}
