use crate::http::request::ParsedRequest;
use crate::http::{Error, Method, ResponseLazy};
use alloc::format;
use alloc::string::String;

use std::io::{self, BufReader, BufWriter, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

fn timeout_err() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "the timeout of the request was reached",
    )
}

fn timeout_at_to_duration(timeout_at: Option<Instant>) -> Result<Option<Duration>, io::Error> {
    if let Some(timeout_at) = timeout_at {
        if let Some(duration) = timeout_at.checked_duration_since(Instant::now()) {
            Ok(Some(duration))
        } else {
            Err(timeout_err())
        }
    } else {
        Ok(None)
    }
}

/// A connection to the server for sending
/// [`Request`](struct.Request.html)s.
pub struct Connection {
    request: ParsedRequest,
    timeout_at: Option<Instant>,
}

impl Connection {
    /// Creates a new `Connection`. See [Request] and [ParsedRequest]
    /// for specifics about *what* is being sent.
    pub(crate) fn new(request: ParsedRequest) -> Connection {
        let timeout = request.config.timeout;
        let timeout_at = timeout.map(|t| Instant::now() + Duration::from_secs(t));
        Connection {
            request,
            timeout_at,
        }
    }

    /// Returns the timeout duration for operations that should end at
    /// timeout and are starting "now".
    ///
    /// The Result will be Err if the timeout has already passed.
    fn timeout(&self) -> Result<Option<Duration>, io::Error> {
        let timeout = timeout_at_to_duration(self.timeout_at);
        log::trace!("Timeout requested, it is currently: {:?}", timeout);
        timeout
    }

    /// Sends the [`Request`](struct.Request.html), consumes this
    /// connection, and returns a [`Response`](struct.Response.html).
    #[cfg(feature = "rustls")]
    pub(crate) fn send_https(mut self) -> Result<ResponseLazy, Error> {
        enforce_timeout(self.timeout_at, move || {
            self.request.url.host = ensure_ascii_host(self.request.url.host)?;
            let bytes = self.request.as_bytes();

            // Rustls setup
            log::trace!("Setting up TLS parameters for {}.", self.request.url.host);
            let dns_name = match ServerName::try_from(&*self.request.url.host) {
                Ok(result) => result,
                Err(err) => return Err(Error::IoError(io::Error::new(io::ErrorKind::Other, err))),
            };
            let sess = ClientConnection::new(CONFIG.clone(), dns_name)
                .map_err(Error::RustlsCreateConnection)?;

            log::trace!("Establishing TCP connection to {}.", self.request.url.host);
            let tcp = self.connect()?;

            // Send request
            log::trace!("Establishing TLS session to {}.", self.request.url.host);
            let mut tls = StreamOwned::new(sess, tcp); // I don't think this actually does any communication.
            log::trace!("Writing HTTPS request to {}.", self.request.url.host);
            let _ = tls.get_ref().set_write_timeout(self.timeout()?);
            tls.write_all(&bytes)?;

            // Receive request
            log::trace!("Reading HTTPS response from {}.", self.request.url.host);
            let response = ResponseLazy::from_stream(
                HttpStream::create_secured(tls, self.timeout_at),
                self.request.config.max_headers_size,
                self.request.config.max_status_line_len,
            )?;
            handle_redirects(self, response)
        })
    }

    /// Sends the [`Request`](struct.Request.html), consumes this
    /// connection, and returns a [`Response`](struct.Response.html).
    #[cfg(all(
        not(feature = "rustls"),
        any(feature = "openssl", feature = "native-tls")
    ))]
    pub(crate) fn send_https(mut self) -> Result<ResponseLazy, Error> {
        enforce_timeout(self.timeout_at, move || {
            self.request.url.host = ensure_ascii_host(self.request.url.host)?;
            let bytes = self.request.as_bytes();

            log::trace!("Setting up TLS parameters for {}.", self.request.url.host);
            let dns_name = &self.request.url.host;
            /*
            let mut builder = TlsConnector::builder();
            ...
            let sess = match builder.build() {
            */
            let sess = match TlsConnector::new() {
                Ok(sess) => sess,
                Err(err) => return Err(Error::IoError(io::Error::new(io::ErrorKind::Other, err))),
            };

            log::trace!("Establishing TCP connection to {}.", self.request.url.host);
            let tcp = self.connect()?;

            // Send request
            log::trace!("Establishing TLS session to {}.", self.request.url.host);
            let mut tls = match sess.connect(dns_name, tcp) {
                Ok(tls) => tls,
                Err(err) => return Err(Error::IoError(io::Error::new(io::ErrorKind::Other, err))),
            };
            log::trace!("Writing HTTPS request to {}.", self.request.url.host);
            let _ = tls.get_ref().set_write_timeout(self.timeout()?);
            tls.write_all(&bytes)?;

            // Receive request
            log::trace!("Reading HTTPS response from {}.", self.request.url.host);
            let response = ResponseLazy::from_stream(
                HttpStream::create_secured(tls, self.timeout_at),
                self.request.config.max_headers_size,
                self.request.config.max_status_line_len,
            )?;
            handle_redirects(self, response)
        })
    }

    /// Sends the [`Request`](struct.Request.html), consumes this
    /// connection, and returns a [`Response`](struct.Response.html).
    pub(crate) fn send(mut self) -> Result<ResponseLazy, Error> {
        enforce_timeout(self.timeout_at, move || {
            self.request.url.host = ensure_ascii_host(self.request.url.host)?;
            let bytes = self.request.as_bytes();

            log::trace!("Establishing TCP connection to {}.", self.request.url.host);
            let tcp = self.connect()?;

            // Send request
            log::trace!("Writing HTTP request.");
            let mut stream = BufWriter::new(tcp);
            let _ = stream.get_ref().set_write_timeout(self.timeout()?);
            stream.write_all(&bytes)?;

            // Receive response
            log::trace!("Reading HTTP response.");
            let tcp = match stream.into_inner() {
                Ok(tcp) => tcp,
                Err(_) => {
                    return Err(Error::Other(
                        "IntoInnerError after writing the request into the TcpStream.",
                    ));
                }
            };
            let stream = HttpStream::create_unsecured(BufReader::new(tcp), self.timeout_at);
            let response = ResponseLazy::from_stream(
                stream,
                self.request.config.max_headers_size,
                self.request.config.max_status_line_len,
            )?;
            handle_redirects(self, response)
        })
    }

    fn connect(&self) -> Result<TcpStream, Error> {
        let tcp_connect = |host: &str, port: u32| -> Result<TcpStream, Error> {
            let host = format!("{}:{}", host, port);
            let mut addrs = host.to_socket_addrs().map_err(Error::IoError)?;
            let sock_address = addrs.next().ok_or(Error::AddressNotFound)?;
            let stream = if let Some(timeout) = self.timeout()? {
                TcpStream::connect_timeout(&sock_address, timeout)
            } else {
                TcpStream::connect(sock_address)
            };
            stream.map_err(Error::from)
        };

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
        tcp_connect(&self.request.url.host, self.request.url.port.port())
    }
}

fn handle_redirects(
    connection: Connection,
    mut response: ResponseLazy,
) -> Result<ResponseLazy, Error> {
    let status_code = response.status_code;
    let url = response.headers.get("location");
    match get_redirect(connection, status_code, url) {
        NextHop::Redirect(connection) => {
            let connection = connection?;
            if connection.request.url.https {
                #[cfg(not(any(
                    feature = "rustls",
                    feature = "openssl",
                    feature = "native-tls"
                )))]
                return Err(Error::HttpsFeatureNotEnabled);
                #[cfg(any(feature = "rustls", feature = "openssl", feature = "native-tls"))]
                return connection.send_https();
            } else {
                connection.send()
            }
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
