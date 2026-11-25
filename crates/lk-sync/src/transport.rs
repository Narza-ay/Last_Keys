//! HTTP transport. The engine talks to a [`Transport`]; native clients use
//! [`UreqTransport`] (rustls with the operating system's trust store).

use crate::error::{Result, SyncError};

/// HTTP method.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    /// GET.
    Get,
    /// POST.
    Post,
    /// PUT.
    Put,
}

/// Raw HTTP response.
#[derive(Debug)]
pub struct HttpResponse {
    /// Status code.
    pub status: u16,
    /// Body bytes.
    pub body: Vec<u8>,
}

/// Sends HTTP requests to one server.
pub trait Transport {
    /// Sends a request with an optional bearer token and JSON body.
    ///
    /// # Errors
    /// [`SyncError::Transport`] on network or TLS failure.
    fn send(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<&[u8]>,
    ) -> Result<HttpResponse>;
}

/// Validates and normalizes a server base URL: `https://` is required,
/// except for the local machine (`localhost`, `127.0.0.0/8`, `::1`), where
/// `http://` is accepted for development and local self-hosting tests.
///
/// # Errors
/// [`SyncError::InvalidUrl`].
pub fn normalize_server_url(input: &str) -> Result<String> {
    let url =
        url::Url::parse(input.trim()).map_err(|_| SyncError::InvalidUrl("not a valid URL"))?;
    let loopback = match url.host() {
        Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => return Err(SyncError::InvalidUrl("missing host")),
    };
    match url.scheme() {
        "https" => {}
        "http" if loopback => {}
        "http" => {
            return Err(SyncError::InvalidUrl(
                "plain HTTP is only allowed for the local machine",
            ));
        }
        _ => return Err(SyncError::InvalidUrl("unsupported scheme")),
    }
    if url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(SyncError::InvalidUrl(
            "unexpected query, fragment or credentials",
        ));
    }
    Ok(url.as_str().trim_end_matches('/').to_owned())
}

/// Native transport over `ureq`.
#[cfg(feature = "http")]
pub struct UreqTransport {
    agent: ureq::Agent,
    base: String,
}

#[cfg(feature = "http")]
impl UreqTransport {
    /// Maximum response size accepted (64 MiB).
    const MAX_RESPONSE: u64 = 64 * 1024 * 1024;

    /// Creates a transport for `base_url` (see [`normalize_server_url`]).
    ///
    /// # Errors
    /// [`SyncError::InvalidUrl`].
    pub fn new(base_url: &str) -> Result<Self> {
        let base = normalize_server_url(base_url)?;
        let tls = ureq::tls::TlsConfig::builder()
            .root_certs(ureq::tls::RootCerts::PlatformVerifier)
            .build();
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .tls_config(tls)
            .http_status_as_error(false)
            .timeout_global(Some(std::time::Duration::from_secs(60)))
            .build()
            .into();
        Ok(Self { agent, base })
    }
}

#[cfg(feature = "http")]
impl Transport for UreqTransport {
    fn send(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<&[u8]>,
    ) -> Result<HttpResponse> {
        let url = format!("{}{path}", self.base);
        let auth = token.map(|t| format!("Bearer {t}"));
        let result = match method {
            Method::Get => {
                let mut req = self.agent.get(&url);
                if let Some(a) = &auth {
                    req = req.header("authorization", a);
                }
                req.call()
            }
            Method::Post | Method::Put => {
                let mut req = if method == Method::Post {
                    self.agent.post(&url)
                } else {
                    self.agent.put(&url)
                };
                if let Some(a) = &auth {
                    req = req.header("authorization", a);
                }
                req.content_type("application/json")
                    .send(body.unwrap_or(b"{}"))
            }
        };
        let mut response = result.map_err(|e| SyncError::Transport(e.to_string()))?;
        let status = response.status().as_u16();
        let body = response
            .body_mut()
            .with_config()
            .limit(Self::MAX_RESPONSE)
            .read_to_vec()
            .map_err(|e| SyncError::Transport(e.to_string()))?;
        Ok(HttpResponse { status, body })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_required_except_on_loopback() {
        assert_eq!(
            normalize_server_url("https://sync.example.com/").unwrap(),
            "https://sync.example.com"
        );
        assert_eq!(
            normalize_server_url("http://127.0.0.1:8080").unwrap(),
            "http://127.0.0.1:8080"
        );
        assert_eq!(
            normalize_server_url("http://localhost:8080/").unwrap(),
            "http://localhost:8080"
        );
        assert_eq!(
            normalize_server_url("http://[::1]:8080").unwrap(),
            "http://[::1]:8080"
        );
        for bad in [
            "http://sync.example.com",
            "http://192.168.1.10:8080",
            "ftp://example.com",
            "https://user:pass@example.com",
            "https://example.com/?x=1",
            "not a url",
        ] {
            assert!(normalize_server_url(bad).is_err(), "{bad}");
        }
    }
}
