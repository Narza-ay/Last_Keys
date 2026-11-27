//! Autofill policy: which stored logins may be offered and filled on which
//! web origin (criterion V-A1, spec AFL-1/AFL-2).
//!
//! Rules, applied to every URL stored in an item against the origin of the
//! page (or frame) as reported by the browser — never by page content:
//!
//! 1. Only `http` and `https` pages are eligible (no `file:`, `data:`,
//!    `javascript:`, `about:`, extension or browser pages).
//! 2. Hosts are compared in their ASCII (punycode) form, lower case, without
//!    a trailing dot, so that a look-alike Unicode domain never equals the
//!    genuine one.
//! 3. [`MatchKind::ExactHost`] when the hosts are equal; otherwise
//!    [`MatchKind::SameSite`] when both hosts have the same registrable
//!    domain according to the Public Suffix List, private suffixes included
//!    (`alice.github.io` and `bob.github.io` are different sites). IP
//!    addresses, `localhost` and hosts that are themselves a public suffix
//!    only match exactly. There is no fuzzy or substring matching.
//! 4. A credential saved for an `https` URL is never offered on an `http`
//!    page (downgrade); one saved for `http` may be used on `https`.
//! 5. Ports must agree: an explicit port in the stored URL must equal the
//!    page's port; without one, the page must use its scheme's default port.

#![forbid(unsafe_code)]

use psl::Psl;
use serde::Serialize;
use thiserror::Error;
use url::{Host, Url};

/// Why a URL is not an eligible origin.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum OriginError {
    /// Not a parsable URL.
    #[error("not a valid URL")]
    Invalid,
    /// Not an `http` or `https` URL.
    #[error("only http and https pages can be filled")]
    UnsupportedScheme,
    /// The URL has no host.
    #[error("the URL has no host")]
    NoHost,
}

/// Scheme of an eligible origin.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Scheme {
    /// Encrypted.
    Https,
    /// Not encrypted.
    Http,
}

/// The host of an origin, normalized.
#[derive(Clone, Debug, PartialEq, Eq)]
enum OriginHost {
    /// ASCII (punycode) domain name, lower case, without a trailing dot.
    Domain(String),
    /// IPv4 or IPv6 address (textual form).
    Ip(String),
}

/// A web origin eligible for autofill.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Origin {
    scheme: Scheme,
    host: OriginHost,
    port: u16,
    explicit_port: bool,
}

impl Origin {
    /// Parses and normalizes a page or item URL. A stored URL without a
    /// scheme is read as `https://`.
    ///
    /// # Errors
    /// [`OriginError`] when the URL is not an eligible web origin.
    pub fn parse(input: &str) -> Result<Self, OriginError> {
        let trimmed = input.trim();
        let url = match Url::parse(trimmed) {
            Ok(url) => url,
            Err(url::ParseError::RelativeUrlWithoutBase) => {
                Url::parse(&format!("https://{trimmed}")).map_err(|_| OriginError::Invalid)?
            }
            Err(_) => return Err(OriginError::Invalid),
        };
        let scheme = match url.scheme() {
            "https" => Scheme::Https,
            "http" => Scheme::Http,
            _ => return Err(OriginError::UnsupportedScheme),
        };
        let host = match url.host().ok_or(OriginError::NoHost)? {
            Host::Domain(domain) => {
                let domain = domain.trim_end_matches('.').to_ascii_lowercase();
                if domain.is_empty() {
                    return Err(OriginError::NoHost);
                }
                OriginHost::Domain(domain)
            }
            Host::Ipv4(ip) => OriginHost::Ip(ip.to_string()),
            Host::Ipv6(ip) => OriginHost::Ip(ip.to_string()),
        };
        let default_port = match scheme {
            Scheme::Https => 443,
            Scheme::Http => 80,
        };
        Ok(Self {
            scheme,
            host,
            port: url.port().unwrap_or(default_port),
            explicit_port: url.port().is_some(),
        })
    }

    /// Scheme.
    #[must_use]
    pub const fn scheme(&self) -> Scheme {
        self.scheme
    }

    /// Host in ASCII form (punycode for international domains).
    #[must_use]
    pub fn host(&self) -> &str {
        match &self.host {
            OriginHost::Domain(d) | OriginHost::Ip(d) => d,
        }
    }

    /// Effective port.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// Registrable domain (eTLD+1, private suffixes included), or `None` for
    /// IP addresses, single-label hosts and hosts that are a public suffix.
    #[must_use]
    pub fn registrable_domain(&self) -> Option<&str> {
        match &self.host {
            OriginHost::Ip(_) => None,
            OriginHost::Domain(d) => registrable_domain(d),
        }
    }

    /// Whether the host contains an internationalized (punycode) label, to
    /// be shown with a warning.
    #[must_use]
    pub fn is_internationalized(&self) -> bool {
        match &self.host {
            OriginHost::Ip(_) => false,
            OriginHost::Domain(d) => d.split('.').any(|label| label.starts_with("xn--")),
        }
    }

    /// The host for display: Unicode form, or ASCII if it cannot be decoded.
    #[must_use]
    pub fn display_host(&self) -> String {
        match &self.host {
            OriginHost::Ip(ip) => ip.clone(),
            OriginHost::Domain(d) => {
                let (unicode, result) = idna::domain_to_unicode(d);
                if result.is_ok() { unicode } else { d.clone() }
            }
        }
    }
}

fn registrable_domain(domain: &str) -> Option<&str> {
    let found = psl::List.domain(domain.as_bytes())?;
    core::str::from_utf8(found.as_bytes()).ok()
}

/// How a stored URL relates to a page.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchKind {
    /// Same registrable domain (e.g. `login.example.com` and
    /// `www.example.com`).
    SameSite,
    /// Same host.
    ExactHost,
}

/// Whether credentials stored for `item` may be used on `page`.
#[must_use]
pub fn match_origins(item: &Origin, page: &Origin) -> Option<MatchKind> {
    // Rule 4: never downgrade from https to http.
    if item.scheme == Scheme::Https && page.scheme == Scheme::Http {
        return None;
    }
    // Rule 5: ports.
    if item.explicit_port {
        if item.port != page.port {
            return None;
        }
    } else if page.explicit_port && !is_default_port(page) {
        return None;
    }
    // Rules 2 and 3: hosts.
    match (&item.host, &page.host) {
        (OriginHost::Ip(a), OriginHost::Ip(b)) => (a == b).then_some(MatchKind::ExactHost),
        (OriginHost::Domain(a), OriginHost::Domain(b)) => {
            if a == b {
                Some(MatchKind::ExactHost)
            } else {
                match (registrable_domain(a), registrable_domain(b)) {
                    (Some(x), Some(y)) if x == y => Some(MatchKind::SameSite),
                    _ => None,
                }
            }
        }
        _ => None,
    }
}

const fn is_default_port(origin: &Origin) -> bool {
    matches!(
        (origin.scheme, origin.port),
        (Scheme::Https, 443) | (Scheme::Http, 80)
    )
}

/// Best match of any of an item's stored URLs against a page URL; unusable
/// stored URLs are ignored.
///
/// # Errors
/// [`OriginError`] when the page itself is not eligible.
pub fn best_match<'a>(
    item_urls: impl IntoIterator<Item = &'a str>,
    page_url: &str,
) -> Result<Option<MatchKind>, OriginError> {
    let page = Origin::parse(page_url)?;
    Ok(item_urls
        .into_iter()
        .filter_map(|u| Origin::parse(u).ok())
        .filter_map(|item| match_origins(&item, &page))
        .max())
}

/// A title for a login saved from a page: its registrable domain, or its
/// host.
#[must_use]
pub fn title_for(page: &Origin) -> String {
    page.registrable_domain().map_or_else(
        || page.display_host(),
        |d| {
            let (unicode, result) = idna::domain_to_unicode(d);
            if result.is_ok() {
                unicode
            } else {
                d.to_owned()
            }
        },
    )
}

/// The URL to store for a login saved from a page (scheme, host and
/// non-default port; no path, query or fragment).
#[must_use]
pub fn url_to_store(page: &Origin) -> String {
    let scheme = match page.scheme {
        Scheme::Https => "https",
        Scheme::Http => "http",
    };
    let host = match &page.host {
        OriginHost::Ip(ip) if ip.contains(':') => format!("[{ip}]"),
        OriginHost::Ip(ip) | OriginHost::Domain(ip) => ip.clone(),
    };
    if page.explicit_port && !is_default_port(page) {
        format!("{scheme}://{host}:{}/", page.port)
    } else {
        format!("{scheme}://{host}/")
    }
}
