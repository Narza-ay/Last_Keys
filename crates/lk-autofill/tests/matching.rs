//! Origin matching (criterion V-A1): exact and same-site matches, Public
//! Suffix List (ICANN and private sections), look-alike domains, IP
//! addresses, ports, schemes, ineligible pages.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use lk_autofill::{
    MatchKind, Origin, OriginError, Scheme, best_match, match_origins, title_for, url_to_store,
};

fn m(item: &str, page: &str) -> Option<MatchKind> {
    best_match([item], page).unwrap()
}

#[test]
fn exact_and_same_site() {
    assert_eq!(
        m("https://example.com/login", "https://example.com/"),
        Some(MatchKind::ExactHost)
    );
    assert_eq!(
        m("example.com", "https://example.com/account"),
        Some(MatchKind::ExactHost)
    );
    assert_eq!(
        m("https://www.example.com", "https://example.com"),
        Some(MatchKind::SameSite)
    );
    assert_eq!(
        m("https://example.com", "https://login.example.com/x"),
        Some(MatchKind::SameSite)
    );
    assert_eq!(
        m("https://a.b.example.com", "https://c.example.com"),
        Some(MatchKind::SameSite)
    );
    // Case, trailing dot, path, query and fragment do not matter.
    assert_eq!(
        m("HTTPS://EXAMPLE.COM./a?b#c", "https://example.com/z"),
        Some(MatchKind::ExactHost)
    );
}

#[test]
fn no_substring_or_suffix_tricks() {
    for page in [
        "https://example.com.evil.com/",
        "https://evilexample.com/",
        "https://example.co/",
        "https://example.com-login.net/",
        "https://example.com@evil.com/", // user info: the host is evil.com
        "https://evil.com/?next=https://example.com",
        "https://evil.com/example.com",
    ] {
        assert_eq!(m("https://example.com", page), None, "{page}");
    }
}

#[test]
fn public_suffix_list_icann_and_private() {
    assert_eq!(
        m("https://www.example.co.uk", "https://example.co.uk"),
        Some(MatchKind::SameSite)
    );
    assert_eq!(m("https://example.co.uk", "https://other.co.uk"), None);
    // Private suffixes: different users' sites are different sites.
    assert_eq!(m("https://alice.github.io", "https://bob.github.io"), None);
    assert_eq!(
        m(
            "https://alice.github.io/repo",
            "https://alice.github.io/other"
        ),
        Some(MatchKind::ExactHost)
    );
    assert_eq!(m("https://a.blogspot.com", "https://b.blogspot.com"), None);
    // A public suffix itself only matches exactly.
    assert_eq!(m("https://co.uk", "https://example.co.uk"), None);
    assert_eq!(
        Origin::parse("https://github.io")
            .unwrap()
            .registrable_domain(),
        None
    );
    assert_eq!(
        Origin::parse("https://x.y.example.co.uk")
            .unwrap()
            .registrable_domain(),
        Some("example.co.uk")
    );
}

#[test]
fn look_alike_domains_never_match() {
    // Cyrillic "а" (U+0430) instead of Latin "a".
    let lookalike = "https://\u{0430}pple.com/";
    assert_eq!(m("https://apple.com", lookalike), None);
    let origin = Origin::parse(lookalike).unwrap();
    assert!(origin.is_internationalized());
    assert!(origin.host().starts_with("xn--"));
    assert_eq!(origin.display_host(), "\u{0430}pple.com");
    // A genuine international domain matches in either form.
    assert_eq!(
        m("https://bücher.de", "https://xn--bcher-kva.de/"),
        Some(MatchKind::ExactHost)
    );
    assert_eq!(
        m("https://xn--bcher-kva.de", "https://www.bücher.de"),
        Some(MatchKind::SameSite)
    );
    assert!(
        !Origin::parse("https://example.com")
            .unwrap()
            .is_internationalized()
    );
}

#[test]
fn ip_addresses_and_local_names_match_exactly() {
    assert_eq!(
        m("http://192.168.1.10:8080", "http://192.168.1.10:8080/admin"),
        Some(MatchKind::ExactHost)
    );
    assert_eq!(
        m("http://192.168.1.10:8080", "http://192.168.1.11:8080/"),
        None
    );
    assert_eq!(
        m("http://192.168.1.10:8080", "http://192.168.1.10:8081/"),
        None
    );
    assert_eq!(
        m("https://[::1]:8443", "https://[::1]:8443/"),
        Some(MatchKind::ExactHost)
    );
    assert_eq!(
        m("http://localhost:3000", "http://localhost:3000/"),
        Some(MatchKind::ExactHost)
    );
    assert_eq!(m("http://localhost:3000", "http://localhost:4000/"), None);
    assert_eq!(m("https://nas", "https://router"), None);
    assert_eq!(m("http://127.0.0.1", "http://localhost/"), None);
    assert_eq!(
        Origin::parse("http://10.0.0.1")
            .unwrap()
            .registrable_domain(),
        None
    );
}

#[test]
fn schemes_and_ports() {
    // Never downgrade https credentials to an http page.
    assert_eq!(m("https://example.com", "http://example.com/"), None);
    // http credentials may be used on the same site over https.
    assert_eq!(
        m("http://example.com", "https://example.com/"),
        Some(MatchKind::ExactHost)
    );
    assert_eq!(
        m("http://example.com", "http://example.com/"),
        Some(MatchKind::ExactHost)
    );
    // Ports.
    assert_eq!(m("https://example.com", "https://example.com:8443/"), None);
    assert_eq!(
        m("https://example.com:8443", "https://example.com:8443/"),
        Some(MatchKind::ExactHost)
    );
    assert_eq!(m("https://example.com:8443", "https://example.com/"), None);
    assert_eq!(
        m("https://example.com:443", "https://example.com/"),
        Some(MatchKind::ExactHost)
    );
    assert_eq!(
        m("https://example.com", "https://example.com:443/"),
        Some(MatchKind::ExactHost)
    );
}

#[test]
fn ineligible_pages_are_refused() {
    for (page, error) in [
        (
            "file:///home/user/login.html",
            OriginError::UnsupportedScheme,
        ),
        ("javascript:alert(1)", OriginError::UnsupportedScheme),
        ("data:text/html,<form>", OriginError::UnsupportedScheme),
        ("about:blank", OriginError::UnsupportedScheme),
        ("chrome://settings", OriginError::UnsupportedScheme),
        (
            "chrome-extension://abcdefghijklmnop/popup.html",
            OriginError::UnsupportedScheme,
        ),
        (
            "moz-extension://1234/popup.html",
            OriginError::UnsupportedScheme,
        ),
        ("ftp://example.com", OriginError::UnsupportedScheme),
        ("https://", OriginError::Invalid),
        ("http://exa mple.com", OriginError::Invalid),
    ] {
        assert_eq!(
            best_match(["https://example.com"], page),
            Err(error),
            "{page}"
        );
    }
    // Unusable stored URLs are ignored, the usable ones still count.
    assert_eq!(
        best_match(
            ["not a url ::", "javascript:x", "https://example.com"],
            "https://example.com/"
        ),
        Ok(Some(MatchKind::ExactHost))
    );
    assert_eq!(best_match([], "https://example.com/"), Ok(None));
}

#[test]
fn best_of_several_urls() {
    assert_eq!(
        best_match(
            ["https://www.example.com", "https://login.example.com"],
            "https://login.example.com/"
        ),
        Ok(Some(MatchKind::ExactHost))
    );
    assert!(MatchKind::ExactHost > MatchKind::SameSite);
}

#[test]
fn saving_from_a_page() {
    let page = Origin::parse("https://login.example.co.uk:443/signin?x=1").unwrap();
    assert_eq!(page.scheme(), Scheme::Https);
    assert_eq!(title_for(&page), "example.co.uk");
    assert_eq!(url_to_store(&page), "https://login.example.co.uk/");
    let local = Origin::parse("http://192.168.1.10:8080/admin").unwrap();
    assert_eq!(title_for(&local), "192.168.1.10");
    assert_eq!(url_to_store(&local), "http://192.168.1.10:8080/");
    let v6 = Origin::parse("https://[::1]:8443/").unwrap();
    assert_eq!(url_to_store(&v6), "https://[::1]:8443/");
    assert_eq!(
        title_for(&Origin::parse("https://www.bücher.de").unwrap()),
        "bücher.de"
    );
    // The stored URL matches the page it was saved from.
    let stored = url_to_store(&page);
    assert_eq!(
        m(&stored, "https://login.example.co.uk/signin"),
        Some(MatchKind::ExactHost)
    );
    assert_eq!(
        match_origins(&Origin::parse(&stored).unwrap(), &page),
        Some(MatchKind::ExactHost)
    );
}
