//! Server configuration (environment variables, see `docs/SELF_HOSTING.md`).

/// Runtime configuration.
#[derive(Clone, Debug)]
pub struct Config {
    /// Session lifetime in seconds.
    pub session_ttl_secs: i64,
    /// Lifetime of a pending OPAQUE login attempt in seconds.
    pub login_attempt_ttl_secs: i64,
    /// Whether new accounts may register.
    pub allow_registration: bool,
    /// Trust `X-Forwarded-For` (only behind a trusted reverse proxy).
    pub trust_proxy_headers: bool,
    /// Requests per minute per key on authentication endpoints.
    pub auth_rate_limit_per_minute: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            session_ttl_secs: 12 * 3600,
            login_attempt_ttl_secs: 120,
            allow_registration: true,
            trust_proxy_headers: false,
            auth_rate_limit_per_minute: 30,
        }
    }
}

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

fn parse<T: std::str::FromStr>(name: &str, default: T) -> Result<T, String> {
    match var(name) {
        None => Ok(default),
        Some(v) => v
            .trim()
            .parse()
            .map_err(|_| format!("invalid value for {name}")),
    }
}

fn parse_bool(name: &str, default: bool) -> Result<bool, String> {
    match var(name).as_deref().map(str::to_ascii_lowercase).as_deref() {
        None => Ok(default),
        Some("1" | "true" | "yes") => Ok(true),
        Some("0" | "false" | "no") => Ok(false),
        Some(_) => Err(format!("invalid boolean for {name}")),
    }
}

impl Config {
    /// Reads the configuration from `LK_*` environment variables.
    ///
    /// # Errors
    /// Returns a message naming the invalid variable.
    pub fn from_env() -> Result<Self, String> {
        let d = Self::default();
        let config = Self {
            session_ttl_secs: parse("LK_SESSION_TTL_SECS", d.session_ttl_secs)?,
            login_attempt_ttl_secs: parse("LK_LOGIN_ATTEMPT_TTL_SECS", d.login_attempt_ttl_secs)?,
            allow_registration: parse_bool("LK_ALLOW_REGISTRATION", d.allow_registration)?,
            trust_proxy_headers: parse_bool("LK_TRUST_PROXY_HEADERS", d.trust_proxy_headers)?,
            auth_rate_limit_per_minute: parse(
                "LK_AUTH_RATE_LIMIT_PER_MINUTE",
                d.auth_rate_limit_per_minute,
            )?,
        };
        if config.session_ttl_secs <= 0 || config.login_attempt_ttl_secs < 0 {
            return Err("TTL values must be positive".to_owned());
        }
        Ok(config)
    }
}
