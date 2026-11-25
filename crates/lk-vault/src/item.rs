//! Item schema, version 1.
//!
//! This is the plaintext structure encrypted inside each item envelope
//! (`lk_core::EncryptedItem::content`). Rules:
//!
//! * Every field change that an older client could not round-trip bumps
//!   [`ITEM_SCHEMA_VERSION`]; unknown fields are rejected, so an older client
//!   refuses to edit a newer item instead of silently dropping data.
//! * Secrets are [`SecretString`]s; the `Debug` output of every structure here
//!   is fully redacted (names, e-mails and usernames are personal data too).
//! * Timestamps are Unix seconds supplied by the caller.

use core::fmt;

use serde::{Deserialize, Serialize};

use crate::error::{Result, VaultError, invalid};
use crate::secret::SecretString;

/// Current item schema version.
pub const ITEM_SCHEMA_VERSION: u16 = 1;

/// Limits (bytes of UTF-8 unless stated otherwise).
pub mod limits {
    /// Title.
    pub const TITLE: usize = 512;
    /// Folder name.
    pub const FOLDER: usize = 256;
    /// One tag.
    pub const TAG: usize = 64;
    /// Number of tags.
    pub const TAGS: usize = 32;
    /// Notes.
    pub const NOTES: usize = 64 * 1024;
    /// Number of custom fields.
    pub const CUSTOM_FIELDS: usize = 64;
    /// Custom field name.
    pub const FIELD_NAME: usize = 256;
    /// Custom field value.
    pub const FIELD_VALUE: usize = 8 * 1024;
    /// Username.
    pub const USERNAME: usize = 512;
    /// Password.
    pub const PASSWORD: usize = 4096;
    /// Number of URLs.
    pub const URLS: usize = 32;
    /// One URL.
    pub const URL: usize = 2048;
    /// Number of backup codes.
    pub const BACKUP_CODES: usize = 64;
    /// One backup code.
    pub const BACKUP_CODE: usize = 128;
    /// Generic short text (names, address lines, ...).
    pub const SHORT_TEXT: usize = 512;
    /// Number of identity documents.
    pub const DOCUMENTS: usize = 32;
    /// Number of password-history entries kept.
    pub const HISTORY: usize = 20;
}

macro_rules! redacted_debug {
    ($($ty:ident),* $(,)?) => {
        $(
            impl fmt::Debug for $ty {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    f.write_str(concat!(stringify!($ty), " { <redacted> }"))
                }
            }
        )*
    };
}

/// Kind of an item, without its data.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemKind {
    /// Website or application login.
    Login,
    /// Secure note.
    SecureNote,
    /// Payment card.
    PaymentCard,
    /// Identity (personal information and identity documents).
    Identity,
}

/// A vault item (plaintext, memory only).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ItemData {
    /// Schema version ([`ITEM_SCHEMA_VERSION`]).
    pub schema: u16,
    /// Display title (required).
    pub title: String,
    /// Marked as favorite.
    #[serde(default)]
    pub favorite: bool,
    /// Folder name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folder: Option<String>,
    /// Tags.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Free-form notes (the body of a secure note).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<SecretString>,
    /// User-defined fields.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub custom_fields: Vec<CustomField>,
    /// Creation time (Unix seconds).
    pub created_at: u64,
    /// Last modification time (Unix seconds).
    pub updated_at: u64,
    /// Type-specific content.
    pub content: ItemContent,
    /// Previous passwords, most recent first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub password_history: Vec<HistoryEntry>,
}

/// Type-specific content.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ItemContent {
    /// Login.
    Login(Login),
    /// Secure note (its text is [`ItemData::notes`]).
    SecureNote(SecureNote),
    /// Payment card.
    PaymentCard(PaymentCard),
    /// Identity.
    Identity(Identity),
}

/// Website or application credentials.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Login {
    /// Username or e-mail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Password.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<SecretString>,
    /// Website addresses (normalized absolute `http`/`https` URLs).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub urls: Vec<String>,
    /// TOTP configuration, normalized as an `otpauth://totp/` URI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp: Option<SecretString>,
    /// Two-factor backup (recovery) codes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub backup_codes: Vec<SecretString>,
}

/// Marker for secure notes.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecureNote {}

/// Payment card.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PaymentCard {
    /// Name printed on the card.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cardholder_name: Option<String>,
    /// Card number, digits only (12–19).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub number: Option<SecretString>,
    /// Expiry month (1–12).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiry_month: Option<u8>,
    /// Expiry year (four digits).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiry_year: Option<u16>,
    /// Security code (3–4 digits).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security_code: Option<SecretString>,
    /// PIN (4–12 digits).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pin: Option<SecretString>,
    /// Billing address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub billing_address: Option<Address>,
}

/// Identity.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    /// Honorific (Mr, Ms, Dr, ...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub honorific: Option<String>,
    /// First name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,
    /// Middle name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub middle_name: Option<String>,
    /// Last name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,
    /// Date of birth, `YYYY-MM-DD`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub birth_date: Option<String>,
    /// E-mail address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Phone number.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phone: Option<String>,
    /// Company.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub company: Option<String>,
    /// Postal address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<Address>,
    /// Identity documents.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub documents: Vec<IdentityDocument>,
}

/// Postal address.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Address {
    /// First line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line1: Option<String>,
    /// Second line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line2: Option<String>,
    /// City.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
    /// Postal code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub postal_code: Option<String>,
    /// Region or state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// Country (ISO 3166-1 alpha-2 code, upper case).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
}

/// Kind of identity document.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DocumentKind {
    /// Passport.
    Passport,
    /// National identity card.
    NationalId,
    /// Driving licence.
    DriverLicense,
    /// Social security / health insurance number.
    SocialSecurity,
    /// Other document.
    Other,
}

/// An identity document (the file itself arrives with attachments, M12).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityDocument {
    /// Document kind.
    pub kind: DocumentKind,
    /// Document number.
    pub number: SecretString,
    /// Issuing country (ISO 3166-1 alpha-2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuing_country: Option<String>,
    /// Expiry date, `YYYY-MM-DD`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiry_date: Option<String>,
}

/// How a custom field is displayed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldKind {
    /// Plain text.
    Text,
    /// Masked until revealed.
    Hidden,
    /// URL.
    Url,
    /// E-mail address.
    Email,
}

/// User-defined field.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustomField {
    /// Field label.
    pub name: String,
    /// Field value.
    pub value: SecretString,
    /// Display kind.
    pub kind: FieldKind,
}

/// A previous password.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryEntry {
    /// The replaced password.
    pub password: SecretString,
    /// When it was replaced (Unix seconds).
    pub replaced_at: u64,
}

redacted_debug!(
    ItemData,
    ItemContent,
    Login,
    SecureNote,
    PaymentCard,
    Identity,
    Address,
    IdentityDocument,
    CustomField,
    HistoryEntry,
);

// ---------------------------------------------------------------- validation

fn check_len(value: &str, max: usize, field: &'static str) -> Result<()> {
    if value.len() > max {
        Err(invalid(field, "too long"))
    } else {
        Ok(())
    }
}

fn check_opt(value: Option<&str>, max: usize, field: &'static str) -> Result<()> {
    value.map_or(Ok(()), |v| check_len(v, max, field))
}

fn check_count<T>(items: &[T], max: usize, field: &'static str) -> Result<()> {
    if items.len() > max {
        Err(invalid(field, "too many entries"))
    } else {
        Ok(())
    }
}

fn check_digits(value: &str, min: usize, max: usize, field: &'static str) -> Result<()> {
    if !(min..=max).contains(&value.len()) || !value.bytes().all(|b| b.is_ascii_digit()) {
        Err(invalid(field, "unexpected format"))
    } else {
        Ok(())
    }
}

fn check_date(value: &str, field: &'static str) -> Result<()> {
    let bytes = value.as_bytes();
    let well_formed = bytes.len() == 10
        && bytes.get(4) == Some(&b'-')
        && bytes.get(7) == Some(&b'-')
        && bytes
            .iter()
            .enumerate()
            .all(|(i, b)| i == 4 || i == 7 || b.is_ascii_digit());
    if !well_formed {
        return Err(invalid(field, "expected YYYY-MM-DD"));
    }
    let month: u8 = value.get(5..7).and_then(|m| m.parse().ok()).unwrap_or(0);
    let day: u8 = value.get(8..10).and_then(|d| d.parse().ok()).unwrap_or(0);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return Err(invalid(field, "expected YYYY-MM-DD"));
    }
    Ok(())
}

fn check_country(value: &str, field: &'static str) -> Result<()> {
    if value.len() == 2 && value.bytes().all(|b| b.is_ascii_uppercase()) {
        Ok(())
    } else {
        Err(invalid(field, "expected an ISO 3166-1 alpha-2 code"))
    }
}

impl Address {
    fn validate(&self) -> Result<()> {
        check_opt(self.line1.as_deref(), limits::SHORT_TEXT, "address line 1")?;
        check_opt(self.line2.as_deref(), limits::SHORT_TEXT, "address line 2")?;
        check_opt(self.city.as_deref(), limits::SHORT_TEXT, "city")?;
        check_opt(
            self.postal_code.as_deref(),
            limits::SHORT_TEXT,
            "postal code",
        )?;
        check_opt(self.region.as_deref(), limits::SHORT_TEXT, "region")?;
        if let Some(c) = &self.country {
            check_country(c, "country")?;
        }
        Ok(())
    }
}

/// Normalizes a website address entered by a user: trims it, adds
/// `https://` when no scheme is given, and requires an absolute `http` or
/// `https` URL with a host.
///
/// # Errors
/// [`VaultError::Invalid`] for anything else.
pub fn normalize_url(input: &str) -> Result<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(invalid("url", "empty"));
    }
    let candidate = if trimmed.contains("://") {
        trimmed.to_owned()
    } else {
        format!("https://{trimmed}")
    };
    let parsed = url::Url::parse(&candidate).map_err(|_| invalid("url", "not a valid address"))?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none_or(str::is_empty) {
        return Err(invalid(
            "url",
            "only http and https addresses are supported",
        ));
    }
    let normalized: String = parsed.into();
    check_len(&normalized, limits::URL, "url")?;
    Ok(normalized)
}

/// Validates a TOTP input (an `otpauth://totp/` URI or a Base32 secret) and
/// returns it normalized as an `otpauth://totp/` URI.
///
/// # Errors
/// [`VaultError::Totp`] if the input is not a valid TOTP configuration.
pub fn normalize_totp(input: &str) -> Result<SecretString> {
    let trimmed = input.trim();
    let totp = if trimmed.to_ascii_lowercase().starts_with("otpauth://") {
        lk_totp::Totp::from_uri(trimmed)?
    } else {
        lk_totp::Totp::from_base32_secret(trimmed)?
    };
    let uri = totp.to_uri()?;
    Ok(SecretString::new(uri.as_str()))
}

/// Luhn checksum of a card number (digits only). A failed check is shown as a
/// warning: some valid cards (e.g. some private-label cards) do not use it.
#[must_use]
pub fn luhn_valid(digits: &str) -> bool {
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let mut sum: u32 = 0;
    for (i, b) in digits.bytes().rev().enumerate() {
        let mut d = u32::from(b.wrapping_sub(b'0'));
        if i % 2 == 1 {
            d = d.saturating_mul(2);
            if d > 9 {
                d = d.saturating_sub(9);
            }
        }
        sum = sum.saturating_add(d);
    }
    sum.is_multiple_of(10)
}

impl Login {
    fn validate(&self) -> Result<()> {
        check_opt(self.username.as_deref(), limits::USERNAME, "username")?;
        check_opt(
            self.password.as_ref().map(SecretString::expose),
            limits::PASSWORD,
            "password",
        )?;
        check_count(&self.urls, limits::URLS, "urls")?;
        for url in &self.urls {
            if normalize_url(url)? != *url {
                return Err(invalid("url", "not normalized"));
            }
        }
        if let Some(totp) = &self.totp {
            lk_totp::Totp::from_uri(totp.expose())?;
        }
        check_count(&self.backup_codes, limits::BACKUP_CODES, "backup codes")?;
        for code in &self.backup_codes {
            check_len(code.expose(), limits::BACKUP_CODE, "backup code")?;
        }
        Ok(())
    }
}

impl PaymentCard {
    fn validate(&self) -> Result<()> {
        check_opt(
            self.cardholder_name.as_deref(),
            limits::SHORT_TEXT,
            "cardholder name",
        )?;
        if let Some(n) = &self.number {
            check_digits(n.expose(), 12, 19, "card number")?;
        }
        if let Some(m) = self.expiry_month
            && !(1..=12).contains(&m)
        {
            return Err(invalid("expiry month", "out of range"));
        }
        if let Some(y) = self.expiry_year
            && !(2000..=2100).contains(&y)
        {
            return Err(invalid("expiry year", "out of range"));
        }
        if let Some(c) = &self.security_code {
            check_digits(c.expose(), 3, 4, "security code")?;
        }
        if let Some(p) = &self.pin {
            check_digits(p.expose(), 4, 12, "PIN")?;
        }
        if let Some(a) = &self.billing_address {
            a.validate()?;
        }
        Ok(())
    }
}

impl Identity {
    fn validate(&self) -> Result<()> {
        for (value, field) in [
            (&self.honorific, "honorific"),
            (&self.first_name, "first name"),
            (&self.middle_name, "middle name"),
            (&self.last_name, "last name"),
            (&self.email, "e-mail"),
            (&self.phone, "phone"),
            (&self.company, "company"),
        ] {
            check_opt(value.as_deref(), limits::SHORT_TEXT, field)?;
        }
        if let Some(d) = &self.birth_date {
            check_date(d, "birth date")?;
        }
        if let Some(a) = &self.address {
            a.validate()?;
        }
        check_count(&self.documents, limits::DOCUMENTS, "documents")?;
        for doc in &self.documents {
            check_len(doc.number.expose(), limits::SHORT_TEXT, "document number")?;
            if doc.number.is_empty() {
                return Err(invalid("document number", "empty"));
            }
            if let Some(c) = &doc.issuing_country {
                check_country(c, "issuing country")?;
            }
            if let Some(d) = &doc.expiry_date {
                check_date(d, "document expiry date")?;
            }
        }
        Ok(())
    }
}

impl ItemData {
    /// Creates a new item of the given content, validated.
    ///
    /// # Errors
    /// [`VaultError::Invalid`] if any field is invalid.
    pub fn new(title: &str, content: ItemContent, now_unix: u64) -> Result<Self> {
        let item = Self {
            schema: ITEM_SCHEMA_VERSION,
            title: title.trim().to_owned(),
            favorite: false,
            folder: None,
            tags: Vec::new(),
            notes: None,
            custom_fields: Vec::new(),
            created_at: now_unix,
            updated_at: now_unix,
            content,
            password_history: Vec::new(),
        };
        item.validate()?;
        Ok(item)
    }

    /// Item kind.
    #[must_use]
    pub const fn kind(&self) -> ItemKind {
        match self.content {
            ItemContent::Login(_) => ItemKind::Login,
            ItemContent::SecureNote(_) => ItemKind::SecureNote,
            ItemContent::PaymentCard(_) => ItemKind::PaymentCard,
            ItemContent::Identity(_) => ItemKind::Identity,
        }
    }

    /// Validates every field.
    ///
    /// # Errors
    /// [`VaultError::Invalid`], [`VaultError::Totp`] or
    /// [`VaultError::UnsupportedSchema`].
    pub fn validate(&self) -> Result<()> {
        if self.schema != ITEM_SCHEMA_VERSION {
            return Err(VaultError::UnsupportedSchema(self.schema));
        }
        if self.title.trim().is_empty() {
            return Err(invalid("title", "required"));
        }
        check_len(&self.title, limits::TITLE, "title")?;
        check_opt(self.folder.as_deref(), limits::FOLDER, "folder")?;
        check_count(&self.tags, limits::TAGS, "tags")?;
        for tag in &self.tags {
            if tag.trim().is_empty() {
                return Err(invalid("tag", "empty"));
            }
            check_len(tag, limits::TAG, "tag")?;
        }
        check_opt(
            self.notes.as_ref().map(SecretString::expose),
            limits::NOTES,
            "notes",
        )?;
        check_count(&self.custom_fields, limits::CUSTOM_FIELDS, "custom fields")?;
        for field in &self.custom_fields {
            if field.name.trim().is_empty() {
                return Err(invalid("custom field name", "required"));
            }
            check_len(&field.name, limits::FIELD_NAME, "custom field name")?;
            check_len(
                field.value.expose(),
                limits::FIELD_VALUE,
                "custom field value",
            )?;
        }
        if self.updated_at < self.created_at {
            return Err(invalid("updated_at", "earlier than created_at"));
        }
        check_count(&self.password_history, limits::HISTORY, "password history")?;
        if !self.password_history.is_empty() && self.kind() != ItemKind::Login {
            return Err(invalid(
                "password history",
                "only logins have a password history",
            ));
        }
        match &self.content {
            ItemContent::Login(l) => l.validate(),
            ItemContent::SecureNote(_) => Ok(()),
            ItemContent::PaymentCard(c) => c.validate(),
            ItemContent::Identity(i) => i.validate(),
        }
    }

    /// Changes the password of a login. The previous password (if any and if
    /// different) is moved to the history, which keeps at most
    /// [`limits::HISTORY`] entries (oldest dropped).
    ///
    /// # Errors
    /// [`VaultError::WrongItemType`] for non-login items;
    /// [`VaultError::Invalid`] if the new password is too long.
    pub fn change_password(&mut self, new_password: SecretString, now_unix: u64) -> Result<()> {
        check_len(new_password.expose(), limits::PASSWORD, "password")?;
        let ItemContent::Login(login) = &mut self.content else {
            return Err(VaultError::WrongItemType);
        };
        if let Some(old) = login.password.replace(new_password)
            && Some(&old) != login.password.as_ref()
            && !old.is_empty()
        {
            self.password_history.insert(
                0,
                HistoryEntry {
                    password: old,
                    replaced_at: now_unix,
                },
            );
            self.password_history.truncate(limits::HISTORY);
        }
        self.updated_at = self.updated_at.max(now_unix);
        Ok(())
    }

    /// Restores the history entry at `index` as the current password; the
    /// current password goes to the top of the history.
    ///
    /// # Errors
    /// [`VaultError::NoSuchHistoryEntry`] or [`VaultError::WrongItemType`].
    pub fn restore_password(&mut self, index: usize, now_unix: u64) -> Result<()> {
        if index >= self.password_history.len() {
            return Err(VaultError::NoSuchHistoryEntry);
        }
        if self.kind() != ItemKind::Login {
            return Err(VaultError::WrongItemType);
        }
        let entry = self.password_history.remove(index);
        self.change_password(entry.password, now_unix)
    }

    /// Permanently deletes the history entry at `index`.
    ///
    /// # Errors
    /// [`VaultError::NoSuchHistoryEntry`].
    pub fn delete_history_entry(&mut self, index: usize, now_unix: u64) -> Result<()> {
        if index >= self.password_history.len() {
            return Err(VaultError::NoSuchHistoryEntry);
        }
        self.password_history.remove(index);
        self.updated_at = self.updated_at.max(now_unix);
        Ok(())
    }

    /// Case-insensitive search over title, folder, tags, username and URLs
    /// (never over secrets).
    #[must_use]
    pub fn matches(&self, query: &str) -> bool {
        let q = query.trim().to_lowercase();
        if q.is_empty() {
            return true;
        }
        let hit = |s: &str| s.to_lowercase().contains(&q);
        if hit(&self.title)
            || self.folder.as_deref().is_some_and(hit)
            || self.tags.iter().any(|t| hit(t))
        {
            return true;
        }
        match &self.content {
            ItemContent::Login(l) => {
                l.username.as_deref().is_some_and(hit) || l.urls.iter().any(|u| hit(u))
            }
            ItemContent::PaymentCard(c) => c.cardholder_name.as_deref().is_some_and(hit),
            ItemContent::Identity(i) => [&i.first_name, &i.last_name, &i.email, &i.company]
                .iter()
                .any(|v| v.as_deref().is_some_and(hit)),
            ItemContent::SecureNote(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn login() -> ItemData {
        ItemData::new(
            "Bank",
            ItemContent::Login(Login {
                username: Some("alice@example.com".into()),
                password: Some("first".into()),
                urls: vec![normalize_url("bank.example.com").unwrap()],
                ..Login::default()
            }),
            100,
        )
        .unwrap()
    }

    #[test]
    fn url_normalization() {
        assert_eq!(
            normalize_url(" example.com ").unwrap(),
            "https://example.com/"
        );
        assert_eq!(
            normalize_url("http://Example.com:8080/login?x=1").unwrap(),
            "http://example.com:8080/login?x=1"
        );
        assert!(normalize_url("").is_err());
        assert!(normalize_url("javascript:alert(1)").is_err());
        assert!(normalize_url("ftp://example.com").is_err());
        assert!(normalize_url("file:///etc/passwd").is_err());
    }

    #[test]
    fn totp_normalization() {
        let uri = normalize_totp("GEZD GNBV GY3T QOJQ").unwrap();
        assert!(uri.expose().starts_with("otpauth://totp/"));
        assert!(normalize_totp("not a secret!").is_err());
    }

    #[test]
    fn luhn() {
        assert!(luhn_valid("4111111111111111"));
        assert!(luhn_valid("79927398713"));
        assert!(!luhn_valid("4111111111111112"));
        assert!(!luhn_valid("41111a"));
        assert!(!luhn_valid(""));
    }

    #[test]
    fn title_required_and_bounded() {
        assert!(ItemData::new("  ", ItemContent::SecureNote(SecureNote {}), 0).is_err());
        let long = "x".repeat(limits::TITLE + 1);
        assert!(ItemData::new(&long, ItemContent::SecureNote(SecureNote {}), 0).is_err());
    }

    #[test]
    fn password_history_is_kept_bounded_and_restorable() {
        let mut item = login();
        for i in 0..25 {
            item.change_password(format!("pw{i}").into(), 200 + i)
                .unwrap();
        }
        assert_eq!(item.password_history.len(), limits::HISTORY);
        assert_eq!(item.password_history[0].password.expose(), "pw23");
        let ItemContent::Login(l) = &item.content else {
            unreachable!()
        };
        assert_eq!(l.password.as_ref().unwrap().expose(), "pw24");
        item.restore_password(0, 300).unwrap();
        let ItemContent::Login(l) = &item.content else {
            unreachable!()
        };
        assert_eq!(l.password.as_ref().unwrap().expose(), "pw23");
        assert_eq!(item.password_history[0].password.expose(), "pw24");
        item.delete_history_entry(0, 301).unwrap();
        assert_ne!(item.password_history[0].password.expose(), "pw24");
        assert_eq!(
            item.restore_password(99, 302),
            Err(VaultError::NoSuchHistoryEntry)
        );
        item.validate().unwrap();
    }

    #[test]
    fn same_password_does_not_create_history() {
        let mut item = login();
        item.change_password("first".into(), 101).unwrap();
        assert!(item.password_history.is_empty());
    }

    #[test]
    fn change_password_on_note_is_rejected() {
        let mut note = ItemData::new("n", ItemContent::SecureNote(SecureNote {}), 0).unwrap();
        assert_eq!(
            note.change_password("x".into(), 1),
            Err(VaultError::WrongItemType)
        );
    }

    #[test]
    fn card_validation() {
        let ok = PaymentCard {
            number: Some("4111111111111111".into()),
            expiry_month: Some(12),
            expiry_year: Some(2030),
            security_code: Some("123".into()),
            ..PaymentCard::default()
        };
        ItemData::new("Visa", ItemContent::PaymentCard(ok.clone()), 0).unwrap();
        for bad in [
            PaymentCard {
                number: Some("4111 1111".into()),
                ..ok.clone()
            },
            PaymentCard {
                expiry_month: Some(13),
                ..ok.clone()
            },
            PaymentCard {
                expiry_year: Some(1999),
                ..ok.clone()
            },
            PaymentCard {
                security_code: Some("12".into()),
                ..ok.clone()
            },
            PaymentCard {
                pin: Some("12a4".into()),
                ..ok
            },
        ] {
            assert!(ItemData::new("Visa", ItemContent::PaymentCard(bad), 0).is_err());
        }
    }

    #[test]
    fn identity_validation() {
        let ok = Identity {
            first_name: Some("Alice".into()),
            birth_date: Some("1990-02-28".into()),
            address: Some(Address {
                country: Some("FR".into()),
                ..Address::default()
            }),
            documents: vec![IdentityDocument {
                kind: DocumentKind::Passport,
                number: "12AB34567".into(),
                issuing_country: Some("FR".into()),
                expiry_date: Some("2031-06-30".into()),
            }],
            ..Identity::default()
        };
        ItemData::new("Me", ItemContent::Identity(ok.clone()), 0).unwrap();
        let bad_date = Identity {
            birth_date: Some("1990-13-01".into()),
            ..ok.clone()
        };
        assert!(ItemData::new("Me", ItemContent::Identity(bad_date), 0).is_err());
        let bad_country = Identity {
            address: Some(Address {
                country: Some("France".into()),
                ..Address::default()
            }),
            ..ok
        };
        assert!(ItemData::new("Me", ItemContent::Identity(bad_country), 0).is_err());
    }

    #[test]
    fn search_covers_metadata_but_not_secrets() {
        let item = login();
        assert!(item.matches("bank"));
        assert!(item.matches("ALICE@"));
        assert!(item.matches("example.com"));
        assert!(!item.matches("first"), "must not search inside passwords");
        assert!(item.matches(""));
    }

    #[test]
    fn debug_never_prints_user_data() {
        let mut item = login();
        item.notes = Some("note-canary".into());
        let printed = format!("{item:?} {:?}", item.content);
        for canary in ["alice", "first", "Bank", "note-canary", "bank.example.com"] {
            assert!(!printed.contains(canary), "{canary} leaked in {printed}");
        }
    }
}
