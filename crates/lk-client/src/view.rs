//! View models for user interfaces. Secret values never appear here: they
//! are replaced by presence flags and fetched one at a time, on explicit user
//! action, through [`crate::Vault::field_value`].

use lk_core::{AccountId, DeviceId, ItemId, Platform};
use lk_sync::SyncReport;
use lk_vault::{
    Address, DocumentKind, FieldKind, IdentityDocument, ItemContent, ItemData, ItemKind,
    SecretString,
};
use serde::{Deserialize, Serialize};

/// One line of the item list.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemSummary {
    /// Item identifier.
    pub id: ItemId,
    /// Item type.
    pub kind: ItemKind,
    /// Title.
    pub title: String,
    /// Secondary line: username, cardholder and last digits, or name.
    pub subtitle: Option<String>,
    /// Favorite.
    pub favorite: bool,
    /// Folder.
    pub folder: Option<String>,
    /// Tags.
    pub tags: Vec<String>,
    /// Host of the first URL of a login.
    pub host: Option<String>,
    /// A TOTP is configured.
    pub has_totp: bool,
    /// Last modification (Unix seconds).
    pub updated_at: u64,
}

fn last4(number: &SecretString) -> Option<String> {
    let digits: Vec<char> = number
        .expose()
        .chars()
        .filter(char::is_ascii_digit)
        .collect();
    let start = digits.len().checked_sub(4)?;
    digits.get(start..).map(|d| d.iter().collect())
}

fn host_of(url: &str) -> Option<String> {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
}

fn join_names(parts: &[&Option<String>]) -> Option<String> {
    let joined = parts
        .iter()
        .filter_map(|p| p.as_deref())
        .filter(|p| !p.trim().is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    (!joined.is_empty()).then_some(joined)
}

impl ItemSummary {
    /// Summary of a decrypted item.
    #[must_use]
    pub fn new(id: ItemId, data: &ItemData) -> Self {
        let (subtitle, host, has_totp) = match &data.content {
            ItemContent::Login(l) => (
                l.username.clone().filter(|u| !u.is_empty()),
                l.urls.first().and_then(|u| host_of(u)),
                l.totp.is_some(),
            ),
            ItemContent::PaymentCard(c) => {
                let digits = c
                    .number
                    .as_ref()
                    .and_then(last4)
                    .map(|d| format!("•••• {d}"));
                let name = c.cardholder_name.clone().filter(|n| !n.trim().is_empty());
                let subtitle = match (name, digits) {
                    (Some(n), Some(d)) => Some(format!("{n} · {d}")),
                    (n, d) => n.or(d),
                };
                (subtitle, None, false)
            }
            ItemContent::Identity(i) => (
                join_names(&[&i.first_name, &i.last_name]).or_else(|| i.email.clone()),
                None,
                false,
            ),
            ItemContent::SecureNote(_) => (None, None, false),
        };
        Self {
            id,
            kind: data.kind(),
            title: data.title.clone(),
            subtitle,
            favorite: data.favorite,
            folder: data.folder.clone(),
            tags: data.tags.clone(),
            host,
            has_totp,
            updated_at: data.updated_at,
        }
    }
}

/// A postal address (also used in edit drafts).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AddressView {
    /// First line.
    #[serde(default)]
    pub line1: Option<String>,
    /// Second line.
    #[serde(default)]
    pub line2: Option<String>,
    /// City.
    #[serde(default)]
    pub city: Option<String>,
    /// Postal code.
    #[serde(default)]
    pub postal_code: Option<String>,
    /// Region or state.
    #[serde(default)]
    pub region: Option<String>,
    /// Country (ISO 3166-1 alpha-2).
    #[serde(default)]
    pub country: Option<String>,
}

impl From<&Address> for AddressView {
    fn from(a: &Address) -> Self {
        Self {
            line1: a.line1.clone(),
            line2: a.line2.clone(),
            city: a.city.clone(),
            postal_code: a.postal_code.clone(),
            region: a.region.clone(),
            country: a.country.clone(),
        }
    }
}

/// A custom field; its value is included only when it is not a hidden field.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomFieldView {
    /// Label.
    pub name: String,
    /// Display kind.
    pub kind: FieldKind,
    /// Value (absent for hidden fields: reveal it explicitly).
    pub value: Option<String>,
    /// The field has a non-empty value.
    pub has_value: bool,
}

/// An identity document; its number is never included.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DocumentView {
    /// Document kind.
    pub kind: DocumentKind,
    /// Issuing country.
    pub issuing_country: Option<String>,
    /// Expiry date (`YYYY-MM-DD`).
    pub expiry_date: Option<String>,
    /// A number is stored.
    pub has_number: bool,
}

impl From<&IdentityDocument> for DocumentView {
    fn from(d: &IdentityDocument) -> Self {
        Self {
            kind: d.kind,
            issuing_country: d.issuing_country.clone(),
            expiry_date: d.expiry_date.clone(),
            has_number: !d.number.is_empty(),
        }
    }
}

/// Type-specific part of an [`ItemView`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(
    tag = "type",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum ContentView {
    /// Login.
    Login {
        /// Username.
        username: Option<String>,
        /// A password is stored.
        has_password: bool,
        /// URLs.
        urls: Vec<String>,
        /// A TOTP is configured.
        has_totp: bool,
        /// Number of backup codes.
        backup_codes: usize,
    },
    /// Secure note (its body is the item's notes).
    SecureNote {},
    /// Payment card.
    PaymentCard {
        /// Cardholder name.
        cardholder_name: Option<String>,
        /// A number is stored.
        has_number: bool,
        /// Last four digits of the number.
        number_last4: Option<String>,
        /// Expiry month (1–12).
        expiry_month: Option<u8>,
        /// Expiry year.
        expiry_year: Option<u16>,
        /// A security code is stored.
        has_security_code: bool,
        /// A PIN is stored.
        has_pin: bool,
        /// Billing address.
        billing_address: Option<AddressView>,
    },
    /// Identity.
    Identity {
        /// Honorific.
        honorific: Option<String>,
        /// First name.
        first_name: Option<String>,
        /// Middle name.
        middle_name: Option<String>,
        /// Last name.
        last_name: Option<String>,
        /// Birth date (`YYYY-MM-DD`).
        birth_date: Option<String>,
        /// E-mail address.
        email: Option<String>,
        /// Phone number.
        phone: Option<String>,
        /// Company.
        company: Option<String>,
        /// Address.
        address: Option<AddressView>,
        /// Identity documents.
        documents: Vec<DocumentView>,
    },
}

/// A previous password (its value is fetched on demand).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryView {
    /// When it was replaced (Unix seconds).
    pub replaced_at: u64,
}

/// Everything shown about an item, without any secret value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemView {
    /// Item identifier.
    pub id: ItemId,
    /// Item type.
    pub kind: ItemKind,
    /// Title.
    pub title: String,
    /// Favorite.
    pub favorite: bool,
    /// Folder.
    pub folder: Option<String>,
    /// Tags.
    pub tags: Vec<String>,
    /// Notes are stored (reveal them explicitly).
    pub has_notes: bool,
    /// Custom fields.
    pub custom_fields: Vec<CustomFieldView>,
    /// Previous passwords, most recent first.
    pub history: Vec<HistoryView>,
    /// Creation time (Unix seconds).
    pub created_at: u64,
    /// Last modification (Unix seconds).
    pub updated_at: u64,
    /// Type-specific content.
    pub content: ContentView,
}

impl ItemView {
    /// View of a decrypted item.
    #[must_use]
    pub fn new(id: ItemId, data: &ItemData) -> Self {
        let content = match &data.content {
            ItemContent::Login(l) => ContentView::Login {
                username: l.username.clone(),
                has_password: l.password.as_ref().is_some_and(|p| !p.is_empty()),
                urls: l.urls.clone(),
                has_totp: l.totp.is_some(),
                backup_codes: l.backup_codes.len(),
            },
            ItemContent::SecureNote(_) => ContentView::SecureNote {},
            ItemContent::PaymentCard(c) => ContentView::PaymentCard {
                cardholder_name: c.cardholder_name.clone(),
                has_number: c.number.as_ref().is_some_and(|n| !n.is_empty()),
                number_last4: c.number.as_ref().and_then(last4),
                expiry_month: c.expiry_month,
                expiry_year: c.expiry_year,
                has_security_code: c.security_code.as_ref().is_some_and(|s| !s.is_empty()),
                has_pin: c.pin.as_ref().is_some_and(|p| !p.is_empty()),
                billing_address: c.billing_address.as_ref().map(AddressView::from),
            },
            ItemContent::Identity(i) => ContentView::Identity {
                honorific: i.honorific.clone(),
                first_name: i.first_name.clone(),
                middle_name: i.middle_name.clone(),
                last_name: i.last_name.clone(),
                birth_date: i.birth_date.clone(),
                email: i.email.clone(),
                phone: i.phone.clone(),
                company: i.company.clone(),
                address: i.address.as_ref().map(AddressView::from),
                documents: i.documents.iter().map(DocumentView::from).collect(),
            },
        };
        Self {
            id,
            kind: data.kind(),
            title: data.title.clone(),
            favorite: data.favorite,
            folder: data.folder.clone(),
            tags: data.tags.clone(),
            has_notes: data.notes.as_ref().is_some_and(|n| !n.is_empty()),
            custom_fields: data
                .custom_fields
                .iter()
                .map(|f| CustomFieldView {
                    name: f.name.clone(),
                    kind: f.kind,
                    value: (f.kind != FieldKind::Hidden).then(|| f.value.expose().to_owned()),
                    has_value: !f.value.is_empty(),
                })
                .collect(),
            history: data
                .password_history
                .iter()
                .map(|h| HistoryView {
                    replaced_at: h.replaced_at,
                })
                .collect(),
            created_at: data.created_at,
            updated_at: data.updated_at,
            content,
        }
    }
}

/// A field whose value can be revealed or copied.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "field",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum Field {
    /// Login username.
    Username,
    /// Login password.
    Password,
    /// Login URL at `index`.
    Url {
        /// Position in the list.
        index: usize,
    },
    /// Current TOTP code.
    TotpCode,
    /// TOTP configuration (`otpauth://` URI).
    TotpSecret,
    /// Backup code at `index`.
    BackupCode {
        /// Position in the list.
        index: usize,
    },
    /// Notes (body of a secure note).
    Notes,
    /// Card number.
    CardNumber,
    /// Card security code.
    SecurityCode,
    /// Card PIN.
    Pin,
    /// Custom field value at `index`.
    CustomField {
        /// Position in the list.
        index: usize,
    },
    /// Previous password at `index` (0 = most recent).
    HistoryPassword {
        /// Position in the history.
        index: usize,
    },
    /// Identity document number at `index`.
    DocumentNumber {
        /// Position in the list.
        index: usize,
    },
}

/// A TOTP code and its validity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TotpView {
    /// Current code.
    pub code: String,
    /// Period in seconds.
    pub period: u64,
    /// Seconds until the code changes.
    pub remaining: u64,
}

/// Status of a device in the account's device list.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceStatus {
    /// The device running this client.
    ThisDevice,
    /// Certified by the account and not revoked.
    Active,
    /// Revoked.
    Revoked,
}

/// One device of the account (verified with the account key).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceView {
    /// Device identifier.
    pub id: DeviceId,
    /// User-visible name.
    pub name: String,
    /// Platform.
    pub platform: Platform,
    /// Status.
    pub status: DeviceStatus,
    /// Enrollment time (Unix seconds).
    pub enrolled_at: u64,
    /// Last request to the server (Unix seconds).
    pub last_seen: Option<u64>,
}

/// Server binding of a vault.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteView {
    /// Server URL.
    pub server: String,
    /// Account e-mail.
    pub email: String,
}

/// Key-derivation parameters in use.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KdfView {
    /// Memory (KiB).
    pub memory_kib: u32,
    /// Passes.
    pub iterations: u32,
    /// Lanes.
    pub parallelism: u32,
}

/// How the vault was unlocked.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnlockMethod {
    /// Master password.
    MasterPassword,
    /// Recovery key.
    RecoveryKey,
}

/// General information about the unlocked vault.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultInfo {
    /// Account identifier.
    pub account_id: AccountId,
    /// This device's identifier.
    pub device_id: DeviceId,
    /// This device's name.
    pub device_name: String,
    /// This device's platform.
    pub platform: Platform,
    /// When this device was enrolled (Unix seconds).
    pub enrolled_at: u64,
    /// Key-derivation parameters.
    pub kdf: KdfView,
    /// A recovery key is configured.
    pub recovery_key_configured: bool,
    /// Number of items.
    pub items: usize,
    /// Local changes not yet synchronized.
    pub pending_changes: usize,
    /// Server binding.
    pub remote: Option<RemoteView>,
    /// How the vault was unlocked.
    pub unlocked_with: UnlockMethod,
}

/// What a synchronization did.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncSummary {
    /// Server states applied locally.
    pub received: usize,
    /// Local changes accepted by the server.
    pub sent: usize,
    /// Real conflicts.
    pub conflicts: usize,
    /// Conflict copies created (nothing was lost).
    pub conflict_copies: usize,
}

impl SyncSummary {
    /// Adds a pass's report.
    pub fn add(&mut self, report: &SyncReport) {
        self.received = self.received.saturating_add(report.pulled);
        self.sent = self.sent.saturating_add(report.pushed);
        self.conflicts = self.conflicts.saturating_add(report.conflicts);
        self.conflict_copies = self
            .conflict_copies
            .saturating_add(report.conflict_copies.len());
    }
}
