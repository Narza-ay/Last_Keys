//! Edit requests from user interfaces. Secret fields are sent as changes
//! ("keep", "set", "clear"), so that an editor never needs to load secrets.

use lk_vault::{
    Address, CustomField, DocumentKind, FieldKind, Identity, IdentityDocument, ItemContent,
    ItemData, ItemKind, Login, PaymentCard, SecretString, SecureNote, normalize_totp,
    normalize_url,
};
use serde::Deserialize;

use crate::error::{ClientError, Result};
use crate::view::AddressView;

/// Change of one secret value.
#[derive(Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(tag = "op", rename_all = "camelCase", deny_unknown_fields)]
pub enum SecretChange {
    /// Keep the current value (nothing, for a new item).
    #[default]
    Keep,
    /// Replace it.
    Set {
        /// New value.
        value: String,
    },
    /// Remove it.
    Clear,
}

impl core::fmt::Debug for SecretChange {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Keep => "Keep",
            Self::Set { .. } => "Set(<redacted>)",
            Self::Clear => "Clear",
        })
    }
}

/// Change of a list of secret values (backup codes).
#[derive(Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(tag = "op", rename_all = "camelCase", deny_unknown_fields)]
pub enum ListChange {
    /// Keep the current list.
    #[default]
    Keep,
    /// Replace the list.
    Set {
        /// New values (empty lines are dropped).
        values: Vec<String>,
    },
    /// Remove every value.
    Clear,
}

impl core::fmt::Debug for ListChange {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Keep => "Keep",
            Self::Set { .. } => "Set(<redacted>)",
            Self::Clear => "Clear",
        })
    }
}

/// A custom field in an edit request.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CustomFieldDraft {
    /// Label.
    pub name: String,
    /// Display kind.
    pub kind: FieldKind,
    /// Value change; `Keep` takes the value of field `source`.
    #[serde(default)]
    pub value: SecretChange,
    /// Index of the field in the current item this one comes from.
    #[serde(default)]
    pub source: Option<usize>,
}

/// An identity document in an edit request.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DocumentDraft {
    /// Document kind.
    pub kind: DocumentKind,
    /// Number change; `Keep` takes the number of document `source`.
    #[serde(default)]
    pub number: SecretChange,
    /// Index of the document in the current item this one comes from.
    #[serde(default)]
    pub source: Option<usize>,
    /// Issuing country (ISO 3166-1 alpha-2).
    #[serde(default)]
    pub issuing_country: Option<String>,
    /// Expiry date (`YYYY-MM-DD`).
    #[serde(default)]
    pub expiry_date: Option<String>,
}

/// Type-specific part of an edit request.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ContentDraft {
    /// Login.
    Login {
        /// Username.
        #[serde(default)]
        username: Option<String>,
        /// Password change (a replaced password goes to the history).
        #[serde(default)]
        password: SecretChange,
        /// URLs (normalized; empty entries dropped).
        #[serde(default)]
        urls: Vec<String>,
        /// TOTP secret or `otpauth://` URI.
        #[serde(default)]
        totp: SecretChange,
        /// Backup codes.
        #[serde(default)]
        backup_codes: ListChange,
    },
    /// Secure note (the body is the draft's notes).
    SecureNote {},
    /// Payment card.
    PaymentCard {
        /// Cardholder name.
        #[serde(default)]
        cardholder_name: Option<String>,
        /// Card number (spaces and dashes are removed).
        #[serde(default)]
        number: SecretChange,
        /// Expiry month (1–12).
        #[serde(default)]
        expiry_month: Option<u8>,
        /// Expiry year.
        #[serde(default)]
        expiry_year: Option<u16>,
        /// Security code.
        #[serde(default)]
        security_code: SecretChange,
        /// PIN.
        #[serde(default)]
        pin: SecretChange,
        /// Billing address.
        #[serde(default)]
        billing_address: Option<AddressView>,
    },
    /// Identity.
    Identity {
        /// Honorific.
        #[serde(default)]
        honorific: Option<String>,
        /// First name.
        #[serde(default)]
        first_name: Option<String>,
        /// Middle name.
        #[serde(default)]
        middle_name: Option<String>,
        /// Last name.
        #[serde(default)]
        last_name: Option<String>,
        /// Birth date (`YYYY-MM-DD`).
        #[serde(default)]
        birth_date: Option<String>,
        /// E-mail address.
        #[serde(default)]
        email: Option<String>,
        /// Phone number.
        #[serde(default)]
        phone: Option<String>,
        /// Company.
        #[serde(default)]
        company: Option<String>,
        /// Address.
        #[serde(default)]
        address: Option<AddressView>,
        /// Identity documents.
        #[serde(default)]
        documents: Vec<DocumentDraft>,
    },
}

impl ContentDraft {
    const fn kind(&self) -> ItemKind {
        match self {
            Self::Login { .. } => ItemKind::Login,
            Self::SecureNote {} => ItemKind::SecureNote,
            Self::PaymentCard { .. } => ItemKind::PaymentCard,
            Self::Identity { .. } => ItemKind::Identity,
        }
    }
}

/// A complete edit request: the new state of every non-secret field, and
/// changes for the secret ones.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ItemDraft {
    /// Title (required).
    pub title: String,
    /// Favorite.
    #[serde(default)]
    pub favorite: bool,
    /// Folder.
    #[serde(default)]
    pub folder: Option<String>,
    /// Tags (trimmed, empty and duplicate tags dropped).
    #[serde(default)]
    pub tags: Vec<String>,
    /// Notes change.
    #[serde(default)]
    pub notes: SecretChange,
    /// Custom fields, in display order.
    #[serde(default)]
    pub custom_fields: Vec<CustomFieldDraft>,
    /// Type-specific content.
    pub content: ContentDraft,
}

/// Trimmed text, `None` when empty.
fn text(value: Option<String>) -> Option<String> {
    value.map(|v| v.trim().to_owned()).filter(|v| !v.is_empty())
}

fn address(value: Option<AddressView>) -> Option<Address> {
    let a = value?;
    let address = Address {
        line1: text(a.line1),
        line2: text(a.line2),
        city: text(a.city),
        postal_code: text(a.postal_code),
        region: text(a.region),
        country: text(a.country).map(|c| c.to_uppercase()),
    };
    (address != Address::default()).then_some(address)
}

/// Applies a change to an optional secret. `normalize` maps a new value.
fn change_opt(
    current: Option<SecretString>,
    change: SecretChange,
    normalize: impl FnOnce(String) -> Result<Option<SecretString>>,
) -> Result<Option<SecretString>> {
    match change {
        SecretChange::Keep => Ok(current),
        SecretChange::Set { value } => normalize(value),
        SecretChange::Clear => Ok(None),
    }
}

fn plain(value: String) -> Result<Option<SecretString>> {
    Ok((!value.is_empty()).then(|| SecretString::new(value)))
}

fn card_number(value: String) -> Result<Option<SecretString>> {
    let digits: String = value
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect();
    Ok((!digits.is_empty()).then(|| SecretString::new(digits)))
}

fn totp(value: String) -> Result<Option<SecretString>> {
    if value.trim().is_empty() {
        return Ok(None);
    }
    Ok(Some(normalize_totp(&value)?))
}

/// Value of a list entry that is kept from `source`, or set, or cleared.
fn entry(
    change: SecretChange,
    source: Option<usize>,
    current: impl Fn(usize) -> Option<SecretString>,
    what: &'static str,
) -> Result<SecretString> {
    match change {
        SecretChange::Keep => source
            .and_then(current)
            .ok_or(ClientError::InvalidDraft(what)),
        SecretChange::Set { value } => Ok(SecretString::new(value)),
        SecretChange::Clear => Ok(SecretString::new("")),
    }
}

impl ItemDraft {
    /// Builds a new item (`Keep` means "no value").
    ///
    /// # Errors
    /// [`ClientError::InvalidDraft`] for a kept list entry, or a validation
    /// error.
    pub fn into_new_item(self, now_unix: u64) -> Result<ItemData> {
        let placeholder = match self.content.kind() {
            ItemKind::Login => ItemContent::Login(Login::default()),
            ItemKind::SecureNote => ItemContent::SecureNote(SecureNote {}),
            ItemKind::PaymentCard => ItemContent::PaymentCard(PaymentCard::default()),
            ItemKind::Identity => ItemContent::Identity(Identity::default()),
        };
        let mut data = ItemData::new(&self.title, placeholder, now_unix)?;
        self.apply(&mut data, now_unix, false)?;
        Ok(data)
    }

    /// Applies the request to an existing item of the same type. A replaced
    /// or removed login password goes to the password history.
    ///
    /// # Errors
    /// [`ClientError::WrongItemType`] if the types differ,
    /// [`ClientError::InvalidDraft`] or a validation error.
    pub fn apply_to(self, data: &mut ItemData, now_unix: u64) -> Result<()> {
        if self.content.kind() != data.kind() {
            return Err(ClientError::WrongItemType);
        }
        self.apply(data, now_unix, true)
    }

    fn apply(self, data: &mut ItemData, now_unix: u64, existing: bool) -> Result<()> {
        data.title = self.title.trim().to_owned();
        data.favorite = self.favorite;
        data.folder = text(self.folder);
        let mut tags: Vec<String> = Vec::new();
        for tag in self.tags {
            let tag = tag.trim().to_owned();
            if !tag.is_empty() && !tags.contains(&tag) {
                tags.push(tag);
            }
        }
        data.tags = tags;
        data.notes = change_opt(data.notes.take(), self.notes, plain)?;

        let old_fields = core::mem::take(&mut data.custom_fields);
        data.custom_fields = self
            .custom_fields
            .into_iter()
            .map(|f| {
                Ok(CustomField {
                    name: f.name.trim().to_owned(),
                    value: entry(
                        f.value,
                        f.source,
                        |i| old_fields.get(i).map(|o| o.value.clone()),
                        "a kept custom field needs its source",
                    )?,
                    kind: f.kind,
                })
            })
            .collect::<Result<_>>()?;

        // Applied after the content, which borrows the item.
        let mut password_change = SecretChange::Keep;
        match (self.content, &mut data.content) {
            (
                ContentDraft::Login {
                    username,
                    password,
                    urls,
                    totp: totp_change,
                    backup_codes,
                },
                ItemContent::Login(login),
            ) => {
                password_change = password;
                login.username = text(username);
                login.urls = urls
                    .iter()
                    .filter(|u| !u.trim().is_empty())
                    .map(|u| normalize_url(u))
                    .collect::<lk_vault::Result<Vec<_>>>()?;
                let mut unique = Vec::new();
                for url in core::mem::take(&mut login.urls) {
                    if !unique.contains(&url) {
                        unique.push(url);
                    }
                }
                login.urls = unique;
                login.totp = change_opt(login.totp.take(), totp_change, totp)?;
                login.backup_codes = match backup_codes {
                    ListChange::Keep => core::mem::take(&mut login.backup_codes),
                    ListChange::Set { values } => values
                        .into_iter()
                        .map(|v| v.trim().to_owned())
                        .filter(|v| !v.is_empty())
                        .map(SecretString::new)
                        .collect(),
                    ListChange::Clear => Vec::new(),
                };
            }
            (ContentDraft::SecureNote {}, ItemContent::SecureNote(_)) => {}
            (
                ContentDraft::PaymentCard {
                    cardholder_name,
                    number,
                    expiry_month,
                    expiry_year,
                    security_code,
                    pin,
                    billing_address,
                },
                ItemContent::PaymentCard(card),
            ) => {
                card.cardholder_name = text(cardholder_name);
                card.number = change_opt(card.number.take(), number, card_number)?;
                card.expiry_month = expiry_month;
                card.expiry_year = expiry_year;
                card.security_code = change_opt(card.security_code.take(), security_code, plain)?;
                card.pin = change_opt(card.pin.take(), pin, plain)?;
                card.billing_address = address(billing_address);
            }
            (
                ContentDraft::Identity {
                    honorific,
                    first_name,
                    middle_name,
                    last_name,
                    birth_date,
                    email,
                    phone,
                    company,
                    address: identity_address,
                    documents,
                },
                ItemContent::Identity(identity),
            ) => {
                identity.honorific = text(honorific);
                identity.first_name = text(first_name);
                identity.middle_name = text(middle_name);
                identity.last_name = text(last_name);
                identity.birth_date = text(birth_date);
                identity.email = text(email);
                identity.phone = text(phone);
                identity.company = text(company);
                identity.address = address(identity_address);
                let old_documents = core::mem::take(&mut identity.documents);
                identity.documents = documents
                    .into_iter()
                    .map(|d| {
                        Ok(IdentityDocument {
                            kind: d.kind,
                            number: entry(
                                d.number,
                                d.source,
                                |i| old_documents.get(i).map(|o| o.number.clone()),
                                "a kept document needs its source",
                            )?,
                            issuing_country: text(d.issuing_country).map(|c| c.to_uppercase()),
                            expiry_date: text(d.expiry_date),
                        })
                    })
                    .collect::<Result<_>>()?;
            }
            _ => return Err(ClientError::WrongItemType),
        }
        apply_password(data, password_change, now_unix, existing)?;
        data.updated_at = data.updated_at.max(now_unix);
        data.validate()?;
        Ok(())
    }
}

fn current_password(data: &ItemData) -> Option<&SecretString> {
    match &data.content {
        ItemContent::Login(l) => l.password.as_ref().filter(|p| !p.is_empty()),
        _ => None,
    }
}

/// Password change of a login. On an existing item, a replaced or removed
/// password goes to the history (through [`ItemData::change_password`]).
fn apply_password(
    data: &mut ItemData,
    change: SecretChange,
    now_unix: u64,
    existing: bool,
) -> Result<()> {
    let change = match change {
        SecretChange::Set { value } if value.is_empty() => SecretChange::Clear,
        other => other,
    };
    match change {
        SecretChange::Keep => {}
        SecretChange::Set { value } => {
            if !existing {
                if let ItemContent::Login(l) = &mut data.content {
                    l.password = Some(SecretString::new(value));
                }
            } else if current_password(data).map(SecretString::expose) != Some(value.as_str()) {
                data.change_password(SecretString::new(value), now_unix)?;
            }
        }
        SecretChange::Clear => {
            if existing && current_password(data).is_some() {
                // Moves the removed password to the history.
                data.change_password(SecretString::new(""), now_unix)?;
            }
            if let ItemContent::Login(l) = &mut data.content {
                l.password = None;
            }
        }
    }
    Ok(())
}
