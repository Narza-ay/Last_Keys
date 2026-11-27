//! Autofill operations (ADR-0011): which logins a page may use, the
//! credentials of one fill, and saving what the user submitted. Every
//! operation re-checks the page's origin against the item with
//! [`lk_autofill`]; callers pass origins reported by the browser, never
//! values read from page content.

use lk_autofill::{MatchKind, Origin, best_match, title_for, url_to_store};
use lk_core::ItemId;
use lk_crypto::Zeroizing;
use lk_vault::{ItemContent, ItemData, Login, SecretString};
use serde::{Serialize, Serializer};

use crate::error::{ClientError, Result};
use crate::vault::Vault;
use crate::view::Field;

/// A login offered on a page (no secret values).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AutofillCandidate {
    /// Item identifier.
    pub id: ItemId,
    /// Title.
    pub title: String,
    /// Username, if any.
    pub username: Option<String>,
    /// How the item's URL relates to the page.
    pub matched: MatchKind,
    /// The item has a password.
    pub has_password: bool,
    /// The item has a TOTP configuration.
    pub has_totp: bool,
    /// Favorite.
    pub favorite: bool,
}

fn secret<S: Serializer>(
    value: &Option<Zeroizing<String>>,
    s: S,
) -> core::result::Result<S::Ok, S::Error> {
    match value {
        Some(v) => s.serialize_some(v.as_str()),
        None => s.serialize_none(),
    }
}

/// What one fill writes into a page.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AutofillCredentials {
    /// Username, if any.
    pub username: Option<String>,
    /// Password, if any.
    #[serde(serialize_with = "secret")]
    pub password: Option<Zeroizing<String>>,
    /// Current TOTP code, if the item has a TOTP configuration.
    #[serde(serialize_with = "secret")]
    pub totp: Option<Zeroizing<String>>,
}

/// What to propose after the user submitted credentials on a page.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum SaveProposal {
    /// No login of this site has this username: save a new one.
    New {
        /// Proposed title (the site's registrable domain).
        title: String,
        /// URL that will be stored (the page's origin).
        url: String,
    },
    /// A login of this site has this username with another password.
    UpdatePassword {
        /// The login to update.
        id: ItemId,
        /// Its title.
        title: String,
    },
    /// The submitted credentials are already stored.
    Unchanged {
        /// The matching login.
        id: ItemId,
    },
}

/// Page and frame of a fill request, as reported by the browser.
#[derive(Clone, Copy, Debug)]
pub struct FillTarget<'a> {
    /// URL of the top-level page.
    pub page_url: &'a str,
    /// URL of the frame that holds the form (the page itself for a
    /// top-level form).
    pub frame_url: &'a str,
    /// The user confirmed filling a frame whose origin differs from the
    /// page's.
    pub cross_origin_confirmed: bool,
}

fn page_origin(url: &str) -> Result<Origin> {
    Origin::parse(url).map_err(|_| ClientError::IneligiblePage)
}

fn login(data: &ItemData) -> Option<&Login> {
    match &data.content {
        ItemContent::Login(l) => Some(l),
        _ => None,
    }
}

fn item_match(data: &ItemData, page_url: &str) -> Result<Option<MatchKind>> {
    let Some(l) = login(data) else {
        return Ok(None);
    };
    best_match(l.urls.iter().map(String::as_str), page_url).map_err(|_| ClientError::IneligiblePage)
}

fn normalized_username(username: Option<&str>) -> String {
    username.unwrap_or_default().trim().to_lowercase()
}

impl Vault {
    /// Logins whose URLs match the top-level page, best matches first
    /// (exact host, then favorites, then title).
    ///
    /// # Errors
    /// [`ClientError::IneligiblePage`] for a page that is not `http` or
    /// `https`; store or decryption errors.
    pub fn autofill_candidates(&self, page_url: &str) -> Result<Vec<AutofillCandidate>> {
        page_origin(page_url)?;
        let mut rows = Vec::new();
        for (stored, data) in self.decrypted()? {
            let (Some(l), Some(matched)) = (login(&data), item_match(&data, page_url)?) else {
                continue;
            };
            rows.push(AutofillCandidate {
                id: stored.item.item_id,
                title: data.title.clone(),
                username: l.username.clone().filter(|u| !u.is_empty()),
                matched,
                has_password: l.password.as_ref().is_some_and(|p| !p.is_empty()),
                has_totp: l.totp.is_some(),
                favorite: data.favorite,
            });
        }
        rows.sort_by(|a, b| {
            b.matched
                .cmp(&a.matched)
                .then(b.favorite.cmp(&a.favorite))
                .then(a.title.to_lowercase().cmp(&b.title.to_lowercase()))
                .then(a.id.cmp(&b.id))
        });
        Ok(rows)
    }

    /// Checks that `id` is a login usable on the target, and returns it.
    fn checked_login(&self, id: &ItemId, target: &FillTarget<'_>) -> Result<ItemData> {
        let page = page_origin(target.page_url)?;
        let frame = page_origin(target.frame_url)?;
        let data = self.item(id)?;
        if login(&data).is_none() {
            return Err(ClientError::WrongItemType);
        }
        if item_match(&data, target.page_url)?.is_none()
            || item_match(&data, target.frame_url)?.is_none()
        {
            return Err(ClientError::OriginMismatch);
        }
        if !same_origin(&frame, &page) && !target.cross_origin_confirmed {
            return Err(ClientError::ConfirmationRequired);
        }
        Ok(data)
    }

    /// The credentials of one fill, after checking that the login matches
    /// both the page and the frame, and that a frame of another origin was
    /// confirmed by the user.
    ///
    /// # Errors
    /// [`ClientError::IneligiblePage`], [`ClientError::OriginMismatch`],
    /// [`ClientError::ConfirmationRequired`], [`ClientError::WrongItemType`],
    /// [`ClientError::ItemNotFound`], TOTP or decryption errors.
    pub fn autofill_credentials(
        &self,
        id: &ItemId,
        target: &FillTarget<'_>,
        now: u64,
    ) -> Result<AutofillCredentials> {
        let data = self.checked_login(id, target)?;
        let Some(l) = login(&data) else {
            return Err(ClientError::WrongItemType);
        };
        let totp = if l.totp.is_some() {
            Some(Zeroizing::new(self.totp(id, now)?.code))
        } else {
            None
        };
        Ok(AutofillCredentials {
            username: l.username.clone().filter(|u| !u.is_empty()),
            password: l
                .password
                .as_ref()
                .filter(|p| !p.is_empty())
                .map(|p| Zeroizing::new(p.expose().to_owned())),
            totp,
        })
    }

    /// One field of a login that matches the page, for a copy made by the
    /// client (username, password or TOTP code only).
    ///
    /// # Errors
    /// As [`Self::autofill_credentials`]; [`ClientError::NoSuchField`] for
    /// another field or an empty one.
    pub fn autofill_field(
        &self,
        id: &ItemId,
        page_url: &str,
        field: Field,
        now: u64,
    ) -> Result<Zeroizing<String>> {
        if !matches!(field, Field::Username | Field::Password | Field::TotpCode) {
            return Err(ClientError::NoSuchField);
        }
        self.checked_login(
            id,
            &FillTarget {
                page_url,
                frame_url: page_url,
                cross_origin_confirmed: false,
            },
        )?;
        self.field_value(id, field, now)
    }

    /// What to propose for credentials submitted on a page.
    ///
    /// # Errors
    /// [`ClientError::IneligiblePage`], [`ClientError::InvalidDraft`] for an
    /// empty password; store or decryption errors.
    pub fn save_proposal(
        &self,
        page_url: &str,
        username: Option<&str>,
        password: &str,
    ) -> Result<SaveProposal> {
        let page = page_origin(page_url)?;
        if password.is_empty() {
            return Err(ClientError::InvalidDraft("the password is empty"));
        }
        let wanted = normalized_username(username);
        let mut best: Option<(MatchKind, ItemId, ItemData)> = None;
        for (stored, data) in self.decrypted()? {
            let Some(l) = login(&data) else { continue };
            if normalized_username(l.username.as_deref()) != wanted {
                continue;
            }
            let Some(matched) = item_match(&data, page_url)? else {
                continue;
            };
            let same_password = l.password.as_ref().is_some_and(|p| p.expose() == password);
            if same_password {
                return Ok(SaveProposal::Unchanged {
                    id: stored.item.item_id,
                });
            }
            if best.as_ref().is_none_or(|(m, _, _)| matched > *m) {
                best = Some((matched, stored.item.item_id, data));
            }
        }
        Ok(match best {
            Some((_, id, data)) => SaveProposal::UpdatePassword {
                id,
                title: data.title,
            },
            None => SaveProposal::New {
                title: title_for(&page),
                url: url_to_store(&page),
            },
        })
    }

    /// Saves submitted credentials: a new login (title and URL from the
    /// page), or a new password for `update`, which must be a login of this
    /// site with this username (its previous password goes to the history).
    ///
    /// # Errors
    /// [`ClientError::IneligiblePage`], [`ClientError::OriginMismatch`] when
    /// `update` does not match the page or the username; validation or store
    /// errors.
    pub fn save_login(
        &mut self,
        page_url: &str,
        username: Option<&str>,
        password: &str,
        update: Option<&ItemId>,
        now: u64,
    ) -> Result<ItemId> {
        let page = page_origin(page_url)?;
        if password.is_empty() {
            return Err(ClientError::InvalidDraft("the password is empty"));
        }
        let username = username.map(str::trim).filter(|u| !u.is_empty());
        if let Some(id) = update {
            let data = self.item(id)?;
            let Some(l) = login(&data) else {
                return Err(ClientError::WrongItemType);
            };
            if item_match(&data, page_url)?.is_none()
                || normalized_username(l.username.as_deref()) != normalized_username(username)
            {
                return Err(ClientError::OriginMismatch);
            }
            let new_password = SecretString::new(password);
            self.update_item(id, now, |data| {
                Ok(data.change_password(new_password, now.max(data.updated_at))?)
            })?;
            return Ok(*id);
        }
        let data = ItemData {
            schema: lk_vault::ITEM_SCHEMA_VERSION,
            title: title_for(&page),
            favorite: false,
            folder: None,
            tags: Vec::new(),
            notes: None,
            custom_fields: Vec::new(),
            created_at: now,
            updated_at: now,
            content: ItemContent::Login(Login {
                username: username.map(str::to_owned),
                password: Some(SecretString::new(password)),
                urls: vec![url_to_store(&page)],
                totp: None,
                backup_codes: Vec::new(),
            }),
            password_history: Vec::new(),
        };
        self.create_item(&data, now)
    }
}

fn same_origin(a: &Origin, b: &Origin) -> bool {
    a.scheme() == b.scheme() && a.host() == b.host() && a.port() == b.port()
}
