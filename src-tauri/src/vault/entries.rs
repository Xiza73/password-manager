//! The credential model and the body encoding that goes inside a sealed vault.
//!
//! Two things shape this module. Secrets are held in a type that wipes itself and refuses to
//! print, so no derived `Debug` and no log line can leak one. And listing is separated from
//! reading: [`VaultData::summaries`] cannot return a password even by mistake, which keeps the
//! whole vault out of the interface's hands when all it needs is a list of sites.

use std::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::secret::SecretString;
use zeroize::Zeroizing;

/// Schema version of the decrypted body.
///
/// Separate from the file format version: that one covers the cryptographic envelope, this one
/// covers what is inside it. They change for different reasons and at different times.
pub const BODY_VERSION: u32 = 1;

/// Slack added to the serialization buffer, in bytes, on top of the per-field estimate.
const CAPACITY_SLACK: usize = 256;

/// Bytes of JSON overhead attributed to one credential: the field names, braces, quotes and
/// commas, plus its identifier.
const OVERHEAD_PER_ENTRY: usize = 128;

/// Worst-case growth of one input byte under JSON string escaping: a control character becomes
/// a six-character `\u00XX` sequence.
const WORST_CASE_ESCAPE: usize = 6;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EntryError {
    #[error("no credential with this identifier")]
    NotFound,
    #[error("a credential needs a site")]
    SiteRequired,
    #[error("the vault contents are malformed")]
    Malformed,
    #[error(
        "these vault contents were written by a newer version of the application (schema {0})"
    )]
    UnsupportedBodyVersion(u32),
}

/// Stable identifier for a credential.
///
/// Random rather than sequential: a counter collides after a restore from backup, and the
/// resulting silent overwrite of one entry by another is not a failure anyone would notice.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EntryId(Uuid);

impl EntryId {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl fmt::Display for EntryId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// The fields a caller supplies when creating or editing a credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialDraft {
    pub site: String,
    pub username: String,
    pub password: SecretString,
    pub notes: SecretString,
}

/// A stored credential.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Credential {
    id: EntryId,
    site: String,
    username: String,
    password: SecretString,
    // Recovery codes and backup keys end up here, so notes are treated as secret too.
    notes: SecretString,
}

impl Credential {
    pub fn id(&self) -> EntryId {
        self.id
    }

    pub fn site(&self) -> &str {
        &self.site
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn password(&self) -> &SecretString {
        &self.password
    }

    pub fn notes(&self) -> &SecretString {
        &self.notes
    }

    fn summary(&self) -> CredentialSummary {
        CredentialSummary {
            id: self.id,
            site: self.site.clone(),
            username: self.username.clone(),
        }
    }
}

impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Hand-written rather than derived, because a derived `Debug` here would print the
        // password the moment anyone logs a credential.
        f.debug_struct("Credential")
            .field("id", &self.id)
            .field("site", &self.site)
            .field("username", &self.username)
            .field("password", &self.password)
            .field("notes", &self.notes)
            .finish()
    }
}

/// What a credential looks like to anything that only needs to list or search.
///
/// There is no password on this type, and that is the point: the interface can hold a list of
/// every entry in the vault without a single secret crossing into it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialSummary {
    pub id: EntryId,
    pub site: String,
    pub username: String,
}

/// The decrypted contents of a vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultData {
    version: u32,
    entries: Vec<Credential>,
}

impl VaultData {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            version: BODY_VERSION,
            entries: Vec::new(),
        }
    }

    pub fn summaries(&self) -> Vec<CredentialSummary> {
        self.entries.iter().map(Credential::summary).collect()
    }

    pub fn get(&self, id: EntryId) -> Result<&Credential, EntryError> {
        self.entries
            .iter()
            .find(|entry| entry.id == id)
            .ok_or(EntryError::NotFound)
    }

    pub fn add(&mut self, draft: CredentialDraft) -> Result<EntryId, EntryError> {
        let site = validated_site(&draft.site)?;
        let id = EntryId::new();

        self.entries.push(Credential {
            id,
            site,
            username: draft.username,
            password: draft.password,
            notes: draft.notes,
        });

        Ok(id)
    }

    pub fn update(&mut self, id: EntryId, draft: CredentialDraft) -> Result<(), EntryError> {
        let site = validated_site(&draft.site)?;
        let entry = self
            .entries
            .iter_mut()
            .find(|entry| entry.id == id)
            .ok_or(EntryError::NotFound)?;

        entry.site = site;
        entry.username = draft.username;
        entry.password = draft.password;
        entry.notes = draft.notes;

        Ok(())
    }

    pub fn remove(&mut self, id: EntryId) -> Result<(), EntryError> {
        let before = self.entries.len();
        self.entries.retain(|entry| entry.id != id);

        if self.entries.len() == before {
            return Err(EntryError::NotFound);
        }

        Ok(())
    }

    /// Filters by site or username. Never by password: matching on secrets would let anyone at
    /// an unlocked screen confirm a guessed password by typing it into the search box.
    pub fn search(&self, query: &str) -> Vec<CredentialSummary> {
        let needle = query.trim().to_lowercase();

        self.entries
            .iter()
            .filter(|entry| {
                needle.is_empty()
                    || entry.site.to_lowercase().contains(&needle)
                    || entry.username.to_lowercase().contains(&needle)
            })
            .map(Credential::summary)
            .collect()
    }

    /// Upper bound on the serialized length.
    ///
    /// Deliberately generous. Being wrong low costs a reallocation, and a reallocation abandons
    /// a copy of every password in the vault in a freed heap block that nothing can reach.
    pub fn capacity_estimate(&self) -> usize {
        let content: usize = self
            .entries
            .iter()
            .map(|entry| {
                entry.site.len()
                    + entry.username.len()
                    + entry.password.expose().len()
                    + entry.notes.expose().len()
            })
            .sum();

        CAPACITY_SLACK + self.entries.len() * OVERHEAD_PER_ENTRY + content * WORST_CASE_ESCAPE
    }

    /// Serializes the vault contents for sealing.
    ///
    /// The buffer is sized up front and returned inside `Zeroizing`, so the plaintext lives in
    /// exactly one allocation and that allocation is wiped.
    pub fn to_bytes(&self) -> Result<Zeroizing<Vec<u8>>, EntryError> {
        let mut buffer = Zeroizing::new(Vec::with_capacity(self.capacity_estimate()));

        serde_json::to_writer(&mut *buffer, self).map_err(|_| EntryError::Malformed)?;

        Ok(buffer)
    }

    /// Parses vault contents that have already been decrypted and authenticated.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EntryError> {
        let data: Self = serde_json::from_slice(bytes).map_err(|_| EntryError::Malformed)?;

        if data.version != BODY_VERSION {
            return Err(EntryError::UnsupportedBodyVersion(data.version));
        }

        Ok(data)
    }
}

fn validated_site(site: &str) -> Result<String, EntryError> {
    let trimmed = site.trim();

    if trimmed.is_empty() {
        return Err(EntryError::SiteRequired);
    }

    Ok(trimmed.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn draft(site: &str, username: &str, password: &str) -> CredentialDraft {
        CredentialDraft {
            site: site.to_owned(),
            username: username.to_owned(),
            password: SecretString::new(password.to_owned()),
            notes: SecretString::new(String::new()),
        }
    }

    fn populated() -> VaultData {
        let mut data = VaultData::new();
        data.add(draft("github.com", "octocat", "hunter2")).unwrap();
        data.add(draft("GitLab.com", "tanuki", "correct-horse"))
            .unwrap();
        data
    }

    #[test]
    fn starts_empty() {
        assert!(VaultData::new().summaries().is_empty());
    }

    #[test]
    fn stores_an_added_credential() {
        let mut data = VaultData::new();

        let id = data.add(draft("github.com", "octocat", "hunter2")).unwrap();
        let stored = data.get(id).unwrap();

        assert_eq!(stored.site(), "github.com");
        assert_eq!(stored.username(), "octocat");
        assert_eq!(stored.password().expose(), "hunter2");
    }

    #[test]
    fn assigns_a_distinct_id_to_every_credential() {
        let mut data = VaultData::new();

        let first = data.add(draft("a.com", "u", "p")).unwrap();
        let second = data.add(draft("a.com", "u", "p")).unwrap();

        assert_ne!(first, second);
    }

    #[test]
    fn reports_an_unknown_credential() {
        let data = populated();

        assert_eq!(data.get(EntryId::new()).unwrap_err(), EntryError::NotFound);
    }

    #[test]
    fn updates_a_credential_in_place() {
        let mut data = VaultData::new();
        let id = data.add(draft("github.com", "octocat", "hunter2")).unwrap();

        data.update(id, draft("github.com", "octocat", "rotated"))
            .unwrap();

        assert_eq!(data.get(id).unwrap().password().expose(), "rotated");
        assert_eq!(data.summaries().len(), 1);
    }

    #[test]
    fn refuses_to_update_an_unknown_credential() {
        let mut data = populated();

        let result = data.update(EntryId::new(), draft("a.com", "u", "p"));

        assert_eq!(result.unwrap_err(), EntryError::NotFound);
    }

    #[test]
    fn removes_a_credential() {
        let mut data = VaultData::new();
        let id = data.add(draft("github.com", "octocat", "hunter2")).unwrap();

        data.remove(id).unwrap();

        assert_eq!(data.get(id).unwrap_err(), EntryError::NotFound);
        assert!(data.summaries().is_empty());
    }

    #[test]
    fn refuses_to_remove_an_unknown_credential() {
        let mut data = populated();

        assert_eq!(
            data.remove(EntryId::new()).unwrap_err(),
            EntryError::NotFound
        );
    }

    #[test]
    fn rejects_a_credential_without_a_site() {
        let mut data = VaultData::new();

        assert_eq!(
            data.add(draft("", "octocat", "hunter2")).unwrap_err(),
            EntryError::SiteRequired
        );
        assert_eq!(
            data.add(draft("   ", "octocat", "hunter2")).unwrap_err(),
            EntryError::SiteRequired
        );
    }

    #[test]
    fn accepts_a_credential_without_a_username_or_password() {
        // Plenty of real entries are a site and a note, or an API key with no user.
        let mut data = VaultData::new();

        assert!(data.add(draft("example.com", "", "")).is_ok());
    }

    #[test]
    fn summaries_describe_every_credential() {
        let data = populated();

        let sites: Vec<_> = data
            .summaries()
            .iter()
            .map(|summary| summary.site.clone())
            .collect();

        assert_eq!(sites, vec!["github.com", "GitLab.com"]);
    }

    #[test]
    fn searches_the_site_case_insensitively() {
        let data = populated();

        let found = data.search("gitlab");

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].site, "GitLab.com");
    }

    #[test]
    fn searches_the_username() {
        let data = populated();

        let found = data.search("OCTO");

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].username, "octocat");
    }

    #[test]
    fn an_empty_query_returns_everything() {
        assert_eq!(populated().search("  ").len(), 2);
    }

    #[test]
    fn a_search_never_matches_on_the_password() {
        let data = populated();

        // Matching secrets would let anyone at an unlocked screen confirm a guess by typing it.
        assert!(data.search("hunter2").is_empty());
    }

    #[test]
    fn secret_debug_output_carries_no_secret() {
        let first = SecretString::new("hunter2".to_owned());
        let second = SecretString::new("a completely different secret".to_owned());

        assert_eq!(format!("{first:?}"), format!("{second:?}"));
    }

    #[test]
    fn credential_debug_output_carries_no_secret() {
        let mut data = VaultData::new();
        let id = data.add(draft("github.com", "octocat", "hunter2")).unwrap();

        let rendered = format!("{:?}", data.get(id).unwrap());

        assert!(rendered.contains("github.com"));
        assert!(!rendered.contains("hunter2"));
    }

    #[test]
    fn round_trips_through_bytes() {
        let data = populated();

        let restored = VaultData::from_bytes(&data.to_bytes().unwrap()).unwrap();

        assert_eq!(restored, data);
    }

    #[test]
    fn round_trips_an_empty_vault() {
        let data = VaultData::new();

        let restored = VaultData::from_bytes(&data.to_bytes().unwrap()).unwrap();

        assert_eq!(restored, data);
    }

    #[test]
    fn round_trips_awkward_content() {
        let mut data = VaultData::new();
        data.add(draft(
            "sitio.español.com",
            "usuario\"con\\comillas",
            "línea1\nlínea2\ttab\u{0}nul",
        ))
        .unwrap();

        let restored = VaultData::from_bytes(&data.to_bytes().unwrap()).unwrap();

        assert_eq!(restored, data);
    }

    #[test]
    fn rejects_malformed_bytes() {
        assert_eq!(
            VaultData::from_bytes(b"not json at all").unwrap_err(),
            EntryError::Malformed
        );
    }

    #[test]
    fn rejects_an_unsupported_body_version() {
        let body = format!("{{\"version\":{},\"entries\":[]}}", BODY_VERSION + 1);

        assert_eq!(
            VaultData::from_bytes(body.as_bytes()).unwrap_err(),
            EntryError::UnsupportedBodyVersion(BODY_VERSION + 1)
        );
    }

    #[test]
    fn the_serialization_buffer_never_grows() {
        let mut data = VaultData::new();
        // Control characters are the worst case for JSON escaping: one byte in, six bytes out.
        // The content has to be long enough that the escaping dominates the fixed slack, or the
        // assertion holds for a reason that has nothing to do with the estimate being right.
        let worst_case = "\u{1}".repeat(500);
        data.add(draft(&worst_case, &worst_case, &worst_case))
            .unwrap();
        data.add(draft("plain.com", "user", "password")).unwrap();

        let estimate = data.capacity_estimate();
        let actual = data.to_bytes().unwrap().len();

        // A grown buffer means a reallocation, and a reallocation leaves a copy of every
        // password in a freed heap block that nothing can reach to wipe.
        assert!(estimate >= actual, "estimate {estimate} < actual {actual}");
        // Guards the guard: if the fixed slack alone covered the payload, this test would pass
        // no matter how wrong the per-byte factor was.
        assert!(actual > CAPACITY_SLACK + 2 * OVERHEAD_PER_ENTRY);
    }
}
