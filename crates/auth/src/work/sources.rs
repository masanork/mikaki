//! Registered source metadata is an operator/verified-Git capability, never an
//! owner upload. Owner/access/head authority stays in the OP's primary store.
use super::*;
use serde_json::{Value, json};

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceInput {
    pub source_id: String,
    pub source_revision: u64,
    pub role: String,
    pub label: String,
    pub repo_name: String,
    pub commit: String,
    pub tree: String,
    pub files: Vec<SourceFile>,
    pub code: Option<SourceCode>,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceFile {
    pub path: String,
    pub blob: String,
    pub mode: String,
    pub bytes: u64,
    pub sha256: Digest,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceCode {
    pub commits: u64,
    pub history_digest: Digest,
    pub objects: u64,
    pub object_bytes: u64,
    pub head_files: u64,
}
#[derive(Debug, Serialize)]
pub struct RegisteredSource {
    data: SourceInput,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    data: SourceInput,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceReadInput {
    pub format_version: u8,
    pub source_id: String,
    pub source_revision: u64,
    pub access_revision: u64,
    pub paths: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    format_version: u8,
    source_id: String,
    source_revision: u64,
    commit: String,
    tree: String,
    files: Vec<ReplyFile>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplyFile {
    path: String,
    blob: String,
    content: String,
}

fn sha1(value: &str) -> Result<(), Denied> {
    if git_oid(value)?.len() != 40 {
        return Err(Denied::InvalidInput);
    }
    Ok(())
}
impl RegisteredSource {
    pub fn from_verified_git(data: SourceInput) -> Result<Self, Denied> {
        data.validate()?;
        let source = Self { data };
        source.authority_record()?;
        Ok(source)
    }
    pub fn restore_authority_record(body: &str) -> Result<Self, Denied> {
        let stored: Stored = records::decode("source", body)?;
        stored.data.validate()?;
        Ok(Self { data: stored.data })
    }
    pub fn authority_record(&self) -> Result<String, Denied> {
        records::encode("source", self)
    }
    pub fn id(&self) -> &str {
        &self.data.source_id
    }
    pub fn revision(&self) -> u64 {
        self.data.source_revision
    }
    pub(super) fn facts(&self) -> &SourceInput {
        &self.data
    }
    pub fn metadata(&self) -> Value {
        json!({"source_id":self.id(),"source_revision":self.revision(),"role":self.data.role,
            "label":self.data.label,"commit":self.data.commit,"tree":self.data.tree,"files":self.data.files,"code":self.data.code})
    }
    fn selected<'a>(&'a self, i: &SourceReadInput) -> Result<Vec<&'a SourceFile>, Denied> {
        if i.format_version != 1
            || i.source_id != self.id()
            || i.source_revision != self.revision()
            || self.data.role == "code"
            || i.paths.is_empty()
            || i.paths.len() > 32
            || !i.paths.windows(2).all(|w| w[0] < w[1])
        {
            return Err(Denied::InvalidInput);
        }
        stored_number(i.access_revision, false)?;
        let selected: Vec<_> = i
            .paths
            .iter()
            .map(|path| {
                self.data
                    .files
                    .iter()
                    .find(|f| &f.path == path)
                    .ok_or(Denied::BindingMismatch)
            })
            .collect::<Result<_, _>>()?;
        if selected.iter().map(|f| f.bytes).sum::<u64>() > 131072 {
            return Err(Denied::InvalidInput);
        }
        Ok(selected)
    }
    /// No owner/session/credential facts cross this private service boundary.
    pub fn service_request(&self, i: &SourceReadInput) -> Result<String, Denied> {
        let files = self.selected(i)?;
        Ok(json!({"format_version":1,"source_id":self.id(),"source_revision":self.revision(),
            "repo_name":self.data.repo_name,"commit":self.data.commit,"tree":self.data.tree,"files":files}).to_string())
    }
    /// Repeat content verification natively against the registered Git receipt.
    /// A source adapter response is data, never an allow decision.
    pub fn verify_reply(&self, i: &SourceReadInput, body: &str) -> Result<Value, Denied> {
        let selected = self.selected(i)?;
        if body.len() > 393216 {
            return Err(Denied::InvalidInput);
        }
        let r: Reply = serde_json::from_str(body).map_err(|_| Denied::InvalidInput)?;
        if r.format_version != 1
            || r.source_id != self.id()
            || r.source_revision != self.revision()
            || r.commit != self.data.commit
            || r.tree != self.data.tree
            || r.files.len() != selected.len()
        {
            return Err(Denied::BindingMismatch);
        }
        let mut files = Vec::new();
        for (expected, received) in selected.iter().zip(r.files) {
            if received.path != expected.path
                || received.blob != expected.blob
                || received.content.len() as u64 != expected.bytes
                || Digest::from_bytes(Sha256::digest(received.content.as_bytes()).into())
                    != expected.sha256
                || received
                    .content
                    .chars()
                    .any(|c| c.is_control() && !matches!(c, '\n' | '\t' | '\r'))
                || received
                    .content
                    .starts_with("version https://git-lfs.github.com/spec/v1\n")
            {
                return Err(Denied::BindingMismatch);
            }
            files.push(
                json!({"path":expected.path,"blob":expected.blob,"mode":expected.mode,
                "bytes":expected.bytes,"sha256":expected.sha256,"content":received.content}),
            );
        }
        Ok(json!({"source":self.metadata(),"access_revision":i.access_revision,"files":files}))
    }
}
impl SourceInput {
    fn validate(&self) -> Result<(), Denied> {
        Id::parse(&self.source_id)?;
        stored_number(self.source_revision, false)?;
        if !matches!(self.role.as_str(), "code" | "personal" | "project")
            || self.label.is_empty()
            || self.label.len() > 160
            || self.label.chars().any(char::is_control)
            || self.repo_name.is_empty()
            || self.repo_name.len() > 64
            || !self
                .repo_name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-_".contains(&b))
            || !self.repo_name.as_bytes()[0].is_ascii_alphanumeric()
            || self.files.len() > 64
            || !self.files.windows(2).all(|w| w[0].path < w[1].path)
        {
            return Err(Denied::InvalidInput);
        }
        sha1(&self.commit)?;
        sha1(&self.tree)?;
        for f in &self.files {
            disclosure::path(&f.path)?;
            sha1(&f.blob)?;
            if f.bytes > 16384 || !matches!(f.mode.as_str(), "100644" | "100755") {
                return Err(Denied::InvalidInput);
            }
        }
        match (&self.code, self.role.as_str()) {
            (Some(c), "code")
                if self.files.is_empty()
                    && c.commits > 0
                    && c.commits <= 4096
                    && c.objects >= c.commits
                    && c.objects <= 65536
                    && c.object_bytes <= 67108864
                    && c.head_files <= 8192 =>
            {
                Ok(())
            }
            (None, "personal" | "project") if !self.files.is_empty() => Ok(()),
            _ => Err(Denied::InvalidInput),
        }
    }
}
