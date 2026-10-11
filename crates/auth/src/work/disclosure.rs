//! Selected text snapshots. Git ancestry/object existence and source access are
//! verified by the trusted Git adapter, not by parsing this closed input schema.
use super::*;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitDisclosureInput {
    pub code: GitCodeInput,
    pub contexts: Vec<GitContextInput>,
    pub snapshot: GitSnapshotInput,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitCodeInput {
    pub repository: String,
    pub commit: String,
    pub tree: String,
    pub commits: Vec<String>,
    pub objects: u64,
    pub object_bytes: u64,
    pub head_files: u64,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitContextInput {
    pub repository: String,
    pub commit: String,
    pub tree: String,
    pub files: Vec<GitFileInput>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitFileInput {
    pub path: String,
    pub blob: String,
    pub mode: String,
    pub content: String,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitSnapshotInput {
    pub repository: String,
    pub commit: String,
    pub tree: String,
    pub parents: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Code {
    repository: Id,
    commit: String,
    tree: String,
    commits: u64,
    history_digest: Digest,
    objects: u64,
    object_bytes: u64,
    head_files: u64,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Context {
    repository: Id,
    commit: String,
    tree: String,
    files: Vec<File>,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    path: String,
    snapshot_path: String,
    blob: String,
    mode: String,
    bytes: u64,
    sha256: Digest,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    repository: Id,
    commit: String,
    tree: String,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Data {
    #[serde(default = "legacy_version", skip_serializing_if = "is_legacy")]
    format_version: u8,
    owner: Id,
    owner_epoch: u64,
    policy_revision: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    policy_projection: Option<Digest>,
    recipient: Id,
    workload: Id,
    expires_at: u64,
    code: Code,
    contexts: Vec<Context>,
    snapshot: Snapshot,
    selected_bytes: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    registered_sources: Vec<SourceBinding>,
}
fn legacy_version() -> u8 {
    1
}
fn is_legacy(version: &u8) -> bool {
    *version == 1
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceBinding {
    source_id: Id,
    source_revision: u64,
    access_revision: u64,
    role: String,
}
#[derive(Debug, Serialize)]
pub struct ResolvedDisclosure {
    data: Data,
    digest: Digest,
}
/// Trusted Native adapter inputs, including opaque verified selections.
pub struct RegisteredDisclosureInput<'a> {
    pub code: &'a RegisteredSource,
    pub code_access_revision: u64,
    pub contexts: &'a [VerifiedSourceSelection<'a>],
    pub snapshot_repository: &'a str,
    pub recipient: &'a str,
    pub workload: &'a str,
    pub expires_at: u64,
    pub policy_projection: Digest,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    data: Data,
    digest: Digest,
}

pub(super) fn path(value: &str) -> Result<(), Denied> {
    if value.is_empty()
        || value.len() > 256
        || value.chars().any(|c| c.is_control() || c == '\\')
        || value.split('/').any(|p| {
            p.is_empty() || p == "." || p == ".." || p.to_ascii_lowercase().starts_with(".git")
        })
    {
        return Err(Denied::InvalidInput);
    }
    Ok(())
}
fn oid(value: &str, length: usize) -> Result<(), Denied> {
    if git_oid(value)?.len() != length {
        return Err(Denied::InvalidInput);
    }
    Ok(())
}
impl ResolvedDisclosure {
    /// Native selected-source capability only. Code history comes from the
    /// trusted registration; context content has been rehashed by verify_selection.
    /// No owner DTO supplies Git facts, history, snapshot IDs or destinations.
    pub fn from_registered_selection(
        input: RegisteredDisclosureInput<'_>,
        session: &OwnerSession,
        environment: &Environment<'_>,
    ) -> Result<Self, Denied> {
        let RegisteredDisclosureInput {
            code,
            code_access_revision,
            contexts,
            snapshot_repository,
            recipient,
            workload,
            expires_at,
            policy_projection,
        } = input;
        session.check(environment)?;
        deadline(environment.now, expires_at, MAX_WORK_SECONDS)?;
        if expires_at > session.expires_at || contexts.len() > 4 {
            return Err(Denied::InvalidInput);
        }
        let c = code.facts();
        let history = c.code.as_ref().ok_or(Denied::BindingMismatch)?;
        if c.role != "code" {
            return Err(Denied::BindingMismatch);
        }
        stored_number(code_access_revision, false)?;
        let mut registered = vec![SourceBinding {
            source_id: Id::parse(code.id())?,
            source_revision: code.revision(),
            access_revision: code_access_revision,
            role: "code".into(),
        }];
        let mut selected = Vec::new();
        let mut snapshot_files = Vec::new();
        let mut selected_bytes = 0;
        let mut names = vec![c.repo_name.as_str()];
        for (index, context) in contexts.iter().enumerate() {
            let s = context.source.facts();
            if !matches!(s.role.as_str(), "personal" | "project")
                || names.contains(&s.repo_name.as_str())
            {
                return Err(Denied::BindingMismatch);
            }
            names.push(&s.repo_name);
            let mut files = Vec::new();
            for f in &context.files {
                let snapshot_path = format!("context/{index:02}/{}", f.path);
                snapshot_files.push((snapshot_path.clone(), f.blob.clone()));
                selected_bytes += f.bytes;
                files.push(File {
                    path: f.path.clone(),
                    snapshot_path,
                    blob: f.blob.clone(),
                    mode: f.mode.clone(),
                    bytes: f.bytes,
                    sha256: f.sha256,
                });
            }
            selected.push(Context {
                repository: Id::parse(context.source.id())?,
                commit: s.commit.clone(),
                tree: s.tree.clone(),
                files,
            });
            registered.push(SourceBinding {
                source_id: Id::parse(context.source.id())?,
                source_revision: context.source.revision(),
                access_revision: context.access_revision,
                role: s.role.clone(),
            });
        }
        let (commit, tree) = selected_snapshot::snapshot(&snapshot_files)?;
        let data = Data {
            format_version: 2,
            owner: session.id.clone(),
            owner_epoch: session.epoch,
            policy_revision: environment.policy_revision,
            policy_projection: Some(policy_projection),
            recipient: Id::parse(recipient)?,
            workload: Id::parse(workload)?,
            expires_at,
            code: Code {
                repository: Id::parse(code.id())?,
                commit: c.commit.clone(),
                tree: c.tree.clone(),
                commits: history.commits,
                history_digest: history.history_digest,
                objects: history.objects,
                object_bytes: history.object_bytes,
                head_files: history.head_files,
            },
            contexts: selected,
            snapshot: Snapshot {
                repository: Id::parse(snapshot_repository)?,
                commit,
                tree,
            },
            selected_bytes,
            registered_sources: registered,
        };
        data.validate()?;
        let disclosure = Self {
            digest: data.digest(),
            data,
        };
        disclosure.authority_record()?;
        Ok(disclosure)
    }
    pub(super) fn preparation_binding(&self) -> Result<preparation::Binding, Denied> {
        self.require_registered_sources()?;
        Ok(preparation::Binding {
            owner: self.data.owner.clone(),
            owner_epoch: self.data.owner_epoch,
            policy_revision: self.data.policy_revision,
            policy_projection: self.data.policy_projection.ok_or(Denied::BindingMismatch)?,
            disclosure: self.digest,
            expires_at: self.data.expires_at,
            reserved_bytes: self.data.code.object_bytes + self.data.selected_bytes,
            source_ids: self.source_ids().into_iter().map(str::to_owned).collect(),
            snapshot_repository: self.data.snapshot.repository.clone(),
        })
    }
    /// Call only after independently checking exact Git objects/ancestry and
    /// owner source access. This is not an HTTP-upload or signature verifier.
    pub fn from_verified_git(
        input: GitDisclosureInput,
        recipient: &str,
        workload: &str,
        session: &OwnerSession,
        environment: &Environment<'_>,
        expires_at: u64,
    ) -> Result<Self, Denied> {
        session.check(environment)?;
        deadline(environment.now, expires_at, MAX_WORK_SECONDS)?;
        let code = input.code;
        let length = git_oid(&code.commit)?.len();
        oid(&code.tree, length)?;
        if code.commits.is_empty()
            || code.commits.len() > 4096
            || !code.commits.iter().any(|c| c == &code.commit)
            || !code.commits.windows(2).all(|w| w[0] < w[1])
        {
            return Err(Denied::InvalidInput);
        }
        let mut history = Sha256::new();
        for commit in &code.commits {
            oid(commit, length)?;
            history.update(commit.as_bytes());
            history.update(b"\n");
        }
        if !input.snapshot.parents.is_empty()
            || input.contexts.len() > 4
            || input.contexts.iter().map(|c| c.files.len()).sum::<usize>() > 32
        {
            return Err(Denied::InvalidInput);
        }
        let mut contexts = Vec::new();
        let mut selected_bytes = 0;
        for (index, context) in input.contexts.into_iter().enumerate() {
            let mut files = Vec::new();
            for file in context.files {
                let bytes = file.content.len() as u64;
                if bytes > 16384
                    || file
                        .content
                        .chars()
                        .any(|c| c.is_control() && !matches!(c, '\n' | '\t' | '\r'))
                    || file
                        .content
                        .starts_with("version https://git-lfs.github.com/spec/v1\n")
                {
                    return Err(Denied::InvalidInput);
                }
                selected_bytes += bytes;
                files.push(File {
                    snapshot_path: format!("context/{index:02}/{}", file.path),
                    path: file.path,
                    blob: file.blob,
                    mode: file.mode,
                    bytes,
                    sha256: Digest::from_bytes(Sha256::digest(file.content.as_bytes()).into()),
                });
            }
            contexts.push(Context {
                repository: Id::parse(&context.repository)?,
                commit: context.commit,
                tree: context.tree,
                files,
            });
        }
        let data = Data {
            format_version: 1,
            owner: session.id.clone(),
            owner_epoch: session.epoch,
            policy_revision: environment.policy_revision,
            policy_projection: None,
            recipient: Id::parse(recipient)?,
            workload: Id::parse(workload)?,
            expires_at,
            code: Code {
                repository: Id::parse(&code.repository)?,
                commit: code.commit,
                tree: code.tree,
                commits: code.commits.len() as u64,
                history_digest: Digest::from_bytes(history.finalize().into()),
                objects: code.objects,
                object_bytes: code.object_bytes,
                head_files: code.head_files,
            },
            contexts,
            snapshot: Snapshot {
                repository: Id::parse(&input.snapshot.repository)?,
                commit: input.snapshot.commit,
                tree: input.snapshot.tree,
            },
            selected_bytes,
            registered_sources: Vec::new(),
        };
        let disclosure = Self {
            digest: data.digest(),
            data,
        };
        disclosure.data.validate()?;
        disclosure.authority_record()?;
        Ok(disclosure)
    }
    /// Upgrade verified Git facts with OP-resolved current registration/access.
    /// Access revisions are trusted primary-store facts, not owner body claims.
    /// The store must repeat these mutable guards in its commit transaction.
    pub fn bind_registered_sources(
        mut self,
        sources: &[(&RegisteredSource, u64)],
        policy_projection: Digest,
    ) -> Result<Self, Denied> {
        if self.data.format_version != 1 || sources.len() != 1 + self.data.contexts.len() {
            return Err(Denied::BindingMismatch);
        }
        for (index, (registered, access_revision)) in sources.iter().enumerate() {
            stored_number(*access_revision, false)?;
            let s = registered.facts();
            if sources[..index]
                .iter()
                .any(|(other, _)| other.facts().repo_name == s.repo_name)
            {
                return Err(Denied::BindingMismatch);
            }
            if index == 0 {
                let c = &self.data.code;
                let history = s.code.as_ref().ok_or(Denied::BindingMismatch)?;
                if s.source_id != c.repository.0
                    || s.role != "code"
                    || s.commit != c.commit
                    || s.tree != c.tree
                    || history.commits != c.commits
                    || history.history_digest != c.history_digest
                    || history.objects != c.objects
                    || history.object_bytes != c.object_bytes
                    || history.head_files != c.head_files
                {
                    return Err(Denied::BindingMismatch);
                }
            } else {
                let c = &self.data.contexts[index - 1];
                if s.source_id != c.repository.0
                    || !matches!(s.role.as_str(), "personal" | "project")
                    || s.commit != c.commit
                    || s.tree != c.tree
                    || c.files.iter().any(|file| {
                        !s.files.iter().any(|f| {
                            f.path == file.path
                                && f.blob == file.blob
                                && f.mode == file.mode
                                && f.bytes == file.bytes
                                && f.sha256 == file.sha256
                        })
                    })
                {
                    return Err(Denied::BindingMismatch);
                }
            }
            self.data.registered_sources.push(SourceBinding {
                source_id: Id::parse(registered.id())?,
                source_revision: registered.revision(),
                access_revision: *access_revision,
                role: s.role.clone(),
            });
        }
        self.data.format_version = 2;
        self.data.policy_projection = Some(policy_projection);
        self.data.validate()?;
        self.digest = self.data.digest();
        self.authority_record()?;
        Ok(self)
    }
    pub fn source_ids(&self) -> Vec<&str> {
        std::iter::once(self.data.code.repository.0.as_str())
            .chain(self.data.contexts.iter().map(|c| c.repository.0.as_str()))
            .collect()
    }
    pub fn require_registered_sources(&self) -> Result<(), Denied> {
        if self.data.format_version != 2 {
            return Err(Denied::BindingMismatch);
        }
        Ok(())
    }
    pub fn digest(&self) -> Digest {
        self.digest
    }
    pub fn owner_id(&self) -> &str {
        &self.data.owner.0
    }
    pub fn expires_at(&self) -> u64 {
        self.data.expires_at
    }
    pub fn selected_bytes(&self) -> u64 {
        self.data.selected_bytes
    }
    pub fn review(&self) -> impl Serialize + '_ {
        &self.data
    }
    pub fn authority_record(&self) -> Result<String, Denied> {
        records::encode("disclosure", self)
    }
    pub fn restore_authority_record(body: &str) -> Result<Self, Denied> {
        let stored: Stored = records::decode("disclosure", body)?;
        stored.data.validate()?;
        if stored.digest != stored.data.digest() {
            return Err(Denied::ReviewMismatch);
        }
        Ok(Self {
            data: stored.data,
            digest: stored.digest,
        })
    }
    pub fn check_request(
        &self,
        request: &WorkRequest,
        environment: &Environment<'_>,
    ) -> Result<(), Denied> {
        environment.check_owner(&self.data.owner, self.data.owner_epoch)?;
        request.check(environment)?;
        if environment.policy_revision != self.data.policy_revision {
            return Err(Denied::StalePolicy);
        }
        if environment.now >= self.data.expires_at || request.expires_at() > self.data.expires_at {
            return Err(Denied::Expired);
        }
        self.check_request_binding(request)
    }

    pub(super) fn check_request_binding(&self, request: &WorkRequest) -> Result<(), Denied> {
        let i = request.input();
        if request.owner_id() != self.owner_id()
            || request.owner_epoch != self.data.owner_epoch
            || request.policy_revision != self.data.policy_revision
            || request.expires_at() > self.data.expires_at
            || i.disclosure_digest != self.digest.to_hex()
            || i.code_repository != self.data.code.repository.0
            || i.base_commit != self.data.code.commit
            || i.recipient != self.data.recipient.0
            || i.workload != self.data.workload.0
            || [i.task_repository.as_str(), i.adoption_repository.as_str()]
                .contains(&self.data.snapshot.repository.0.as_str())
        {
            return Err(Denied::BindingMismatch);
        }
        Ok(())
    }
}
impl Data {
    fn validate(&self) -> Result<(), Denied> {
        match self.format_version {
            1 if self.registered_sources.is_empty() && self.policy_projection.is_none() => {}
            2 if self.registered_sources.len() == 1 + self.contexts.len()
                && self.policy_projection.is_some() =>
            {
                for (index, source) in self.registered_sources.iter().enumerate() {
                    stored_number(source.source_revision, false)?;
                    stored_number(source.access_revision, false)?;
                    let id = if index == 0 {
                        &self.code.repository
                    } else {
                        &self.contexts[index - 1].repository
                    };
                    if &source.source_id != id
                        || if index == 0 {
                            source.role != "code"
                        } else {
                            !matches!(source.role.as_str(), "personal" | "project")
                        }
                    {
                        return Err(Denied::InvalidInput);
                    }
                }
            }
            _ => return Err(Denied::InvalidInput),
        }
        stored_number(self.owner_epoch, true)?;
        stored_number(self.policy_revision, false)?;
        stored_number(self.expires_at, false)?;
        let length = git_oid(&self.code.commit)?.len();
        oid(&self.code.tree, length)?;
        oid(&self.snapshot.commit, length)?;
        oid(&self.snapshot.tree, length)?;
        if self.code.commits == 0
            || self.code.commits > 4096
            || self.code.objects < self.code.commits
            || self.code.objects > 65536
            || self.code.object_bytes > 67108864
            || self.code.head_files > 8192
            || self.code.repository == self.snapshot.repository
            || self.contexts.len() > 4
            || !self
                .contexts
                .windows(2)
                .all(|w| w[0].repository.0 < w[1].repository.0)
        {
            return Err(Denied::InvalidInput);
        }
        let mut count = 0;
        let mut bytes = 0;
        for (index, context) in self.contexts.iter().enumerate() {
            oid(&context.commit, length)?;
            oid(&context.tree, length)?;
            if context.repository == self.code.repository
                || context.repository == self.snapshot.repository
                || context.files.is_empty()
                || !context.files.windows(2).all(|w| w[0].path < w[1].path)
            {
                return Err(Denied::InvalidInput);
            }
            for file in &context.files {
                path(&file.path)?;
                oid(&file.blob, length)?;
                if file.bytes > 16384
                    || !matches!(file.mode.as_str(), "100644" | "100755")
                    || file.snapshot_path != format!("context/{index:02}/{}", file.path)
                {
                    return Err(Denied::InvalidInput);
                }
                count += 1;
                bytes += file.bytes;
            }
        }
        if count > 32 || bytes > 131072 || bytes != self.selected_bytes {
            return Err(Denied::InvalidInput);
        }
        Ok(())
    }
    fn digest(&self) -> Digest {
        let mut h = Hash::new(if self.format_version == 2 {
            "mikaki.work-disclosure.v2"
        } else {
            "mikaki.work-disclosure.v1"
        });
        h.text(&self.owner.0);
        h.number(self.owner_epoch);
        h.number(self.policy_revision);
        h.text(&self.recipient.0);
        h.text(&self.workload.0);
        h.number(self.expires_at);
        h.text(&self.code.repository.0);
        h.text(&self.code.commit);
        h.text(&self.code.tree);
        h.number(self.code.commits);
        h.bytes(&self.code.history_digest.0);
        h.number(self.code.objects);
        h.number(self.code.object_bytes);
        h.number(self.code.head_files);
        h.number(self.contexts.len() as u64);
        for context in &self.contexts {
            h.text(&context.repository.0);
            h.text(&context.commit);
            h.text(&context.tree);
            h.number(context.files.len() as u64);
            for file in &context.files {
                h.text(&file.path);
                h.text(&file.snapshot_path);
                h.text(&file.blob);
                h.text(&file.mode);
                h.number(file.bytes);
                h.bytes(&file.sha256.0);
            }
        }
        h.text(&self.snapshot.repository.0);
        h.text(&self.snapshot.commit);
        h.text(&self.snapshot.tree);
        h.number(self.selected_bytes);
        if self.format_version == 2 {
            h.number(self.registered_sources.len() as u64);
            for source in &self.registered_sources {
                h.text(&source.source_id.0);
                h.number(source.source_revision);
                h.number(source.access_revision);
                h.text(&source.role);
            }
            if let Some(projection) = self.policy_projection {
                h.bytes(&projection.0);
            }
        }
        h.finish()
    }
}
