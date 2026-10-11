//! Private candidate Git retention receipts. Adapter facts are not CI verdicts.
use super::*;

pub const MAX_CANDIDATE_BUNDLE_BYTES: u64 = 8 * 1024 * 1024;

/// Only the independent Git adapter supplies these facts, never an owner or
/// workload claim. Construction validates shape/binding, not Git object bytes.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateGitFacts {
    pub commit: String,
    pub tree: String,
    pub base_commit: String,
    pub objects: u64,
    pub object_bytes: u64,
    pub inventory_digest: Digest,
    pub bundle_digest: Digest,
    pub bundle_bytes: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Data {
    format: String,
    candidate: Digest,
    request: Digest,
    owner: Id,
    preparation_id: Id,
    preparation_digest: Digest,
    task_repo_id: Id,
    commit: String,
    tree: String,
    base_commit: String,
    objects: u64,
    object_bytes: u64,
    inventory_digest: Digest,
    bundle_digest: Digest,
    bundle_bytes: u64,
}
#[derive(Serialize)]
pub struct CandidatePayload {
    data: Data,
    digest: Digest,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    data: Data,
    digest: Digest,
}
impl CandidatePayload {
    pub fn from_verified_git(
        c: &Candidate,
        request: &WorkRequest,
        preparation: &Preparation,
        task_repo_id: &str,
        facts: CandidateGitFacts,
    ) -> Result<Self, Denied> {
        if c.request_digest() != request.digest()
            || c.owner_id() != preparation.owner_id()
            || request.input().task_repository != preparation.task_repository()
            || request.input().disclosure_digest != preparation.disclosure_digest().to_hex()
            || facts.commit != c.commit()
            || facts.tree != c.tree()
            || facts.base_commit != request.input().base_commit
            || facts.objects == 0
            || facts.objects > 65536
            || facts.object_bytes == 0
            || facts.object_bytes > 67108864
            || facts.bundle_bytes == 0
            || facts.bundle_bytes > MAX_CANDIDATE_BUNDLE_BYTES
        {
            return Err(Denied::BindingMismatch);
        }
        // The first storage/transport profile is self-contained v2/SHA-1.
        // Structural SHA-256 candidate support does not qualify that Git format.
        for oid in [&facts.commit, &facts.tree, &facts.base_commit] {
            if git_oid(oid)?.len() != 40 {
                return Err(Denied::InvalidInput);
            }
        }
        let data = Data {
            format: "git-bundle-v2-sha1".into(),
            candidate: c.digest(),
            request: request.digest(),
            owner: Id::parse(c.owner_id())?,
            preparation_id: Id::parse(preparation.id())?,
            preparation_digest: preparation.digest(),
            task_repo_id: Id::parse(task_repo_id)?,
            commit: facts.commit,
            tree: facts.tree,
            base_commit: facts.base_commit,
            objects: facts.objects,
            object_bytes: facts.object_bytes,
            inventory_digest: facts.inventory_digest,
            bundle_digest: facts.bundle_digest,
            bundle_bytes: facts.bundle_bytes,
        };
        let mut h = Hash::new("mikaki.work-candidate-payload.v1");
        h.bytes(
            serde_json::to_string(&data)
                .map_err(|_| Denied::InvalidInput)?
                .as_bytes(),
        );
        Ok(Self {
            data,
            digest: h.finish(),
        })
    }
    pub fn restore_authority_record(
        body: &str,
        c: &Candidate,
        request: &WorkRequest,
        p: &Preparation,
        task_repo_id: &str,
    ) -> Result<Self, Denied> {
        if body.len() > 4096 {
            return Err(Denied::InvalidInput);
        }
        let raw: Stored = records::decode("candidate_payload", body)?;
        let d = raw.data;
        let restored = Self::from_verified_git(
            c,
            request,
            p,
            task_repo_id,
            CandidateGitFacts {
                commit: d.commit,
                tree: d.tree,
                base_commit: d.base_commit,
                objects: d.objects,
                object_bytes: d.object_bytes,
                inventory_digest: d.inventory_digest,
                bundle_digest: d.bundle_digest,
                bundle_bytes: d.bundle_bytes,
            },
        )?;
        if d.format != restored.data.format
            || d.candidate != c.digest()
            || d.request != request.digest()
            || d.owner.0 != c.owner_id()
            || d.preparation_id.0 != p.id()
            || d.preparation_digest != p.digest()
            || d.task_repo_id.0 != task_repo_id
            || raw.digest != restored.digest
        {
            return Err(Denied::BindingMismatch);
        }
        Ok(restored)
    }
    pub fn authority_record(&self) -> Result<String, Denied> {
        records::encode("candidate_payload", self)
    }
    pub fn digest(&self) -> Digest {
        self.digest
    }
    pub fn candidate_digest(&self) -> Digest {
        self.data.candidate
    }
    pub fn preparation_id(&self) -> &str {
        &self.data.preparation_id.0
    }
    pub fn owner_id(&self) -> &str {
        &self.data.owner.0
    }
    pub fn bundle_bytes(&self) -> u64 {
        self.data.bundle_bytes
    }
    pub fn bundle_digest(&self) -> Digest {
        self.data.bundle_digest
    }
    pub fn object_key(&self) -> String {
        format!(
            "work-candidate/v1/{}/{}/{}.bundle",
            self.data.preparation_digest.to_hex(),
            self.data.candidate.to_hex(),
            self.data.bundle_digest.to_hex()
        )
    }
    pub fn verify_bundle_bytes(&self, bytes: &[u8]) -> Result<(), Denied> {
        if bytes.len() as u64 != self.bundle_bytes()
            || Digest::from_bytes(Sha256::digest(bytes).into()) != self.bundle_digest()
        {
            return Err(Denied::BindingMismatch);
        }
        Ok(())
    }
}
