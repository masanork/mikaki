//! Deterministic, parentless Git snapshot. Git SHA-1 names are object IDs, not
//! authorization digests; disclosure/consent commitments continue to use SHA-256.
use super::Denied;
use sha1::{Digest as _, Sha1};
use std::collections::BTreeMap;

pub(super) fn object(kind: &str, bytes: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(format!("{kind} {}\0", bytes.len()));
    h.update(bytes);
    h.finalize().into()
}
pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
#[derive(Default)]
struct Tree(BTreeMap<String, Entry>);
enum Entry {
    Blob([u8; 20]),
    Tree(Tree),
}
impl Tree {
    fn insert(&mut self, path: &[&str], blob: [u8; 20]) -> Result<(), Denied> {
        let (head, rest) = path.split_first().ok_or(Denied::InvalidInput)?;
        if rest.is_empty() {
            if self.0.insert((*head).into(), Entry::Blob(blob)).is_some() {
                return Err(Denied::BindingMismatch);
            }
        } else {
            let entry = self
                .0
                .entry((*head).into())
                .or_insert_with(|| Entry::Tree(Tree::default()));
            match entry {
                Entry::Tree(tree) => tree.insert(rest, blob)?,
                Entry::Blob(_) => return Err(Denied::BindingMismatch),
            }
        }
        Ok(())
    }
    fn oid(&self) -> [u8; 20] {
        // Git compares directory names with a trailing '/', rather than ordinary
        // string order (for example a.c sorts before a/file).
        let mut entries: Vec<_> = self.0.iter().collect();
        entries.sort_by_key(|(name, entry)| match entry {
            Entry::Blob(_) => name.as_bytes().to_vec(),
            Entry::Tree(_) => [name.as_bytes(), b"/"].concat(),
        });
        let mut bytes = Vec::new();
        for (name, entry) in entries {
            let (mode, oid) = match entry {
                Entry::Blob(oid) => ("100644", *oid),
                Entry::Tree(tree) => ("40000", tree.oid()),
            };
            bytes.extend_from_slice(format!("{mode} {name}\0").as_bytes());
            bytes.extend_from_slice(&oid);
        }
        object("tree", &bytes)
    }
}
pub(super) fn snapshot(files: &[(String, String)]) -> Result<(String, String), Denied> {
    let mut root = Tree::default();
    for (path, blob) in files {
        super::disclosure::path(path)?;
        if super::git_oid(blob)?.len() != 40 {
            return Err(Denied::InvalidInput);
        }
        let mut oid = [0; 20];
        for (i, byte) in oid.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&blob[i * 2..i * 2 + 2], 16)
                .map_err(|_| Denied::InvalidInput)?;
        }
        root.insert(&path.split('/').collect::<Vec<_>>(), oid)?;
    }
    let tree = hex(&root.oid());
    let body = format!(
        "tree {tree}\nauthor Mikaki Snapshot <snapshot@mikaki.invalid> 946684800 +0000\ncommitter Mikaki Snapshot <snapshot@mikaki.invalid> 946684800 +0000\n\nMikaki selected context snapshot\n"
    );
    Ok((hex(&object("commit", body.as_bytes())), tree))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn snapshot_matches_git_cli_for_directory_order_and_unicode_paths() {
        // Independent git hash-object/update-index/write-tree/commit-tree vector.
        let x = "587be6b4c3f93f93c489c0111bba5596147a26cb";
        let files = vec![
            ("context/00/a.c".into(), x.into()),
            ("context/00/a/file".into(), x.into()),
            (
                "context/01/日本語.md".into(),
                "34b417333d03571a5b9bfeabfdd89a472817191d".into(),
            ),
        ];
        assert_eq!(
            snapshot(&files).unwrap(),
            (
                "52e169ead0cab49baff2f83334d1febe92bc0bf9".into(),
                "248aa6d6f9a325241d0190fe59605696e3e19382".into()
            )
        );
        let reversed = files.into_iter().rev().collect::<Vec<_>>();
        assert_eq!(
            snapshot(&reversed).unwrap().1,
            "248aa6d6f9a325241d0190fe59605696e3e19382"
        );
    }
    #[test]
    fn empty_selection_has_the_git_empty_tree() {
        assert_eq!(
            snapshot(&[]).unwrap().1,
            "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
        );
    }
    #[test]
    fn snapshot_refuses_duplicate_paths_file_directory_collisions_and_unsafe_paths() {
        let blob = "587be6b4c3f93f93c489c0111bba5596147a26cb";
        for paths in [vec!["a", "a"], vec!["a", "a/b"], vec!["a/b", "a"]] {
            let files = paths
                .into_iter()
                .map(|p| (p.into(), blob.into()))
                .collect::<Vec<_>>();
            assert_eq!(snapshot(&files).err(), Some(Denied::BindingMismatch));
        }
        for path in ["../wallet", ".git/config", "a//b", "a\\b"] {
            assert_eq!(
                snapshot(&[(path.into(), blob.into())]).err(),
                Some(Denied::InvalidInput)
            );
        }
    }
}
