"""Exercise the sharing migration's fail-closed D1 constraints with SQLite."""

import sqlite3
import unittest
from pathlib import Path


MIGRATIONS = Path(__file__).resolve().parents[1] / "crates/worker/migrations"


class VaultSharingSqlTest(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("CREATE TABLE account_security(account_id TEXT PRIMARY KEY)")
        for name in (
            "0002_vault_attribute_storage.sql",
            "0007_vault_recipient_keys.sql",
            "0008_vault_attribute_sharing.sql",
        ):
            self.db.executescript((MIGRATIONS / name).read_text())
        self.db.execute("INSERT INTO account_security(account_id) VALUES('owner')")
        self.db.execute(
            """INSERT INTO vault_attribute_head
               (account_id,attribute_id,revision,format_version,object_key,
                ciphertext_sha256,owner_envelope,deleted,updated_at)
               VALUES('owner','name',1,1,'blob',?,'owner-wrap',0,100)""",
            ("d" * 43,),
        )
        self.db.execute(
            """INSERT INTO vault_recipient_key
               (key_id,service_id,algorithm,public_key,secret_ref,generation,
                state,revision,created_at)
               VALUES(?,'userinfo','ML-KEM-768',zeroblob(1184),'TEST_SEED',1,'staged',1,100)""",
            ("k" * 43,),
        )
        self.db.execute(
            """UPDATE vault_recipient_key SET state='active',revision=2,activated_at=101
               WHERE key_id=?""",
            ("k" * 43,),
        )
        self.db.execute(
            """INSERT INTO vault_attribute_recipient_envelope
               (envelope_id,account_id,attribute_id,attribute_revision,recipient_service,
                recipient_key_id,recipient_generation,suite,ciphertext_sha256,frame,created_at)
               VALUES(?,'owner','name',1,'userinfo',?,1,
                'ML-KEM-768-HKDF-SHA256-AES-256-GCM-draft04-v1',
                ?,zeroblob(1187),102)""",
            ("e" * 43, "k" * 43, "d" * 43),
        )

    def tearDown(self):
        self.db.close()

    def grant(self):
        self.db.execute(
            """INSERT INTO vault_attribute_grant
               (account_id,attribute_id,recipient_service,purpose,envelope_id,attribute_revision,
                version,status,expires_at,updated_at)
               VALUES('owner','name','userinfo','oidc.userinfo.name',?,1,1,'active',604902,102)""",
            ("e" * 43,),
        )

    def test_disabled_by_default_and_policy_revision(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.grant()
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute("UPDATE vault_share_policy SET enabled=1 WHERE id=1")
        self.db.execute("UPDATE vault_share_policy SET enabled=1,revision=2 WHERE id=1")
        self.grant()

    def test_head_update_revokes_grant(self):
        self.db.execute("UPDATE vault_share_policy SET enabled=1,revision=2 WHERE id=1")
        self.grant()
        self.db.execute(
            """UPDATE vault_attribute_head SET revision=2,ciphertext_sha256=?,
               updated_at=103 WHERE account_id='owner' AND attribute_id='name'""",
            ("x" * 43,),
        )
        self.assertEqual(
            self.db.execute("SELECT status,version FROM vault_attribute_grant").fetchone(),
            ("revoked", 2),
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute(
                "UPDATE vault_attribute_grant SET status='active',version=3 WHERE account_id='owner'"
            )

    def test_key_state_and_digest_must_match(self):
        self.db.execute("UPDATE vault_share_policy SET enabled=1,revision=2 WHERE id=1")
        self.db.execute(
            """UPDATE vault_recipient_key SET state='disabled',revision=3,retired_at=103
               WHERE key_id=?""",
            ("k" * 43,),
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.grant()

    def test_disabling_policy_revokes_active_grants(self):
        self.db.execute("UPDATE vault_share_policy SET enabled=1,revision=2 WHERE id=1")
        self.grant()
        self.db.execute("UPDATE vault_share_policy SET enabled=0,revision=3 WHERE id=1")
        self.assertEqual(
            self.db.execute("SELECT status,version FROM vault_attribute_grant").fetchone(),
            ("revoked", 2),
        )

    def test_changing_ttl_revokes_existing_grants(self):
        self.db.execute("UPDATE vault_share_policy SET enabled=1,revision=2 WHERE id=1")
        self.grant()
        self.db.execute(
            "UPDATE vault_share_policy SET grant_ttl_seconds=60,revision=3 WHERE id=1"
        )
        self.assertEqual(
            self.db.execute("SELECT status,version FROM vault_attribute_grant").fetchone(),
            ("revoked", 2),
        )


if __name__ == "__main__":
    unittest.main()
