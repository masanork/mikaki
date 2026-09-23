"""Exercise the D1 recipient-key lifecycle constraints with SQLite."""

import sqlite3
import unittest
from pathlib import Path


MIGRATION = (
    Path(__file__).resolve().parents[1]
    / "crates/worker/migrations/0007_vault_recipient_keys.sql"
)


class RecipientKeySqlTest(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.executescript(MIGRATION.read_text())

    def tearDown(self):
        self.db.close()

    def stage(self, suffix, generation):
        self.db.execute(
            """INSERT INTO vault_recipient_key
               (key_id,service_id,algorithm,public_key,secret_ref,generation,
                state,revision,created_at)
               VALUES(?,?,?,?,?,?,'staged',1,100)""",
            (suffix * 43, "userinfo", "ML-KEM-768", bytes([generation]) * 1184,
             f"VAULT_USERINFO_MLKEM_{suffix}", generation),
        )

    def test_promotion_rotation_and_emergency_stop(self):
        self.stage("a", 1)
        self.stage("b", 2)
        self.db.execute(
            "UPDATE vault_recipient_key SET state='active',revision=2,activated_at=101 WHERE key_id=?",
            ("a" * 43,),
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute(
                "UPDATE vault_recipient_key SET state='active',revision=2,activated_at=102 WHERE key_id=?",
                ("b" * 43,),
            )
        # The two updates form one D1 batch when rotation is implemented.
        with self.db:
            self.db.execute(
                "UPDATE vault_recipient_key SET state='decrypt_only',revision=3,retired_at=103 WHERE key_id=?",
                ("a" * 43,),
            )
            self.db.execute(
                "UPDATE vault_recipient_key SET state='active',revision=2,activated_at=103 WHERE key_id=?",
                ("b" * 43,),
            )
        self.db.execute(
            "UPDATE vault_recipient_key SET state='disabled',revision=4 WHERE key_id=?",
            ("a" * 43,),
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute(
                "UPDATE vault_recipient_key SET state='active',revision=5,retired_at=NULL WHERE key_id=?",
                ("a" * 43,),
            )
        self.db.execute(
            "UPDATE vault_recipient_key SET state='disabled',revision=3,retired_at=104 WHERE key_id=?",
            ("b" * 43,),
        )
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM vault_recipient_key WHERE state='active'").fetchone()[0],
            0,
        )

    def test_immutable_identity_and_monotonic_revision(self):
        self.stage("c", 1)
        for change in (
            "public_key=zeroblob(1184),revision=2",
            "secret_ref='different',revision=2",
            "generation=2,revision=2",
            "revision=1,state='active',activated_at=101",
            "revision=2,state='decrypt_only',activated_at=101,retired_at=102",
        ):
            with self.subTest(change=change), self.assertRaises(sqlite3.IntegrityError):
                self.db.execute(f"UPDATE vault_recipient_key SET {change} WHERE key_id=?", ("c" * 43,))
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute("DELETE FROM vault_recipient_key WHERE key_id=?", ("c" * 43,))

    def test_invalid_key_and_staged_stop(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute(
                """INSERT INTO vault_recipient_key
                   (key_id,service_id,algorithm,public_key,secret_ref,generation,
                    state,revision,created_at) VALUES(?,?,?,?,?,1,'staged',1,100)""",
                ("x" * 43, "userinfo", "ML-KEM-768", b"short", "binding"),
            )
        self.stage("d", 1)
        self.db.execute(
            "UPDATE vault_recipient_key SET state='disabled',revision=2,retired_at=101 WHERE key_id=?",
            ("d" * 43,),
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute(
                """INSERT INTO vault_recipient_key
                   (key_id,service_id,algorithm,public_key,secret_ref,generation,
                    state,revision,created_at,activated_at)
                   VALUES(?,?,?,?,?,2,'active',1,100,101)""",
                ("e" * 43, "userinfo", "ML-KEM-768", bytes([2]) * 1184,
                 "VAULT_USERINFO_MLKEM_E"),
            )

    def test_activation_and_retirement_times_are_fixed(self):
        self.stage("f", 1)
        self.db.execute(
            "UPDATE vault_recipient_key SET state='active',revision=2,activated_at=101 WHERE key_id=?",
            ("f" * 43,),
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute(
                """UPDATE vault_recipient_key SET state='decrypt_only',revision=3,
                   activated_at=102,retired_at=103 WHERE key_id=?""",
                ("f" * 43,),
            )
        self.db.execute(
            "UPDATE vault_recipient_key SET state='decrypt_only',revision=3,retired_at=103 WHERE key_id=?",
            ("f" * 43,),
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute(
                "UPDATE vault_recipient_key SET state='disabled',revision=4,retired_at=104 WHERE key_id=?",
                ("f" * 43,),
            )


if __name__ == "__main__":
    unittest.main()
