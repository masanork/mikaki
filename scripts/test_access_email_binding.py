"""Exercise the Access email binding migration with SQLite foreign keys enabled."""

import pathlib
import sqlite3
import unittest


MIGRATION = pathlib.Path(__file__).resolve().parents[1] / "crates/worker/migrations/0009_access_email_bindings.sql"


class AccessEmailBindingTest(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.executescript(
            "PRAGMA foreign_keys=ON;"
            "CREATE TABLE client(client_id TEXT PRIMARY KEY) STRICT;"
            "CREATE TABLE account_security(account_id TEXT PRIMARY KEY) STRICT;"
            "INSERT INTO client VALUES('access'),('other');"
            "INSERT INTO account_security VALUES('alice'),('bob');"
        )
        self.db.executescript(MIGRATION.read_text())

    def insert(self, client, account, email, active=1):
        self.db.execute(
            "INSERT INTO access_email_binding VALUES(?,?,?,1,?,123)",
            (client, account, email, active),
        )

    def test_active_email_is_unique_per_client_even_with_ascii_case_changes(self):
        self.insert("access", "alice", "Alice@example.test")
        with self.assertRaises(sqlite3.IntegrityError):
            self.insert("access", "bob", "alice@example.test")
        self.insert("other", "bob", "alice@example.test")
        self.db.execute("UPDATE access_email_binding SET active=0,revision=2 WHERE account_id='alice'")
        self.insert("access", "bob", "alice@example.test")

    def test_mutations_advance_revision_and_deletion_is_forbidden(self):
        self.insert("access", "alice", "alice@example.test")
        for statement in [
            "UPDATE access_email_binding SET active=0",
            "UPDATE access_email_binding SET revision=0",
            "DELETE FROM access_email_binding",
        ]:
            with self.subTest(statement=statement), self.assertRaises(sqlite3.IntegrityError):
                self.db.execute(statement)
        self.db.execute("UPDATE access_email_binding SET revision=2, active=0")
        self.assertEqual(self.db.execute("SELECT revision,active FROM access_email_binding").fetchone(), (2, 0))

    def test_unknown_foreign_keys_and_invalid_metadata_are_rejected(self):
        for values in [
            ("missing", "alice", "alice@example.test", 1),
            ("access", "missing", "alice@example.test", 1),
            ("access", "alice", " alice@example.test", 1),
            ("access", "alice", "a\nb@example.test", 1),
            ("access", "alice", "a@example.test", 2),
        ]:
            with self.subTest(values=values), self.assertRaises(sqlite3.IntegrityError):
                self.insert(*values)


class ScopeMigrationTest(unittest.TestCase):
    def test_existing_scope_and_immutability_survive_rebuild(self):
        db = sqlite3.connect(":memory:")
        migrations = MIGRATION.parent
        for path in sorted(migrations.glob("*.sql")):
            if path.name >= "0010_access_email_scope.sql":
                break
            db.executescript(path.read_text())
        # Insert the historical row with foreign keys disabled; this test targets
        # the table rebuild and does not construct an entire login session.
        db.execute("INSERT INTO code_context(code_hash,nonce,scope) VALUES(?,?,?)", ("a" * 43, None, "profile openid"))
        db.executescript((migrations / "0010_access_email_scope.sql").read_text())
        self.assertEqual(db.execute("SELECT scope FROM code_context").fetchone()[0], "profile openid")
        with self.assertRaises(sqlite3.IntegrityError):
            db.execute("UPDATE code_context SET scope='openid email profile'")
        self.assertIsNotNone(db.execute("SELECT name FROM sqlite_master WHERE type='view' AND name='identity_age_eligible'").fetchone())


if __name__ == "__main__":
    unittest.main()
