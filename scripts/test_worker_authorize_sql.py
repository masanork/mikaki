#!/usr/bin/env python3
"""SQLite contract checks for the exact SQL used by Worker authorization issuance."""
import sqlite3
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / 'crates/worker/migrations/0001_oidc_initial.sql'
SQL = ROOT / 'crates/worker/sql'
REDIRECT = 'https://client.example/callback'
COOKIE_HASH = 'C' * 43


def run_batch(db, *, redirect=REDIRECT, cookie_hash=COOKIE_HASH,
              active=True, revision=1, fail_after=None, sid='S' * 43,
              code_hash='A' * 43, nonce='test-nonce', candidate_sub='Z' * 43):
    now = int(time.time())
    commands = [
        ('insert-pairwise-subject.sql', ('account', 'sector.example', candidate_sub)),
        ('insert-authorization-client-session.sql',
         (sid, 'sso', cookie_hash, 'client', revision, redirect, now)),
        ('insert-authorization-code.sql',
         (code_hash, 'client', sid, revision, redirect, 'P' * 43, now + 60, now)),
        ('insert-authorization-code-context.sql', (code_hash, nonce)),
        ('guard-authorization-code.sql', (code_hash, 'client', redirect, nonce, now)),
        ('delete-authorization-code-guard.sql', (code_hash,)),
    ]
    db.execute('BEGIN IMMEDIATE')
    try:
        for index, (name, parameters) in enumerate(commands):
            db.execute((SQL / name).read_text(), parameters)
            if fail_after == index:
                raise RuntimeError('injected failure')
        db.commit()
    except BaseException:
        db.rollback()
        raise


def seeded_db():
    db = sqlite3.connect(':memory:')
    db.execute('PRAGMA foreign_keys=ON')
    db.executescript(MIGRATION.read_text())
    now = int(time.time())
    db.execute("INSERT INTO account_security VALUES('account',0,1)")
    db.execute("INSERT INTO credential VALUES('cred','account',1)")
    db.execute("INSERT INTO client VALUES('client',1,1,'sector.example')")
    db.execute('INSERT INTO client_redirect_uri VALUES(?,?)', ('client', REDIRECT))
    db.execute("INSERT INTO app_connection VALUES('account','client',1,1)")
    db.execute("INSERT INTO sso_session VALUES('sso','account','cred',0,?,0)", (now + 600,))
    db.execute('INSERT INTO sso_context VALUES(?,?,?)', ('sso', COOKIE_HASH, now - 10))
    db.commit()
    return db


class WorkerAuthorizationSql(unittest.TestCase):
    def setUp(self):
        self.db = seeded_db()

    def tearDown(self):
        self.db.close()

    def counts(self):
        return tuple(self.db.execute(f'SELECT count(*) FROM {table}').fetchone()[0]
                     for table in ('pairwise_subject', 'client_session', 'authorization_code',
                                   'code_context', 'atomic_guard'))

    def test_issues_code_and_stable_pairwise_subject_together(self):
        run_batch(self.db)
        first_sub = self.db.execute('SELECT sub FROM client_session').fetchone()[0]
        run_batch(self.db, sid='T' * 43, code_hash='B' * 43, candidate_sub='Y' * 43)
        self.assertEqual(self.counts(), (1, 2, 2, 2, 0))
        self.assertEqual(self.db.execute('SELECT DISTINCT sub FROM client_session').fetchall(),
                         [(first_sub,)])

    def test_unregistered_redirect_rolls_back_pairwise_and_session(self):
        with self.assertRaises(sqlite3.IntegrityError):
            run_batch(self.db, redirect='https://evil.example/callback')
        self.assertEqual(self.counts(), (0, 0, 0, 0, 0))

    def test_wrong_cookie_or_stale_client_revision_cannot_issue(self):
        for changes in ({'cookie_hash': 'X' * 43}, {'revision': 2}):
            with self.subTest(changes=changes):
                with self.assertRaises(sqlite3.IntegrityError):
                    run_batch(self.db, **changes)
                self.assertEqual(self.counts(), (0, 0, 0, 0, 0))

    def test_each_batch_failure_rolls_back_every_insert(self):
        for index in range(6):
            with self.subTest(statement=index):
                with self.assertRaises(RuntimeError):
                    run_batch(self.db, code_hash=chr(65 + index) * 43, fail_after=index)
                self.assertEqual(self.counts(), (0, 0, 0, 0, 0))


if __name__ == '__main__':
    unittest.main()
