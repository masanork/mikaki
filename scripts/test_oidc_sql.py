#!/usr/bin/env python3
"""SQLite上の原子操作設計試験。D1/署名/HTTPの試験ではない。"""
import concurrent.futures
import sqlite3
import tempfile
import threading
import time
import unittest
from pathlib import Path

SQL = Path(__file__).resolve().parents[1] / 'design' / 'sql'


def statements(name):
    source = '\n'.join(line for line in (SQL / name).read_text().splitlines()
                       if not line.lstrip().startswith('--'))
    return [s.strip() for s in source.split(';') if s.strip()]


def batch(db, name, params, fail_after=None):
    # D1 batch相当のロールバック境界をSQLite transactionで検証する。
    db.execute('BEGIN IMMEDIATE')
    try:
        for i, statement in enumerate(statements(name)):
            db.execute(statement, params)
            if fail_after == i:
                raise RuntimeError('injected storage failure')
        db.commit()
    except BaseException:
        db.rollback()
        raise


def seed(db):
    db.executescript((SQL / 'oidc-critical-schema.sql').read_text())
    now = int(time.time())
    db.executescript("""
      INSERT INTO account_security VALUES('a',0,1);
      INSERT INTO credential VALUES('cred','a',1);
      INSERT INTO client VALUES('c',1,1);
      INSERT INTO client_key VALUES('c','ck',1,1);
      INSERT INTO signing_key VALUES('opk',1,1);
      INSERT INTO app_connection VALUES('a','c',1,1);
    """)
    db.execute('INSERT INTO sso_session VALUES(?,?,?,?,?,?)',
               ('sso', 'a', 'cred', 0, now + 3600, 0))
    db.execute('INSERT INTO client_session VALUES(?,?,?,?,?,?,?)',
               ('c', 'sid', 'sso', 'a', 'sub', 1, 0))
    db.execute('INSERT INTO authorization_code VALUES(?,?,?,?,?,?,?,?,?)',
               ('codehash', 'c', 'sid', 1, 'https://app.example/cb', 'challenge', now + 600, None, None))
    db.commit()


def params(operation='exchange', jti='assertion'):
    return dict(client_id='c', client_kid='ck', client_key_revision=1,
                jti=jti, endpoint='https://login.example/token', operation_id=operation,
                retain_until=int(time.time())+300, code_hash='codehash',
                redirect_uri='https://app.example/cb', pkce_challenge='challenge',
                signing_kid='opk', signing_generation=1, access_hash='access-'+operation,
                access_expires_at=int(time.time())+300)


class StoreContract(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:')
        seed(self.db)

    def tearDown(self):
        self.db.close()

    def accept(self, p):
        batch(self.db, 'accept-assertion.sql', p)

    def unchanged_code(self):
        self.assertIsNone(self.db.execute('SELECT consumed_by FROM authorization_code').fetchone()[0])
        self.assertEqual(self.db.execute('SELECT count(*) FROM token_issue').fetchone()[0], 0)

    def test_success_and_reuse(self):
        p = params(); self.accept(p)
        self.assertEqual(self.db.execute('SELECT count(*) FROM valid_client_session').fetchone()[0], 0)
        batch(self.db, 'exchange-code.sql', p)
        self.assertEqual(self.db.execute('SELECT count(*) FROM token_issue').fetchone()[0], 1)
        self.assertEqual(self.db.execute('SELECT count(*) FROM valid_client_session').fetchone()[0], 1)
        other = params('again', 'again'); self.accept(other)
        with self.assertRaises(sqlite3.IntegrityError):
            batch(self.db, 'exchange-code.sql', other)
        self.assertEqual(self.db.execute('SELECT consumed_by FROM authorization_code').fetchone()[0], 'exchange')

    def test_assertion_reuse_and_endpoint_binding(self):
        p = params(); self.accept(p)
        with self.assertRaises(sqlite3.IntegrityError):
            self.accept(params('other', 'assertion'))
        p['endpoint'] = 'https://login.example/session/check'
        with self.assertRaises(sqlite3.IntegrityError):
            batch(self.db, 'exchange-code.sql', p)
        self.unchanged_code()

    def test_guard_rejects_zero_rows_without_unconsuming_assertion(self):
        p = params(); self.accept(p); p['pkce_challenge'] = 'wrong'
        with self.assertRaises(sqlite3.IntegrityError):
            batch(self.db, 'exchange-code.sql', p)
        self.unchanged_code()
        self.assertEqual(self.db.execute('SELECT count(*) FROM assertion_use').fetchone()[0], 1)

    def test_failure_at_every_exchange_statement_rolls_back(self):
        p = params(); self.accept(p)
        for pos in range(len(statements('exchange-code.sql'))):
            with self.subTest(statement=pos):
                with self.assertRaises(RuntimeError):
                    batch(self.db, 'exchange-code.sql', p, fail_after=pos)
                self.unchanged_code()
                self.assertEqual(self.db.execute('SELECT count(*) FROM atomic_guard').fetchone()[0], 0)

    def test_failed_insert_rolls_back_consumption(self):
        self.db.execute("CREATE TRIGGER fail_issue BEFORE INSERT ON token_issue BEGIN SELECT RAISE(ABORT,'injected'); END")
        self.db.commit()
        p = params(); self.accept(p)
        with self.assertRaises(sqlite3.IntegrityError):
            batch(self.db, 'exchange-code.sql', p)
        self.unchanged_code()

    def test_expiry_boundary(self):
        self.db.execute("UPDATE authorization_code SET expires_at=CAST(strftime('%s','now') AS INTEGER)")
        self.db.commit()
        p = params(); self.accept(p)
        with self.assertRaises(sqlite3.IntegrityError):
            batch(self.db, 'exchange-code.sql', p)
        self.unchanged_code()

    def test_invalidations_reject_exchange(self):
        mutations = [
            'UPDATE account_security SET epoch=1',
            'UPDATE credential SET active=0',
            'UPDATE app_connection SET grant_version=2',
            'UPDATE app_connection SET active=0',
            'UPDATE sso_session SET revoked=1',
            'UPDATE client_session SET revoked=1',
            'UPDATE client SET revision=2',
            'UPDATE client SET active=0',
            'UPDATE client_key SET active=0',
            'UPDATE signing_key SET active=0',
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                db = sqlite3.connect(':memory:'); seed(db); p = params()
                try:
                    batch(db, 'accept-assertion.sql', p)
                    db.execute(mutation); db.commit()
                    with self.assertRaises(sqlite3.IntegrityError):
                        batch(db, 'exchange-code.sql', p)
                    self.assertIsNone(db.execute('SELECT consumed_by FROM authorization_code').fetchone()[0])
                finally:
                    db.close()

    def test_new_epoch_session_survives_old_event(self):
        p = params(); self.accept(p); batch(self.db, 'exchange-code.sql', p)
        batch(self.db, 'revoke-all.sql', dict(account_id='a', expected_epoch=0, operation_id='logout'))
        self.assertEqual(self.db.execute('SELECT count(*) FROM valid_client_session').fetchone()[0], 0)
        self.db.execute("INSERT INTO sso_session SELECT 'new-sso',account_id,credential_id,1,expires_at,0 FROM sso_session WHERE sso_id='sso'")
        self.db.execute("INSERT INTO client_session VALUES('c','new-sid','new-sso','a','sub',1,0)")
        self.db.execute("INSERT INTO authorization_code SELECT 'new-code',client_id,'new-sid',client_revision,redirect_uri,pkce_challenge,expires_at,NULL,NULL FROM authorization_code WHERE code_hash='codehash'")
        self.db.commit()
        p = params('new-exchange', 'new-jti'); p['code_hash'] = 'new-code'
        self.accept(p); batch(self.db, 'exchange-code.sql', p)
        self.assertEqual(self.db.execute('SELECT sid FROM valid_client_session').fetchall(), [('new-sid',)])
        self.assertEqual(self.db.execute('SELECT through_epoch FROM revocation_event').fetchone()[0], 0)

    def test_revoke_stale_expected_epoch_cannot_make_new_event(self):
        batch(self.db, 'revoke-all.sql', dict(account_id='a', expected_epoch=0, operation_id='first'))
        with self.assertRaises(sqlite3.IntegrityError):
            batch(self.db, 'revoke-all.sql', dict(account_id='a', expected_epoch=0, operation_id='stale'))
        self.assertEqual(self.db.execute('SELECT count(*) FROM revocation_event').fetchone()[0], 1)
        self.assertEqual(self.db.execute('SELECT epoch FROM account_security').fetchone()[0], 1)

    def test_failure_at_every_revoke_statement_rolls_back(self):
        p = dict(account_id='a', expected_epoch=0, operation_id='logout')
        for pos in range(len(statements('revoke-all.sql'))):
            with self.assertRaises(RuntimeError):
                batch(self.db, 'revoke-all.sql', p, fail_after=pos)
            self.assertEqual(self.db.execute('SELECT epoch FROM account_security').fetchone()[0], 0)
            self.assertEqual(self.db.execute('SELECT count(*) FROM revocation_event').fetchone()[0], 0)

    def test_expired_access_candidate_does_not_consume_code(self):
        p = params(); self.accept(p); p['access_expires_at'] = 1
        with self.assertRaises(sqlite3.IntegrityError):
            batch(self.db, 'exchange-code.sql', p)
        self.unchanged_code()

    def test_access_expiry_does_not_end_session_but_issue_revocation_does(self):
        p = params(); self.accept(p); batch(self.db, 'exchange-code.sql', p)
        self.db.execute('UPDATE token_issue SET access_expires_at=1'); self.db.commit()
        self.assertEqual(self.db.execute('SELECT count(*) FROM valid_client_session').fetchone()[0], 1)
        self.db.execute('UPDATE token_issue SET revoked=1'); self.db.commit()
        self.assertEqual(self.db.execute('SELECT count(*) FROM valid_client_session').fetchone()[0], 0)

    def test_parallel_exchange_has_one_winner(self):
        with tempfile.TemporaryDirectory(prefix='sakimori-sql-') as directory:
            path = str(Path(directory)/'test.sqlite')
            db = sqlite3.connect(path); seed(db); db.close()
            barrier = threading.Barrier(2)
            def attempt(index):
                db = sqlite3.connect(path, timeout=5)
                db.execute('PRAGMA foreign_keys=ON')
                p = params('parallel-'+str(index), 'jti-'+str(index))
                try:
                    batch(db, 'accept-assertion.sql', p)
                    barrier.wait(timeout=5)
                    try:
                        batch(db, 'exchange-code.sql', p)
                        return True
                    except sqlite3.IntegrityError:
                        return False
                finally:
                    db.close()
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                self.assertEqual(sorted(pool.map(attempt, range(2))), [False, True])
            db = sqlite3.connect(path)
            try:
                self.assertEqual(db.execute('SELECT count(*) FROM token_issue').fetchone()[0], 1)
            finally:
                db.close()


if __name__ == '__main__':
    unittest.main(verbosity=2)
