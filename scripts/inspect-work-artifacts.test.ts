import assert from 'node:assert/strict';
import test from 'node:test';
import {
  protectedJournals,
  journalAllocations,
  projectJournalAllocations,
  repositoryInventory,
  tokenInventory,
  inspectAllocations,
  opBindingObservation,
  inspectionReadKind,
  type ReadAPI,
} from './inspect-work-artifacts.ts';
import { ARTIFACTS_ACCOUNT } from './work-artifacts-git.ts';

const timestamp = '2026-10-10T12:00:00.000Z';
const repoName = 'wk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-code';
function repository(index = 0) {
  const name = `wk-${index.toString(16).padStart(32, '0')}-${index % 2 ? 'snapshot' : 'code'}`;
  return {
    id: index.toString(16).padStart(16, '0'),
    name,
    description: 'unneeded private metadata',
    default_branch: 'main',
    created_at: timestamp,
    updated_at: timestamp,
    last_push_at: null,
    source: null,
    read_only: false,
    remote: `https://${ARTIFACTS_ACCOUNT}.artifacts.cloudflare.net/git/mikaki-dev/${name}.git`,
  };
}
function page(result: unknown[], cursor = '') {
  return {
    success: true,
    errors: [],
    messages: [],
    result,
    result_info: { cursor, per_page: 200, count: result.length },
  };
}
function tokenPage(result: unknown[], number = 1, total = result.length, pages = 1) {
  return {
    success: true,
    errors: [],
    messages: [],
    result,
    result_info: {
      page: number,
      per_page: 100,
      total_pages: pages,
      total_count: total,
      count: result.length,
    },
  };
}
const token = {
  id: 'aaaaaaaaaaaaaaaa',
  scope: 'write',
  state: 'revoked',
  created_at: timestamp,
  expires_at: timestamp,
};
test('HTTP target policy accepts exact v4 GET paths and refuses other resources and query shapes', () => {
  const base = `/accounts/${ARTIFACTS_ACCOUNT}`;
  const repos = `${base}/artifacts/namespaces/mikaki-dev/repos`;
  const allowed = new Set([repoName]);
  assert.equal(inspectionReadKind(`${repos}?limit=200`, allowed), 'artifacts');
  assert.equal(inspectionReadKind(`${repos}?limit=200&page=2`, allowed), 'artifacts');
  assert.equal(
    inspectionReadKind(`${repos}?limit=200&cursor=opaque%2Fa%3Fb`, allowed),
    'artifacts',
  );
  assert.equal(inspectionReadKind(`${repos}/${repoName}`, allowed), 'artifacts');
  assert.equal(
    inspectionReadKind(`${repos}/${repoName}/tokens?state=all&per_page=100&page=1`, allowed),
    'artifacts',
  );
  assert.equal(
    inspectionReadKind(`${base}/workers/scripts/mikaki-auth/settings`, allowed),
    'workers',
  );
  for (const path of [
    `${repos}?limit=200&limit=200`,
    `${repos}?limit=200&search=other`,
    `${repos}?limit=200&page=5`,
    `${repos}/${repoName}/tokens?state=active&per_page=100&page=1`,
    `${repos}/${repoName}/tokens?state=all&per_page=100&page=9`,
    `${repos}/mikaki`,
    `${repos}/${repoName}/../mikaki`,
    `${repos}/${repoName}/tokens/aaaaaaaaaaaaaaaa`,
    `${base}/artifacts/namespaces/mikaki-dev/tokens`,
    `${base}/workers/scripts/mikaki-auth/settings?include=secret`,
    `${repos}/${repoName}#fragment`,
    `${base}/artifacts/namespaces/other/repos?limit=200`,
  ])
    assert.throws(() => inspectionReadKind(path, allowed), /inspection_target_denied/);
});
function allocations() {
  return Array.from({ length: 6 }, (_, index) => ({
    journal: protectedJournals[Math.floor(index / 2)].directory,
    role: index % 2 ? ('snapshot' as const) : ('task' as const),
    attempt_id: String(index).repeat(43),
    name: repository(index).name,
    repo_id: repository(index).id,
    digest: 'a'.repeat(64),
    retained_state: index % 2 ? ('outcome_unknown' as const) : ('closed' as const),
    observed_token_id: index === 0 ? token.id : null,
    cleanup_acknowledged: false,
  }));
}
function fixture(change?: (path: string, value: unknown, count: number) => unknown) {
  const calls: string[] = [];
  const get: ReadAPI = async (path) => {
    calls.push(path);
    const u = new URL(`https://example.invalid${path}`);
    let value: unknown;
    if (u.pathname.endsWith('/repos'))
      value = page(Array.from({ length: 6 }, (_, i) => repository(i)));
    else if (u.pathname.endsWith('/tokens')) value = tokenPage([token]);
    else {
      const info = Array.from({ length: 6 }, (_, i) => repository(i)).find((r) =>
        u.pathname.endsWith(`/${r.name}`),
      );
      assert.ok(info);
      value = { success: true, errors: [], messages: [], result: info };
    }
    return change ? change(path, value, calls.filter((v) => v === path).length) : value;
  };
  return { get, calls };
}
test('complete read-only inspection preserves unknown states and makes no adoption or closure claim', async () => {
  const f = fixture();
  const records: unknown[] = [];
  const result = await inspectAllocations(allocations(), f.get, async (v) => {
    records.push(v);
  });
  assert.equal(result.unknown_attempts, 3);
  assert.equal(result.allocations.length, 6);
  assert.equal(result.allocations[0].observed_token?.id, token.id);
  assert.ok(result.allocations.every((a) => !a.closure_requalified && !a.productive_adoption));
  assert.ok(!JSON.stringify(records).includes('unneeded private metadata'));
  assert.equal(f.calls.length, 20);
  assert.ok(
    f.calls
      .filter((p) => p.includes('/tokens?'))
      .every((p) => p.endsWith('state=all&per_page=100&page=1')),
  );
});
test('same-name replacement and missing protected identity stop before any token read', async () => {
  const f = fixture((path, value) => {
    if (path.includes('?limit='))
      return page(
        Array.from({ length: 6 }, (_, i) => ({
          ...repository(i),
          id: 'f'.repeat(16 - i) + '0'.repeat(i),
        })),
      );
    return value;
  });
  await assert.rejects(
    inspectAllocations(allocations(), f.get, async () => {}),
    /protected_repository_mismatch/,
  );
  assert.equal(f.calls.length, 1);
});
test('changing repository identity or metadata between token reads refuses the result', async () => {
  const f = fixture((path, value, count) => {
    if (path.endsWith(repository(0).name) && count === 2)
      return {
        success: true,
        errors: [],
        messages: [],
        result: { ...repository(0), updated_at: '2026-10-10T12:01:00.000Z' },
      };
    return value;
  });
  await assert.rejects(
    inspectAllocations(allocations(), f.get, async () => {}),
    /protected_repository_changed/,
  );
});
test('repository pagination rejects repeated cursors, duplicates, oversized and invalid pages', async () => {
  await assert.rejects(
    repositoryInventory(async () => page([], 'repeated')),
    /repository_cursor_repeated/,
  );
  await assert.rejects(
    repositoryInventory(async () => page([repository(), repository()])),
    /repository_inventory_duplicate/,
  );
  await assert.rejects(
    repositoryInventory(async () => page(Array.from({ length: 201 }, (_, i) => repository(i)))),
  );
  await assert.rejects(repositoryInventory(async () => ({ ...page([]), success: false })));
});
test('repository pagination follows only the returned encoded cursor and terminates explicitly', async () => {
  const calls: string[] = [];
  const found = await repositoryInventory(async (path) => {
    calls.push(path);
    return calls.length === 1 ? page([repository(0)], 'opaque/a?b') : page([repository(1)]);
  });
  assert.equal(found.length, 2);
  assert.ok(calls[1].endsWith('&cursor=opaque%2Fa%3Fb'));
});
test('observed ready metadata and offset repository pages require complete stable totals', async () => {
  let calls = 0;
  const offset = (result: unknown[], page: number, total: number) => ({
    success: true,
    errors: [],
    messages: [],
    result,
    result_info: {
      page,
      per_page: 200,
      total_pages: Math.ceil(total / 200),
      count: result.length,
      total_count: total,
    },
  });
  const found = await repositoryInventory(async (path) => {
    calls++;
    if (calls === 1)
      return offset(
        Array.from({ length: 200 }, (_, i) => ({ ...repository(i), status: 'ready' })),
        1,
        201,
      );
    assert.ok(path.endsWith('&page=2'));
    return offset([{ ...repository(200), status: 'ready' }], 2, 201);
  });
  assert.equal(found.length, 201);
  assert.equal(found[0].status, 'ready');
  await assert.rejects(
    repositoryInventory(async () => offset([], 1, 1)),
    /repository_inventory_incomplete/,
  );
  await assert.rejects(
    repositoryInventory(async () => offset([{ ...repository(0), status: 'unknown' }], 1, 1)),
  );
  let pageNumber = 0;
  await assert.rejects(
    repositoryInventory(async () =>
      ++pageNumber === 1
        ? offset(
            Array.from({ length: 200 }, (_, i) => repository(i)),
            1,
            201,
          )
        : offset([repository(200)], 2, 202),
    ),
    /repository_inventory_incomplete/,
  );
});
test('token inventory requires all states and exact stable offset completeness', async () => {
  assert.deepEqual(await tokenInventory(async () => tokenPage([]), repoName), []);
  await assert.rejects(
    tokenInventory(async () => tokenPage([token, token]), repoName),
    /token_inventory_duplicate/,
  );
  await assert.rejects(
    tokenInventory(async () => tokenPage([], 1, 1), repoName),
    /token_inventory_incomplete/,
  );
  await assert.rejects(
    tokenInventory(async () => tokenPage([], 2), repoName),
    /token_inventory_incomplete/,
  );
  await assert.rejects(
    tokenInventory(async () => tokenPage([], 1, 201, 1), repoName),
    /token_inventory_incomplete/,
  );
  await assert.rejects(
    tokenInventory(async () => tokenPage([{ ...token, plaintext: 'must not persist' }]), repoName),
  );
});
test('six unique pinned roles and final stable inventory are required', async () => {
  const f = fixture();
  await assert.rejects(
    inspectAllocations([...allocations().slice(0, 5), allocations()[0]], f.get, async () => {}),
    /protected_allocations_incomplete/,
  );
  assert.equal(f.calls.length, 0);
  const changing = fixture((path, value, count) =>
    path.includes('?limit=') && count === 2 ? page([]) : value,
  );
  await assert.rejects(
    inspectAllocations(allocations(), changing.get, async () => {}),
    /repository_inventory_changed/,
  );
});
test('OP projection excludes secret values and cannot qualify enrollment from binding names', () => {
  const observation = opBindingObservation({
    success: true,
    errors: [],
    messages: [],
    result: {
      bindings: [
        { name: 'OP_PRIVATE_JWK', type: 'secret_text', text: 'secret material' },
        { name: 'WORK_AUTHORITY_CHECKPOINT', type: 'service', service: 'unqualified-service' },
      ],
    },
  });
  assert.equal(observation.checkpoint_binding_present, true);
  assert.equal(observation.enrollment_qualified, false);
  assert.ok(!JSON.stringify(observation).includes('secret material'));
  assert.ok(!JSON.stringify(observation).includes('unqualified-service'));
});
test('journal projection preserves unknowns and checks plan/result/ledger identity without exporting keys', () => {
  const slots = allocations()
    .slice(0, 2)
    .map((a) => {
      const plan = {
        attempt_id: a.attempt_id,
        name: a.name,
        namespace: 'mikaki-dev',
        digest: a.digest,
        effect: 'repo.create',
        role: a.role,
        checkpoint: { authority: 'synthetic-managed-work' },
      };
      return {
        id: a.attempt_id,
        plan,
        result: { attempt_id: a.attempt_id, state: a.retained_state, repo_id: a.repo_id },
        ledger: { plan, state: a.retained_state, repo_id: a.repo_id, closure: null },
      };
    });
  const raw = {
    format_version: 1,
    synthetic_key: 'private synthetic key',
    task: slots[0],
    snapshot: slots[1],
  };
  const projected = projectJournalAllocations(protectedJournals[0].directory, raw);
  assert.equal(projected[1].retained_state, 'outcome_unknown');
  assert.ok(!JSON.stringify(projected).includes('private synthetic key'));
  const changed = structuredClone(raw);
  changed.snapshot.result.repo_id = 'f'.repeat(16);
  assert.throws(
    () => projectJournalAllocations(protectedJournals[0].directory, changed),
    /protected_journal_identity_changed/,
  );
  assert.throws(
    () => journalAllocations(protectedJournals[0].directory, Buffer.from(JSON.stringify(raw))),
    /protected_journal_changed/,
  );
});
