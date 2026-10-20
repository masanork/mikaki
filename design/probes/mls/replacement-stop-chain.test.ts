import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { test } from 'node:test';
import {
  replacementStopRecoveries,
  replacementRecoveryLink,
  recoveryReplaced,
  type ReplacementInfo,
  type ReplacementStopInfo,
} from './replacement-types.ts';
import type { InvitationOffer, RecoveryInfo } from './delivery-types.ts';
const opaque = () => randomBytes(32).toString('base64url');
function sample() {
  const a = { scope: opaque(), fingerprint: opaque() },
    b = { scope: opaque(), fingerprint: opaque() },
    c = { scope: opaque(), fingerprint: opaque() };
  const offer = (endpoints: (typeof a)[]): InvitationOffer => {
    const [a, b] = [...endpoints].sort((a, b) => (a.scope < b.scope ? -1 : 1));
    return {
      channel: { id: randomUUID(), group: randomBytes(16).toString('base64url'), a, b },
      inviter_scope: a.scope,
    };
  };
  const previous = offer([a, b]),
    next = offer([a, c]),
    child = offer([a, c]);
  const replacements: ReplacementInfo[] = [
    { previous, next, operation_id: randomUUID(), phase: 'abandoned', abandoned: [] },
  ];
  const recoveries: RecoveryInfo[] = [
    {
      offer: next,
      operation_id: randomUUID(),
      reason: 'cancel_invitation',
      phase: 'closed',
      next: child,
      successor_failed: true,
      replacement_id: next.channel.id,
      inbox_ids: [],
      abandoned: [],
    },
    {
      offer: child,
      operation_id: randomUUID(),
      reason: 'cancel_invitation',
      phase: 'closed',
      next: null,
      deferred_from: next.channel.id,
      inbox_ids: [],
      abandoned: [],
    },
  ];
  const stop: ReplacementStopInfo = {
    previous,
    next,
    operation_id: randomUUID(),
    phase: 'stopped',
    recovery_id: recoveries[0].operation_id,
    recovery_chain: recoveries.map((r) => r.operation_id),
    abandoned: [],
  };
  const value = { previous, next, child, replacements, recoveries, stop };
  // Journal descriptors cross a JSON boundary; mutations must not share refs.
  return JSON.parse(JSON.stringify(value)) as typeof value;
}
test('exact confirmed deferred closes resolve only after their linked retirement, including later unrelated recovery records', () => {
  const p = sample();
  assert.deepEqual(replacementRecoveryLink(p.previous, p.next, p.recoveries, p.replacements), {
    recovery_id: p.stop.recovery_id,
    recovery_chain: p.stop.recovery_chain,
  });
  assert.deepEqual(replacementStopRecoveries(p.stop, p.recoveries, p.replacements), p.recoveries);
  for (const recovery of p.recoveries)
    assert.equal(recoveryReplaced(recovery, p.replacements, [p.stop], p.recoveries), false);
  p.stop.phase = 'retired';
  for (const recovery of p.recoveries)
    assert.equal(recoveryReplaced(recovery, p.replacements, [p.stop], p.recoveries), true);
  const later: RecoveryInfo = {
    ...structuredClone(p.recoveries[1]),
    operation_id: randomUUID(),
    offer: {
      ...p.child,
      channel: {
        ...p.child.channel,
        id: randomUUID(),
        group: randomBytes(16).toString('base64url'),
      },
    },
  };
  delete later.deferred_from;
  p.recoveries.push(later);
  assert.equal(recoveryReplaced(later, p.replacements, [p.stop], p.recoveries), false);
  assert.equal(replacementStopRecoveries(p.stop, p.recoveries, p.replacements).length, 2);
});
test('older single-root links remain readable without a chain field', () => {
  const p = sample();
  p.recoveries.length = 1;
  p.recoveries[0].next = null;
  delete p.recoveries[0].successor_failed;
  delete p.stop.recovery_chain;
  assert.equal(replacementStopRecoveries(p.stop, p.recoveries, p.replacements).length, 1);
  assert.deepEqual(replacementRecoveryLink(p.previous, p.next, p.recoveries, p.replacements), {
    recovery_id: p.stop.recovery_id,
  });
});
test('a different offer cannot inherit a retired close through a reused operation UUID', () => {
  const p = sample();
  p.stop.phase = 'retired';
  for (const original of p.recoveries) {
    const unrelated: RecoveryInfo = {
      ...structuredClone(original),
      offer: {
        ...structuredClone(p.previous),
        channel: {
          ...structuredClone(p.previous.channel),
          id: randomUUID(),
          group: randomBytes(16).toString('base64url'),
        },
      },
    };
    assert.equal(recoveryReplaced(unrelated, p.replacements, [p.stop], p.recoveries), false);
  }
});
const invalid: [string, (p: ReturnType<typeof sample>) => void][] = [
  [
    'missing root UUID',
    (p) => {
      delete p.stop.recovery_id;
    },
  ],
  [
    'missing descendant declaration',
    (p) => {
      delete p.stop.recovery_chain;
    },
  ],
  [
    'reversed UUID order',
    (p) => {
      p.stop.recovery_chain!.reverse();
    },
  ],
  [
    'duplicate UUID',
    (p) => {
      p.stop.recovery_chain![1] = p.stop.recovery_chain![0];
    },
  ],
  [
    'unknown close',
    (p) => {
      p.stop.recovery_chain![1] = randomUUID();
    },
  ],
  [
    'unconfirmed child close',
    (p) => {
      p.recoveries[1].phase = 'closing';
    },
  ],
  [
    'already activated child',
    (p) => {
      p.recoveries[1].phase = 'rejoined';
    },
  ],
  [
    'pending child proposal',
    (p) => {
      p.recoveries[1].next = structuredClone(p.previous);
    },
  ],
  [
    'failed child without retained descendant',
    (p) => {
      p.recoveries[1].successor_failed = true;
    },
  ],
  [
    'missing parent failure',
    (p) => {
      delete p.recoveries[0].successor_failed;
    },
  ],
  [
    'missing deferred link',
    (p) => {
      delete p.recoveries[1].deferred_from;
    },
  ],
  [
    'wrong deferred link',
    (p) => {
      p.recoveries[1].deferred_from = randomUUID();
    },
  ],
  [
    'changed child endpoints',
    (p) => {
      p.recoveries[1].offer.channel.a.fingerprint = opaque();
    },
  ],
  [
    'unrelated root descriptor',
    (p) => {
      p.stop.next.inviter_scope = opaque();
    },
  ],
  [
    'unrelated replacement',
    (p) => {
      p.replacements[0].previous.channel.group = opaque();
    },
  ],
  [
    'unclosed replacement',
    (p) => {
      p.replacements[0].phase = 'recovering';
    },
  ],
  [
    'duplicate group',
    (p) => {
      p.recoveries[1].offer.channel.group = p.next.channel.group;
    },
  ],
  [
    'pending veto',
    (p) => {
      p.recoveries[0].cancellations = [
        { next: p.child, operation_id: randomUUID(), outcome: 'pending' },
      ];
    },
  ],
  [
    'unrelated admitted veto',
    (p) => {
      p.recoveries[0].cancellations = [
        { next: p.previous, operation_id: randomUUID(), outcome: 'admitted' },
      ];
    },
  ],
];
for (const [name, change] of invalid)
  test(`reject deferred stop link: ${name}`, () => {
    const p = structuredClone(sample());
    change(p);
    assert.deepEqual(replacementStopRecoveries(p.stop, p.recoveries, p.replacements), []);
    p.stop.phase = 'retired';
    assert.equal(recoveryReplaced(p.recoveries[1], p.replacements, [p.stop], p.recoveries), false);
  });
test('an admitted veto remains linked only to the exact subsequently closed child', () => {
  const p = sample();
  p.recoveries[0].cancellations = [
    { next: p.child, operation_id: randomUUID(), outcome: 'admitted' },
  ];
  assert.equal(replacementStopRecoveries(p.stop, p.recoveries, p.replacements).length, 2);
});
