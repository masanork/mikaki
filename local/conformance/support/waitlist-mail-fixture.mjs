// Test-only mail sink: no remote email binding or real recipients.
import Op from '../../../crates/worker/build/worker/shim.mjs';
export default class MailFixture extends Op {
  constructor(ctx, env) {
    super(ctx, {
      ...env,
      DB: new Proxy(env.DB, {
        get(target, property) {
          if (property === 'batch')
            return async (statements) => {
              if (
                await target
                  .prepare('SELECT revoke_before_batch FROM fixture_mail_control WHERE id=1')
                  .first('revoke_before_batch')
              ) {
                await target.batch([
                  target.prepare("UPDATE account_role SET active=0 WHERE role='admin'"),
                  target.prepare(
                    'UPDATE fixture_mail_control SET revoke_before_batch=0 WHERE id=1',
                  ),
                ]);
              }
              return target.batch(statements);
            };
          const value = Reflect.get(target, property, target);
          return typeof value === 'function' && property !== 'constructor'
            ? value.bind(target)
            : value;
        },
      }),
      ENROLLMENT_EMAIL: {
        async send(message) {
          const fail = await env.DB.prepare(
            'SELECT fail FROM fixture_mail_control WHERE id=1',
          ).first('fail');
          if (fail) throw new Error('Fixture provider unavailable');
          const messageId = crypto.randomUUID();
          await env.DB.prepare('INSERT INTO fixture_mail_capture(id,message) VALUES(?1,?2)')
            .bind(messageId, JSON.stringify(message))
            .run();
          return { messageId };
        },
      },
    });
  }
}
