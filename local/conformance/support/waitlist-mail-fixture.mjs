// Test-only mail sink: no remote email binding or real recipients.
import Op from '../../../crates/worker/build/worker/shim.mjs';
export default class MailFixture extends Op {
  constructor(ctx, env) {
    super(ctx, {
      ...env,
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
