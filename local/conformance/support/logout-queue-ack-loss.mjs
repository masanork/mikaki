import RustWorker from '../../../crates/worker/build/worker/shim.mjs';

let sourceAttempts = 0;
let deadLetterMessages = 0;

export default class LogoutQueueAckLossFixture extends RustWorker {
  async fetch(request, env, context) {
    const url = new URL(request.url);
    if (url.pathname === '/__test/queue-observations') {
      return Response.json({ sourceAttempts, deadLetterMessages });
    }
    return super.fetch(request, env, context);
  }

  async queue(batch, env, context) {
    if (batch.queue.endsWith('-dlq-local')) {
      deadLetterMessages += batch.messages.length;
      batch.ackAll();
      return;
    }

    sourceAttempts++;
    const messages = batch.messages.map(
      (message) =>
        new Proxy(message, {
          get(target, property) {
            if (property === 'ack') return () => {};
            const value = Reflect.get(target, property, target);
            return typeof value === 'function' ? value.bind(target) : value;
          },
        }),
    );
    const unacknowledgedBatch = new Proxy(batch, {
      get(target, property) {
        if (property === 'messages') return messages;
        const value = Reflect.get(target, property, target);
        return typeof value === 'function' ? value.bind(target) : value;
      },
    });

    // Run the real Rust consumer and let all D1 / RP side effects finish, then
    // simulate a consumer crash before the Queue acknowledgement is committed.
    await super.queue(unacknowledgedBatch, env, context);
    throw new Error('injected logout Queue acknowledgement loss');
  }
}
