/** Foreground one-to-one product UI. The host supplies an opened Vault device
 * with explicit, witnessed peer-key review. No enrollment or polling. */
import { walletPresentationLink } from './wallet-presentation.ts';
import type { VaultMlsDevice } from './vault-device.js';
import {
  replacement,
  replacementCode,
  parseReplacementCode,
  replacementStopRecoveries,
  replacementRecoveryLink,
  recoveryReplaced,
} from './replacement-types.ts';
import type { ChatSnapshot } from './device-store.js';
import { contactCode, parseContactCode, type VerifiedDevice } from './peer-review.ts';
import {
  invitation,
  encode,
  decode,
  rejoinChain,
  type InvitationOffer,
  type InvitationProgress,
} from './delivery-types.ts';

const PREFIX = 'mikaki-chat-v1:';
export function invitationCode(value: InvitationOffer): string {
  return PREFIX + encode(new TextEncoder().encode(JSON.stringify(invitation(value))));
}
export function parseInvitationCode(code: string): InvitationOffer {
  if (!code.startsWith(PREFIX) || code.length > 4096) throw new Error('invalid_invitation_code');
  try {
    return invitation(
      JSON.parse(
        new TextDecoder('utf-8', { fatal: true }).decode(decode(code.slice(PREFIX.length))),
      ) as InvitationOffer,
    );
  } catch {
    throw new Error('invalid_invitation_code');
  }
}
const equal = (a: InvitationOffer, b: InvitationOffer) => JSON.stringify(a) === JSON.stringify(b);
const phases: Record<InvitationProgress['phase'] | 'cancelled', string> = {
  waiting_peer: '相手の承認を待っています。',
  proposal_cancelled:
    '相手が再参加案を取り消しました。この案の取り消しを確認して、別のコードを選び直してください。',
  recovery_required:
    '参加を完了できません。招待が停止済み、または期限切れです。停止を確認して、新しい会話への参加をやり直してください。',
  cancelled:
    'この切り替え案は中止済みです。旧会話は停止したままです。別案を確認して、改めて承認してください。',
  waiting_key_package: '相手の参加準備を待っています。',
  waiting_welcome: '招待への参加を待っています。',
  waiting_activation: '相手の参加完了を待っています。',
  active: '会話を開始できます。',
  pending: '準備中です。「同期」で続きを進めてください。',
};
const receiveFailure =
  'メッセージを検証できず、同期を停止しました。相手と状況を確認し、必要なら会話を停止して再参加してください。';
const errors: Record<string, string> = {
  replacement_stop_unavailable:
    '双方の承認済みの参加先を確認できません。停止するコードと現在の端末情報を確認してください。',
  replacement_stop_unconfirmed:
    '停止の確認ができません。送信を停止したまま、同じ停止操作を再試行してください。',
  replacement_stop_conflict: '保存済みの停止対象と一致しません。元の停止操作を再試行してください。',
  replacement_stop_receipt_mismatch:
    '停止の応答が保存した対象と一致しません。送信は再開せず、同じ操作を再試行してください。',
  replacement_origin_advanced:
    'この端末は参加処理が進んでいます。現在の会話の停止操作を使ってください。',
  rejoin_cancellation_pending: '取り消しの結果を確認中です。同じ取り消し操作を再試行してください。',
  rejoin_cancellation_conflict:
    '保存済みの取り消し操作と一致しません。元の操作を再試行してください。',
  rejoin_cancellation_unconfirmed:
    '取り消しを確認できません。元の会話は停止したまま、同じ操作を再試行してください。',
  rejoin_cancellation_ledger_full: '再参加案の取り消し記録が保存上限に達しました。',
  rejoin_cancelled: '取り消した再参加案は再利用できません。別のコードを確認してください。',
  replacement_predecessor_unavailable:
    '元の参加者と現在の端末鍵の対応を確認できません。最新の端末情報を確認してください。',
  replacement_cancelled: '中止した切り替え案は再利用できません。新しい案を確認してください。',
  replacement_cancellation_pending: '中止の結果を確認中です。同じ操作を再試行してください。',
  replacement_cancellation_unconfirmed:
    '中止の確認ができません。旧会話は停止したまま、同じ中止操作を再試行してください。',
  replacement_status_unavailable:
    '切り替え案や端末の状態を確認できません。最新の端末情報を確認してください。',
  replacement_already_active: 'この会話は参加済みです。会話の停止操作を使ってください。',
  replacement_already_closed: 'この会話はすでに停止しています。送信は再開できません。',
  replacement_unconfirmed_or_denied:
    '鍵切り替えを確認できません。双方の同じコードと現在の端末状態を確認して再試行してください。',
  replacement_authority_changed:
    '端末やアカウントの状態が変わりました。新しい登録情報を確認してください。',
  replacement_roster_mismatch: '以前の会話と新しい端末鍵の組み合わせを確認できません。',
  invalid_replacement_code: '鍵切り替えコードを確認してください。',
  invalid_channel_replacement: '一方の端末鍵だけを変更した、新しい会話のコードが必要です。',
  replacement_intent_conflict:
    '承認済みの鍵切り替えコードと異なります。双方で同じコードを確認してください。',
  replacement_conflict_or_limit:
    '鍵切り替えの条件または保存上限を確認できません。双方のコードと端末を確認してください。',
  invalid_invitation_code: '招待コードを確認してください。',
  chat_offer_scope: 'この端末に宛てた招待ではありません。',
  chat_offer_peer: '確認済みの相手・端末と一致しません。',
  invitation_conflict: '別の招待を同時に承認できません。',
  rejoin_intent_conflict:
    '承認済みの再参加コードと異なります。双方で同じコードを確認してください。',
  channel_conflict: '別の会話案と競合しています。双方で承認したコードを確認してください。',
  invalid_channel_successor: '停止した会話と同じ端末の、新しい再参加コードが必要です。',
  mls_receive_rejected: receiveFailure,
  message_rejected: receiveFailure,
  rejoin_conflict_or_limit:
    '別の再参加案との競合、または保存上限により進めません。双方のコードと端末の状態を確認してください。',
  invitation_precondition_or_limit:
    '招待の参加条件を満たしていないか、保存上限に達しています。相手と端末の状態を確認してください。',
  invitation_conflict_or_limit:
    '別の招待との競合、または保存上限により進めません。承認したコードを確認してください。',
  commit_pending:
    '鍵の更新が完了していません。同期を再試行し、解消しない場合は相手と復旧を確認してください。',
  conversation_frozen: '会話は停止しています。送信できません。',
  chat_not_active: '双方の参加が完了するまで送信できません。',
  chat_history_full: 'この端末の送信履歴が上限に達しました。',
  operation_ledger_full: 'この端末の操作記録が上限に達しました。',
  recovery_ledger_full: 'この端末の再参加回数が上限に達しました。',
  invitation_expired_recovery_required:
    '招待の有効期限が切れました。相手と確認して会話を停止し、再参加してください。',
  invalid_peer_contact: '端末コードを確認してください。',
  fingerprint_mismatch: '入力した指紋が一致しません。別の連絡手段で相手に確認してください。',
  peer_review_changed: '確認内容が別の操作で更新されました。最新の端末コードを確認してください。',
  unexpected_peer: 'この会話の相手とは異なるアカウント・端末のコードです。',
  invalid_signature: '端末情報の署名を確認できません。コードを相手に確認してください。',
  untrusted_issuer: 'このサービスの署名鍵は信頼設定に含まれていません。',
  untrusted_issuer_key: 'このサービスの署名鍵は信頼設定と一致しません。',
  binding_not_current:
    'ご自身または相手の端末情報の有効期限を確認できません。自分の端末コードを表示し直し、相手にも新しいコードを依頼してください。',
  first_trust_required: '相手の端末・鍵の確認を完了してください。',
  device_revoked: 'この端末の鍵は失効しています。送信を再開できません。',
  device_key_changed: '相手の鍵が変更されています。新しい指紋の確認が必要です。',
  device_key_mismatch: '確認済みの鍵と、会話に参加している鍵が一致しません。',
  registry_conflict: '同じ登録情報に異なる鍵が見つかりました。この画面では承認できません。',
  invalid_key_change:
    'この鍵への変更は承認できません。最新の端末コードと指紋を相手に確認してください。',
  stale_binding: '以前の端末情報には戻せません。相手に最新のコードを依頼してください。',
};

function node<K extends keyof HTMLElementTagNameMap>(tag: K, text = ''): HTMLElementTagNameMap[K] {
  const result = document.createElement(tag);
  result.textContent = text;
  return result;
}

/** Owns this device handle. dispose/lock/hidden-page destroys all displayed
 * plaintext synchronously; an in-flight result cannot repaint the view. */
export class MlsChatView {
  readonly #root: HTMLElement;
  readonly #device: VaultMlsDevice;
  readonly #heading: 'h1' | 'h2';
  #unsubscribe: (() => void) | undefined;
  #snapshot: ChatSnapshot | undefined;
  #proposal: InvitationOffer | undefined;
  #replacementProposal: { previous: InvitationOffer; next: InvitationOffer } | undefined;
  #stopProposal: { previous: InvitationOffer; next: InvitationOffer } | undefined;
  #draft = '';
  readonly #onDraft: ((dirty: boolean) => void) | undefined;
  #pending: { id: string; text: string; offer: InvitationOffer } | undefined;
  #busy = false;
  #closed = false;
  #blocked = false;
  #notice = '';
  #error = '';
  #confirmStop = false;
  #stopReason: 'leave' | 'epoch_conflict' | 'cancel_invitation' = 'leave';
  #ownCode = '';
  #pendingReview:
    { operation: string; id: string; previous: string; fingerprint: string } | undefined;

  constructor(
    root: HTMLElement,
    device: VaultMlsDevice,
    offer?: InvitationOffer,
    embedded = false,
    onDraft?: (dirty: boolean) => void,
  ) {
    this.#onDraft = onDraft;
    this.#root = root;
    this.#device = device;
    this.#heading = embedded ? 'h2' : 'h1';
    this.#proposal = offer ? invitation(offer) : undefined;
    this.#unsubscribe = device.onClose(this.#locked);
    this.#render();
  }
  async open(): Promise<void> {
    await this.#run(async () => {
      await this.#refresh();
      if (this.#proposal) {
        try {
          this.#checkOffer(this.#proposal);
        } catch (error) {
          this.#proposal = undefined;
          throw error;
        }
      }
      if (
        this.#snapshot?.invitation?.phase === 'active' &&
        (!this.#recovery() || this.#recovery()?.phase === 'rejoined')
      )
        await this.#sync();
    });
  }
  hasDrafts(): boolean {
    return !!this.#draft || !!this.#pending || !!this.#pendingReview;
  }
  readonly dispose = (): void => {
    this.#device.close();
    this.#locked();
  };
  readonly #locked = (): void => {
    this.#closed = true;
    this.#snapshot = undefined;
    this.#proposal = undefined;
    this.#replacementProposal = undefined;
    this.#stopProposal = undefined;
    this.#pending = undefined;
    this.#draft = '';
    this.#onDraft?.(false);
    this.#error = '';
    this.#notice = '';
    this.#ownCode = '';
    this.#pendingReview = undefined;
    this.#unsubscribe?.();
    this.#unsubscribe = undefined;
    this.#root.replaceChildren(node('p', 'チャットをロックしました。Vaultを開き直してください。'));
  };
  async #refresh(): Promise<void> {
    const snapshot = await this.#device.chatSnapshot();
    if (!this.#closed) {
      this.#snapshot = snapshot;
      if (
        this.#proposal &&
        snapshot.recoveries.some((r) =>
          r.cancellations?.some(
            (c) => c.outcome === 'cancelled' && c.next.channel.id === this.#proposal!.channel.id,
          ),
        )
      )
        this.#proposal = undefined;
      if (
        this.#replacementProposal &&
        snapshot.replacements.some(
          (r) =>
            r.phase === 'cancelled' &&
            r.next.channel.id === this.#replacementProposal!.next.channel.id,
        )
      )
        this.#replacementProposal = undefined;
      if (
        this.#pendingReview &&
        (snapshot.peer_review?.id !== this.#pendingReview.id ||
          snapshot.trust.peer?.accepted.fingerprint === this.#pendingReview.fingerprint)
      )
        this.#pendingReview = undefined;
    }
  }
  async #run(action: () => Promise<void>): Promise<void> {
    if (this.#busy || this.#closed) return;
    this.#busy = true;
    this.#error = '';
    this.#render();
    try {
      await action();
    } catch (error) {
      if (!this.#closed) {
        const code = error instanceof Error ? error.message : '';
        this.#error =
          errors[code] ??
          '操作を完了できませんでした。通信・端末の状態を確認し、同じ操作を再試行してください。';
      }
    } finally {
      if (!this.#closed) {
        try {
          await this.#refresh();
        } catch {
          // An unverified/stale view must never continue offering send actions.
          this.#snapshot = undefined;
          this.#blocked = true;
          this.#error = '端末の状態を確認できません。「状態を再確認」を押してください。';
        }
        if (!this.#closed) {
          this.#busy = false;
          this.#render();
        }
      }
    }
  }
  #checkOffer(offer: InvitationOffer): void {
    const snapshot = this.#snapshot;
    if (!snapshot) throw new Error('chat_not_open');
    const own = [offer.channel.a, offer.channel.b].find((e) => e.scope === snapshot.own.scope);
    if (!own || own.fingerprint !== snapshot.own.fingerprint) throw new Error('chat_offer_scope');
    const recovery = this.#recovery();
    if (
      snapshot.recoveries.some((r) =>
        r.cancellations?.some(
          (c) =>
            c.outcome === 'cancelled' &&
            (c.next.channel.id === offer.channel.id ||
              c.next.channel.group === offer.channel.group),
        ),
      )
    )
      throw new Error('rejoin_cancelled');
    if (recovery && recovery.phase !== 'rejoined') {
      const old = recovery.offer.channel,
        next = offer.channel;
      if (
        JSON.stringify(old.a) !== JSON.stringify(next.a) ||
        JSON.stringify(old.b) !== JSON.stringify(next.b)
      )
        throw new Error('chat_offer_peer');
      if (old.id === next.id || old.group === next.group)
        throw new Error('invalid_channel_successor');
      if (recovery.next && !equal(recovery.next, offer)) throw new Error('rejoin_intent_conflict');
    } else if (snapshot.invitation && !equal(snapshot.invitation.offer, offer)) {
      throw new Error('invitation_conflict');
    }
  }
  async #sync(): Promise<void> {
    try {
      await this.#advance();
      this.#blocked = false;
    } catch (error) {
      this.#blocked = true;
      throw error;
    }
  }
  async #advance(): Promise<void> {
    const s = this.#snapshot;
    if (!s) return;
    const pending = s.replacements.at(-1);
    const stop = s.replacement_stops.at(-1);
    if (stop?.phase === 'stopping') {
      await this.#device.stopReplacement(stop.previous, stop.next);
      this.#notice =
        '参加先の停止を確認しました。最新の指紋と新しいコードを双方で確認してください。';
      return;
    }
    if (pending?.phase === 'recovering') {
      await this.#device.recoverReplacement(pending.previous, pending.next);
      this.#notice = '会話の停止を確認しました。新しい参加コードを双方で確認してください。';
      return;
    }
    if (pending && !['active', 'abandoned'].includes(pending.phase)) {
      this.#notice =
        phases[(await this.#device.syncReplacement(pending.previous, pending.next)).phase];
      return;
    }
    if (stop?.phase === 'stopped') return;
    const r = this.#recovery();
    if (r && r.phase !== 'rejoined') {
      if (r.phase === 'closing') {
        await this.#device.closeConversation(r.offer, r.reason);
        this.#notice = '会話の停止を確認しました。';
      } else if (r.next) {
        if (r.cancellations?.at(-1)?.outcome === 'pending') {
          this.#notice =
            (await this.#device.cancelRejoin(r.offer, r.next)) === 'cancelled'
              ? '再参加案を取り消しました。別のコードを確認して承認してください。'
              : '双方の承認が成立しています。同期で参加するか、再参加先を停止してください。';
        } else this.#notice = phases[(await this.#device.syncRejoin(r.offer, r.next)).phase];
      }
    } else if (s.invitation) {
      if (s.invitation.phase !== 'active') {
        // A saved explicit consent may precede a failed HTTP request.
        if (
          !s.recoveries.some((r) => r.next && equal(r.next, s.invitation!.offer)) &&
          !s.replacements.some((r) => equal(r.next, s.invitation!.offer))
        )
          await this.#device.approveInvitation(s.invitation.offer);
        this.#notice = phases[(await this.#device.syncInvitation(s.invitation.offer)).phase];
      } else {
        const result = await this.#device.syncDelivery(s.invitation.offer.channel);
        this.#notice = `同期しました。送信 ${result.sent} 件、受信 ${result.received} 件。`;
      }
    }
  }
  async #send(): Promise<void> {
    const offer = this.#snapshot?.invitation?.offer;
    if (!offer || !this.#draft.trim()) return;
    if (new TextEncoder().encode(this.#draft).length > 4096) {
      this.#error = '本文はUTF-8で4,096バイト以内にしてください。';
      return;
    }
    this.#pending ??= { id: crypto.randomUUID(), text: this.#draft, offer };
    const pending = this.#pending;
    const receipt = await this.#device.sendText(pending.id, pending.offer.channel, pending.text);
    // A returned rejection is durable and did not enqueue a message. A thrown
    // response is ambiguous: retain the exact operation and text until retry.
    this.#pending = undefined;
    if (!receipt.ok) throw new Error(receipt.error ?? 'send_failed');
    this.#draft = '';
    this.#onDraft?.(false);
    await this.#refresh();
    await this.#sync();
  }
  #button(label: string, action: () => Promise<void>, disabled = false): HTMLButtonElement {
    const b = node('button', label);
    b.type = 'button';
    b.disabled = this.#busy || disabled;
    b.addEventListener('click', () => void this.#run(action));
    return b;
  }
  #code(parent: HTMLElement, offer: InvitationOffer): void {
    const label = node('label', '共有する招待コード');
    const code = node('textarea');
    code.readOnly = true;
    code.rows = 3;
    code.value = invitationCode(offer);
    label.append(code);
    parent.append(
      label,
      node('p', 'この公開コードを相手に伝え、同じ会話と指紋を確認してから双方で承認してください。'),
    );
  }
  #render(): void {
    if (this.#closed) return;
    this.#onDraft?.(this.hasDrafts());
    const panel = node('section');
    panel.className = 'mls-chat';
    panel.setAttribute('aria-label', '暗号化チャット');
    panel.setAttribute('aria-busy', String(this.#busy));
    panel.append(
      node(this.#heading, '暗号化チャット'),
      node('p', '1対1のテキスト会話 · 限定ベータ'),
    );
    const status = node('p', this.#notice);
    status.setAttribute('role', 'status');
    const error = node('p', this.#error);
    error.setAttribute('role', 'alert');
    panel.append(status, error);
    const s = this.#snapshot;
    if (!s) {
      panel.append(this.#button('状態を再確認', () => this.#refresh()));
      this.#root.replaceChildren(panel);
      return;
    }
    const recovery = this.#recovery();
    const pending = s.replacements.at(-1);
    const stopping = s.replacement_stops.some((s) => s.phase !== 'retired');
    const replacing = !!pending && !['active', 'abandoned'].includes(pending.phase);
    const frozen = !!recovery && recovery.phase !== 'rejoined';
    const joined = !stopping && !replacing && !frozen && s.invitation?.phase === 'active';
    const trusted = this.#trusted();
    const active = joined && !this.#blocked && trusted;
    this.#peerPanel(panel);
    panel.append(
      node(
        'h2',
        replacing
          ? pending.phase === 'cancelled'
            ? '切り替え案は中止済みです'
            : '新しい鍵への切り替えを確認中'
          : frozen || stopping
            ? '会話は停止しています'
            : joined
              ? this.#blocked || !trusted
                ? '同期を停止しています'
                : '会話中'
              : '参加の確認',
      ),
    );
    if (stopping) {
      panel.append(
        node(
          'p',
          '旧会話と停止した参加先には送信できません。最新の指紋と新しいコードを双方で確認してください。',
        ),
      );
    } else if (frozen) {
      panel.append(
        node(
          'p',
          recovery.phase === 'closing'
            ? '停止の確認中です。送信は停止済みです。'
            : 'この会話には送信できません。',
        ),
      );
      panel.append(
        node(
          'p',
          '受信履歴は残ります。送信待ちの暗号文は、新しい会話に自動で転送しません。以前の送信が相手に届いている場合もあります。',
        ),
      );
    } else if (!joined && s.invitation) {
      panel.append(
        node(
          'p',
          '双方の承認・参加が完了するまで送信できません。「同期」で参加状況を確認してください。',
        ),
      );
    }
    panel.append(
      this.#button(
        recovery?.phase === 'closing' ? '停止の確認を再試行' : '同期',
        () => this.#sync(),
        (stopping &&
          s.replacement_stops.at(-1)?.phase === 'stopped' &&
          (!pending || ['active', 'abandoned', 'cancelled'].includes(pending.phase))) ||
          (!stopping &&
            !replacing &&
            (!s.invitation || (frozen && recovery.phase === 'closed' && !recovery.next))),
      ),
    );
    if (s.invitation && !frozen && !replacing) {
      const details = node('details');
      details.append(node('summary', '会話と指紋を確認'));
      this.#reviewDetails(details, s.invitation.offer);
      this.#code(details, s.invitation.offer);
      panel.append(details);
    }
    this.#history(panel, s);
    const form = node('form');
    const label = node('label', 'メッセージ');
    const draft = node('textarea');
    draft.value = this.#draft;
    draft.rows = 3;
    draft.maxLength = 4096;
    draft.disabled = !active || this.#busy || !!this.#pending;
    draft.addEventListener('input', () => {
      this.#draft = draft.value;
      this.#onDraft?.(this.hasDrafts());
    });
    label.append(draft);
    const send = node('button', this.#pending ? '同じ送信を再試行' : '送信');
    send.type = 'submit';
    send.disabled = !active || this.#busy;
    form.addEventListener('submit', (event) => {
      event.preventDefault();
      void this.#run(() => this.#send());
    });
    form.append(
      label,
      send,
      node(
        'p',
        '下書きは保存しません。送信後の本文と受信履歴は、この端末のVaultで暗号化して保持します。',
      ),
    );
    panel.append(form);
    this.#replacementReview(panel);
    this.#stoppedReplacementReview(panel);
    if (!stopping && s.invitation && !frozen && !replacing) this.#termination(panel, !!joined);
    if (!stopping && !replacing && (!s.invitation || (frozen && recovery.phase === 'closed')))
      this.#invitationReview(panel);
    const lock = this.#button('チャットをロック', async () => this.dispose());
    // Lock remains available while a network request is pending.
    lock.disabled = false;
    panel.append(lock);
    this.#root.replaceChildren(panel);
  }
  #reviewDetails(parent: HTMLElement, offer: InvitationOffer): void {
    const own = this.#snapshot!.own.scope;
    const peer = offer.channel.a.scope === own ? offer.channel.b : offer.channel.a;
    const list = node('dl');
    for (const [label, value] of [
      ['会話ID', offer.channel.id],
      ['あなたの指紋', this.#snapshot!.own.fingerprint],
      ['相手の指紋', peer.fingerprint],
      ['招待する側', offer.inviter_scope === own ? 'あなた' : '相手'],
    ])
      list.append(node('dt', label), node('dd', value));
    parent.append(list);
  }
  #trusted(): boolean {
    return this.#snapshot?.trust.peer?.state === 'current' && this.#snapshot.trust.group_usable;
  }
  #verifiedDetails(parent: HTMLElement, value: VerifiedDevice): void {
    const list = node('dl');
    for (const [label, text] of [
      ['サービス', value.device.issuer],
      ['アカウントID', value.device.account_id],
      ['端末ID', value.device.device_id],
      ['鍵の世代', String(value.device.generation)],
      ['登録の更新番号', String(value.revision)],
      ['指紋', value.fingerprint],
      ['登録状態', value.status === 'active' ? '有効' : '失効'],
      ['コードの有効期限', new Date(value.expires_at * 1000).toLocaleString('ja-JP')],
    ])
      list.append(node('dt', label), node('dd', text));
    parent.append(list);
  }
  #peerPanel(panel: HTMLElement): void {
    const s = this.#snapshot!,
      peer = s.trust.peer,
      review = s.peer_review;
    const details = node('details');
    details.open = !this.#trusted();
    const state = peer?.state ?? 'unconfirmed';
    const labels = {
      unconfirmed: '未確認',
      current: s.trust.group_usable ? '確認済み' : '鍵は確認済み・会話の更新が必要',
      key_changed: '鍵の変更を検知・送信停止',
      revoked: '失効を検知・送信停止',
      registry_conflict: '登録情報の不整合・送信停止',
      expired: '確認情報の期限切れ・送信停止',
    };
    details.append(node('summary', `相手の端末・鍵：${labels[state]}`));
    details.append(
      node(
        'p',
        '署名の検証と相手本人の確認は別です。会う・電話するなど、別の連絡手段で指紋を確認して入力してください。',
      ),
    );
    if (peer) {
      details.append(node('h2', '確認済みの相手の鍵'));
      this.#verifiedDetails(
        details,
        state === 'current' || state === 'expired' ? peer.latest : peer.accepted,
      );
      if (!s.trust.group_usable && state === 'current')
        details.append(
          node(
            'p',
            '新しい鍵は確認済みですが、古い会話には送信できません。同じ鍵の再参加では復旧できません。新しい鍵を会話へ参加させる手続きが必要です。',
          ),
        );
    }
    details.append(node('p', `あなたの指紋：${s.own.fingerprint}`));
    details.append(
      this.#button('自分の端末コードを表示', async () => {
        this.#ownCode = contactCode(await this.#device.ownContact());
      }),
    );
    if (this.#ownCode) {
      const label = node('label', '自分の端末コード');
      const code = node('textarea');
      code.readOnly = true;
      code.rows = 3;
      code.value = this.#ownCode;
      label.append(code);
      details.append(
        label,
        node(
          'p',
          '端末コードは短時間で期限が切れます。期限切れの場合は表示し直してください。指紋は別の連絡手段で伝えてください。',
        ),
      );
    }
    const form = node('form'),
      label = node('label', '相手の端末コード'),
      input = node('textarea');
    input.rows = 3;
    input.maxLength = 8192;
    input.disabled = this.#busy || !!this.#pendingReview;
    label.append(input);
    const inspect = node('button', '署名を検証して確認内容を表示');
    inspect.type = 'submit';
    inspect.disabled = this.#busy || !!this.#pendingReview;
    form.append(label, inspect);
    form.addEventListener('submit', (event) => {
      event.preventDefault();
      const value = input.value.trim();
      void this.#run(async () => {
        await this.#device.stagePeer(parseContactCode(value));
        this.#notice =
          '署名を検証し、確認内容を保存しました。相手の指紋を別の連絡手段で確認してください。';
      });
    });
    details.append(form);
    if (
      review &&
      (!peer ||
        peer.state !== 'current' ||
        peer.accepted.fingerprint !== review.verified.fingerprint ||
        this.#pendingReview)
    ) {
      details.append(node('h2', '署名を検証した端末情報'));
      this.#verifiedDetails(details, review.verified);
      const expired = review.verified.expires_at <= Math.floor(Date.now() / 1000);
      const conflict = review.observation === 'registry_conflict';
      const changed = !!peer && peer.accepted.fingerprint !== review.verified.fingerprint;
      const needsApproval =
        (!peer || changed) &&
        (!peer ||
          (review.verified.device.generation > peer.accepted.device.generation &&
            review.verified.revision > peer.accepted.revision)) &&
        !expired &&
        review.verified.status === 'active' &&
        !conflict &&
        state !== 'revoked';
      if (expired)
        details.append(
          node('p', '確認待ちの端末コードは期限切れです。新しいコードを相手に依頼してください。'),
        );
      else if (conflict) details.append(node('p', errors.registry_conflict));
      else if (review.verified.status === 'revoked')
        details.append(node('p', errors.device_revoked));
      else if (
        changed &&
        peer &&
        review.verified.device.generation <= peer.accepted.device.generation
      )
        details.append(
          node('p', '同じ世代の異なる鍵は承認できません。相手に正規の鍵更新を確認してください。'),
        );
      if (needsApproval || (this.#pendingReview && this.#pendingReview.id === review.id)) {
        if (changed)
          details.append(
            node('p', '指紋の変更を承認しても、古い会話の鍵や未送信メッセージは引き継ぎません。'),
          );
        const approval = node('form'),
          label = node('label', '別の連絡手段で確認した相手の指紋'),
          expected = node('input');
        expected.type = 'text';
        expected.autocomplete = 'off';
        expected.maxLength = 43;
        expected.minLength = 43;
        expected.required = true;
        expected.pattern = '[A-Za-z0-9_\\-]{43}';
        expected.spellcheck = false;
        expected.value = this.#pendingReview?.fingerprint ?? '';
        expected.disabled = this.#busy || !!this.#pendingReview;
        label.append(expected);
        const button = node(
          'button',
          this.#pendingReview
            ? '同じ鍵確認を再試行'
            : changed
              ? '新しい指紋を確認して承認'
              : '指紋を確認して承認',
        );
        button.type = 'submit';
        button.disabled = this.#busy;
        approval.append(label, button);
        approval.addEventListener('submit', (event) => {
          event.preventDefault();
          const fingerprint = expected.value.trim();
          void this.#run(async () => {
            this.#pendingReview ??= {
              operation: crypto.randomUUID(),
              id: review.id,
              previous: peer?.accepted.fingerprint ?? 'unconfirmed',
              fingerprint,
            };
            const p = this.#pendingReview;
            const receipt = await this.#device.approvePeerReview(
              p.operation,
              p.id,
              p.previous,
              p.fingerprint,
            );
            this.#pendingReview = undefined;
            if (!receipt.ok) throw new Error(receipt.error ?? 'peer_review_failed');
            this.#notice = '指紋の確認を保存しました。会話の参加状態を確認してください。';
          });
        });
        details.append(approval);
      }
    }
    panel.append(details);
  }
  #recovery() {
    const s = this.#snapshot,
      r = s?.recoveries.at(-1);
    return r && !recoveryReplaced(r, s!.replacements, s!.replacement_stops, s!.recoveries)
      ? r
      : undefined;
  }
  #checkReplacement(previous: InvitationOffer, next: InvitationOffer): void {
    replacement(previous, next);
    const s = this.#snapshot!;
    const own = [next.channel.a, next.channel.b].find((e) => e.scope === s.own.scope);
    if (!own || own.fingerprint !== s.own.fingerprint) throw new Error('chat_offer_scope');
    const peer = own === next.channel.a ? next.channel.b : next.channel.a;
    if (s.trust.peer?.state !== 'current' || s.trust.peer.accepted.fingerprint !== peer.fingerprint)
      throw new Error('chat_offer_peer');
    const bridged = s.replacement_stops.some((stop) => {
      const chain = replacementStopRecoveries(stop, s.recoveries, s.replacements);
      return (
        stop.phase === 'stopped' &&
        equal(stop.previous, previous) &&
        ((stop.native_origin && !!s.invitation && equal(stop.next, s.invitation.offer)) ||
          (s.invitation?.phase === 'recovery_required' &&
            !!chain.length &&
            equal(chain.at(-1)!.offer, s.invitation.offer)))
      );
    });
    if (s.invitation && !equal(s.invitation.offer, previous) && !bridged)
      throw new Error('invitation_conflict');
    const saved = s.replacements.find((r) => r.next.channel.id === next.channel.id);
    if (saved && (!equal(saved.previous, previous) || !equal(saved.next, next)))
      throw new Error('replacement_intent_conflict');
    if (
      saved?.phase === 'cancelled' ||
      s.replacements.some(
        (r) => r.phase === 'cancelled' && r.next.channel.group === next.channel.group,
      )
    )
      throw new Error('replacement_cancelled');
    const latest = s.replacements.at(-1);
    if (
      latest &&
      latest.phase !== 'active' &&
      !(
        (latest.phase === 'abandoned' &&
          s.replacement_stops.some(
            (v) =>
              v.phase === 'stopped' && equal(v.previous, previous) && equal(v.next, latest.next),
          )) ||
        ((latest.phase === 'cancelled' || equal(latest.next, next)) &&
          equal(latest.previous, previous))
      )
    )
      throw new Error('replacement_intent_conflict');
    if (
      s.replacement_stops.some(
        (v) => v.next.channel.id === next.channel.id || v.next.channel.group === next.channel.group,
      )
    )
      throw new Error('retired_or_unexpected_group');
  }
  #replacementReview(panel: HTMLElement): void {
    const s = this.#snapshot!,
      saved = s.replacements.at(-1);
    const stop = s.replacement_stops.at(-1);
    if (stop?.phase === 'stopping') return;
    if (
      saved?.phase === 'active' &&
      replacement(saved.previous, saved.next).stable.scope === s.own.scope &&
      stop?.phase !== 'stopped' &&
      s.invitation &&
      equal(s.invitation.offer, saved.next) &&
      s.trust.peer?.state === 'current' &&
      s.trust.peer.accepted.fingerprint !==
        (saved.next.channel.a.scope === s.own.scope ? saved.next.channel.b : saved.next.channel.a)
          .fingerprint
    ) {
      const section = node('section');
      section.append(
        node('h2', '最新の鍵で参加し直す'),
        node(
          'p',
          'この参加先では相手の鍵が更新されています。参加先を停止し、新しい指紋とコードを双方で確認してください。以前の会話は再開しません。',
        ),
      );
      this.#reviewDetails(section, saved.next);
      this.#stopConfirmation(section, saved.previous, saved.next);
      panel.append(section);
      return;
    }
    if (saved?.phase === 'abandoned' && stop?.phase !== 'stopped') {
      const recovery = s.recoveries.at(-1);
      const link = replacementRecoveryLink(
        saved.previous,
        saved.next,
        s.recoveries,
        s.replacements,
      );
      const selectedPeer =
        saved.next.channel.a.scope === s.own.scope ? saved.next.channel.b : saved.next.channel.a;
      if (
        recovery &&
        s.trust.peer?.state === 'current' &&
        s.trust.peer.accepted.fingerprint !== selectedPeer.fingerprint &&
        s.invitation?.phase === 'recovery_required' &&
        equal(s.invitation.offer, recovery.offer) &&
        link
      ) {
        const section = node('section');
        section.append(
          node('h2', '最新の鍵で参加し直す'),
          node(
            'p',
            '以前の参加先の停止記録を保持しています。相手の鍵が更新されたため、最新の指紋と新しいコードを双方で確認して承認してください。',
          ),
        );
        this.#reviewDetails(section, saved.next);
        this.#closedTargets(
          section,
          replacementStopRecoveries(
            { previous: saved.previous, next: saved.next, ...link },
            s.recoveries,
            s.replacements,
          ).map((r) => r.offer),
        );
        this.#stopConfirmation(section, saved.previous, saved.next);
        panel.append(section);
      }
      return;
    }
    if (saved && !['active', 'cancelled', 'abandoned'].includes(saved.phase)) {
      const section = node('section');
      section.append(
        node('h2', '承認した鍵切り替え'),
        node(
          'p',
          '旧会話への送信を停止しています。相手にも同じコードの承認を依頼し、「同期」で続きを進めてください。',
        ),
      );
      const label = node('label', '共有する鍵切り替えコード'),
        code = node('textarea');
      code.readOnly = true;
      code.rows = 4;
      code.value = replacementCode(saved.previous, saved.next);
      label.append(code);
      section.append(label);
      this.#reviewDetails(section, saved.next);
      const selectedPeer =
        saved.next.channel.a.scope === s.own.scope ? saved.next.channel.b : saved.next.channel.a;
      if (
        s.trust.peer?.state === 'current' &&
        s.trust.peer.accepted.fingerprint !== selectedPeer.fingerprint
      )
        section.append(
          node(
            'p',
            '相手の鍵が更新されています。承認待ちの古い案を中止し、最新の指紋と新しいコードを双方で確認してください。',
          ),
        );
      if (
        saved.phase !== 'recovering' &&
        s.trust.peer?.state === 'current' &&
        s.trust.peer.accepted.fingerprint !== selectedPeer.fingerprint
      )
        this.#stopConfirmation(section, saved.previous, saved.next);
      section.append(
        node(
          'p',
          '双方が異なる案を選んだ場合は、現在の案を中止してから、相手と選び直した同じコードを確認してください。',
        ),
      );
      if (
        s.trust.peer?.state === 'current' &&
        s.trust.peer.accepted.fingerprint !== selectedPeer.fingerprint &&
        (saved.phase === 'recovery_required' || saved.cancellation?.outcome === 'admitted')
      ) {
        panel.append(section);
        return;
      }
      if (saved.phase === 'recovering') {
        section.append(
          node('p', '参加の停止を確認中です。「同期」で同じ停止操作を再試行できます。'),
        );
      } else if (
        saved.phase === 'recovery_required' ||
        saved.cancellation?.outcome === 'admitted'
      ) {
        section.append(
          node(
            'p',
            '双方の承認後でも、参加が完了しない場合はこの招待を停止してやり直せます。旧会話は再開しません。再参加には新しいコードへの双方の承認が必要です。',
          ),
        );
        const label = node('label'),
          check = node('input');
        check.type = 'checkbox';
        check.disabled = this.#busy;
        label.append(
          check,
          document.createTextNode('この招待を停止し、新しい会話への参加をやり直します'),
        );
        const stop = this.#button(
          '参加を停止してやり直す',
          async () => {
            if (!check.checked) return;
            this.#draft = '';
            this.#onDraft?.(false);
            this.#pending = undefined;
            this.#replacementProposal = undefined;
            await this.#device.recoverReplacement(saved.previous, saved.next);
            this.#notice = '参加を停止しました。新しい参加コードを双方で確認してください。';
          },
          true,
        );
        check.addEventListener('change', () => {
          stop.disabled = this.#busy || !check.checked;
        });
        section.append(label, stop);
      } else if (saved.phase === 'cancelling') {
        section.append(
          node('p', '中止の結果を確認中です。送信は停止したままです。'),
          this.#button('中止の確認を再試行', async () => {
            const outcome = await this.#device.cancelReplacement(saved.previous, saved.next);
            this.#notice =
              outcome === 'cancelled'
                ? phases.cancelled
                : '双方の承認が完了済みです。同期で参加を完了してから会話を停止してください。';
          }),
        );
      } else {
        const label = node('label'),
          check = node('input');
        check.type = 'checkbox';
        check.disabled = this.#busy;
        label.append(
          check,
          document.createTextNode('この切り替え案を中止し、旧会話を停止したままにします'),
        );
        const stop = this.#button(
          'この切り替え案を中止',
          async () => {
            if (!check.checked) return;
            this.#replacementProposal = undefined;
            this.#draft = '';
            this.#onDraft?.(false);
            this.#pending = undefined;
            const outcome = await this.#device.cancelReplacement(saved.previous, saved.next);
            this.#notice =
              outcome === 'cancelled'
                ? phases.cancelled
                : '双方の承認が完了済みです。同期で参加を完了してから会話を停止してください。';
          },
          true,
        );
        check.addEventListener('change', () => {
          stop.disabled = this.#busy || !check.checked;
        });
        section.append(label, stop);
      }
      panel.append(section);
      return;
    }
    const review = s.peer_review,
      peer = s.trust.peer;
    const old =
      stop?.phase === 'stopped'
        ? stop.previous
        : (s.invitation?.offer ?? (saved?.phase === 'cancelled' ? saved.previous : undefined));
    const oldPeer = old
      ? old.channel.a.scope === s.own.scope
        ? old.channel.b
        : old.channel.a
      : undefined;
    const canCreate =
      (!this.#recovery() ||
        this.#recovery()!.phase === 'rejoined' ||
        (this.#recovery()!.phase === 'closed' && !this.#recovery()!.next)) &&
      (s.invitation?.phase === 'active' ||
        saved?.phase === 'cancelled' ||
        stop?.phase === 'stopped') &&
      peer?.state === 'current' &&
      review &&
      review.verified.fingerprint === peer.accepted.fingerprint &&
      (saved?.phase === 'cancelled' ||
        stop?.phase === 'stopped' ||
        oldPeer?.fingerprint !== peer.accepted.fingerprint);
    if (old && !canCreate) return;
    const section = node('section');
    if (saved?.phase === 'cancelled') section.append(node('p', phases.cancelled));
    section.append(
      node('h2', '新しい端末鍵で会話を始める'),
      node(
        'p',
        '同じアカウント・端末の新しい鍵を、一方ずつ参加させます。承認すると旧会話を閉じます。双方の承認後、新しい会話を作ります。旧会話の送信待ちは転送しません。新しい端末には過去の履歴を移しません。',
      ),
    );
    if (canCreate)
      section.append(
        this.#button('鍵切り替えコードを作る', async () => {
          const endpoints = [
            { scope: s.own.scope, fingerprint: s.own.fingerprint },
            { scope: review.contact.scope, fingerprint: peer.accepted.fingerprint },
          ].sort((a, b) => (a.scope < b.scope ? -1 : 1));
          const next = {
            channel: {
              id: crypto.randomUUID(),
              group: encode(crypto.getRandomValues(new Uint8Array(16))),
              a: endpoints[0],
              b: endpoints[1],
            },
            inviter_scope: s.own.scope,
          };
          this.#checkReplacement(old!, next);
          this.#replacementProposal = { previous: old!, next };
        }),
      );
    const form = node('form'),
      label = node('label', '受け取った鍵切り替えコード'),
      code = node('textarea');
    code.rows = 4;
    code.maxLength = 8192;
    code.disabled = this.#busy;
    label.append(code);
    const inspect = node('button', '鍵切り替えコードを確認');
    inspect.type = 'submit';
    inspect.disabled = this.#busy;
    form.append(label, inspect);
    form.addEventListener('submit', (event) => {
      event.preventDefault();
      const value = code.value.trim();
      void this.#run(async () => {
        const { previous, next } = parseReplacementCode(value);
        this.#checkReplacement(previous, next);
        this.#replacementProposal = { previous, next };
      });
    });
    section.append(form);
    const proposed = this.#replacementProposal;
    if (proposed) {
      const { previous, next } = proposed;
      const retired = replacement(previous, next).retired;
      const before = node('dl');
      before.append(
        node('dt', '停止する旧会話ID'),
        node('dd', previous.channel.id),
        node('dt', '置き換える旧鍵の指紋'),
        node('dd', retired.fingerprint),
      );
      section.append(before);
      this.#reviewDetails(section, next);
      const label = node('label', '共有する鍵切り替えコード'),
        code = node('textarea');
      code.readOnly = true;
      code.rows = 4;
      code.value = replacementCode(previous, next);
      label.append(code);
      section.append(label);
      const consent = node('label'),
        check = node('input');
      check.type = 'checkbox';
      check.disabled = this.#busy;
      consent.append(
        check,
        document.createTextNode(
          '確認した新しい指紋とコードが一致し、旧会話を閉じることに同意します',
        ),
      );
      const approve = this.#button(
        '新しい鍵での会話を承認',
        async () => {
          if (!check.checked) return;
          this.#checkReplacement(previous, next);
          this.#draft = '';
          this.#onDraft?.(false);
          this.#pending = undefined;
          this.#notice = phases[(await this.#device.approveReplacement(previous, next)).phase];
          this.#replacementProposal = undefined;
        },
        true,
      );
      check.addEventListener('change', () => {
        approve.disabled = this.#busy || !check.checked;
      });
      section.append(consent, approve);
    }
    panel.append(section);
  }
  #stopConfirmation(section: HTMLElement, previous: InvitationOffer, next: InvitationOffer): void {
    section.append(node('p', `元の会話ID: ${previous.channel.id}`));
    section.append(
      node(
        'p',
        '双方が承認した後に鍵が更新された場合は、その参加先を停止してから最新の鍵で承認し直してください。旧本文は転送しません。',
      ),
    );
    const label = node('label'),
      check = node('input');
    check.type = 'checkbox';
    check.disabled = this.#busy;
    label.append(
      check,
      document.createTextNode('承認済みの参加先を停止し、最新の鍵で承認し直します'),
    );
    const button = this.#button(
      '承認済みの参加先を停止',
      async () => {
        if (!check.checked) return;
        this.#draft = '';
        this.#onDraft?.(false);
        this.#pending = undefined;
        this.#replacementProposal = undefined;
        await this.#device.stopReplacement(previous, next);
        this.#stopProposal = undefined;
        this.#notice =
          '参加先の停止を確認しました。最新の指紋と新しいコードを双方で確認してください。';
      },
      true,
    );
    check.addEventListener('change', () => {
      button.disabled = this.#busy || !check.checked;
    });
    section.append(label, button);
  }
  #closedTargets(section: HTMLElement, offers: InvitationOffer[]): void {
    if (offers.length < 2) return;
    section.append(node('p', `停止を確認した参加先: ${offers.length}件`));
    const list = node('ul');
    for (const offer of offers) list.append(node('li', offer.channel.id));
    section.append(list);
  }
  #stoppedReplacementReview(panel: HTMLElement): void {
    const s = this.#snapshot!,
      stop = s.replacement_stops.at(-1);
    if (stop && stop.phase !== 'retired') {
      const section = node('section');
      section.append(
        node('h2', '鍵更新後の参加先の停止'),
        node(
          'p',
          stop.phase === 'stopping'
            ? '停止の結果を確認中です。「同期」で同じ停止操作を再試行してください。'
            : '停止を確認しました。最新の指紋を確認し、新しい鍵切り替えコードを双方で承認してください。',
        ),
      );
      section.append(node('p', `停止する参加先ID: ${stop.next.channel.id}`));
      section.append(node('p', `元の会話ID: ${stop.previous.channel.id}`));
      this.#closedTargets(
        section,
        s.replacement_stops
          .filter((v) => v.phase !== 'retired')
          .flatMap((v) => {
            const chain = replacementStopRecoveries(v, s.recoveries, s.replacements);
            return chain.length ? chain.map((r) => r.offer) : v.phase === 'stopped' ? [v.next] : [];
          }),
      );
      panel.append(section);
      return;
    }
    if (s.invitation || s.replacements.length) return;
    const section = node('section'),
      form = node('form'),
      label = node('label', '停止する承認済みの鍵切り替えコード'),
      input = node('textarea');
    section.append(node('h2', '以前に承認した参加先を停止する'));
    input.rows = 4;
    input.maxLength = 8192;
    input.disabled = this.#busy;
    label.append(input);
    const inspect = node('button', '停止対象のコードを確認');
    inspect.type = 'submit';
    inspect.disabled = this.#busy;
    form.append(label, inspect);
    form.addEventListener('submit', (event) => {
      event.preventDefault();
      const value = input.value.trim();
      void this.#run(async () => {
        const { previous, next } = parseReplacementCode(value);
        this.#stopProposal = { previous, next };
      });
    });
    section.append(form);
    if (this.#stopProposal) {
      section.append(node('p', `停止する参加先ID: ${this.#stopProposal.next.channel.id}`));
      const list = node('dl');
      list.append(node('dt', '現在のあなたの指紋'), node('dd', s.own.fingerprint));
      for (const [i, endpoint] of [
        this.#stopProposal.next.channel.a,
        this.#stopProposal.next.channel.b,
      ].entries())
        list.append(node('dt', `以前の参加者${i + 1}の指紋`), node('dd', endpoint.fingerprint));
      section.append(list);
      this.#stopConfirmation(section, this.#stopProposal.previous, this.#stopProposal.next);
    }
    panel.append(section);
  }
  #invitationReview(panel: HTMLElement): void {
    const r = this.#recovery();
    if (r && !r.next && this.#snapshot!.trust.peer?.state === 'current') {
      const peer =
        r.offer.channel.a.scope === this.#snapshot!.own.scope
          ? r.offer.channel.b
          : r.offer.channel.a;
      if (peer.fingerprint !== this.#snapshot!.trust.peer!.accepted.fingerprint) {
        const section = node('section');
        section.append(
          node('h2', '相手の鍵が更新されています'),
          node(
            'p',
            '以前の鍵の再参加コードは使えません。確認した最新の指紋で、鍵切り替えコードを双方で承認してください。',
          ),
        );
        panel.append(section);
        return;
      }
    }
    const cancellation = r?.cancellations?.at(-1);
    if (r?.next && cancellation?.outcome === 'pending') {
      const section = node('section');
      section.append(
        node('h2', '再参加案の取り消しを確認中'),
        node('p', '通信や保存が完了していません。同じ取り消し要求で結果を確認します。'),
      );
      this.#reviewDetails(section, r.next);
      section.append(
        this.#button('取り消しの確認を再試行', async () => {
          const outcome = await this.#device.cancelRejoin(r.offer, r.next!);
          this.#proposal = undefined;
          this.#notice =
            outcome === 'cancelled'
              ? '再参加案を取り消しました。別のコードを確認して承認してください。'
              : '双方の承認が成立しています。同期で参加するか、再参加先を停止してください。';
        }),
      );
      panel.append(section);
      return;
    }
    if (r?.successor_failed && r.next) {
      const section = node('section');
      section.append(
        node('h2', '再参加をやり直す'),
        node(
          'p',
          'この再参加先は停止済み、または期限切れです。旧会話は再開しません。招待の停止を確認し、新しいコードを双方で承認してください。',
        ),
      );
      this.#reviewDetails(section, r.next);
      const label = node('label'),
        check = node('input');
      check.type = 'checkbox';
      check.disabled = this.#busy;
      label.append(
        check,
        document.createTextNode('この再参加先を停止し、新しい会話への参加をやり直します'),
      );
      const stop = this.#button(
        '再参加先を停止してやり直す',
        async () => {
          if (!check.checked) return;
          this.#proposal = undefined;
          this.#draft = '';
          this.#onDraft?.(false);
          this.#pending = undefined;
          await this.#device.recoverRejoin(r.offer, r.next!);
          this.#notice = '再参加先を停止しました。新しい参加コードを双方で確認してください。';
        },
        true,
      );
      check.addEventListener('change', () => {
        stop.disabled = this.#busy || !check.checked;
      });
      section.append(label, stop);
      panel.append(section);
      return;
    }
    if (r?.next) this.#proposal = r.next;
    const section = node('section');
    section.append(node('h2', r ? '新しい会話への再参加' : '招待を確認'));
    const snapshot = this.#snapshot!;
    if (
      !r &&
      !snapshot.invitation &&
      snapshot.trust.peer?.state === 'current' &&
      snapshot.peer_review?.verified.fingerprint === snapshot.trust.peer.accepted.fingerprint
    ) {
      const peer = snapshot.peer_review;
      section.append(
        this.#button('招待コードを作る', async () => {
          const endpoints = [
            { scope: snapshot.own.scope, fingerprint: snapshot.own.fingerprint },
            { scope: peer.contact.scope, fingerprint: peer.verified.fingerprint },
          ].sort((a, b) => (a.scope < b.scope ? -1 : 1));
          this.#proposal = invitation({
            channel: {
              id: crypto.randomUUID(),
              group: encode(crypto.getRandomValues(new Uint8Array(16))),
              a: endpoints[0]!,
              b: endpoints[1]!,
            },
            inviter_scope: snapshot.own.scope,
          });
          this.#checkOffer(this.#proposal);
        }),
      );
    }
    if (r && !r.next)
      section.append(
        this.#button('再参加コードを作る', async () => {
          this.#proposal = {
            channel: {
              ...r.offer.channel,
              id: crypto.randomUUID(),
              group: encode(crypto.getRandomValues(new Uint8Array(16))),
            },
            inviter_scope: this.#snapshot!.own.scope,
          };
        }),
      );
    const form = node('form');
    const label = node('label', '受け取った招待コード');
    const code = node('textarea');
    code.rows = 3;
    code.maxLength = 4096;
    code.disabled = this.#busy;
    label.append(code);
    const review = node('button', 'コードを確認');
    review.type = 'submit';
    review.disabled = this.#busy;
    form.append(label, review);
    form.addEventListener('submit', (event) => {
      event.preventDefault();
      const value = code.value.trim();
      void this.#run(async () => {
        const offer = parseInvitationCode(value);
        this.#checkOffer(offer);
        this.#proposal = offer;
      });
    });
    section.append(form);
    if (this.#proposal) {
      const offer = this.#proposal;
      this.#reviewDetails(section, offer);
      this.#code(section, offer);
      if (r?.next) {
        const admitted = cancellation?.outcome === 'admitted';
        section.append(
          node(
            'p',
            admitted
              ? '双方の承認が成立しているため、案の取り消しはできません。「同期」で参加を続けるか、この再参加先を停止して新しいコードでやり直せます。'
              : 'このコードで再参加を承認済みです。相手にも同じコードの承認を依頼し、「同期」で再試行してください。',
          ),
        );
        const label = node('label'),
          check = node('input');
        check.type = 'checkbox';
        check.disabled = this.#busy;
        label.append(
          check,
          document.createTextNode(
            admitted
              ? '双方が承認した再参加先を停止し、新しい会話への参加をやり直します'
              : 'この再参加案を取り消し、元の会話を停止したままにします',
          ),
        );
        const cancel = this.#button(
          admitted ? '再参加先を停止してやり直す' : 'この再参加案を取り消す',
          async () => {
            if (!check.checked) return;
            this.#proposal = undefined;
            this.#draft = '';
            this.#onDraft?.(false);
            this.#pending = undefined;
            if (admitted) {
              await this.#device.recoverRejoin(r.offer, r.next!);
              this.#notice = '再参加先を停止しました。新しい参加コードを双方で確認してください。';
            } else {
              const outcome = await this.#device.cancelRejoin(r.offer, r.next!);
              this.#notice =
                outcome === 'cancelled'
                  ? '再参加案を取り消しました。別のコードを確認して承認してください。'
                  : '双方の承認が成立しています。同期で参加するか、再参加先を停止してください。';
            }
          },
          true,
        );
        check.addEventListener('change', () => {
          cancel.disabled = this.#busy || !check.checked;
        });
        section.append(label, cancel);
      } else {
        const label = node('label');
        const check = node('input');
        check.type = 'checkbox';
        check.disabled = this.#busy;
        label.append(
          check,
          document.createTextNode(
            '別の連絡手段で確認した相手の指紋と、この会話のコードが一致しています',
          ),
        );
        const approve = this.#button(
          r ? 'このコードで再参加を承認' : 'この招待を承認',
          async () => {
            if (!check.checked) return;
            this.#checkOffer(offer);
            if (r) {
              await this.#device.approveRejoin(r.offer, offer);
              this.#notice = phases[(await this.#device.syncRejoin(r.offer, offer)).phase];
            } else {
              await this.#device.approveInvitation(offer);
              this.#notice = phases[(await this.#device.syncInvitation(offer)).phase];
            }
            this.#proposal = undefined;
          },
          true,
        );
        check.addEventListener('change', () => {
          const root = r
            ? rejoinChain(this.#snapshot!.recoveries, r.offer.channel.id)[0]
            : undefined;
          const deferred =
            root?.replacement_id &&
            this.#snapshot?.replacements.some(
              (v) => v.next.channel.id === root.replacement_id && v.phase === 'abandoned',
            );
          const trusted =
            this.#trusted() || (deferred && this.#snapshot?.trust.peer?.state === 'current');
          approve.disabled = this.#busy || !check.checked || !trusted;
        });
        section.append(label, approve);
      }
    }
    panel.append(section);
  }
  #termination(panel: HTMLElement, active: boolean): void {
    const offer = this.#snapshot!.invitation!.offer;
    if (!this.#confirmStop) {
      panel.append(
        this.#button(active ? '会話を停止する' : '招待を中止する', async () => {
          this.#confirmStop = true;
          this.#stopReason = active ? 'leave' : 'cancel_invitation';
        }),
      );
      return;
    }
    const section = node('section');
    section.append(
      node('h2', 'この会話を停止しますか'),
      node(
        'p',
        '停止した会話には戻せません。相手も送信できなくなります。再参加には双方の新しい承認が必要です。',
      ),
    );
    if (active) {
      const label = node('label', '停止する理由');
      const select = node('select');
      for (const [value, text] of [
        ['leave', '会話を終了する'],
        ['epoch_conflict', '同期の問題から復旧する'],
      ]) {
        const option = node('option', text);
        option.value = value;
        select.append(option);
      }
      select.value = this.#stopReason;
      select.addEventListener('change', () => {
        this.#stopReason = select.value as 'leave' | 'epoch_conflict';
      });
      label.append(select);
      section.append(label);
    }
    section.append(
      this.#button('停止を確定', async () => {
        const reason = this.#stopReason;
        this.#confirmStop = false;
        this.#proposal = undefined;
        this.#draft = '';
        this.#onDraft?.(false);
        this.#pending = undefined;
        await this.#device.closeConversation(offer, reason);
        this.#notice = '会話を停止しました。履歴は保持されています。';
      }),
      this.#button('戻る', async () => {
        this.#confirmStop = false;
      }),
    );
    panel.append(section);
  }
  #history(panel: HTMLElement, s: ChatSnapshot): void {
    const section = node('section');
    section.setAttribute('aria-label', 'メッセージ履歴');
    section.append(node('h2', 'メッセージ履歴'));
    const messages = [
      ...s.sent.map((m) => ({
        ...m,
        author: 'あなた',
        state: {
          queued: '送信待ち',
          accepted: 'サーバー受理済み（既読ではありません）',
          isolated: '停止した会話で保留・自動転送なし',
        }[m.status],
      })),
      ...s.received.flatMap((m) => {
        const event = m.event as { kind?: unknown; text?: unknown } | null;
        return event?.kind === 'application' && typeof event.text === 'string'
          ? [
              {
                id: m.id,
                channel_id: m.channel_id,
                position: m.position ?? 0,
                text: event.text,
                author: '相手',
                state: '受信済み',
              },
            ]
          : [];
      }),
    ].sort((a, b) => a.position - b.position);
    const list = node('ol');
    for (const message of messages) {
      const row = node('li');
      row.dataset.messageId = message.id;
      const old = message.channel_id && message.channel_id !== s.invitation?.offer.channel.id;
      row.append(
        node('p', `${message.author} · ${message.state}${old ? ' · 以前の会話' : ''}`),
        node(
          'p',
          walletPresentationLink(message.text)
            ? message.author === 'あなた'
              ? '証明書の提示を依頼しました。'
              : '証明書の提示を依頼されています。'
            : message.text,
        ),
      );
      const request = message.author === '相手' ? walletPresentationLink(message.text) : null;
      if (request) {
        const card = node('div');
        card.className = 'chat-wallet-request';
        card.append(
          node('strong', '証明書の提示依頼'),
          node('p', 'Walletで相手と提示する内容を確認してください。'),
        );
        const open = node('a', 'Walletで提示内容を確認');
        open.href = request;
        card.append(open);
        row.append(card);
      }
      list.append(row);
    }
    section.append(list);
    panel.append(section);
  }
}
