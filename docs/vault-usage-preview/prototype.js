import { createWovenGate } from '/woven-gate.js';

const element = (id) => document.getElementById(id);
const content = element('content');
const status = element('status');
const gate = createWovenGate(
  element('fence'),
  document.querySelector('canvas'),
  'https://auth.mikaki.org',
  'https://auth.mikaki.org',
  'fence',
);
const model = {
  opened: false,
  name: '山田 太郎',
  approved: false,
  shared: false,
  ceremonyCount: 0,
  applicationAuthorized: false,
  view: 'threads',
};
const record = {
  title: '次の作業への引き継ぎ',
  text: '決めたこと\n申請書は、添付書類を揃えてから提出する。\n\n次にすること\n不足している書類を確認し、提出用の一覧を作る。',
};
function escape(value) {
  return value.replace(
    /[&<>"']/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c],
  );
}
function announce(text) {
  status.textContent = text;
}
function headingFocus() {
  content.querySelector('h2')?.focus();
}
function view(next, focus = false) {
  model.view = next;
  announce('');
  for (const button of document.querySelectorAll('[data-view]')) {
    if (button.dataset.view === next) button.setAttribute('aria-current', 'page');
    else button.removeAttribute('aria-current');
  }
  if (next === 'threads') {
    content.innerHTML = `<section class="panel"><div class="section-head"><h2 tabindex="-1">会話</h2><span class="muted">保管したやりとり</span></div><div class="rows"><button class="record" data-action="human-thread"><span>引っ越しの相談<small>あなた・佐藤さん · 人との会話</small></span><span class="arrow" aria-hidden="true">›</span></button><button class="record" data-action="ai-thread"><span>AIと申請を準備<small>あなた・申請補助AI · 書類と手続きの履歴</small></span><span class="arrow" aria-hidden="true">›</span></button></div></section>`;
  } else if (next === 'profile') {
    content.innerHTML = `<section class="panel"><div class="section-head"><h2 tabindex="-1">自分の情報</h2><span class="badge">自分で確認</span></div><div class="profile-layout"><form id="profile-form"><label>表示名<input id="name" value="${escape(model.name)}" maxlength="256" required /></label><div class="fact"><span>この情報を使うアプリ</span><strong>narashi</strong></div><div class="actions"><button class="primary">保存</button></div></form><aside class="aside"><h3>自分の情報を、自分で選ぶ。</h3><p>アプリに渡す情報は、接続と許可から選べます。</p><button data-action="connections">接続と許可を見る</button></aside></div></section>`;
    element('profile-form').addEventListener('submit', (event) => {
      event.preventDefault();
      const name = element('name').value.trim();
      if (!name) return;
      model.name = name;
      announce('保存しました。');
    });
  } else if (next === 'records') {
    content.innerHTML = `${model.approved ? '' : '<div class="task"><div><strong>AIから、保管する記録の提案</strong><small>作業の要点を、次にも使える形に。</small></div><button data-action="review">内容を確認</button></div>'}<section class="panel"><div class="section-head"><h2 tabindex="-1">記録</h2><span class="muted">アプリやAIから残した情報</span></div><div class="rows"><button class="record" data-action="comparison"><span>住まいの候補を比較<small>比較結果 · サンプルAI · 10月2日</small></span><span class="arrow" aria-hidden="true">›</span></button><button class="record" data-action="application"><span>申請書の下書き<small>成果物 · サンプルアプリ · 10月1日</small></span><span class="arrow" aria-hidden="true">›</span></button>${model.approved ? `<button class="record" data-action="recap"><span>${record.title}<small>引き継ぎ · サンプルAI · 自分で確認</small></span><span class="arrow" aria-hidden="true">›</span></button>` : ''}</div></section>`;
  } else {
    content.innerHTML = `<section class="panel"><div class="section-head"><h2 tabindex="-1">接続と許可</h2></div><h3>narashi</h3><p class="muted">表示名 · サインインに使用</p>${model.shared ? '<div class="permission"><h3>次の作業をするAI</h3><p>「次の作業への引き継ぎ」のコピー · 読むだけ · 1時間</p><p class="muted">停止すると、これからの取得を止めます。渡したコピーは取り戻せません。</p><button data-action="stop">取得を停止</button></div>' : '<div class="permission"><p class="muted">AIへの共有はありません。</p></div>'}</section>`;
  }
  if (focus) headingFocus();
}
function conversation(kind) {
  announce('');
  const ai = kind === 'ai-thread';
  content.innerHTML = `<section class="panel reading"><button data-action="threads">会話へ戻る</button><h2 tabindex="-1">${ai ? 'AIと申請を準備' : '引っ越しの相談'}</h2><p class="source">${ai ? '参加者：あなた・申請補助AI（サンプルAIサービス）' : '参加者：あなた・佐藤さん'}</p>${ai ? '<p class="muted">この会話は、参加しているAIサービスに渡す内容です。</p>' : ''}<ol class="messages"><li class="message own"><span>あなた · 10:00</span><p>${ai ? 'この手続きを進めたいです。必要な書類を整理してください。' : '来週、引っ越し先を見に行こうと思っています。'}</p></li><li class="message"><span>${ai ? '申請補助AI' : '佐藤さん'} · 10:02</span><p>${ai ? '申請書の下書きを用意しました。送信前に、内容と宛先を確認してください。' : '土曜日なら一緒に行けます。候補の比較結果も確認しましょう。'}</p></li></ol>${ai ? `<div class="linked-artifact"><h3>申請書案 v1</h3><p class="muted">宛先：サンプル窓口 · 添付なし</p><button data-action="review-application">申請内容を確認</button></div><section class="history" aria-labelledby="history-title"><h3 id="history-title">手続きの履歴</h3><ol><li><strong>下書きを作成</strong><span>申請補助AI · 申請書案 v1</span></li>${model.applicationAuthorized ? '<li><strong>本人が申請を許可</strong><span>あなた · 申請書案 v1 · サンプル窓口</span></li>' : ''}<li class="pending"><strong>${model.applicationAuthorized ? '送信・受付は未確認' : '本人の確認待ち'}</strong><span>窓口の受付通知はまだありません。</span></li></ol></section>` : '<div class="linked-artifact"><h3>この会話に関連する記録</h3><button data-action="comparison">住まいの候補を比較</button></div>'}</section>`;
  headingFocus();
}
function reviewApplication() {
  announce('');
  content.innerHTML = `<section class="panel reading"><button data-action="ai-thread">会話へ戻る</button><h2 tabindex="-1">申請内容を確認</h2><p class="source">申請補助AIが作成した下書き · v1</p><div class="review-text">申請内容：サンプル手続きの申請\n申請者：${escape(model.name)}\n宛先：サンプル窓口\n添付書類：なし</div><p class="muted">${model.applicationAuthorized ? 'この内容への許可を記録しています。送信・受付は未確認です。' : '許可する内容は、この版と宛先に限ります。'}</p><div class="actions">${model.applicationAuthorized ? '' : '<button class="primary" data-action="authorize-application">この内容で申請を許可</button>'}<button data-action="ai-thread">会話へ戻る</button></div></section>`;
  headingFocus();
}
function review() {
  announce('');
  content.innerHTML = `<section class="panel reading"><button data-action="records">記録へ戻る</button><h2 tabindex="-1">この記録を保管しますか？</h2><p class="source">提案：サンプルAI · 新しい記録</p><h3>${record.title}</h3><div class="review-text">${record.text}</div><p class="muted">AIが作った要約です。内容を確認してから保管します。</p><div class="actions"><button class="primary" data-action="accept">この内容で保管</button><button data-action="records">戻る</button></div></section>`;
  headingFocus();
}
function read(kind) {
  announce('');
  const title =
    kind === 'recap'
      ? record.title
      : kind === 'comparison'
        ? '住まいの候補を比較'
        : '申請書の下書き';
  const text =
    kind === 'recap'
      ? record.text
      : kind === 'comparison'
        ? '候補Aは通勤時間が短く、候補Bは家賃が低い。\n次回は現地を見て、周辺環境を確認する。'
        : '提出前に、必要な添付書類を確認する。\nこの下書きはまだ提出されていません。';
  content.innerHTML = `<section class="panel reading"><button data-action="records">記録へ戻る</button><h2 tabindex="-1">${title}</h2><p class="source">サンプルAI・アプリの記録 · 自分で確認</p><div class="review-text">${text}</div>${kind === 'recap' ? '<div class="actions"><button data-action="share">別のAIに渡す</button></div>' : ''}</section>`;
  headingFocus();
}
function sharing() {
  announce('');
  content.innerHTML = `<section class="panel reading"><h2 tabindex="-1">この記録をAIに渡す</h2><div class="permission"><dl><dt>接続先</dt><dd>次の作業をするAI</dd><dt>サービス</dt><dd>サンプルAIサービス</dd><dt>渡す情報</dt><dd>${record.title}</dd><dt>できること</dt><dd>読むだけ</dd><dt>期間</dt><dd>1時間</dd><dt>渡し方</dt><dd>この時点のコピー</dd></dl></div><p class="muted">渡した内容は、相手側に残ることがあります。</p><div class="actions"><button class="primary" data-action="allow">この記録だけ渡す</button><button data-action="recap">戻る</button></div></section>`;
  headingFocus();
}
element('open').addEventListener('click', () => {
  model.opened = true;
  model.ceremonyCount++;
  document.body.dataset.ceremonyCount = String(model.ceremonyCount);
  element('closed').hidden = true;
  element('workspace').hidden = false;
  element('lock').hidden = false;
  view(model.view);
  element('main').focus();
});
element('lock').addEventListener('click', () => {
  model.opened = false;
  content.replaceChildren();
  announce('');
  element('workspace').hidden = true;
  element('lock').hidden = true;
  element('closed').hidden = false;
  element('open').focus();
});
document.addEventListener('click', (event) => {
  const button = event.target instanceof Element ? event.target.closest('button') : null;
  if (!button || !model.opened) return;
  if (button.dataset.view) view(button.dataset.view, true);
  const action = button.dataset.action;
  if (['threads', 'records', 'connections'].includes(action)) view(action, true);
  if (['human-thread', 'ai-thread'].includes(action)) conversation(action);
  if (action === 'review-application') reviewApplication();
  if (action === 'authorize-application') {
    model.applicationAuthorized = true;
    conversation('ai-thread');
    announce('この内容への許可を記録しました。送信・受付は未確認です。');
  }
  if (action === 'review') review();
  if (['recap', 'comparison', 'application'].includes(action)) read(action);
  if (action === 'accept') {
    model.approved = true;
    view('records', true);
    announce('記録を保管しました。');
  }
  if (action === 'share') sharing();
  if (action === 'allow') {
    model.shared = true;
    view('connections', true);
    announce('選んだ記録の取得を許可しました。');
  }
  if (action === 'stop') {
    model.shared = false;
    view('connections', true);
    announce('これからの取得を停止しました。');
  }
});
window.addEventListener('pagehide', () => gate?.destroy());
