// Display adapter. Read summaries never become issuer-signed credentials.
// Mirrors Multipaz's Document / Credential distinction without exporting native keys.
export const documentTypes = Object.freeze({
  my_number_card: {
    title: 'マイナンバーカード',
    subtitle: 'MY NUMBER CARD',
    theme: 'sakura',
    icon: 'i-sakura',
  },
  driving_license: {
    title: '運転免許証',
    subtitle: 'DRIVING LICENCE',
    theme: 'indigo',
    icon: 'i-driving',
  },
  passport: { title: 'パスポート', subtitle: 'PASSPORT', theme: 'burgundy', icon: 'i-passport' },
});
const passportTrustStates = new Set([
  'not_configured',
  'unknown_issuer',
  'csca_verified',
  'invalid_certificate',
  'unsupported_certificate',
  'certificate_not_yet_valid',
  'certificate_expired',
  'policy_invalid',
  'clock_unavailable',
]);
function passportConsistent(report) {
  return (
    report?.state === 'consistent' &&
    passportTrustStates.has(report.issuer_trust) &&
    report.checked_data_groups?.length === 1 &&
    report.checked_data_groups[0] === 1
  );
}
function passportTrustCurrent(report, at) {
  return (
    passportConsistent(report) &&
    report.issuer_trust === 'csca_verified' &&
    Number.isSafeInteger(report.checked_at) &&
    Number.isSafeInteger(report.valid_until) &&
    report.checked_at <= at / 1000 &&
    report.checked_at < report.valid_until &&
    at / 1000 < report.valid_until
  );
}
export function passportAuthenticationNote(report, at = Date.now()) {
  if (passportConsistent(report)) {
    const scope = '写真など他のデータは未検証です。';
    if (passportTrustCurrent(report, at)) {
      const revocation = {
        good: '署名付きCRLで失効リストに掲載されていないことを確認しました。',
        revoked:
          '署名証明書またはCSCAが失効リストに掲載されています。この記録を本人確認には使えません。',
        missing: '失効情報がないため、失効状態は未確認です。',
        stale: '失効情報が古いため、失効状態は未確認です。',
        not_yet_valid: '失効情報の有効開始前のため、失効状態は未確認です。',
        invalid: '失効情報の検証に失敗しました。失効状態は未確認です。',
        unsupported: 'この失効情報の形式には未対応です。失効状態は未確認です。',
      }[report.revocation];
      if (revocation)
        return (
          'DG1のハッシュ・SOD署名・発行国CSCAへの証明書チェーンを確認しました。' +
          revocation +
          scope
        );
    }
    if (report.issuer_trust === 'csca_verified')
      return (
        'DG1のハッシュとSOD署名の整合性を確認しました。発行国・失効情報の確認期限が切れたか、検証結果の日時を確認できません。一覧を更新してください。' +
        scope
      );
    const issuer = {
      not_configured: '発行国への信頼は未確認です（CSCA未設定）。',
      unknown_issuer: '対応する発行国の信頼ルートが見つかりません。',
      certificate_expired: '署名証明書またはCSCAの有効期限が切れています。',
      certificate_not_yet_valid: '署名証明書またはCSCAの有効開始前です。',
      unsupported_certificate: 'この証明書チェーンの方式・制約には未対応です。',
      invalid_certificate: '発行国への証明書チェーンを検証できませんでした。',
      policy_invalid: '信頼ルート・失効情報の設定を確認できませんでした。',
      clock_unavailable: '端末の時刻を確認できませんでした。',
    }[report.issuer_trust];
    return 'DG1のハッシュとSOD署名の整合性を確認しました。' + issuer + scope;
  }
  if (report?.state === 'invalid')
    return 'DG1と署名情報の整合性を確認できませんでした。発行国の署名は未検証です。';
  if (report?.state === 'unsupported')
    return 'この署名方式・形式には未対応です。発行国の署名は未検証です。';
  return '署名情報を確認していません。発行国の署名は未検証です。';
}
function passportBadge(report, at) {
  if (!passportConsistent(report)) return '読取記録';
  if (passportTrustCurrent(report, at)) {
    return (
      {
        good: '発行国署名 · DG1確認',
        revoked: '失効リスト掲載',
        stale: '発行国署名 · 失効情報期限切れ',
        missing: '発行国署名 · 失効未確認',
        invalid: '発行国署名 · 失効未確認',
        unsupported: '発行国署名 · 失効未確認',
        not_yet_valid: '発行国署名 · 失効未確認',
      }[report.revocation] ?? '署名整合 · 発行国未確認'
    );
  }
  return report.issuer_trust === 'csca_verified'
    ? '署名整合 · 信頼期限切れ'
    : '署名整合 · 発行国未確認';
}
export function walletDocument(record, at = Date.now()) {
  const p = record.preview;
  const type = documentTypes[p?.document_type];
  if (!type || p.verification !== 'unverified') throw Error('invalid_document_summary');
  const expiry = p.expiry_date;
  const expired =
    typeof expiry === 'string' &&
    /^\d{4}-\d{2}-\d{2}$/.test(expiry) &&
    expiry < new Date(at).toLocaleDateString('sv-SE');
  const authentication = p.document_type === 'passport' ? record.passport_authentication : null;
  return {
    ...type,
    id: record.id,
    source: 'card_read',
    documentType: p.document_type,
    displayName: p.name,
    status: expired ? '期限切れ · 読取記録' : passportBadge(authentication, at),
    savedAt: record.saved_at,
    expiry,
    passportSaved: p.document_type === 'passport' && record.passport_saved === true,
    passportAuthentication: authentication,
    fields: {
      name: p.name,
      address: p.address,
      birthdate: p.birth_date,
      gender: p.gender,
      document_expiry_date: expiry,
    },
    // Issuance and reader trust must be established separately.
    presentation: { formats: [], available: false },
  };
}
export function walletCredential(record) {
  if (!['dc+sd-jwt', 'mso_mdoc'].includes(record.format)) throw Error('invalid_wallet_inventory');
  return {
    ...record,
    source: 'issued_credential',
    theme: 'credential',
    icon: 'i-shield',
    subtitle: record.format === 'mso_mdoc' ? 'MDOC CREDENTIAL' : 'SD-JWT CREDENTIAL',
    displayName:
      typeof record.fields?.name === 'string'
        ? record.fields.name
        : typeof record.fields?.name_mrz === 'string'
          ? record.fields.name_mrz
          : '',
    presentation: { formats: [record.format], available: true },
  };
}
