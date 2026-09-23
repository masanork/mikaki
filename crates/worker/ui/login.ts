const root = document.getElementById('login');
const button = document.getElementById('passkey');
const consent = document.getElementById('consent');
const error = document.getElementById('error');

if (
  !(root instanceof HTMLElement) ||
  !(button instanceof HTMLButtonElement) ||
  !(consent instanceof HTMLInputElement) ||
  !(error instanceof HTMLElement)
) {
  throw new Error('Invalid login page');
}

const tx = root.dataset['tx'];
const challenge = root.dataset['challenge'];
const rpId = root.dataset['rpId'];
if (!tx || !challenge || !rpId) throw new Error('Invalid login transaction');

function decode(value: string): Uint8Array<ArrayBuffer> {
  return Uint8Array.from(atob(value.replaceAll('-', '+').replaceAll('_', '/')), (char) =>
    char.charCodeAt(0),
  );
}

function encode(value: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(value)))
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replaceAll('=', '');
}

button.addEventListener('click', async () => {
  if (!consent.checked) return;
  try {
    const credential = await navigator.credentials.get({
      publicKey: {
        challenge: decode(challenge),
        rpId,
        userVerification: 'required',
        timeout: 120000,
      },
    });
    if (
      !(credential instanceof PublicKeyCredential) ||
      !(credential.response instanceof AuthenticatorAssertionResponse)
    ) {
      throw new Error('cancelled');
    }
    const response = {
      id: credential.id,
      client_data: encode(credential.response.clientDataJSON),
      authenticator_data: encode(credential.response.authenticatorData),
      signature: encode(credential.response.signature),
      user_handle: credential.response.userHandle ? encode(credential.response.userHandle) : null,
    };
    const result = await fetch('/login/finish', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tx, consent: true, response }),
    });
    if (!result.ok) throw new Error('rejected');
    const body: unknown = await result.json();
    if (
      typeof body !== 'object' ||
      body === null ||
      !('location' in body) ||
      typeof body.location !== 'string'
    ) {
      throw new Error('invalid response');
    }
    location.assign(body.location);
  } catch {
    error.hidden = false;
  }
});
