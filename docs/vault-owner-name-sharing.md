# Owner record-v2 name sharing

The first #113 sharing slice connects one saved `personal/name` record to the
dedicated UserInfo Claim Worker and a separate consent for one connected relying
party. It uses the current Owner key and record-v2 APIs. It adds no migration,
recipient key, policy activation, RP scope change, or automatic disclosure.

After unlocking Vault, the owner explicitly opens the name-sharing panel. It
reads and decrypts the saved record again, displays that exact name and revision,
and checks the current Owner key, recipient directory and sharing policies.
Unsaved changes must be saved or discarded before approving an operation.
Saving, reloading a changed record, or deleting the name clears an outdated
sharing preview. Refresh sharing status before approving the new saved version.

The first approval encrypts only this record's key for the dedicated `userinfo`
recipient, for `oidc.userinfo.name`. It never distributes the Vault root key.
The panel separately lists active connected `private_key_jwt` clients. A second
approval authorizes one selected client to obtain this self-entered name through
UserInfo; it does not verify the person's identity. A system Grant alone cannot
release the claim. Ordinary `openid` login needs neither approval nor a name.

The panel shows the policy's maximum duration before approval and the server's
actual expiry afterward. RP release expiry is also bounded by the system Grant.
Fresh status checks compare the current record, Owner key, recipient, policy and
client/connection authority. An expired stored `active` row is not displayed as
current permission. Owners can withdraw a recorded active consent even when a
new recipient verification is unavailable.

Every prepared mutation has immutable body bytes, an operation ID and an exact
revision fence. A response lost after submission leaves editing frozen while the
owner retries that same operation. A successful receipt is historical evidence;
the panel reads current authority again before displaying a permission. A
definitively rejected operation requires a fresh preview and explicit approval.
Locking clears previews and local pending operations. Revocation stops future
release; it cannot recall plaintext already received by an application.

The production policies remain disabled. Docs currently requests only `openid`
and has no name-consuming feature. Production activation requires a named
recipient application, its actual profile-consumption contract, registered and
verified recipient material, and intended-device qualification. This slice does
not complete broader record sharing, conversation ingestion or explicit AI
write-proposal approval under #113/#115.

Local helper and browser regressions qualify the UI and retry boundaries with a
synthetic PRF. The browser panel fixture uses the real Owner Vault Worker for
encrypted record storage and controlled sharing status/response fixtures. The
separate live record-v2 UserInfo suite exercises the actual OP, Claim Worker,
Secrets Store, conditional disclosure audit and reference RP. Neither substitutes
for an intended physical passkey or a production name-consuming application.
