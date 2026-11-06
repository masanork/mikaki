#!/bin/sh
# Local test CA and debug APK only; runs against a disposable emulator.
set -eu
: "${ANDROID_HOME:?Android SDK required}"
: "${ANDROID_NDK_HOME:?Android NDK required}"
: "${JAVA_HOME:?JDK required}"
: "${MIKAKI_ANDROID_ADB:?absolute adb path required}"
: "${MIKAKI_ANDROID_APP_SERIAL:?emulator serial required}"
case "$MIKAKI_ANDROID_ADB" in /*) ;; *) exit 1 ;; esac
case "$MIKAKI_ANDROID_APP_SERIAL" in emulator-[0-9]*) ;; *) exit 1 ;; esac
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
umask 077
tls_dir=$(mktemp -d "${TMPDIR:-/tmp}/mikaki-installation-https.XXXXXX")
trap 'rm -rf "$tls_dir"' EXIT HUP INT TERM
cat > "$tls_dir/server.ext" <<'EXT'
subjectAltName=DNS:auth.example
extendedKeyUsage=serverAuth
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
EXT
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$tls_dir/ca.key" >/dev/null 2>&1
openssl req -x509 -new -key "$tls_dir/ca.key" -sha256 -days 2 -subj '/CN=Mikaki local qualification CA' -addext 'basicConstraints=critical,CA:TRUE' -out "$tls_dir/ca.crt" >/dev/null 2>&1
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$tls_dir/server.key" >/dev/null 2>&1
openssl req -new -key "$tls_dir/server.key" -subj '/CN=auth.example' -out "$tls_dir/server.csr" >/dev/null 2>&1
openssl x509 -req -in "$tls_dir/server.csr" -CA "$tls_dir/ca.crt" -CAkey "$tls_dir/ca.key" -CAcreateserial -out "$tls_dir/server.crt" -days 2 -sha256 -extfile "$tls_dir/server.ext" >/dev/null 2>&1
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$tls_dir/untrusted.key" -out "$tls_dir/untrusted.crt" -days 2 -sha256 -subj '/CN=auth.example' -addext 'subjectAltName=DNS:auth.example' >/dev/null 2>&1
export MIKAKI_INSTALLATION_TEST_CA="$tls_dir/ca.crt"
export MIKAKI_INSTALLATION_TLS_DIR="$tls_dir"
(unset MIKAKI_ANDROID_APP_APK MIKAKI_ANDROID_KEYSTORE_SERIAL; cd "$root" && npm run test:installation-worker-qualification)
(cd "$root/apps/mikaki-client" && npm run tauri -- android build --debug --target aarch64 --ci --apk --features installation-https-qualification)
export MIKAKI_ANDROID_APP_APK="$root/apps/mikaki-client/src-tauri/gen/android/app/build/outputs/apk/universal/debug/app-universal-debug.apk"
(cd "$root" && node --test --test-concurrency=1 design/probes/android-device-registry/android-https-qualification.test.mjs)
