#!/bin/sh
# Test-only APK on a disposable emulator; never target a connected physical device.
set -eu
: "${MIKAKI_ANDROID_ADB:?absolute adb path required}"
: "${MIKAKI_ANDROID_KEYSTORE_SERIAL:?emulator serial required}"
: "${MIKAKI_INSTALLATION_TEST_APK:?test APK path required}"
case "$MIKAKI_ANDROID_ADB" in /*) ;; *) exit 1 ;; esac
case "$MIKAKI_ANDROID_KEYSTORE_SERIAL" in emulator-[0-9]*) ;; *) exit 1 ;; esac
id=$(python3 -c 'import secrets; print(secrets.token_hex(16))')
run() {
  "$MIKAKI_ANDROID_ADB" -s "$MIKAKI_ANDROID_KEYSTORE_SERIAL" shell am instrument -w -r \
    -e class app.mikaki.native_dpop.InstallationRecoveryProbeTest#perform \
    -e probe_id "$id" -e probe_mode "$1" \
    app.mikaki.native_dpop.test/androidx.test.runner.AndroidJUnitRunner
}
cleanup() { run cleanup >/dev/null 2>&1 || :; }
trap cleanup EXIT HUP INT TERM
"$MIKAKI_ANDROID_ADB" -s "$MIKAKI_ANDROID_KEYSTORE_SERIAL" install -r -t "$MIKAKI_INSTALLATION_TEST_APK"
for mode in create advance verify; do
  result=$(run "$mode")
  printf '%s\n' "$result" | grep -q 'OK (1 test)' || { printf '%s\n' "$result"; exit 1; }
  printf '%s: OK\n' "$mode"
done
