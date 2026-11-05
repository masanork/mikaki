#!/bin/sh
# Only run the debug qualification APK on a disposable emulator.
set -eu
: "${MIKAKI_ANDROID_ADB:?absolute adb path required}"
: "${MIKAKI_ANDROID_KEYSTORE_SERIAL:?emulator serial required}"
: "${MIKAKI_INSTALLATION_IPC_APK:?debug qualification APK required}"
case "$MIKAKI_ANDROID_ADB" in /*) ;; *) exit 1 ;; esac
case "$MIKAKI_ANDROID_KEYSTORE_SERIAL" in emulator-[0-9]*) ;; *) exit 1 ;; esac
adb() { "$MIKAKI_ANDROID_ADB" -s "$MIKAKI_ANDROID_KEYSTORE_SERIAL" "$@"; }
adb install -r -t "$MIKAKI_INSTALLATION_IPC_APK"
adb shell am force-stop app.tossa.mikaki
adb shell run-as app.tossa.mikaki rm -f installation-ipc-qualification.txt
adb shell monkey -p app.tossa.mikaki -c android.intent.category.LAUNCHER 1 >/dev/null
for attempt in $(seq 1 45); do
  result=$(adb shell run-as app.tossa.mikaki cat installation-ipc-qualification.txt 2>/dev/null | tr -d '\r' || :)
  case "$result" in ok) printf 'installation IPC: OK\n'; exit 0 ;; error) printf 'installation IPC: failed\n' >&2; exit 1 ;; esac
  sleep 1
done
printf 'installation IPC: no result\n' >&2
exit 1
