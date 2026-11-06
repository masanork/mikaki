#!/bin/sh
# Only run the debug qualification APK on a disposable emulator.
set -eu
: "${MIKAKI_ANDROID_ADB:?absolute adb path required}"
: "${MIKAKI_ANDROID_KEYSTORE_SERIAL:?emulator serial required}"
: "${MIKAKI_INSTALLATION_IPC_APK:?debug qualification APK required}"
case "$MIKAKI_ANDROID_ADB" in /*) ;; *) exit 1 ;; esac
case "$MIKAKI_ANDROID_KEYSTORE_SERIAL" in emulator-[0-9]*) ;; *) exit 1 ;; esac
adb() { "$MIKAKI_ANDROID_ADB" -s "$MIKAKI_ANDROID_KEYSTORE_SERIAL" "$@"; }
launch() { adb shell monkey -p app.tossa.mikaki -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1; }
wait_for() {
  for attempt in $(seq 1 45); do
    result=$(adb shell run-as app.tossa.mikaki cat installation-ipc-qualification.txt 2>/dev/null | tr -d '\r' || :)
    if [ "$result" = "$1" ]; then return 0; fi
    if [ "$result" = error ]; then printf 'installation IPC: failed\n' >&2; return 1; fi
    sleep 1
  done
  printf 'installation IPC: timed out awaiting %s\n' "$1" >&2
  return 1
}
adb install -r -t "$MIKAKI_INSTALLATION_IPC_APK"
adb shell am force-stop app.tossa.mikaki
adb shell run-as app.tossa.mikaki rm -f installation-ipc-qualification.txt installation-ipc-fixture.json
launch
wait_for prepared
first_pid=$(adb shell pidof app.tossa.mikaki | tr -d '\r')
test -n "$first_pid"
adb shell am force-stop app.tossa.mikaki
adb shell run-as app.tossa.mikaki rm -f installation-ipc-qualification.txt
launch
wait_for ok
second_pid=$(adb shell pidof app.tossa.mikaki | tr -d '\r')
test -n "$second_pid"
test "$first_pid" != "$second_pid"
printf 'installation IPC: recovery across process restart OK\n'
