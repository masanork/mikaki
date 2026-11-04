#!/bin/sh
# Build a test-only APK containing the actual device-session Keystore class.
# The isolated project avoids modifying Tauri's shared Cargo registry checkout.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
project=$(mktemp -d "${TMPDIR:-/tmp}/mikaki-installation-fixture.XXXXXX")
plugin="$root/apps/mikaki-client/plugins/native-dpop/android"
gradle="$root/apps/mikaki-client/src-tauri/gen/android"
test -x "$gradle/gradlew"
mkdir -p "$project/fixture/src/main/java" "$project/fixture/src/androidTest/java"
cp "$plugin/src/main/java/DeviceSessionKeyStore.kt" "$project/fixture/src/main/java/"
cp "$plugin/src/main/AndroidManifest.xml" "$project/fixture/src/main/"
cp "$plugin/src/androidTest/java/InstallationProbeTest.kt" "$project/fixture/src/androidTest/java/"
cp "$plugin/src/androidTest/java/DeviceSessionKeyStoreTest.kt" "$project/fixture/src/androidTest/java/"
cp "$gradle/build.gradle.kts" "$project/build.gradle.kts"
cp "$gradle/gradle.properties" "$project/gradle.properties"
printf "include ':fixture'\n" > "$project/settings.gradle"
cat > "$project/fixture/build.gradle.kts" <<'GRADLE'
plugins { id("com.android.library"); id("org.jetbrains.kotlin.android") }
android {
    namespace = "app.mikaki.native_dpop"
    compileSdk = 37
    defaultConfig { minSdk = 24; testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner" }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_1_8; targetCompatibility = JavaVersion.VERSION_1_8 }
}
kotlin { compilerOptions { jvmTarget = org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_1_8 } }
dependencies {
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
    androidTestImplementation("androidx.test:runner:1.7.0")
}
GRADLE
"$gradle/gradlew" -p "$project" :fixture:assembleDebugAndroidTest --no-daemon --max-workers=2 >&2
printf '%s\n' "$project/fixture/build/outputs/apk/androidTest/debug/fixture-debug-androidTest.apk"
