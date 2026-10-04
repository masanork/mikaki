rootProject.name = "mikaki-android-attestation-verifier"

val checkout =
  System.getenv("MIKAKI_KEYATTESTATION_CHECKOUT")
    ?: error("Set MIKAKI_KEYATTESTATION_CHECKOUT to the pinned android/keyattestation checkout")
val revision =
  providers
    .exec { commandLine("git", "-C", checkout, "rev-parse", "HEAD") }
    .standardOutput
    .asText
    .get()
    .trim()

check(revision == "55c35040a1b5b72e6d63bfb150c5c68a175c1462") {
  "Unexpected keyattestation revision"
}

check(
  providers
    .exec { commandLine("git", "-C", checkout, "status", "--porcelain", "--untracked-files=no") }
    .standardOutput
    .asText
    .get()
    .isBlank()
) {
  "Modified upstream source"
}

check(
  providers
    .exec {
      commandLine(
        "git",
        "-C",
        checkout,
        "ls-files",
        "--others",
        "--exclude-standard",
        "--",
        "src",
        "build.gradle.kts",
        "settings.gradle.kts",
        "roots.json",
      )
    }
    .standardOutput
    .asText
    .get()
    .isBlank()
) {
  "Untracked upstream source"
}

includeBuild(checkout) {
  dependencySubstitution {
    substitute(module("com.android.keyattestation:keyattestation")).using(project(":"))
  }
}
