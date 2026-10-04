plugins {
  kotlin("jvm") version "2.2.0"
  application
}

repositories {
  mavenCentral()
  google()
}

dependencies {
  implementation("com.android.keyattestation:keyattestation:0.1-SNAPSHOT")
  implementation("com.google.code.gson:gson:2.11.0")
  implementation("com.google.protobuf:protobuf-javalite:4.28.3")
  implementation("com.google.guava:guava:33.5.0-jre")
  implementation("org.bouncycastle:bcpkix-jdk18on:1.86")
  testImplementation(kotlin("test-junit5"))
  testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.11.0")
  testRuntimeOnly("org.junit.platform:junit-platform-launcher:1.11.0")
}

kotlin { jvmToolchain(21) }

application { mainClass.set("app.mikaki.attestation.ServerKt") }

tasks.test { useJUnitPlatform() }

// Integration launcher is confined to test output; never ship fixture trust in installDist.
tasks.register("integrationClasspath") {
  dependsOn(tasks.testClasses)
  doLast {
    layout.buildDirectory
      .file("integration-classpath.txt")
      .get()
      .asFile
      .writeText(sourceSets.test.get().runtimeClasspath.asPath)
  }
}

dependencyLocking { lockAllConfigurations() }

// Format only this service; no mutation of the pinned upstream checkout.
val formatter by configurations.creating
val kotlinFiles =
  fileTree("src") { include("**/*.kt") } + files("build.gradle.kts", "settings.gradle.kts")

dependencies { formatter("com.facebook:ktfmt:0.61") }

tasks.register<JavaExec>("formatKotlin") {
  classpath = formatter
  mainClass.set("com.facebook.ktfmt.cli.Main")
  args("--google-style")
  args(kotlinFiles.files.map { it.absolutePath })
}

// Retain the upstream licence when distributing its compiled library.
distributions {
  main {
    contents {
      from(file("${System.getenv("MIKAKI_KEYATTESTATION_CHECKOUT")}/LICENSE")) {
        into("licenses/android-keyattestation")
      }
    }
  }
}
